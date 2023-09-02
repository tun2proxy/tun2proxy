use crate::{
    error::{Error, Result},
    tun2proxy::{
        ConnectionInfo, ConnectionManager, Direction, IncomingDataEvent, IncomingDirection, OutgoingDataEvent,
        OutgoingDirection, ProxyHandler,
    },
};
use socks5_impl::protocol::{self, handshake, password_method, Address, AuthMethod, StreamOperation, UserKey, Version};
use std::{collections::VecDeque, convert::TryFrom, net::SocketAddr};

#[derive(Eq, PartialEq, Debug)]
#[allow(dead_code)]
enum SocksState {
    ClientHello,
    ServerHello,
    SendAuthData,
    ReceiveAuthResponse,
    SendRequest,
    ReceiveResponse,
    Established,
}

struct SocksProxyImpl {
    info: ConnectionInfo,
    state: SocksState,
    client_inbuf: VecDeque<u8>,
    server_inbuf: VecDeque<u8>,
    client_outbuf: VecDeque<u8>,
    server_outbuf: VecDeque<u8>,
    data_buf: VecDeque<u8>,
    version: Version,
    credentials: Option<UserKey>,
    command: protocol::Command,
    udp_associate: Option<SocketAddr>,
}

impl SocksProxyImpl {
    fn new(
        info: &ConnectionInfo,
        credentials: Option<UserKey>,
        version: Version,
        command: protocol::Command,
    ) -> Result<Self> {
        let mut result = Self {
            info: info.clone(),
            state: SocksState::ServerHello,
            client_inbuf: VecDeque::default(),
            server_inbuf: VecDeque::default(),
            client_outbuf: VecDeque::default(),
            server_outbuf: VecDeque::default(),
            data_buf: VecDeque::default(),
            version,
            credentials,
            command,
            udp_associate: None,
        };
        result.send_client_hello()?;
        Ok(result)
    }

    fn send_client_hello_socks4(&mut self) -> Result<(), Error> {
        let credentials = &self.credentials;
        self.server_outbuf
            .extend(&[self.version as u8, protocol::Command::Connect.into()]);
        self.server_outbuf.extend(self.info.dst.port().to_be_bytes());
        let mut ip_vec = Vec::<u8>::new();
        let mut name_vec = Vec::<u8>::new();
        match &self.info.dst {
            Address::SocketAddress(SocketAddr::V4(addr)) => {
                ip_vec.extend(addr.ip().octets().as_ref());
            }
            Address::SocketAddress(SocketAddr::V6(_)) => {
                return Err("SOCKS4 does not support IPv6".into());
            }
            Address::DomainAddress(host, _) => {
                ip_vec.extend(&[0, 0, 0, host.len() as u8]);
                name_vec.extend(host.as_bytes());
                name_vec.push(0);
            }
        }
        self.server_outbuf.extend(ip_vec);
        if let Some(credentials) = credentials {
            self.server_outbuf.extend(credentials.username.as_bytes());
            if !credentials.password.is_empty() {
                self.server_outbuf.push_back(b':');
                self.server_outbuf.extend(credentials.password.as_bytes());
            }
        }
        self.server_outbuf.push_back(0);
        self.server_outbuf.extend(name_vec);
        Ok(())
    }

    fn send_client_hello_socks5(&mut self) -> Result<(), Error> {
        let credentials = &self.credentials;
        // Providing unassigned methods is supposed to bypass China's GFW.
        // For details, refer to https://github.com/blechschmidt/tun2proxy/issues/35.
        #[rustfmt::skip]
        let mut methods = vec![
            AuthMethod::NoAuth,
            AuthMethod::from(4_u8),
            AuthMethod::from(100_u8),
        ];
        if credentials.is_some() {
            methods.push(AuthMethod::UserPass);
        }
        handshake::Request::new(methods).write_to_stream(&mut self.server_outbuf)?;
        Ok(())
    }

    fn send_client_hello(&mut self) -> Result<(), Error> {
        match self.version {
            Version::V4 => {
                self.send_client_hello_socks4()?;
            }
            Version::V5 => {
                self.send_client_hello_socks5()?;
            }
        }
        self.state = SocksState::ServerHello;
        Ok(())
    }

    fn receive_server_hello_socks4(&mut self) -> Result<(), Error> {
        if self.server_inbuf.len() < 8 {
            return Ok(());
        }

        if self.server_inbuf[1] != 0x5a {
            return Err("SOCKS4 server replied with an unexpected reply code.".into());
        }

        self.server_inbuf.drain(0..8);
        self.server_outbuf.append(&mut self.data_buf);
        self.data_buf.clear();

        self.state = SocksState::Established;
        self.state_change()
    }

    fn receive_server_hello_socks5(&mut self) -> Result<(), Error> {
        let response = handshake::Response::retrieve_from_stream(&mut self.server_inbuf.clone());
        if let Err(e) = &response {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                log::trace!("receive_server_hello_socks5 needs more data \"{}\"...", e);
                return Ok(());
            } else {
                return Err(e.to_string().into());
            }
        }
        let respones = response?;
        self.server_inbuf.drain(0..respones.len());
        let auth_method = respones.method;

        if auth_method != AuthMethod::NoAuth && self.credentials.is_none()
            || (auth_method != AuthMethod::NoAuth && auth_method != AuthMethod::UserPass) && self.credentials.is_some()
        {
            return Err("SOCKS5 server requires an unsupported authentication method.".into());
        }

        self.state = if auth_method == AuthMethod::UserPass {
            SocksState::SendAuthData
        } else {
            SocksState::SendRequest
        };
        self.state_change()
    }

    fn receive_server_hello(&mut self) -> Result<(), Error> {
        match self.version {
            Version::V4 => self.receive_server_hello_socks4(),
            Version::V5 => self.receive_server_hello_socks5(),
        }
    }

    fn send_auth_data(&mut self) -> Result<(), Error> {
        let tmp = UserKey::default();
        let credentials = self.credentials.as_ref().unwrap_or(&tmp);
        let request = password_method::Request::new(&credentials.username, &credentials.password);
        request.write_to_stream(&mut self.server_outbuf)?;
        self.state = SocksState::ReceiveAuthResponse;
        self.state_change()
    }

    fn receive_auth_data(&mut self) -> Result<(), Error> {
        use password_method::Response;
        let response = Response::retrieve_from_stream(&mut self.server_inbuf.clone());
        if let Err(e) = &response {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                log::trace!("receive_auth_data needs more data \"{}\"...", e);
                return Ok(());
            } else {
                return Err(e.to_string().into());
            }
        }
        let response = response?;
        self.server_inbuf.drain(0..response.len());
        if response.status != password_method::Status::Succeeded {
            return Err(format!("SOCKS authentication failed: {:?}", response.status).into());
        }
        self.state = SocksState::SendRequest;
        self.state_change()
    }

    fn send_request_socks5(&mut self) -> Result<(), Error> {
        let addr = if self.command == protocol::Command::UdpAssociate {
            Address::unspecified()
        } else {
            self.info.dst.clone()
        };
        protocol::Request::new(self.command, addr).write_to_stream(&mut self.server_outbuf)?;
        self.state = SocksState::ReceiveResponse;
        self.state_change()
    }

    fn receive_connection_status(&mut self) -> Result<(), Error> {
        let response = protocol::Response::retrieve_from_stream(&mut self.server_inbuf.clone());
        if let Err(e) = &response {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                log::trace!("receive_connection_status needs more data \"{}\"...", e);
                return Ok(());
            } else {
                return Err(e.to_string().into());
            }
        }
        let response = response?;
        self.server_inbuf.drain(0..response.len());
        if response.reply != protocol::Reply::Succeeded {
            return Err(format!("SOCKS connection failed: {}", response.reply).into());
        }
        if self.command == protocol::Command::UdpAssociate {
            self.udp_associate = Some(SocketAddr::try_from(&response.address)?);
            assert!(self.data_buf.is_empty());
            log::trace!("UDP associate recieved address {}", response.address);
        }

        self.server_outbuf.append(&mut self.data_buf);
        self.data_buf.clear();

        self.state = SocksState::Established;
        self.state_change()
    }

    fn relay_traffic(&mut self) -> Result<(), Error> {
        self.client_outbuf.extend(self.server_inbuf.iter());
        self.server_outbuf.extend(self.client_inbuf.iter());
        self.server_inbuf.clear();
        self.client_inbuf.clear();
        Ok(())
    }

    fn state_change(&mut self) -> Result<(), Error> {
        match self.state {
            SocksState::ServerHello => self.receive_server_hello(),

            SocksState::SendAuthData => self.send_auth_data(),

            SocksState::ReceiveAuthResponse => self.receive_auth_data(),

            SocksState::SendRequest => self.send_request_socks5(),

            SocksState::ReceiveResponse => self.receive_connection_status(),

            SocksState::Established => self.relay_traffic(),

            _ => Ok(()),
        }
    }
}

impl ProxyHandler for SocksProxyImpl {
    fn get_connection_info(&self) -> &ConnectionInfo {
        &self.info
    }

    fn push_data(&mut self, event: IncomingDataEvent<'_>) -> Result<(), Error> {
        let IncomingDataEvent { direction, buffer } = event;
        match direction {
            IncomingDirection::FromServer => {
                self.server_inbuf.extend(buffer.iter());
            }
            IncomingDirection::FromClient => {
                if self.state == SocksState::Established {
                    self.client_inbuf.extend(buffer.iter());
                } else {
                    self.data_buf.extend(buffer.iter());
                }
            }
        }

        self.state_change()
    }

    fn consume_data(&mut self, dir: OutgoingDirection, size: usize) {
        let buffer = match dir {
            OutgoingDirection::ToServer => &mut self.server_outbuf,
            OutgoingDirection::ToClient => &mut self.client_outbuf,
        };
        buffer.drain(0..size);
    }

    fn peek_data(&mut self, dir: OutgoingDirection) -> OutgoingDataEvent {
        let buffer = match dir {
            OutgoingDirection::ToServer => &mut self.server_outbuf,
            OutgoingDirection::ToClient => &mut self.client_outbuf,
        };
        OutgoingDataEvent {
            direction: dir,
            buffer: buffer.make_contiguous(),
        }
    }

    fn connection_established(&self) -> bool {
        self.state == SocksState::Established
    }

    fn have_data(&mut self, dir: Direction) -> bool {
        match dir {
            Direction::Incoming(incoming) => match incoming {
                IncomingDirection::FromServer => !self.server_inbuf.is_empty(),
                IncomingDirection::FromClient => !self.client_inbuf.is_empty() || !self.data_buf.is_empty(),
            },
            Direction::Outgoing(outgoing) => match outgoing {
                OutgoingDirection::ToServer => !self.server_outbuf.is_empty(),
                OutgoingDirection::ToClient => !self.client_outbuf.is_empty(),
            },
        }
    }

    fn reset_connection(&self) -> bool {
        false
    }

    fn get_udp_associate(&self) -> Option<SocketAddr> {
        self.udp_associate
    }
}

pub(crate) struct SocksProxyManager {
    server: SocketAddr,
    credentials: Option<UserKey>,
    version: Version,
}

impl ConnectionManager for SocksProxyManager {
    fn new_proxy_handler(&self, info: &ConnectionInfo, udp_associate: bool) -> Result<Box<dyn ProxyHandler>> {
        use socks5_impl::protocol::Command::{Connect, UdpAssociate};
        let command = if udp_associate { UdpAssociate } else { Connect };
        let credentials = self.credentials.clone();
        Ok(Box::new(SocksProxyImpl::new(info, credentials, self.version, command)?))
    }

    fn get_server_addr(&self) -> SocketAddr {
        self.server
    }
}

impl SocksProxyManager {
    pub(crate) fn new(server: SocketAddr, version: Version, credentials: Option<UserKey>) -> Self {
        Self {
            server,
            credentials,
            version,
        }
    }
}
