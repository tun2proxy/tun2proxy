use crate::{
    error::Error,
    tun2proxy::{
        Connection, ConnectionManager, Direction, IncomingDataEvent, IncomingDirection,
        OutgoingDataEvent, OutgoingDirection, TcpProxy,
    },
};
use smoltcp::wire::IpProtocol;
use socks5_impl::protocol::{self, Address, UserKey};
use std::{collections::VecDeque, net::SocketAddr, rc::Rc};

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

#[repr(u8)]
#[derive(Copy, Clone, PartialEq, Debug)]
pub enum SocksVersion {
    V4 = 4,
    V5 = 5,
}

#[allow(dead_code)]
enum SocksAuthentication {
    None = 0,
    GssApi = 1,
    Password = 2,
    ChallengeHandshake = 3,
    Unassigned = 4,
    Unassigned100 = 100,
}

#[allow(dead_code)]
#[repr(u8)]
#[derive(Debug, Eq, PartialEq)]
enum SocksReplies {
    Succeeded,
    GeneralFailure,
    ConnectionDisallowed,
    NetworkUnreachable,
    ConnectionRefused,
    TtlExpired,
    CommandUnsupported,
    AddressUnsupported,
}

impl std::fmt::Display for SocksReplies {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

pub(crate) struct SocksConnection {
    connection: Connection,
    state: SocksState,
    client_inbuf: VecDeque<u8>,
    server_inbuf: VecDeque<u8>,
    client_outbuf: VecDeque<u8>,
    server_outbuf: VecDeque<u8>,
    data_buf: VecDeque<u8>,
    version: SocksVersion,
    credentials: Option<UserKey>,
}

impl SocksConnection {
    pub fn new(
        connection: &Connection,
        manager: Rc<dyn ConnectionManager>,
        version: SocksVersion,
    ) -> Result<Self, Error> {
        let mut result = Self {
            connection: connection.clone(),
            state: SocksState::ServerHello,
            client_inbuf: VecDeque::default(),
            server_inbuf: VecDeque::default(),
            client_outbuf: VecDeque::default(),
            server_outbuf: VecDeque::default(),
            data_buf: VecDeque::default(),
            version,
            credentials: manager.get_credentials().clone(),
        };
        result.send_client_hello()?;
        Ok(result)
    }

    fn send_client_hello(&mut self) -> Result<(), Error> {
        let credentials = &self.credentials;
        match self.version {
            SocksVersion::V4 => {
                self.server_outbuf
                    .extend(&[self.version as u8, protocol::Command::Connect.into()]);
                self.server_outbuf
                    .extend(self.connection.dst.port().to_be_bytes());
                let mut ip_vec = Vec::<u8>::new();
                let mut name_vec = Vec::<u8>::new();
                match &self.connection.dst {
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
            }

            SocksVersion::V5 => {
                // Providing unassigned methods is supposed to bypass China's GFW.
                // For details, refer to https://github.com/blechschmidt/tun2proxy/issues/35.
                if credentials.is_some() {
                    self.server_outbuf.extend(&[
                        self.version as u8,
                        4u8,
                        SocksAuthentication::None as u8,
                        SocksAuthentication::Password as u8,
                        SocksAuthentication::Unassigned as u8,
                        SocksAuthentication::Unassigned100 as u8,
                    ]);
                } else {
                    self.server_outbuf.extend(&[
                        self.version as u8,
                        3u8,
                        SocksAuthentication::None as u8,
                        SocksAuthentication::Unassigned as u8,
                        SocksAuthentication::Unassigned100 as u8,
                    ]);
                }
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
        if self.server_inbuf.len() < 2 {
            return Ok(());
        }
        if self.server_inbuf[0] != 5 {
            return Err("SOCKS5 server replied with an unexpected version.".into());
        }

        let auth_method = self.server_inbuf[1];

        if auth_method != SocksAuthentication::None as u8 && self.credentials.is_none()
            || (auth_method != SocksAuthentication::None as u8
                && auth_method != SocksAuthentication::Password as u8)
                && self.credentials.is_some()
        {
            return Err("SOCKS5 server requires an unsupported authentication method.".into());
        }

        self.server_inbuf.drain(0..2);

        if auth_method == SocksAuthentication::Password as u8 {
            self.state = SocksState::SendAuthData;
        } else {
            self.state = SocksState::SendRequest;
        }
        self.state_change()
    }

    fn receive_server_hello(&mut self) -> Result<(), Error> {
        match self.version {
            SocksVersion::V4 => self.receive_server_hello_socks4(),
            SocksVersion::V5 => self.receive_server_hello_socks5(),
        }
    }

    fn send_auth_data(&mut self) -> Result<(), Error> {
        let tmp = UserKey::default();
        let credentials = self.credentials.as_ref().unwrap_or(&tmp);
        self.server_outbuf
            .extend(&[1u8, credentials.username.len() as u8]);
        self.server_outbuf.extend(credentials.username.as_bytes());
        self.server_outbuf
            .extend(&[credentials.password.len() as u8]);
        self.server_outbuf.extend(credentials.password.as_bytes());
        self.state = SocksState::ReceiveAuthResponse;
        self.state_change()
    }

    fn receive_auth_data(&mut self) -> Result<(), Error> {
        if self.server_inbuf.len() < 2 {
            return Ok(());
        }
        if self.server_inbuf[0] != 1 || self.server_inbuf[1] != 0 {
            return Err("SOCKS authentication failed.".into());
        }
        self.server_inbuf.drain(0..2);
        self.state = SocksState::SendRequest;
        self.state_change()
    }

    fn receive_connection_status(&mut self) -> Result<(), Error> {
        let response = protocol::Response::rebuild_from_stream(&mut self.server_inbuf);
        if let Err(e) = &response {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                log::trace!("Waiting for more data \"{}\"...", e);
                return Ok(());
            } else {
                return Err(e.to_string().into());
            }
        }
        let response = response?;
        if response.reply != protocol::Reply::Succeeded {
            return Err(format!("SOCKS connection failed: {}", response.reply).into());
        }
        assert!(self.server_inbuf.is_empty());
        self.server_outbuf.append(&mut self.data_buf);
        self.data_buf.clear();

        self.state = SocksState::Established;
        self.state_change()
    }

    fn send_request(&mut self) -> Result<(), Error> {
        protocol::Request::new(protocol::Command::Connect, self.connection.dst.clone())
            .write_to_stream(&mut self.server_outbuf)?;
        self.state = SocksState::ReceiveResponse;
        self.state_change()
    }

    fn relay_traffic(&mut self) -> Result<(), Error> {
        self.client_outbuf.extend(self.server_inbuf.iter());
        self.server_outbuf.extend(self.client_inbuf.iter());
        self.server_inbuf.clear();
        self.client_inbuf.clear();
        Ok(())
    }

    pub fn state_change(&mut self) -> Result<(), Error> {
        match self.state {
            SocksState::ServerHello => self.receive_server_hello(),

            SocksState::SendAuthData => self.send_auth_data(),

            SocksState::ReceiveAuthResponse => self.receive_auth_data(),

            SocksState::SendRequest => self.send_request(),

            SocksState::ReceiveResponse => self.receive_connection_status(),

            SocksState::Established => self.relay_traffic(),

            _ => Ok(()),
        }
    }
}

impl TcpProxy for SocksConnection {
    fn push_data(&mut self, event: IncomingDataEvent<'_>) -> Result<(), Error> {
        let direction = event.direction;
        let buffer = event.buffer;
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
        let buffer = if dir == OutgoingDirection::ToServer {
            &mut self.server_outbuf
        } else {
            &mut self.client_outbuf
        };
        buffer.drain(0..size);
    }

    fn peek_data(&mut self, dir: OutgoingDirection) -> OutgoingDataEvent {
        let buffer = if dir == OutgoingDirection::ToServer {
            &mut self.server_outbuf
        } else {
            &mut self.client_outbuf
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
                IncomingDirection::FromClient => {
                    !self.client_inbuf.is_empty() || !self.data_buf.is_empty()
                }
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
}

pub struct SocksManager {
    server: SocketAddr,
    credentials: Option<UserKey>,
    version: SocksVersion,
}

impl ConnectionManager for SocksManager {
    fn handles_connection(&self, connection: &Connection) -> bool {
        connection.proto == IpProtocol::Tcp
    }

    fn new_connection(
        &self,
        connection: &Connection,
        manager: Rc<dyn ConnectionManager>,
    ) -> Result<Option<Box<dyn TcpProxy>>, Error> {
        if connection.proto != IpProtocol::Tcp {
            return Ok(None);
        }
        Ok(Some(Box::new(SocksConnection::new(
            connection,
            manager,
            self.version,
        )?)))
    }

    fn close_connection(&self, _: &Connection) {}

    fn get_server(&self) -> SocketAddr {
        self.server
    }

    fn get_credentials(&self) -> &Option<UserKey> {
        &self.credentials
    }
}

impl SocksManager {
    pub fn new(
        server: SocketAddr,
        version: SocksVersion,
        credentials: Option<UserKey>,
    ) -> Rc<Self> {
        Rc::new(Self {
            server,
            credentials,
            version,
        })
    }
}
