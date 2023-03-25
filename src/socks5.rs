use crate::error::Error;
use crate::tun2proxy::{
    Connection, ConnectionManager, Credentials, DestinationHost, IncomingDataEvent,
    IncomingDirection, OutgoingDataEvent, OutgoingDirection, TcpProxy,
};
use smoltcp::wire::IpProtocol;
use std::collections::VecDeque;
use std::net::{IpAddr, SocketAddr};
use std::rc::Rc;

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
#[derive(Copy, Clone)]
enum SocksAddressType {
    Ipv4 = 1,
    DomainName = 3,
    Ipv6 = 4,
}

#[derive(Copy, Clone)]
pub enum SocksVersion {
    V4 = 4,
    V5 = 5,
}

#[allow(dead_code)]
enum SocksAuthentication {
    None = 0,
    Password = 2,
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
    manager: Rc<dyn ConnectionManager>,
    version: SocksVersion,
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
            client_inbuf: Default::default(),
            server_inbuf: Default::default(),
            client_outbuf: Default::default(),
            server_outbuf: Default::default(),
            data_buf: Default::default(),
            manager,
            version,
        };
        result.send_client_hello()?;
        Ok(result)
    }

    fn send_client_hello(&mut self) -> Result<(), Error> {
        let credentials = self.manager.get_credentials();
        match self.version {
            SocksVersion::V4 => {
                self.server_outbuf.extend(&[
                    4u8,
                    1,
                    (self.connection.dst.port >> 8) as u8,
                    (self.connection.dst.port & 0xff) as u8,
                ]);
                let mut ip_vec = Vec::<u8>::new();
                let mut name_vec = Vec::<u8>::new();
                match &self.connection.dst.host {
                    DestinationHost::Address(dst_ip) => {
                        match dst_ip {
                            IpAddr::V4(ip) => ip_vec.extend(ip.octets().as_ref()),
                            IpAddr::V6(_) => return Err("SOCKS4 does not support IPv6".into()),
                        };
                    }
                    DestinationHost::Hostname(host) => {
                        ip_vec.extend(&[0, 0, 0, host.len() as u8]);
                        name_vec.extend(host.as_bytes());
                        name_vec.push(0);
                    }
                }
                self.server_outbuf.extend(ip_vec);
                if let Some(credentials) = credentials {
                    self.server_outbuf.extend(&credentials.username);
                    if !credentials.password.is_empty() {
                        self.server_outbuf.push_back(b':');
                        self.server_outbuf.extend(&credentials.password);
                    }
                }
                self.server_outbuf.push_back(0);
                self.server_outbuf.extend(name_vec);
            }

            SocksVersion::V5 => {
                if credentials.is_some() {
                    self.server_outbuf
                        .extend(&[5u8, 1, SocksAuthentication::Password as u8]);
                } else {
                    self.server_outbuf
                        .extend(&[5u8, 1, SocksAuthentication::None as u8]);
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

        if self.server_inbuf[1] != 0 && self.manager.get_credentials().is_none()
            || self.server_inbuf[1] != 2 && self.manager.get_credentials().is_some()
        {
            return Err("SOCKS5 server requires an unsupported authentication method.".into());
        }

        self.server_inbuf.drain(0..2);

        if self.manager.get_credentials().is_some() {
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
        let tmp = Credentials::default();
        let credentials = self.manager.get_credentials().as_ref().unwrap_or(&tmp);
        self.server_outbuf
            .extend(&[1u8, credentials.username.len() as u8]);
        self.server_outbuf.extend(&credentials.username);
        self.server_outbuf
            .extend(&[credentials.password.len() as u8]);
        self.server_outbuf.extend(&credentials.password);
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
        if self.server_inbuf.len() < 4 {
            return Ok(());
        }
        let ver = self.server_inbuf[0];
        let rep = self.server_inbuf[1];
        let _rsv = self.server_inbuf[2];
        let atyp = self.server_inbuf[3];

        if ver != 5 {
            return Err("SOCKS5 server replied with an unexpected version.".into());
        }

        if rep != 0 {
            return Err("SOCKS5 connection unsuccessful.".into());
        }

        if atyp != SocksAddressType::Ipv4 as u8
            && atyp != SocksAddressType::Ipv6 as u8
            && atyp != SocksAddressType::DomainName as u8
        {
            return Err("SOCKS5 server replied with unrecognized address type.".into());
        }

        if atyp == SocksAddressType::DomainName as u8 && self.server_inbuf.len() < 5 {
            return Ok(());
        }

        if atyp == SocksAddressType::DomainName as u8
            && self.server_inbuf.len() < 7 + (self.server_inbuf[4] as usize)
        {
            return Ok(());
        }

        let message_length = if atyp == SocksAddressType::Ipv4 as u8 {
            10
        } else if atyp == SocksAddressType::Ipv6 as u8 {
            22
        } else {
            7 + (self.server_inbuf[4] as usize)
        };

        self.server_inbuf.drain(0..message_length);
        self.server_outbuf.append(&mut self.data_buf);
        self.data_buf.clear();

        self.state = SocksState::Established;
        self.state_change()
    }

    fn send_request(&mut self) -> Result<(), Error> {
        self.server_outbuf.extend(&[5u8, 1, 0]);
        match &self.connection.dst.host {
            DestinationHost::Address(dst_ip) => {
                let cmd = if dst_ip.is_ipv4() {
                    SocksAddressType::Ipv4
                } else {
                    SocksAddressType::Ipv6
                };
                self.server_outbuf.extend(&[cmd as u8]);
                match dst_ip {
                    IpAddr::V4(ip) => self.server_outbuf.extend(ip.octets().as_ref()),
                    IpAddr::V6(ip) => self.server_outbuf.extend(ip.octets().as_ref()),
                };
            }
            DestinationHost::Hostname(host) => {
                self.server_outbuf
                    .extend(&[SocksAddressType::DomainName as u8, host.len() as u8]);
                self.server_outbuf.extend(host.as_bytes());
            }
        }
        self.server_outbuf.extend(&[
            (self.connection.dst.port >> 8) as u8,
            (self.connection.dst.port & 0xff) as u8,
        ]);
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
}

pub struct SocksManager {
    server: SocketAddr,
    credentials: Option<Credentials>,
    version: SocksVersion,
}

impl ConnectionManager for SocksManager {
    fn handles_connection(&self, connection: &Connection) -> bool {
        connection.proto == IpProtocol::Tcp.into()
    }

    fn new_connection(
        &self,
        connection: &Connection,
        manager: Rc<dyn ConnectionManager>,
    ) -> Result<Option<Box<dyn TcpProxy>>, Error> {
        if connection.proto != IpProtocol::Tcp.into() {
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

    fn get_credentials(&self) -> &Option<Credentials> {
        &self.credentials
    }
}

impl SocksManager {
    pub fn new(
        server: SocketAddr,
        version: SocksVersion,
        credentials: Option<Credentials>,
    ) -> Rc<Self> {
        Rc::new(Self {
            server,
            credentials,
            version,
        })
    }
}
