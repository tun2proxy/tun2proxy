use crate::tun2proxy::{
    Connection, ConnectionManager, IncomingDataEvent, IncomingDirection, OutgoingDataEvent,
    OutgoingDirection, ProxyError, TcpProxy,
};
use std::collections::VecDeque;
use std::net::{IpAddr, SocketAddr};

#[derive(Eq, PartialEq, Debug)]
#[allow(dead_code)]
enum SocksState {
    ClientHello,
    ServerHello,
    SendRequest,
    ReceiveResponse,
    Established,
}

#[allow(dead_code)]
#[repr(u8)]
#[derive(Copy, Clone)]
enum SocksAddressType {
    Ipv4 = 1,
    DomainName = 3,
    Ipv6 = 4,
}

#[allow(dead_code)]
#[repr(u8)]
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

pub struct SocksConnection {
    connection: Connection,
    state: SocksState,
    client_inbuf: VecDeque<u8>,
    server_inbuf: VecDeque<u8>,
    client_outbuf: VecDeque<u8>,
    server_outbuf: VecDeque<u8>,
    data_buf: VecDeque<u8>,
}

impl SocksConnection {
    pub fn new(connection: &Connection) -> Self {
        let mut result = Self {
            connection: *connection,
            state: SocksState::ServerHello,
            client_inbuf: Default::default(),
            server_inbuf: Default::default(),
            client_outbuf: Default::default(),
            server_outbuf: Default::default(),
            data_buf: Default::default(),
        };
        result.server_outbuf.extend(&[5u8, 1, 0]);
        result.state = SocksState::ServerHello;
        result
    }

    pub fn state_change(&mut self) -> Result<(), ProxyError> {
        let dst_ip = self.connection.dst.ip();

        match self.state {
            SocksState::ServerHello if self.server_inbuf.len() >= 2 => {
                if self.server_inbuf[0] != 5 {
                    return Err(ProxyError::new(
                        "SOCKS server replied with an unexpected version.".into(),
                    ));
                }

                if self.server_inbuf[1] != 0 {
                    return Err(ProxyError::new(
                        "SOCKS server requires an unsupported authentication method.".into(),
                    ));
                }

                self.server_inbuf.drain(0..2);

                let cmd = if dst_ip.is_ipv4() { 1 } else { 4 };
                self.server_outbuf.extend(&[5u8, 1, 0, cmd]);
                match dst_ip {
                    IpAddr::V4(ip) => self.server_outbuf.extend(ip.octets().as_ref()),
                    IpAddr::V6(ip) => self.server_outbuf.extend(ip.octets().as_ref()),
                };
                self.server_outbuf.extend(&[
                    (self.connection.dst.port() >> 8) as u8,
                    (self.connection.dst.port() & 0xff) as u8,
                ]);

                self.state = SocksState::ReceiveResponse;
                return self.state_change();
            }

            SocksState::ReceiveResponse if self.server_inbuf.len() >= 4 => {
                let ver = self.server_inbuf[0];
                let rep = self.server_inbuf[1];
                let _rsv = self.server_inbuf[2];
                let atyp = self.server_inbuf[3];

                if ver != 5 {
                    return Err(ProxyError::new(
                        "SOCKS server replied with an unexpected version.".into(),
                    ));
                }

                if rep != 0 {
                    return Err(ProxyError::new("SOCKS connection unsuccessful.".into()));
                }

                if atyp != SocksAddressType::Ipv4 as u8
                    && atyp != SocksAddressType::Ipv6 as u8
                    && atyp != SocksAddressType::DomainName as u8
                {
                    return Err(ProxyError::new(
                        "SOCKS server replied with unrecognized address type.".into(),
                    ));
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
                return self.state_change();
            }

            SocksState::Established => {
                self.client_outbuf.extend(self.server_inbuf.iter());
                self.server_outbuf.extend(self.client_inbuf.iter());
                self.server_inbuf.clear();
                self.client_inbuf.clear();
            }

            _ => {}
        }
        Ok(())
    }
}

impl TcpProxy for SocksConnection {
    fn push_data(&mut self, event: IncomingDataEvent<'_>) -> Result<(), ProxyError> {
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

pub struct Socks5Manager {
    server: std::net::SocketAddr,
    authentication: SocksAuthentication,
    username: Vec<u8>,
    password: Vec<u8>,
}

impl ConnectionManager for Socks5Manager {
    fn handles_connection(&self, connection: &Connection) -> bool {
        connection.proto == smoltcp::wire::IpProtocol::Tcp.into()
    }

    fn new_connection(&mut self, connection: &Connection) -> Option<std::boxed::Box<dyn TcpProxy>> {
        if connection.proto != smoltcp::wire::IpProtocol::Tcp.into() {
            return None;
        }
        Some(std::boxed::Box::new(SocksConnection::new(connection)))
    }

    fn close_connection(&mut self, _: &Connection) {}

    fn get_server(&self) -> SocketAddr {
        self.server
    }
}

impl Socks5Manager {
    pub fn new(server: SocketAddr) -> Self {
        Self {
            server,
            authentication: SocksAuthentication::None,
            username: Default::default(),
            password: Default::default(),
        }
    }

    #[allow(dead_code)]
    pub fn set_credentials(&mut self, username: &[u8], password: &[u8]) {
        assert!(username.len() <= 255 && password.len() <= 255);
        self.authentication = SocksAuthentication::Password;
        self.username = Vec::from(username);
        self.password = Vec::from(password);
    }
}
