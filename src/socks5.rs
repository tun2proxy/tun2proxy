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
}

impl SocksConnection {
    pub fn new(connection: &Connection, manager: Rc<dyn ConnectionManager>) -> Self {
        let mut result = Self {
            connection: connection.clone(),
            state: SocksState::ServerHello,
            client_inbuf: Default::default(),
            server_inbuf: Default::default(),
            client_outbuf: Default::default(),
            server_outbuf: Default::default(),
            data_buf: Default::default(),
            manager,
        };
        result.send_client_hello();
        result
    }

    fn send_client_hello(&mut self) {
        let credentials = self.manager.get_credentials();
        if credentials.is_some() {
            self.server_outbuf
                .extend(&[5u8, 1, SocksAuthentication::Password as u8]);
        } else {
            self.server_outbuf
                .extend(&[5u8, 1, SocksAuthentication::None as u8]);
        }
        self.state = SocksState::ServerHello;
    }

    fn receive_server_hello(&mut self) -> Result<(), Error> {
        if self.server_inbuf.len() < 2 {
            return Ok(());
        }
        if self.server_inbuf[0] != 5 {
            return Err("SOCKS server replied with an unexpected version.".into());
        }

        if self.server_inbuf[1] != 0 && self.manager.get_credentials().is_none()
            || self.server_inbuf[1] != 2 && self.manager.get_credentials().is_some()
        {
            return Err("SOCKS server requires an unsupported authentication method.".into());
        }

        self.server_inbuf.drain(0..2);

        if self.manager.get_credentials().is_some() {
            self.state = SocksState::SendAuthData;
        } else {
            self.state = SocksState::SendRequest;
        }
        self.state_change()
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
            return Err("SOCKS server replied with an unexpected version.".into());
        }

        if rep != 0 {
            return Err("SOCKS connection unsuccessful.".into());
        }

        if atyp != SocksAddressType::Ipv4 as u8
            && atyp != SocksAddressType::Ipv6 as u8
            && atyp != SocksAddressType::DomainName as u8
        {
            return Err("SOCKS server replied with unrecognized address type.".into());
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

    pub fn state_change(&mut self) -> Result<(), Error> {
        match self.state {
            SocksState::ServerHello => self.receive_server_hello(),

            SocksState::SendAuthData => self.send_auth_data(),

            SocksState::ReceiveAuthResponse => self.receive_auth_data(),

            SocksState::SendRequest => self.send_request(),

            SocksState::ReceiveResponse => self.receive_connection_status(),

            SocksState::Established => {
                self.client_outbuf.extend(self.server_inbuf.iter());
                self.server_outbuf.extend(self.client_inbuf.iter());
                self.server_inbuf.clear();
                self.client_inbuf.clear();
                Ok(())
            }

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

pub struct Socks5Manager {
    server: SocketAddr,
    credentials: Option<Credentials>,
}

impl ConnectionManager for Socks5Manager {
    fn handles_connection(&self, connection: &Connection) -> bool {
        connection.proto == IpProtocol::Tcp
    }

    fn new_connection(
        &self,
        connection: &Connection,
        manager: Rc<dyn ConnectionManager>,
    ) -> Option<Box<dyn TcpProxy>> {
        if connection.proto != IpProtocol::Tcp {
            return None;
        }
        Some(Box::new(SocksConnection::new(connection, manager)))
    }

    fn close_connection(&self, _: &Connection) {}

    fn get_server(&self) -> SocketAddr {
        self.server
    }

    fn get_credentials(&self) -> &Option<Credentials> {
        &self.credentials
    }
}

impl Socks5Manager {
    pub fn new(server: SocketAddr, credentials: Option<Credentials>) -> Rc<Self> {
        Rc::new(Self {
            server,
            credentials,
        })
    }
}
