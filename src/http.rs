use crate::error::Error;
use crate::tun2proxy::{
    Connection, ConnectionManager, Direction, IncomingDataEvent, IncomingDirection,
    OutgoingDataEvent, OutgoingDirection, TcpProxy,
};
use crate::Credentials;
use base64::Engine;
use smoltcp::wire::IpProtocol;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::rc::Rc;

#[derive(Eq, PartialEq, Debug)]
#[allow(dead_code)]
enum HttpState {
    SendRequest,
    ExpectStatusCode,
    ExpectResponse,
    Established,
}

pub struct HttpConnection {
    state: HttpState,
    client_inbuf: VecDeque<u8>,
    server_inbuf: VecDeque<u8>,
    client_outbuf: VecDeque<u8>,
    server_outbuf: VecDeque<u8>,
    data_buf: VecDeque<u8>,
    crlf_state: u8,
}

impl HttpConnection {
    fn new(connection: &Connection, manager: Rc<dyn ConnectionManager>) -> Self {
        let mut server_outbuf: VecDeque<u8> = VecDeque::new();
        {
            let credentials = manager.get_credentials();
            server_outbuf.extend(b"CONNECT ".iter());
            server_outbuf.extend(connection.dst.to_string().as_bytes());
            server_outbuf.extend(b" HTTP/1.1\r\nHost: ".iter());
            server_outbuf.extend(connection.dst.to_string().as_bytes());
            server_outbuf.extend(b"\r\n".iter());
            if let Some(credentials) = credentials {
                server_outbuf.extend(b"Proxy-Authorization: Basic ");
                let mut auth_plain = credentials.username.clone();
                auth_plain.extend(b":".iter());
                auth_plain.extend(&credentials.password);
                let auth_b64 = base64::engine::general_purpose::STANDARD.encode(auth_plain);
                server_outbuf.extend(auth_b64.as_bytes().iter());
                server_outbuf.extend(b"\r\n".iter());
            }
            server_outbuf.extend(b"\r\n".iter());
        }

        Self {
            state: HttpState::ExpectStatusCode,
            client_inbuf: Default::default(),
            server_inbuf: Default::default(),
            client_outbuf: Default::default(),
            server_outbuf,
            data_buf: Default::default(),
            crlf_state: Default::default(),
        }
    }

    fn state_change(&mut self) -> Result<(), Error> {
        let http_len = "HTTP/1.1 200".len();
        match self.state {
            HttpState::ExpectStatusCode if self.server_inbuf.len() > http_len => {
                let status_line: Vec<u8> =
                    self.server_inbuf.range(0..http_len + 1).copied().collect();
                let slice = &status_line.as_slice()[0.."HTTP/1.1 2".len()];
                if slice != b"HTTP/1.1 2" && slice != b"HTTP/1.0 2"
                    || self.server_inbuf[http_len] != b' '
                {
                    let status_str = String::from_utf8_lossy(&status_line.as_slice()[0..http_len]);
                    let e =
                        format!("Expected success status code. Server replied with {status_str}.");
                    return Err(e.into());
                }
                self.state = HttpState::ExpectResponse;
                return self.state_change();
            }
            HttpState::ExpectResponse => {
                let mut counter = 0usize;
                for b_ref in self.server_inbuf.iter() {
                    let b = *b_ref;
                    if b == b'\n' {
                        self.crlf_state += 1;
                    } else if b != b'\r' {
                        self.crlf_state = 0;
                    }
                    counter += 1;

                    if self.crlf_state == 2 {
                        self.server_inbuf.drain(0..counter);

                        self.server_outbuf.append(&mut self.data_buf);
                        self.data_buf.clear();

                        self.state = HttpState::Established;
                        return self.state_change();
                    }
                }

                self.server_inbuf.drain(0..counter);
            }
            HttpState::Established => {
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

impl TcpProxy for HttpConnection {
    fn push_data(&mut self, event: IncomingDataEvent<'_>) -> Result<(), Error> {
        let direction = event.direction;
        let buffer = event.buffer;
        match direction {
            IncomingDirection::FromServer => {
                self.server_inbuf.extend(buffer.iter());
            }
            IncomingDirection::FromClient => {
                if self.state == HttpState::Established {
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
        self.state == HttpState::Established
    }

    fn have_data(&mut self, dir: Direction) -> bool {
        match dir {
            Direction::Incoming(incoming) => match incoming {
                IncomingDirection::FromServer => self.server_inbuf.len() > 0,
                IncomingDirection::FromClient => {
                    self.client_inbuf.len() > 0 || self.data_buf.len() > 0
                }
            },
            Direction::Outgoing(outgoing) => match outgoing {
                OutgoingDirection::ToServer => self.server_outbuf.len() > 0,
                OutgoingDirection::ToClient => self.client_outbuf.len() > 0,
            },
        }
    }
}

pub(crate) struct HttpManager {
    server: SocketAddr,
    credentials: Option<Credentials>,
}

impl ConnectionManager for HttpManager {
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
        Ok(Some(Box::new(HttpConnection::new(connection, manager))))
    }

    fn close_connection(&self, _: &Connection) {}

    fn get_server(&self) -> SocketAddr {
        self.server
    }

    fn get_credentials(&self) -> &Option<Credentials> {
        &self.credentials
    }
}

impl HttpManager {
    pub fn new(server: SocketAddr, credentials: Option<Credentials>) -> Rc<Self> {
        Rc::new(Self {
            server,
            credentials,
        })
    }
}
