use crate::tun2proxy::{Connection, TcpProxy, IncomingDirection, OutgoingDirection, OutgoingDataEvent, IncomingDataEvent, ConnectionManager};
use std::collections::VecDeque;
use std::net::SocketAddr;

#[derive(Eq, PartialEq, Debug)]
#[allow(dead_code)]
enum HttpState {
    SendRequest,
    ExpectResponse,
    Established
}

pub struct HttpConnection {
    state: HttpState,
    client_inbuf: VecDeque<u8>,
    server_inbuf: VecDeque<u8>,
    client_outbuf: VecDeque<u8>,
    server_outbuf: VecDeque<u8>,
    data_buf: VecDeque<u8>,
    crlf_state: u8
}

impl HttpConnection {
    fn new(connection: &Connection) -> Self {
        let mut result = Self {
            state: HttpState::ExpectResponse,
            client_inbuf: Default::default(),
            server_inbuf: Default::default(),
            client_outbuf: Default::default(),
            server_outbuf: Default::default(),
            data_buf: Default::default(),
            crlf_state: Default::default()
        };


        result.server_outbuf.extend(b"CONNECT ".iter());
        result.destination_to_server_outbuf(connection);
        result.server_outbuf.extend(b" HTTP/1.1\r\nHost: ".iter());
        result.destination_to_server_outbuf(connection);
        result.server_outbuf.extend(b"\r\n\r\n".iter());

        result
    }

    fn destination_to_server_outbuf(&mut self, connection: &Connection) {
        let ipv6 = connection.dst.is_ipv6();
        if ipv6 {
            self.server_outbuf.extend(b"[".iter());
        }
        self.server_outbuf.extend(connection.dst.ip().to_string().as_bytes());
        if ipv6 {
            self.server_outbuf.extend(b"]".iter());
        }
        self.server_outbuf.extend(b":".iter());
        self.server_outbuf.extend(connection.dst.port().to_string().as_bytes());
    }

    fn state_change(&mut self) {
        match self.state {
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

                        self.client_outbuf.extend(self.server_inbuf.iter());
                        self.server_outbuf.extend(self.client_inbuf.iter());
                        self.server_inbuf.clear();
                        self.client_inbuf.clear();

                        self.state = HttpState::Established;
                        return;
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
            _ => {
                unreachable!();
            }
        }
    }
}


impl TcpProxy for HttpConnection {
    fn push_data(&mut self, event: IncomingDataEvent<'_>) {
        let direction = event.direction;
        let buffer = event.buffer;
        match direction {
            IncomingDirection::FromServer => {
                self.server_inbuf.extend(buffer.iter());
            },
            IncomingDirection::FromClient => {
                if self.state == HttpState::Established {
                    self.client_inbuf.extend(buffer.iter());
                } else {
                    self.data_buf.extend(buffer.iter());
                }
            }
        }

        self.state_change();

    }

    fn consume_data(&mut self, dir: OutgoingDirection, size: usize) {
        let buffer = if dir == OutgoingDirection::ToServer
        {
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
        let event = OutgoingDataEvent {
            direction: dir,
            buffer: buffer.make_contiguous()
        };
        return event;
    }
}

pub struct HttpManager {
    server: std::net::SocketAddr,
}

impl ConnectionManager for HttpManager {
    fn handles_connection(&self, connection: &Connection) -> bool {
        connection.proto == smoltcp::wire::IpProtocol::Tcp.into()
    }

    fn new_connection(&mut self, connection: &Connection) -> Option<std::boxed::Box<dyn TcpProxy>> {
        if connection.proto != smoltcp::wire::IpProtocol::Tcp.into() {
            return None;
        }
        Some(std::boxed::Box::new(HttpConnection::new(&connection)))
    }

    fn close_connection(&mut self, _: &Connection) {}

    fn get_server(&self) -> SocketAddr {
        self.server
    }
}

impl HttpManager {
    pub fn new(server: SocketAddr) -> Self {
        Self {
            server,
        }
    }
}