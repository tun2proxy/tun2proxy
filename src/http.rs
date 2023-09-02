use crate::{
    error::Error,
    tun2proxy::{
        ConnectionInfo, ConnectionManager, Direction, IncomingDataEvent, IncomingDirection, OutgoingDataEvent,
        OutgoingDirection, ProxyHandler,
    },
};
use base64::Engine;
use httparse::Response;
use smoltcp::wire::IpProtocol;
use socks5_impl::protocol::UserKey;
use std::{
    cell::RefCell,
    collections::{hash_map::RandomState, HashMap, VecDeque},
    iter::FromIterator,
    net::SocketAddr,
    rc::Rc,
    str,
};
use unicase::UniCase;

#[derive(Eq, PartialEq, Debug)]
#[allow(dead_code)]
enum AuthenticationScheme {
    None,
    Basic,
    Digest,
}

#[derive(Eq, PartialEq, Debug)]
#[allow(dead_code)]
enum HttpState {
    SendRequest,
    ExpectResponseHeaders,
    ExpectResponse,
    Reset,
    Established,
}

pub(crate) type DigestState = digest_auth::WwwAuthenticateHeader;

pub struct HttpConnection {
    state: HttpState,
    client_inbuf: VecDeque<u8>,
    server_inbuf: VecDeque<u8>,
    client_outbuf: VecDeque<u8>,
    server_outbuf: VecDeque<u8>,
    data_buf: VecDeque<u8>,
    crlf_state: u8,
    counter: usize,
    skip: usize,
    digest_state: Rc<RefCell<Option<DigestState>>>,
    before: bool,
    credentials: Option<UserKey>,
    info: ConnectionInfo,
}

static PROXY_AUTHENTICATE: &str = "Proxy-Authenticate";
static PROXY_AUTHORIZATION: &str = "Proxy-Authorization";
static CONNECTION: &str = "Connection";
static TRANSFER_ENCODING: &str = "Transfer-Encoding";
static CONTENT_LENGTH: &str = "Content-Length";

impl HttpConnection {
    fn new(
        info: &ConnectionInfo,
        credentials: Option<UserKey>,
        digest_state: Rc<RefCell<Option<DigestState>>>,
    ) -> Result<Self, Error> {
        let mut res = Self {
            state: HttpState::ExpectResponseHeaders,
            client_inbuf: VecDeque::default(),
            server_inbuf: VecDeque::default(),
            client_outbuf: VecDeque::default(),
            server_outbuf: VecDeque::default(),
            data_buf: VecDeque::default(),
            skip: 0,
            counter: 0,
            crlf_state: 0,
            digest_state,
            before: false,
            credentials,
            info: info.clone(),
        };

        res.send_tunnel_request()?;
        Ok(res)
    }

    fn send_tunnel_request(&mut self) -> Result<(), Error> {
        self.server_outbuf.extend(b"CONNECT ");
        self.server_outbuf.extend(self.info.dst.to_string().as_bytes());
        self.server_outbuf.extend(b" HTTP/1.1\r\nHost: ");
        self.server_outbuf.extend(self.info.dst.to_string().as_bytes());
        self.server_outbuf.extend(b"\r\n");

        self.send_auth_data(if self.digest_state.borrow().is_none() {
            AuthenticationScheme::Basic
        } else {
            AuthenticationScheme::Digest
        })?;

        self.server_outbuf.extend(b"\r\n");
        Ok(())
    }

    fn send_auth_data(&mut self, scheme: AuthenticationScheme) -> Result<(), Error> {
        let Some(credentials) = &self.credentials else {
            return Ok(());
        };

        match scheme {
            AuthenticationScheme::Digest => {
                let uri = self.info.dst.to_string();

                let context = digest_auth::AuthContext::new_with_method(
                    &credentials.username,
                    &credentials.password,
                    &uri,
                    Option::<&'_ [u8]>::None,
                    digest_auth::HttpMethod::CONNECT,
                );

                let mut state = self.digest_state.borrow_mut();
                let response = state.as_mut().unwrap().respond(&context)?;

                self.server_outbuf
                    .extend(format!("{}: {}\r\n", PROXY_AUTHORIZATION, response.to_header_string()).as_bytes());
            }
            AuthenticationScheme::Basic => {
                let cred = format!("{}:{}", credentials.username, credentials.password);
                let auth_b64 = base64::engine::general_purpose::STANDARD.encode(cred);
                self.server_outbuf
                    .extend(format!("{}: Basic {}\r\n", PROXY_AUTHORIZATION, auth_b64).as_bytes());
            }
            AuthenticationScheme::None => {}
        }

        Ok(())
    }

    fn state_change(&mut self) -> Result<(), Error> {
        match self.state {
            HttpState::ExpectResponseHeaders => {
                while self.counter < self.server_inbuf.len() {
                    let b = self.server_inbuf[self.counter];
                    if b == b'\n' {
                        self.crlf_state += 1;
                    } else if b != b'\r' {
                        self.crlf_state = 0;
                    }

                    self.counter += 1;
                    if self.crlf_state == 2 {
                        break;
                    }
                }

                if self.crlf_state != 2 {
                    // Waiting for the end of the headers yet
                    return Ok(());
                }

                self.counter = 0;
                self.crlf_state = 0;

                let mut headers = [httparse::EMPTY_HEADER; 16];
                let mut res = Response::new(&mut headers);

                // First make the buffer contiguous
                let slice = self.server_inbuf.make_contiguous();
                let status = res.parse(slice)?;
                if status.is_partial() {
                    // TODO: Optimize in order to detect 200
                    return Ok(());
                }
                let len = status.unwrap();
                let status_code = res.code.unwrap();
                let version = res.version.unwrap();

                if status_code == 200 {
                    // Connection successful
                    self.state = HttpState::Established;
                    self.server_inbuf.clear();

                    self.server_outbuf.append(&mut self.data_buf);
                    self.data_buf.clear();

                    return self.state_change();
                }

                if status_code != 407 {
                    let e = format!(
                        "Expected success status code. Server replied with {} [Reason: {}].",
                        status_code,
                        res.reason.unwrap()
                    );
                    return Err(e.into());
                }

                let headers_map: HashMap<UniCase<&str>, &[u8], RandomState> =
                    HashMap::from_iter(headers.map(|x| (UniCase::new(x.name), x.value)));

                let Some(auth_data) = headers_map.get(&UniCase::new(PROXY_AUTHENTICATE)) else {
                    return Err("Proxy requires auth but doesn't send it datails".into());
                };

                if !auth_data[..6].eq_ignore_ascii_case(b"digest") {
                    // Fail to auth and the scheme isn't in the
                    // supported auth method schemes
                    return Err("Bad credentials".into());
                }

                // Analize challenge params
                let data = str::from_utf8(auth_data)?;
                let state = digest_auth::parse(data)?;
                if self.before && !state.stale {
                    return Err("Bad credentials".into());
                }

                // Update the digest state
                self.digest_state.replace(Some(state));
                self.before = true;

                let closed = match headers_map.get(&UniCase::new(CONNECTION)) {
                    Some(conn_header) => conn_header.eq_ignore_ascii_case(b"close"),
                    None => false,
                };

                if closed || version == 0 {
                    // Close mio stream connection and reset it
                    // Reset all the buffers
                    self.server_inbuf.clear();
                    self.server_outbuf.clear();
                    self.send_tunnel_request()?;

                    self.state = HttpState::Reset;
                    return Ok(());
                }

                // The HTTP/1.1 expected to be keep alive waiting for the next frame so, we must
                // compute the lenght of the response in order to detect the next frame (response)
                // [RFC-9112](https://datatracker.ietf.org/doc/html/rfc9112#body.content-length)

                // Transfer-Encoding isn't supported yet
                if headers_map.get(&UniCase::new(TRANSFER_ENCODING)).is_some() {
                    unimplemented!("Header Transfer-Encoding not supported");
                }

                let content_length = match headers_map.get(&UniCase::new(CONTENT_LENGTH)) {
                    Some(v) => {
                        let value = str::from_utf8(v)?;

                        // https://www.rfc-editor.org/rfc/rfc9110#section-5.6.1
                        match value.parse::<usize>() {
                            Ok(x) => x,
                            Err(_) => {
                                let mut it = value.split(',').map(|x| x.parse::<usize>());
                                let f = it.next().unwrap()?;
                                for k in it {
                                    if k? != f {
                                        return Err("Malformed response".into());
                                    }
                                }
                                f
                            }
                        }
                    }
                    None => {
                        // Close the connection by information miss
                        self.server_inbuf.clear();
                        self.server_outbuf.clear();
                        self.send_tunnel_request()?;

                        self.state = HttpState::Reset;
                        return Ok(());
                    }
                };

                // Handshake state
                self.state = HttpState::ExpectResponse;
                self.skip = content_length + len;

                return self.state_change();
            }
            HttpState::ExpectResponse => {
                if self.skip > 0 {
                    let cnt = self.skip.min(self.server_inbuf.len());
                    self.server_inbuf.drain(..cnt);
                    self.skip -= cnt;
                }

                if self.skip == 0 {
                    // Expected to the server_inbuff to be empty

                    // self.server_outbuf.append(&mut self.data_buf);
                    // self.data_buf.clear();
                    self.send_tunnel_request()?;
                    self.state = HttpState::ExpectResponseHeaders;

                    return self.state_change();
                }
            }
            HttpState::Established => {
                self.client_outbuf.extend(self.server_inbuf.iter());
                self.server_outbuf.extend(self.client_inbuf.iter());
                self.server_inbuf.clear();
                self.client_inbuf.clear();
            }
            HttpState::Reset => {
                self.state = HttpState::ExpectResponseHeaders;
                return self.state_change();
            }
            _ => {}
        }
        Ok(())
    }
}

impl ProxyHandler for HttpConnection {
    fn get_connection_info(&self) -> &ConnectionInfo {
        &self.info
    }

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
        self.state == HttpState::Reset
    }

    fn get_udp_associate(&self) -> Option<SocketAddr> {
        None
    }
}

pub(crate) struct HttpManager {
    server: SocketAddr,
    credentials: Option<UserKey>,
    digest_state: Rc<RefCell<Option<DigestState>>>,
}

impl ConnectionManager for HttpManager {
    fn new_proxy_handler(&self, info: &ConnectionInfo, _: bool) -> Result<Box<dyn ProxyHandler>, Error> {
        if info.protocol != IpProtocol::Tcp {
            return Err("Invalid protocol".into());
        }
        Ok(Box::new(HttpConnection::new(
            info,
            self.credentials.clone(),
            self.digest_state.clone(),
        )?))
    }

    fn get_server_addr(&self) -> SocketAddr {
        self.server
    }
}

impl HttpManager {
    pub fn new(server: SocketAddr, credentials: Option<UserKey>) -> Self {
        Self {
            server,
            credentials,
            digest_state: Rc::new(RefCell::new(None)),
        }
    }
}
