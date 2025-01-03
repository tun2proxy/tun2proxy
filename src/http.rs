use crate::{
    directions::{IncomingDataEvent, IncomingDirection, OutgoingDataEvent, OutgoingDirection},
    error::{Error, Result},
    proxy_handler::{ProxyHandler, ProxyHandlerManager},
    session_info::{IpProtocol, SessionInfo},
};
use httparse::Response;
use socks5_impl::protocol::UserKey;
use std::{
    collections::{hash_map::RandomState, HashMap, VecDeque},
    iter::FromIterator,
    net::SocketAddr,
    str,
    sync::Arc,
};
use tokio::sync::Mutex;
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
    server_addr: SocketAddr,
    state: HttpState,
    client_inbuf: VecDeque<u8>,
    server_inbuf: VecDeque<u8>,
    client_outbuf: VecDeque<u8>,
    server_outbuf: VecDeque<u8>,
    crlf_state: u8,
    counter: usize,
    skip: usize,
    digest_state: Arc<Mutex<Option<DigestState>>>,
    before: bool,
    credentials: Option<UserKey>,
    info: SessionInfo,
    domain_name: Option<String>,
}

static PROXY_AUTHENTICATE: &str = "Proxy-Authenticate";
static PROXY_AUTHORIZATION: &str = "Proxy-Authorization";
static CONNECTION: &str = "Connection";
static TRANSFER_ENCODING: &str = "Transfer-Encoding";
static CONTENT_LENGTH: &str = "Content-Length";

impl HttpConnection {
    async fn new(
        server_addr: SocketAddr,
        info: SessionInfo,
        domain_name: Option<String>,
        credentials: Option<UserKey>,
        digest_state: Arc<Mutex<Option<DigestState>>>,
    ) -> Result<Self> {
        let mut res = Self {
            server_addr,
            state: HttpState::ExpectResponseHeaders,
            client_inbuf: VecDeque::default(),
            server_inbuf: VecDeque::default(),
            client_outbuf: VecDeque::default(),
            server_outbuf: VecDeque::default(),
            skip: 0,
            counter: 0,
            crlf_state: 0,
            digest_state,
            before: false,
            credentials,
            info,
            domain_name,
        };

        res.send_tunnel_request().await?;
        Ok(res)
    }

    async fn send_tunnel_request(&mut self) -> Result<(), Error> {
        let host = if let Some(domain_name) = &self.domain_name {
            format!("{}:{}", domain_name, self.info.dst.port())
        } else {
            self.info.dst.to_string()
        };

        self.server_outbuf.extend(b"CONNECT ");
        self.server_outbuf.extend(host.as_bytes());
        self.server_outbuf.extend(b" HTTP/1.1\r\nHost: ");
        self.server_outbuf.extend(host.as_bytes());
        self.server_outbuf.extend(b"\r\n");

        let scheme = if self.digest_state.lock().await.is_none() {
            AuthenticationScheme::Basic
        } else {
            AuthenticationScheme::Digest
        };
        self.send_auth_data(scheme).await?;

        self.server_outbuf.extend(b"\r\n");
        Ok(())
    }

    async fn send_auth_data(&mut self, scheme: AuthenticationScheme) -> Result<()> {
        let Some(credentials) = &self.credentials else {
            return Ok(());
        };

        match scheme {
            AuthenticationScheme::Digest => {
                let uri = if let Some(domain_name) = &self.domain_name {
                    format!("{}:{}", domain_name, self.info.dst.port())
                } else {
                    self.info.dst.to_string()
                };

                let context = digest_auth::AuthContext::new_with_method(
                    &credentials.username,
                    &credentials.password,
                    &uri,
                    Option::<&'_ [u8]>::None,
                    digest_auth::HttpMethod::CONNECT,
                );

                let mut state = self.digest_state.lock().await;
                let response = state.as_mut().unwrap().respond(&context).unwrap();

                self.server_outbuf
                    .extend(format!("{}: {}\r\n", PROXY_AUTHORIZATION, response.to_header_string()).as_bytes());
            }
            AuthenticationScheme::Basic => {
                let auth_b64 = base64easy::encode(credentials.to_string(), base64easy::EngineKind::Standard);
                self.server_outbuf
                    .extend(format!("{}: Basic {}\r\n", PROXY_AUTHORIZATION, auth_b64).as_bytes());
            }
            AuthenticationScheme::None => {}
        }

        Ok(())
    }

    async fn state_change(&mut self) -> Result<()> {
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

                let header_size = self.counter;

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
                    // The server may have sent a banner already (SMTP, SSH, etc.).
                    // Therefore, server_inbuf must retain this data.
                    self.server_inbuf.drain(0..header_size);
                    return Box::pin(self.state_change()).await;
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
                self.digest_state.lock().await.replace(state);
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
                    self.send_tunnel_request().await?;

                    self.state = HttpState::Reset;
                    return Ok(());
                }

                // The HTTP/1.1 expected to be keep alive waiting for the next frame so, we must
                // compute the length of the response in order to detect the next frame (response)
                // [RFC-9112](https://datatracker.ietf.org/doc/html/rfc9112#body.content-length)

                // Transfer-Encoding isn't supported yet
                if headers_map.contains_key(&UniCase::new(TRANSFER_ENCODING)) {
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
                        self.send_tunnel_request().await?;

                        self.state = HttpState::Reset;
                        return Ok(());
                    }
                };

                // Handshake state
                self.state = HttpState::ExpectResponse;
                self.skip = content_length + len;

                return Box::pin(self.state_change()).await;
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
                    self.send_tunnel_request().await?;
                    self.state = HttpState::ExpectResponseHeaders;

                    return Box::pin(self.state_change()).await;
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
                return Box::pin(self.state_change()).await;
            }
            _ => {}
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl ProxyHandler for HttpConnection {
    fn get_server_addr(&self) -> SocketAddr {
        self.server_addr
    }

    fn get_session_info(&self) -> SessionInfo {
        self.info
    }

    fn get_domain_name(&self) -> Option<String> {
        self.domain_name.clone()
    }

    async fn push_data(&mut self, event: IncomingDataEvent<'_>) -> std::io::Result<()> {
        let direction = event.direction;
        let buffer = event.buffer;
        match direction {
            IncomingDirection::FromServer => {
                self.server_inbuf.extend(buffer.iter());
            }
            IncomingDirection::FromClient => {
                self.client_inbuf.extend(buffer.iter());
            }
        }

        self.state_change().await?;
        Ok(())
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

    fn data_len(&self, dir: OutgoingDirection) -> usize {
        match dir {
            OutgoingDirection::ToServer => self.server_outbuf.len(),
            OutgoingDirection::ToClient => self.client_outbuf.len(),
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
    digest_state: Arc<Mutex<Option<DigestState>>>,
}

#[async_trait::async_trait]
impl ProxyHandlerManager for HttpManager {
    async fn new_proxy_handler(
        &self,
        info: SessionInfo,
        domain_name: Option<String>,
        _udp_associate: bool,
    ) -> std::io::Result<Arc<Mutex<dyn ProxyHandler>>> {
        if info.protocol != IpProtocol::Tcp {
            return Err(Error::from("Protocol not supported by HTTP proxy").into());
        }
        Ok(Arc::new(Mutex::new(
            HttpConnection::new(self.server, info, domain_name, self.credentials.clone(), self.digest_state.clone()).await?,
        )))
    }
}

impl HttpManager {
    pub fn new(server: SocketAddr, credentials: Option<UserKey>) -> Self {
        Self {
            server,
            credentials,
            digest_state: Arc::new(Mutex::new(None)),
        }
    }
}
