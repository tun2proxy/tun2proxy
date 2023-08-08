use crate::{error::Error, error::Result, virtdevice::VirtualTunDevice, NetworkInterface, Options};
use mio::{event::Event, net::TcpStream, unix::SourceFd, Events, Interest, Poll, Token};
use smoltcp::{
    iface::{Config, Interface, SocketHandle, SocketSet},
    phy::{Device, Medium, RxToken, TunTapInterface, TxToken},
    socket::{tcp, tcp::State, udp, udp::UdpMetadata},
    time::Instant,
    wire::{IpCidr, IpProtocol, Ipv4Packet, Ipv6Packet, TcpPacket, UdpPacket, UDP_HEADER_LEN},
};
use socks5_impl::protocol::{Address, UserKey};
use std::{
    collections::{HashMap, HashSet},
    convert::{From, TryFrom},
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, Shutdown::Both, SocketAddr},
    os::unix::io::AsRawFd,
    rc::Rc,
    str::FromStr,
};

#[derive(Hash, Clone, Eq, PartialEq, Debug)]
pub(crate) struct ConnectionInfo {
    pub(crate) src: SocketAddr,
    pub(crate) dst: Address,
    pub(crate) protocol: IpProtocol,
}

impl Default for ConnectionInfo {
    fn default() -> Self {
        Self {
            src: SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0),
            dst: Address::unspecified(),
            protocol: IpProtocol::Tcp,
        }
    }
}

impl ConnectionInfo {
    #[allow(dead_code)]
    pub fn new(src: SocketAddr, dst: Address, protocol: IpProtocol) -> Self {
        Self { src, dst, protocol }
    }

    fn to_named(&self, name: String) -> Self {
        let mut result = self.clone();
        result.dst = Address::from((name, result.dst.port()));
        // let p = self.protocol;
        // log::trace!("{p} replace dst \"{}\" -> \"{}\"", self.dst, result.dst);
        result
    }
}

impl std::fmt::Display for ConnectionInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{} {} -> {}", self.protocol, self.src, self.dst)
    }
}

#[derive(Eq, PartialEq, Debug)]
pub(crate) enum IncomingDirection {
    FromServer,
    FromClient,
}

#[derive(Eq, PartialEq, Debug)]
pub(crate) enum OutgoingDirection {
    ToServer,
    ToClient,
}

#[derive(Eq, PartialEq, Debug)]
pub(crate) enum Direction {
    Incoming(IncomingDirection),
    Outgoing(OutgoingDirection),
}

#[allow(dead_code)]
pub(crate) enum ConnectionEvent<'a> {
    NewConnection(&'a ConnectionInfo),
    ConnectionClosed(&'a ConnectionInfo),
}

#[derive(Debug)]
pub(crate) struct DataEvent<'a, T> {
    pub(crate) direction: T,
    pub(crate) buffer: &'a [u8],
}

pub(crate) type IncomingDataEvent<'a> = DataEvent<'a, IncomingDirection>;
pub(crate) type OutgoingDataEvent<'a> = DataEvent<'a, OutgoingDirection>;

fn get_transport_info(
    protocol: IpProtocol,
    transport_offset: usize,
    packet: &[u8],
) -> Result<((u16, u16), bool, usize, usize)> {
    match protocol {
        IpProtocol::Udp => UdpPacket::new_checked(packet)
            .map(|result| {
                (
                    (result.src_port(), result.dst_port()),
                    false,
                    transport_offset + UDP_HEADER_LEN,
                    packet.len() - UDP_HEADER_LEN,
                )
            })
            .map_err(|e| e.into()),
        IpProtocol::Tcp => TcpPacket::new_checked(packet)
            .map(|result| {
                let header_len = result.header_len() as usize;
                (
                    (result.src_port(), result.dst_port()),
                    result.syn() && !result.ack(),
                    transport_offset + header_len,
                    packet.len() - header_len,
                )
            })
            .map_err(|e| e.into()),
        _ => Err(format!("Unsupported protocol {protocol} in IP packet").into()),
    }
}

fn connection_tuple(frame: &[u8]) -> Result<(ConnectionInfo, bool, usize, usize)> {
    if let Ok(packet) = Ipv4Packet::new_checked(frame) {
        let protocol = packet.next_header();

        let mut a = [0_u8; 4];
        a.copy_from_slice(packet.src_addr().as_bytes());
        let src_addr = IpAddr::from(a);
        a.copy_from_slice(packet.dst_addr().as_bytes());
        let dst_addr = IpAddr::from(a);
        let header_len = packet.header_len().into();

        let (ports, first_packet, payload_offset, payload_size) =
            get_transport_info(protocol, header_len, &frame[header_len..])?;
        let info = ConnectionInfo {
            src: SocketAddr::new(src_addr, ports.0),
            dst: SocketAddr::new(dst_addr, ports.1).into(),
            protocol,
        };
        return Ok((info, first_packet, payload_offset, payload_size));
    }

    if let Ok(packet) = Ipv6Packet::new_checked(frame) {
        // TODO: Support extension headers.
        let protocol = packet.next_header();

        let mut a = [0_u8; 16];
        a.copy_from_slice(packet.src_addr().as_bytes());
        let src_addr = IpAddr::from(a);
        a.copy_from_slice(packet.dst_addr().as_bytes());
        let dst_addr = IpAddr::from(a);
        let header_len = packet.header_len();

        let (ports, first_packet, payload_offset, payload_size) =
            get_transport_info(protocol, header_len, &frame[header_len..])?;
        let info = ConnectionInfo {
            src: SocketAddr::new(src_addr, ports.0),
            dst: SocketAddr::new(dst_addr, ports.1).into(),
            protocol,
        };
        return Ok((info, first_packet, payload_offset, payload_size));
    }
    Err("Neither IPv6 nor IPv4 packet".into())
}

const SERVER_WRITE_CLOSED: u8 = 1;
const CLIENT_WRITE_CLOSED: u8 = 2;

struct TcpConnectState {
    smoltcp_handle: Option<SocketHandle>,
    mio_stream: TcpStream,
    token: Token,
    tcp_proxy_handler: Box<dyn TcpProxy>,
    close_state: u8,
    wait_read: bool,
    wait_write: bool,
}

pub(crate) trait TcpProxy {
    fn push_data(&mut self, event: IncomingDataEvent<'_>) -> Result<(), Error>;
    fn consume_data(&mut self, dir: OutgoingDirection, size: usize);
    fn peek_data(&mut self, dir: OutgoingDirection) -> OutgoingDataEvent;
    fn connection_established(&self) -> bool;
    fn have_data(&mut self, dir: Direction) -> bool;
    fn reset_connection(&self) -> bool;
}

pub(crate) trait UdpProxy {
    fn send_frame(&mut self, destination: &Address, frame: &[u8]) -> Result<(), Error>;
    fn receive_frame(&mut self, source: &SocketAddr, frame: &[u8]) -> Result<(), Error>;
}

pub(crate) trait ConnectionManager {
    fn handles_connection(&self, info: &ConnectionInfo) -> bool;
    fn new_tcp_proxy(&self, info: &ConnectionInfo) -> Result<Box<dyn TcpProxy>, Error>;
    fn close_connection(&self, info: &ConnectionInfo);
    fn get_server_addr(&self) -> SocketAddr;
    fn get_credentials(&self) -> &Option<UserKey>;
}

const TUN_TOKEN: Token = Token(0);
const EXIT_TOKEN: Token = Token(2);

pub struct TunToProxy<'a> {
    tun: TunTapInterface,
    poll: Poll,
    iface: Interface,
    connection_map: HashMap<ConnectionInfo, TcpConnectState>,
    connection_managers: Vec<Rc<dyn ConnectionManager>>,
    next_token: usize,
    token_to_info: HashMap<Token, ConnectionInfo>,
    sockets: SocketSet<'a>,
    device: VirtualTunDevice,
    options: Options,
    write_sockets: HashSet<Token>,
    _exit_receiver: mio::unix::pipe::Receiver,
    exit_sender: mio::unix::pipe::Sender,
}

impl<'a> TunToProxy<'a> {
    pub fn new(interface: &NetworkInterface, options: Options) -> Result<Self, Error> {
        let tun = match interface {
            NetworkInterface::Named(name) => TunTapInterface::new(name.as_str(), Medium::Ip)?,
            NetworkInterface::Fd(fd) => TunTapInterface::from_fd(*fd, Medium::Ip, options.mtu.unwrap_or(1500))?,
        };
        let poll = Poll::new()?;
        poll.registry()
            .register(&mut SourceFd(&tun.as_raw_fd()), TUN_TOKEN, Interest::READABLE)?;

        let (exit_sender, mut exit_receiver) = mio::unix::pipe::new()?;
        poll.registry()
            .register(&mut exit_receiver, EXIT_TOKEN, Interest::READABLE)?;

        #[rustfmt::skip]
        let config = match tun.capabilities().medium {
            Medium::Ethernet =>  Config::new(smoltcp::wire::EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]).into()),
            Medium::Ip => Config::new(smoltcp::wire::HardwareAddress::Ip),
            Medium::Ieee802154 => todo!(),
        };
        let mut device = VirtualTunDevice::new(tun.capabilities());
        let gateway4: Ipv4Addr = Ipv4Addr::from_str("0.0.0.1")?;
        let gateway6: Ipv6Addr = Ipv6Addr::from_str("::1")?;
        let mut iface = Interface::new(config, &mut device, Instant::now());
        iface.update_ip_addrs(|ip_addrs| {
            ip_addrs.push(IpCidr::new(gateway4.into(), 0)).unwrap();
            ip_addrs.push(IpCidr::new(gateway6.into(), 0)).unwrap()
        });
        iface.routes_mut().add_default_ipv4_route(gateway4.into())?;
        iface.routes_mut().add_default_ipv6_route(gateway6.into())?;
        iface.set_any_ip(true);

        let tun = Self {
            tun,
            poll,
            iface,
            connection_map: HashMap::default(),
            next_token: usize::from(EXIT_TOKEN) + 1,
            token_to_info: HashMap::default(),
            connection_managers: Vec::default(),
            sockets: SocketSet::new([]),
            device,
            options,
            write_sockets: HashSet::default(),
            _exit_receiver: exit_receiver,
            exit_sender,
        };
        Ok(tun)
    }

    fn new_token(&mut self) -> Token {
        let token = Token(self.next_token);
        self.next_token += 1;
        token
    }

    pub(crate) fn add_connection_manager(&mut self, manager: Rc<dyn ConnectionManager>) {
        self.connection_managers.push(manager);
    }

    fn expect_smoltcp_send(&mut self) -> Result<(), Error> {
        self.iface.poll(Instant::now(), &mut self.device, &mut self.sockets);

        while let Some(vec) = self.device.exfiltrate_packet() {
            let slice = vec.as_slice();

            // TODO: Actual write. Replace.
            self.tun
                .transmit(Instant::now())
                .ok_or("tx token not available")?
                .consume(slice.len(), |buf| {
                    buf[..].clone_from_slice(slice);
                });
        }
        Ok(())
    }

    fn remove_connection(&mut self, info: &ConnectionInfo) -> Result<(), Error> {
        if let Some(mut conn) = self.connection_map.remove(info) {
            _ = conn.mio_stream.shutdown(Both);
            if let Some(handle) = conn.smoltcp_handle {
                let socket = self.sockets.get_mut::<tcp::Socket>(handle);
                socket.close();
                self.sockets.remove(handle);
            }
            self.expect_smoltcp_send()?;
            let token = &conn.token;
            self.token_to_info.remove(token);
            _ = self.poll.registry().deregister(&mut conn.mio_stream);
            log::info!("Close {}", info);
        }
        Ok(())
    }

    fn get_connection_manager(&self, info: &ConnectionInfo) -> Option<Rc<dyn ConnectionManager>> {
        for manager in self.connection_managers.iter() {
            if manager.handles_connection(info) {
                return Some(manager.clone());
            }
        }
        None
    }

    fn check_change_close_state(&mut self, info: &ConnectionInfo) -> Result<(), Error> {
        let state = self.connection_map.get_mut(info);
        if state.is_none() {
            return Ok(());
        }
        let state = state.unwrap();
        let mut closed_ends = 0;
        if (state.close_state & SERVER_WRITE_CLOSED) == SERVER_WRITE_CLOSED
            && !state
                .tcp_proxy_handler
                .have_data(Direction::Incoming(IncomingDirection::FromServer))
            && !state
                .tcp_proxy_handler
                .have_data(Direction::Outgoing(OutgoingDirection::ToClient))
        {
            if let Some(socket_handle) = state.smoltcp_handle {
                let socket = self.sockets.get_mut::<tcp::Socket>(socket_handle);
                socket.close();
            }
            closed_ends += 1;
        }

        if (state.close_state & CLIENT_WRITE_CLOSED) == CLIENT_WRITE_CLOSED
            && !state
                .tcp_proxy_handler
                .have_data(Direction::Incoming(IncomingDirection::FromClient))
            && !state
                .tcp_proxy_handler
                .have_data(Direction::Outgoing(OutgoingDirection::ToServer))
        {
            _ = state.mio_stream.shutdown(Shutdown::Write);
            closed_ends += 1;
        }

        if closed_ends == 2 {
            self.remove_connection(info)?;
        }
        Ok(())
    }

    fn tunsocket_read_and_forward(&mut self, info: &ConnectionInfo) -> Result<(), Error> {
        // Scope for mutable borrow of self.
        {
            let state = match self.connection_map.get_mut(info) {
                Some(state) => state,
                None => return Ok(()),
            };
            let socket = match state.smoltcp_handle {
                Some(handle) => self.sockets.get_mut::<tcp::Socket>(handle),
                None => return Ok(()),
            };
            let mut error = Ok(());
            while socket.can_recv() && error.is_ok() {
                socket.recv(|data| {
                    let event = IncomingDataEvent {
                        direction: IncomingDirection::FromClient,
                        buffer: data,
                    };
                    error = state.tcp_proxy_handler.push_data(event);
                    (data.len(), ())
                })?;
            }

            if !socket.may_recv()
                && socket.state() != State::Listen
                && socket.state() != State::SynSent
                && socket.state() != State::SynReceived
            {
                // We cannot yet close the write end of the mio stream here because we may still
                // need to send data.
                state.close_state |= CLIENT_WRITE_CLOSED;
            }

            // Expect ACKs etc. from smoltcp sockets.
            self.expect_smoltcp_send()?;
        }

        self.check_change_close_state(info)?;

        Ok(())
    }

    fn update_mio_socket_interest(poll: &mut Poll, state: &mut TcpConnectState) -> Result<()> {
        // Maybe we did not listen for any events before. Therefore, just swallow the error.
        _ = poll.registry().deregister(&mut state.mio_stream);

        // If we do not wait for read or write events, we do not need to register them.
        if !state.wait_read && !state.wait_write {
            return Ok(());
        }

        // This ugliness is due to the way Interest is implemented (as a NonZeroU8 wrapper).
        let interest = match (state.wait_read, state.wait_write) {
            (true, false) => Interest::READABLE,
            (false, true) => Interest::WRITABLE,
            (true, true) => Interest::READABLE | Interest::WRITABLE,
            (false, false) => Interest::READABLE | Interest::WRITABLE,
        };

        poll.registry().register(&mut state.mio_stream, state.token, interest)?;
        Ok(())
    }

    // A raw packet was received on the tunnel interface.
    fn receive_tun(&mut self, frame: &mut [u8]) -> Result<(), Error> {
        let mut handler = || -> Result<(), Error> {
            let (info, first_packet, payload_offset, payload_size) = connection_tuple(frame)?;
            let dst = SocketAddr::try_from(&info.dst)?;
            let connection_info = match &mut self.options.virtual_dns {
                None => info.clone(),
                Some(virtual_dns) => {
                    let dst_ip = dst.ip();
                    virtual_dns.touch_ip(&dst_ip);
                    match virtual_dns.resolve_ip(&dst_ip) {
                        None => info.clone(),
                        Some(name) => info.to_named(name.clone()),
                    }
                }
            };
            if connection_info.protocol == IpProtocol::Tcp {
                let server_addr = self
                    .get_connection_manager(&connection_info)
                    .ok_or("get_connection_manager")?
                    .get_server_addr();
                if first_packet {
                    let mut done = false;
                    for manager in self.connection_managers.iter_mut() {
                        let tcp_proxy_handler = manager.new_tcp_proxy(&connection_info);
                        if tcp_proxy_handler.is_err() {
                            continue;
                        }
                        let tcp_proxy_handler = tcp_proxy_handler?;
                        let mut socket = tcp::Socket::new(
                            tcp::SocketBuffer::new(vec![0; 1024 * 128]),
                            tcp::SocketBuffer::new(vec![0; 1024 * 128]),
                        );
                        socket.set_ack_delay(None);
                        socket.listen(dst)?;
                        let handle = self.sockets.add(socket);

                        let mut client = TcpStream::connect(server_addr)?;
                        let token = self.new_token();
                        let i = Interest::READABLE;
                        self.poll.registry().register(&mut client, token, i)?;

                        let state = TcpConnectState {
                            smoltcp_handle: Some(handle),
                            mio_stream: client,
                            token,
                            tcp_proxy_handler,
                            close_state: 0,
                            wait_read: true,
                            wait_write: false,
                        };
                        self.connection_map.insert(connection_info.clone(), state);

                        self.token_to_info.insert(token, connection_info.clone());

                        log::info!("Connect done {} ({})", connection_info, dst);
                        done = true;
                        break;
                    }
                    if !done {
                        log::debug!("No connection manager for {} ({})", connection_info, dst);
                    }
                } else if !self.connection_map.contains_key(&connection_info) {
                    log::debug!("Not found {} ({})", connection_info, dst);
                    return Ok(());
                } else {
                    log::trace!("Subsequent packet {} ({})", connection_info, dst);
                }

                // Inject the packet to advance the smoltcp socket state
                self.device.inject_packet(frame);

                // Having advanced the socket state, we expect the socket to ACK
                // Exfiltrate the response packets generated by the socket and inject them
                // into the tunnel interface.
                self.expect_smoltcp_send()?;

                // Read from the smoltcp socket and push the data to the connection handler.
                self.tunsocket_read_and_forward(&connection_info)?;

                // The connection handler builds up the connection or encapsulates the data.
                // Therefore, we now expect it to write data to the server.
                self.write_to_server(&connection_info)?;
            } else if connection_info.protocol == IpProtocol::Udp {
                log::trace!("{} ({})", connection_info, dst);
                let port = connection_info.dst.port();
                if let (Some(virtual_dns), true) = (&mut self.options.virtual_dns, port == 53) {
                    let payload = &frame[payload_offset..payload_offset + payload_size];
                    let response = virtual_dns.receive_query(payload)?;
                    {
                        let rx_buffer = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY], vec![0; 4096]);
                        let tx_buffer = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY], vec![0; 4096]);
                        let mut socket = udp::Socket::new(rx_buffer, tx_buffer);
                        socket.bind(dst)?;
                        let meta = UdpMetadata::from(connection_info.src);
                        socket.send_slice(response.as_slice(), meta)?;
                        let handle = self.sockets.add(socket);
                        self.expect_smoltcp_send()?;
                        self.sockets.remove(handle);
                    }
                }
                // Otherwise, UDP is not yet supported.
            } else {
                log::warn!("Unsupported protocol: {} ({})", connection_info, dst);
            }
            Ok::<(), Error>(())
        };
        if let Err(error) = handler() {
            log::error!("{}", error);
        }
        Ok(())
    }

    fn write_to_server(&mut self, info: &ConnectionInfo) -> Result<(), Error> {
        if let Some(state) = self.connection_map.get_mut(info) {
            let event = state.tcp_proxy_handler.peek_data(OutgoingDirection::ToServer);
            let buffer_size = event.buffer.len();
            if buffer_size == 0 {
                state.wait_write = false;
                Self::update_mio_socket_interest(&mut self.poll, state)?;
                self.check_change_close_state(info)?;
                return Ok(());
            }
            let result = state.mio_stream.write(event.buffer);
            match result {
                Ok(written) => {
                    state
                        .tcp_proxy_handler
                        .consume_data(OutgoingDirection::ToServer, written);
                    state.wait_write = written < buffer_size;
                    Self::update_mio_socket_interest(&mut self.poll, state)?;
                }
                Err(error) if error.kind() != std::io::ErrorKind::WouldBlock => {
                    return Err(error.into());
                }
                _ => {
                    // WOULDBLOCK case
                    state.wait_write = true;
                    Self::update_mio_socket_interest(&mut self.poll, state)?;
                }
            }
        }
        self.check_change_close_state(info)?;
        Ok(())
    }

    fn write_to_client(&mut self, token: Token, info: &ConnectionInfo) -> Result<(), Error> {
        while let Some(state) = self.connection_map.get_mut(info) {
            let socket_handle = match state.smoltcp_handle {
                Some(handle) => handle,
                None => break,
            };
            let event = state.tcp_proxy_handler.peek_data(OutgoingDirection::ToClient);
            let buflen = event.buffer.len();
            let consumed;
            {
                let socket = self.sockets.get_mut::<tcp::Socket>(socket_handle);
                if socket.may_send() {
                    if let Some(virtual_dns) = &mut self.options.virtual_dns {
                        // Unwrapping is fine because every smoltcp socket is bound to an.
                        virtual_dns.touch_ip(&IpAddr::from(socket.local_endpoint().unwrap().addr));
                    }
                    consumed = socket.send_slice(event.buffer)?;
                    state
                        .tcp_proxy_handler
                        .consume_data(OutgoingDirection::ToClient, consumed);
                    self.expect_smoltcp_send()?;
                    if consumed < buflen {
                        self.write_sockets.insert(token);
                        break;
                    } else {
                        self.write_sockets.remove(&token);
                        if consumed == 0 {
                            break;
                        }
                    }
                } else {
                    break;
                }
            }

            self.check_change_close_state(info)?;
        }
        Ok(())
    }

    fn tun_event(&mut self, event: &Event) -> Result<(), Error> {
        if event.is_readable() {
            while let Some((rx_token, _)) = self.tun.receive(Instant::now()) {
                rx_token.consume(|frame| self.receive_tun(frame))?;
            }
        }
        Ok(())
    }

    fn send_to_smoltcp(&mut self) -> Result<(), Error> {
        let cloned = self.write_sockets.clone();
        for token in cloned.iter() {
            if let Some(connection) = self.token_to_info.get(token) {
                let connection = connection.clone();
                if let Err(error) = self.write_to_client(*token, &connection) {
                    self.remove_connection(&connection)?;
                    log::error!("Write to client: {}: ", error);
                }
            }
        }
        Ok(())
    }

    fn mio_socket_event(&mut self, event: &Event) -> Result<(), Error> {
        let e = "connection not found";
        let conn_info = match self.token_to_info.get(&event.token()) {
            Some(conn_info) => conn_info.clone(),
            None => {
                // We may have closed the connection in an earlier iteration over the poll events,
                // e.g. because an event through the tunnel interface indicated that the connection
                // should be closed.
                log::trace!("{e}");
                return Ok(());
            }
        };

        let server = self.get_connection_manager(&conn_info).ok_or(e)?.get_server_addr();

        let mut block = || -> Result<(), Error> {
            if event.is_readable() || event.is_read_closed() {
                {
                    let state = self.connection_map.get_mut(&conn_info).ok_or(e)?;

                    // TODO: Move this reading process to its own function.
                    let mut vecbuf = Vec::<u8>::new();
                    let read_result = state.mio_stream.read_to_end(&mut vecbuf);
                    let read = match read_result {
                        Ok(read_result) => read_result,
                        Err(error) => {
                            if error.kind() != std::io::ErrorKind::WouldBlock {
                                log::error!("Read from proxy: {}", error);
                            }
                            vecbuf.len()
                        }
                    };

                    let data = vecbuf.as_slice();
                    let data_event = IncomingDataEvent {
                        direction: IncomingDirection::FromServer,
                        buffer: &data[0..read],
                    };
                    if let Err(error) = state.tcp_proxy_handler.push_data(data_event) {
                        log::error!("{}", error);
                        self.remove_connection(&conn_info.clone())?;
                        return Ok(());
                    }

                    // The handler request for reset the server connection
                    if state.tcp_proxy_handler.reset_connection() {
                        _ = self.poll.registry().deregister(&mut state.mio_stream);
                        // Closes the connection with the proxy
                        state.mio_stream.shutdown(Both)?;

                        log::info!("RESET {}", conn_info);

                        state.mio_stream = TcpStream::connect(server)?;

                        state.wait_read = true;
                        state.wait_write = true;

                        Self::update_mio_socket_interest(&mut self.poll, state)?;

                        return Ok(());
                    }

                    if read == 0 || event.is_read_closed() {
                        state.wait_read = false;
                        state.close_state |= SERVER_WRITE_CLOSED;
                        Self::update_mio_socket_interest(&mut self.poll, state)?;
                        self.check_change_close_state(&conn_info)?;
                        self.expect_smoltcp_send()?;
                    }
                }

                // We have read from the proxy server and pushed the data to the connection handler.
                // Thus, expect data to be processed (e.g. decapsulated) and forwarded to the client.
                self.write_to_client(event.token(), &conn_info)?;

                // The connection handler could have produced data that is to be written to the
                // server.
                self.write_to_server(&conn_info)?;
            }

            if event.is_writable() {
                self.write_to_server(&conn_info)?;
            }
            Ok::<(), Error>(())
        };
        if let Err(error) = block() {
            log::error!("{}", error);
            self.remove_connection(&conn_info)?;
        }
        Ok(())
    }

    pub fn run(&mut self) -> Result<(), Error> {
        let mut events = Events::with_capacity(1024);
        loop {
            if let Err(err) = self.poll.poll(&mut events, None) {
                if err.kind() == std::io::ErrorKind::Interrupted {
                    log::warn!("Poll interrupted: \"{err}\", ignored, continue polling");
                    continue;
                }
                return Err(err.into());
            }
            for event in events.iter() {
                match event.token() {
                    EXIT_TOKEN => {
                        log::info!("Exiting tun2proxy...");
                        return Ok(());
                    }
                    TUN_TOKEN => self.tun_event(event)?,
                    _ => self.mio_socket_event(event)?,
                }
            }
            self.send_to_smoltcp()?;
        }
    }

    pub fn shutdown(&mut self) -> Result<(), Error> {
        self.exit_sender.write_all(&[1])?;
        Ok(())
    }
}
