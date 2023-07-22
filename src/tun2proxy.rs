use crate::{error::Error, virtdevice::VirtualTunDevice, NetworkInterface, Options};
use mio::{event::Event, net::TcpStream, unix::SourceFd, Events, Interest, Poll, Token};
use smoltcp::{
    iface::{Config, Interface, SocketHandle, SocketSet},
    phy::{Device, Medium, RxToken, TunTapInterface, TxToken},
    socket::{tcp, tcp::State, udp, udp::UdpMetadata},
    time::Instant,
    wire::{IpCidr, IpProtocol, Ipv4Packet, Ipv6Packet, TcpPacket, UdpPacket},
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
pub(crate) struct Connection {
    pub(crate) src: SocketAddr,
    pub(crate) dst: Address,
    pub(crate) proto: IpProtocol,
}

impl Connection {
    fn to_named(&self, name: String) -> Self {
        let mut result = self.clone();
        result.dst = Address::from((name, result.dst.port()));
        log::trace!("Replace dst \"{}\" -> \"{}\"", self.dst, result.dst);
        result
    }
}

impl std::fmt::Display for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{} -> {}", self.src, self.dst)
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
    NewConnection(&'a Connection),
    ConnectionClosed(&'a Connection),
}

pub(crate) struct DataEvent<'a, T> {
    pub(crate) direction: T,
    pub(crate) buffer: &'a [u8],
}

pub(crate) type IncomingDataEvent<'a> = DataEvent<'a, IncomingDirection>;
pub(crate) type OutgoingDataEvent<'a> = DataEvent<'a, OutgoingDirection>;

fn get_transport_info(
    proto: IpProtocol,
    transport_offset: usize,
    packet: &[u8],
) -> Option<((u16, u16), bool, usize, usize)> {
    match proto {
        IpProtocol::Udp => match UdpPacket::new_checked(packet) {
            Ok(result) => Some((
                (result.src_port(), result.dst_port()),
                false,
                transport_offset + 8,
                packet.len() - 8,
            )),
            Err(_) => None,
        },
        IpProtocol::Tcp => match TcpPacket::new_checked(packet) {
            Ok(result) => Some((
                (result.src_port(), result.dst_port()),
                result.syn() && !result.ack(),
                transport_offset + result.header_len() as usize,
                packet.len(),
            )),
            Err(_) => None,
        },
        _ => None,
    }
}

fn connection_tuple(frame: &[u8]) -> Option<(Connection, bool, usize, usize)> {
    if let Ok(packet) = Ipv4Packet::new_checked(frame) {
        let proto = packet.next_header();

        let mut a = [0_u8; 4];
        a.copy_from_slice(packet.src_addr().as_bytes());
        let src_addr = IpAddr::from(a);
        a.copy_from_slice(packet.dst_addr().as_bytes());
        let dst_addr = IpAddr::from(a);

        return if let Some((ports, first_packet, payload_offset, payload_size)) = get_transport_info(
            proto,
            packet.header_len().into(),
            &frame[packet.header_len().into()..],
        ) {
            let connection = Connection {
                src: SocketAddr::new(src_addr, ports.0),
                dst: SocketAddr::new(dst_addr, ports.1).into(),
                proto,
            };
            Some((connection, first_packet, payload_offset, payload_size))
        } else {
            None
        };
    }

    match Ipv6Packet::new_checked(frame) {
        Ok(packet) => {
            // TODO: Support extension headers.
            let proto = packet.next_header();

            let mut a = [0_u8; 16];
            a.copy_from_slice(packet.src_addr().as_bytes());
            let src_addr = IpAddr::from(a);
            a.copy_from_slice(packet.dst_addr().as_bytes());
            let dst_addr = IpAddr::from(a);

            if let Some((ports, first_packet, payload_offset, payload_size)) =
                get_transport_info(proto, packet.header_len(), &frame[packet.header_len()..])
            {
                let connection = Connection {
                    src: SocketAddr::new(src_addr, ports.0),
                    dst: SocketAddr::new(dst_addr, ports.1).into(),
                    proto,
                };
                Some((connection, first_packet, payload_offset, payload_size))
            } else {
                None
            }
        }
        _ => None,
    }
}

const SERVER_WRITE_CLOSED: u8 = 1;
const CLIENT_WRITE_CLOSED: u8 = 2;

struct ConnectionState {
    smoltcp_handle: SocketHandle,
    mio_stream: TcpStream,
    token: Token,
    handler: Box<dyn TcpProxy>,
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

pub(crate) trait ConnectionManager {
    fn handles_connection(&self, connection: &Connection) -> bool;
    fn new_connection(
        &self,
        connection: &Connection,
        manager: Rc<dyn ConnectionManager>,
    ) -> Result<Option<Box<dyn TcpProxy>>, Error>;
    fn close_connection(&self, connection: &Connection);
    fn get_server(&self) -> SocketAddr;
    fn get_credentials(&self) -> &Option<UserKey>;
}

const TUN_TOKEN: Token = Token(0);
const UDP_TOKEN: Token = Token(1);
const EXIT_TOKEN: Token = Token(2);

pub struct TunToProxy<'a> {
    tun: TunTapInterface,
    poll: Poll,
    iface: Interface,
    connections: HashMap<Connection, ConnectionState>,
    connection_managers: Vec<Rc<dyn ConnectionManager>>,
    next_token: usize,
    token_to_connection: HashMap<Token, Connection>,
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
            NetworkInterface::Fd(fd) => {
                TunTapInterface::from_fd(*fd, Medium::Ip, options.mtu.unwrap_or(1500))?
            }
        };
        let poll = Poll::new()?;
        poll.registry().register(
            &mut SourceFd(&tun.as_raw_fd()),
            TUN_TOKEN,
            Interest::READABLE,
        )?;

        let (exit_sender, mut exit_receiver) = mio::unix::pipe::new()?;
        poll.registry()
            .register(&mut exit_receiver, EXIT_TOKEN, Interest::READABLE)?;

        let config = match tun.capabilities().medium {
            Medium::Ethernet => Config::new(
                smoltcp::wire::EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]).into(),
            ),
            Medium::Ip => Config::new(smoltcp::wire::HardwareAddress::Ip),
            Medium::Ieee802154 => todo!(),
        };
        let mut virt = VirtualTunDevice::new(tun.capabilities());
        let gateway4: Ipv4Addr = Ipv4Addr::from_str("0.0.0.1")?;
        let gateway6: Ipv6Addr = Ipv6Addr::from_str("::1")?;
        let mut iface = Interface::new(config, &mut virt, Instant::now());
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
            connections: HashMap::default(),
            next_token: usize::from(EXIT_TOKEN) + 1,
            token_to_connection: HashMap::default(),
            connection_managers: Vec::default(),
            sockets: SocketSet::new([]),
            device: virt,
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
        self.iface
            .poll(Instant::now(), &mut self.device, &mut self.sockets);

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

    fn remove_connection(&mut self, connection: &Connection) -> Result<(), Error> {
        if let Some(mut conn) = self.connections.remove(connection) {
            let token = &conn.token;
            self.token_to_connection.remove(token);
            self.sockets.remove(conn.smoltcp_handle);
            _ = self.poll.registry().deregister(&mut conn.mio_stream);
            log::info!("CLOSE {}", connection);
        }
        Ok(())
    }

    fn get_connection_manager(&self, connection: &Connection) -> Option<Rc<dyn ConnectionManager>> {
        for manager in self.connection_managers.iter() {
            if manager.handles_connection(connection) {
                return Some(manager.clone());
            }
        }
        None
    }

    fn check_change_close_state(&mut self, connection: &Connection) -> Result<(), Error> {
        let state = self.connections.get_mut(connection);
        if state.is_none() {
            return Ok(());
        }
        let state = state.unwrap();
        let mut closed_ends = 0;
        if (state.close_state & SERVER_WRITE_CLOSED) == SERVER_WRITE_CLOSED
            && !state
                .handler
                .have_data(Direction::Incoming(IncomingDirection::FromServer))
            && !state
                .handler
                .have_data(Direction::Outgoing(OutgoingDirection::ToClient))
        {
            let socket = self.sockets.get_mut::<tcp::Socket>(state.smoltcp_handle);
            socket.close();
            closed_ends += 1;
        }

        if (state.close_state & CLIENT_WRITE_CLOSED) == CLIENT_WRITE_CLOSED
            && !state
                .handler
                .have_data(Direction::Incoming(IncomingDirection::FromClient))
            && !state
                .handler
                .have_data(Direction::Outgoing(OutgoingDirection::ToServer))
        {
            _ = state.mio_stream.shutdown(Shutdown::Write);
            closed_ends += 1;
        }

        if closed_ends == 2 {
            self.remove_connection(connection)?;
        }
        Ok(())
    }

    fn tunsocket_read_and_forward(&mut self, connection: &Connection) -> Result<(), Error> {
        // Scope for mutable borrow of self.
        {
            let state = self.connections.get_mut(connection);
            if state.is_none() {
                return Ok(());
            }
            let state = state.unwrap();
            let socket = self.sockets.get_mut::<tcp::Socket>(state.smoltcp_handle);
            let mut error = Ok(());
            while socket.can_recv() && error.is_ok() {
                socket.recv(|data| {
                    let event = IncomingDataEvent {
                        direction: IncomingDirection::FromClient,
                        buffer: data,
                    };
                    error = state.handler.push_data(event);
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

        self.check_change_close_state(connection)?;

        Ok(())
    }

    // Update the poll registry depending on the connection's event interests.
    fn update_mio_socket_interest(&mut self, connection: &Connection) -> Result<(), Error> {
        let state = self
            .connections
            .get_mut(connection)
            .ok_or("connection not found")?;

        // Maybe we did not listen for any events before. Therefore, just swallow the error.
        _ = self.poll.registry().deregister(&mut state.mio_stream);

        // If we do not wait for read or write events, we do not need to register them.
        if !state.wait_read && !state.wait_write {
            return Ok(());
        }

        // This ugliness is due to the way Interest is implemented (as a NonZeroU8 wrapper).
        let interest;
        if state.wait_read && !state.wait_write {
            interest = Interest::READABLE;
        } else if state.wait_write && !state.wait_read {
            interest = Interest::WRITABLE;
        } else {
            interest = Interest::READABLE | Interest::WRITABLE;
        }

        self.poll
            .registry()
            .register(&mut state.mio_stream, state.token, interest)?;
        Ok(())
    }

    // A raw packet was received on the tunnel interface.
    fn receive_tun(&mut self, frame: &mut [u8]) -> Result<(), Error> {
        if let Some((connection, first_packet, offset, size)) = connection_tuple(frame) {
            let resolved_conn = match &mut self.options.virtdns {
                None => connection.clone(),
                Some(virt_dns) => {
                    let ip = SocketAddr::try_from(connection.dst.clone())?.ip();
                    virt_dns.touch_ip(&ip);
                    match virt_dns.resolve_ip(&ip) {
                        None => connection.clone(),
                        Some(name) => connection.to_named(name.clone()),
                    }
                }
            };
            let dst = connection.dst;
            let handler = || -> Result<(), Error> {
                if resolved_conn.proto == IpProtocol::Tcp {
                    let cm = self.get_connection_manager(&resolved_conn);
                    if cm.is_none() {
                        log::trace!("no connect manager");
                        return Ok(());
                    }
                    let server = cm.unwrap().get_server();
                    if first_packet {
                        for manager in self.connection_managers.iter_mut() {
                            if let Some(handler) =
                                manager.new_connection(&resolved_conn, manager.clone())?
                            {
                                let mut socket = tcp::Socket::new(
                                    tcp::SocketBuffer::new(vec![0; 1024 * 128]),
                                    tcp::SocketBuffer::new(vec![0; 1024 * 128]),
                                );
                                socket.set_ack_delay(None);
                                let dst = SocketAddr::try_from(dst)?;
                                socket.listen(dst)?;
                                let handle = self.sockets.add(socket);

                                let client = TcpStream::connect(server)?;

                                let token = self.new_token();

                                let mut state = ConnectionState {
                                    smoltcp_handle: handle,
                                    mio_stream: client,
                                    token,
                                    handler,
                                    close_state: 0,
                                    wait_read: true,
                                    wait_write: false,
                                };

                                self.token_to_connection
                                    .insert(token, resolved_conn.clone());
                                self.poll.registry().register(
                                    &mut state.mio_stream,
                                    token,
                                    Interest::READABLE,
                                )?;

                                self.connections.insert(resolved_conn.clone(), state);

                                log::info!("CONNECT {}", resolved_conn,);
                                break;
                            }
                        }
                    } else if !self.connections.contains_key(&resolved_conn) {
                        return Ok(());
                    }

                    // Inject the packet to advance the smoltcp socket state
                    self.device.inject_packet(frame);

                    // Having advanced the socket state, we expect the socket to ACK
                    // Exfiltrate the response packets generated by the socket and inject them
                    // into the tunnel interface.
                    self.expect_smoltcp_send()?;

                    // Read from the smoltcp socket and push the data to the connection handler.
                    self.tunsocket_read_and_forward(&resolved_conn)?;

                    // The connection handler builds up the connection or encapsulates the data.
                    // Therefore, we now expect it to write data to the server.
                    self.write_to_server(&resolved_conn)?;
                } else if resolved_conn.proto == IpProtocol::Udp && resolved_conn.dst.port() == 53 {
                    if let Some(virtual_dns) = &mut self.options.virtdns {
                        let payload = &frame[offset..offset + size];
                        if let Some(response) = virtual_dns.receive_query(payload) {
                            let rx_buffer = udp::PacketBuffer::new(
                                vec![udp::PacketMetadata::EMPTY],
                                vec![0; 4096],
                            );
                            let tx_buffer = udp::PacketBuffer::new(
                                vec![udp::PacketMetadata::EMPTY],
                                vec![0; 4096],
                            );
                            let mut socket = udp::Socket::new(rx_buffer, tx_buffer);
                            let dst = SocketAddr::try_from(dst)?;
                            socket.bind(dst)?;
                            socket
                                .send_slice(
                                    response.as_slice(),
                                    UdpMetadata::from(resolved_conn.src),
                                )
                                .expect("failed to send DNS response");
                            let handle = self.sockets.add(socket);
                            self.expect_smoltcp_send()?;
                            self.sockets.remove(handle);
                        }
                    }
                    // Otherwise, UDP is not yet supported.
                }
                Ok::<(), Error>(())
            };
            if let Err(error) = handler() {
                log::error!("{}", error);
            }
        }
        Ok(())
    }

    fn write_to_server(&mut self, connection: &Connection) -> Result<(), Error> {
        if let Some(state) = self.connections.get_mut(connection) {
            let event = state.handler.peek_data(OutgoingDirection::ToServer);
            let buffer_size = event.buffer.len();
            if buffer_size == 0 {
                state.wait_write = false;
                self.update_mio_socket_interest(connection)?;
                self.check_change_close_state(connection)?;
                return Ok(());
            }
            let result = state.mio_stream.write(event.buffer);
            match result {
                Ok(written) => {
                    state
                        .handler
                        .consume_data(OutgoingDirection::ToServer, written);
                    state.wait_write = written < buffer_size;
                    self.update_mio_socket_interest(connection)?;
                }
                Err(error) if error.kind() != std::io::ErrorKind::WouldBlock => {
                    return Err(error.into());
                }
                _ => {
                    // WOULDBLOCK case
                    state.wait_write = true;
                    self.update_mio_socket_interest(connection)?;
                }
            }
        }
        self.check_change_close_state(connection)?;
        Ok(())
    }

    fn write_to_client(&mut self, token: Token, connection: &Connection) -> Result<(), Error> {
        while let Some(state) = self.connections.get_mut(connection) {
            let socket_handle = state.smoltcp_handle;
            let event = state.handler.peek_data(OutgoingDirection::ToClient);
            let buflen = event.buffer.len();
            let consumed;
            {
                let socket = self.sockets.get_mut::<tcp::Socket>(socket_handle);
                if socket.may_send() {
                    if let Some(virtdns) = &mut self.options.virtdns {
                        // Unwrapping is fine because every smoltcp socket is bound to an.
                        virtdns.touch_ip(&IpAddr::from(socket.local_endpoint().unwrap().addr));
                    }
                    consumed = socket.send_slice(event.buffer)?;
                    state
                        .handler
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

            self.check_change_close_state(connection)?;
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
            if let Some(connection) = self.token_to_connection.get(token) {
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
        let conn_ref = self.token_to_connection.get(&event.token());
        // We may have closed the connection in an earlier iteration over the poll
        // events, e.g. because an event through the tunnel interface indicated that the connection
        // should be closed.
        if conn_ref.is_none() {
            log::trace!("{e}");
            return Ok(());
        }
        let connection = conn_ref.unwrap().clone();
        let server = self
            .get_connection_manager(&connection)
            .unwrap()
            .get_server();

        let mut block = || -> Result<(), Error> {
            if event.is_readable() || event.is_read_closed() {
                {
                    let state = self.connections.get_mut(&connection).ok_or(e)?;

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
                    if let Err(error) = state.handler.push_data(data_event) {
                        state.mio_stream.shutdown(Both)?;
                        {
                            let socket = self.sockets.get_mut::<tcp::Socket>(
                                self.connections.get(&connection).ok_or(e)?.smoltcp_handle,
                            );
                            socket.close();
                        }
                        self.expect_smoltcp_send()?;
                        log::error! {"{error}"}
                        self.remove_connection(&connection.clone())?;
                        return Ok(());
                    }

                    // The handler request for reset the server connection
                    if state.handler.reset_connection() {
                        _ = self.poll.registry().deregister(&mut state.mio_stream);
                        // Closes the connection with the proxy
                        state.mio_stream.shutdown(Both)?;

                        log::info!("RESET {}", connection);

                        state.mio_stream = TcpStream::connect(server)?;

                        state.wait_read = true;
                        state.wait_write = true;

                        self.update_mio_socket_interest(&connection)?;

                        return Ok(());
                    }

                    if read == 0 || event.is_read_closed() {
                        state.wait_read = false;
                        state.close_state |= SERVER_WRITE_CLOSED;
                        self.update_mio_socket_interest(&connection)?;
                        self.check_change_close_state(&connection)?;
                        self.expect_smoltcp_send()?;
                    }
                }

                // We have read from the proxy server and pushed the data to the connection handler.
                // Thus, expect data to be processed (e.g. decapsulated) and forwarded to the client.
                self.write_to_client(event.token(), &connection)?;

                // The connection handler could have produced data that is to be written to the
                // server.
                self.write_to_server(&connection)?;
            }

            if event.is_writable() {
                self.write_to_server(&connection)?;
            }
            Ok::<(), Error>(())
        };
        if let Err(error) = block() {
            log::error!("{}", error);
            self.remove_connection(&connection)?;
        }
        Ok(())
    }

    fn udp_event(&mut self, _event: &Event) {}

    pub fn run(&mut self) -> Result<(), Error> {
        let mut events = Events::with_capacity(1024);
        loop {
            match self.poll.poll(&mut events, None) {
                Ok(()) => {
                    for event in events.iter() {
                        match event.token() {
                            EXIT_TOKEN => {
                                log::info!("exiting...");
                                return Ok(());
                            }
                            TUN_TOKEN => self.tun_event(event)?,
                            UDP_TOKEN => self.udp_event(event),
                            _ => self.mio_socket_event(event)?,
                        }
                    }
                    self.send_to_smoltcp()?;
                }
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::Interrupted {
                        log::warn!("Poll interrupted: \"{e}\", ignored, continue polling");
                    } else {
                        return Err(e.into());
                    }
                }
            }
        }
    }

    pub fn shutdown(&mut self) -> Result<(), Error> {
        self.exit_sender.write_all(&[1])?;
        Ok(())
    }
}
