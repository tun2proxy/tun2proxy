use crate::error::Error;
use crate::tun2proxy::DestinationHost::Hostname;
use crate::virtdevice::VirtualTunDevice;
use crate::virtdns::VirtualDns;
use log::{error, info};
use mio::event::Event;
use mio::net::TcpStream;
use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Token};
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, Medium, RxToken, TunTapInterface, TxToken};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant;
use smoltcp::wire::{IpCidr, IpProtocol, Ipv4Packet, Ipv6Packet, TcpPacket, UdpPacket};
use std::collections::{HashMap, HashSet};
use std::convert::{From, TryFrom};
use std::fmt::{Display, Formatter};
use std::io::{Read, Write};
use std::net::Shutdown::Both;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::unix::io::AsRawFd;
use std::rc::Rc;
use std::str::FromStr;

#[derive(Hash, Clone, Eq, PartialEq)]
pub enum DestinationHost {
    Address(IpAddr),
    Hostname(String),
}

impl ToString for DestinationHost {
    fn to_string(&self) -> String {
        match self {
            DestinationHost::Address(addr) => addr.to_string(),
            Hostname(name) => name.clone(),
        }
    }
}

#[derive(Hash, Clone, Eq, PartialEq)]
pub(crate) struct Destination {
    pub(crate) host: DestinationHost,
    pub(crate) port: u16,
}

impl TryFrom<Destination> for SocketAddr {
    type Error = Error;
    fn try_from(value: Destination) -> Result<Self, Self::Error> {
        let ip = match value.host {
            DestinationHost::Address(addr) => addr,
            Hostname(e) => {
                return Err(e.into());
            }
        };
        Ok(SocketAddr::new(ip, value.port))
    }
}

impl From<SocketAddr> for Destination {
    fn from(addr: SocketAddr) -> Self {
        Self {
            host: DestinationHost::Address(addr.ip()),
            port: addr.port(),
        }
    }
}

impl Display for Destination {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let host_part = match self.host {
            DestinationHost::Address(addr) => match addr {
                IpAddr::V4(_) => addr.to_string(),
                IpAddr::V6(_) => format!("[{addr}]"),
            },
            Hostname(_) => self.host.to_string(),
        };
        write!(f, "{}:{}", host_part, self.port)
    }
}

#[derive(Hash, Clone, Eq, PartialEq)]
pub(crate) struct Connection {
    pub(crate) src: SocketAddr,
    pub(crate) dst: Destination,
    pub(crate) proto: u8,
}

impl Connection {
    fn to_named(&self, name: String) -> Self {
        let mut result = self.clone();
        result.dst.host = Hostname(name);
        result
    }
}

impl Display for Connection {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
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
    proto: u8,
    transport_offset: usize,
    packet: &[u8],
) -> Option<((u16, u16), bool, usize, usize)> {
    if proto == IpProtocol::Udp.into() {
        match UdpPacket::new_checked(packet) {
            Ok(result) => Some((
                (result.src_port(), result.dst_port()),
                false,
                transport_offset + 8,
                packet.len() - 8,
            )),
            Err(_) => None,
        }
    } else if proto == IpProtocol::Tcp.into() {
        match TcpPacket::new_checked(packet) {
            Ok(result) => Some((
                (result.src_port(), result.dst_port()),
                result.syn() && !result.ack(),
                transport_offset + result.header_len() as usize,
                packet.len(),
            )),
            Err(_) => None,
        }
    } else {
        None
    }
}

fn connection_tuple(frame: &[u8]) -> Option<(Connection, bool, usize, usize)> {
    if let Ok(packet) = Ipv4Packet::new_checked(frame) {
        let proto: u8 = packet.next_header().into();

        let mut a: [u8; 4] = Default::default();
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
            let proto: u8 = packet.next_header().into();

            let mut a: [u8; 16] = Default::default();
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

const WRITE_CLOSED: u8 = 1;

struct ConnectionState {
    smoltcp_handle: SocketHandle,
    mio_stream: TcpStream,
    token: Token,
    handler: Box<dyn TcpProxy>,
    smoltcp_socket_state: u8,
}

#[derive(Default, Clone, Debug)]
pub struct Credentials {
    pub(crate) username: Vec<u8>,
    pub(crate) password: Vec<u8>,
}

impl Credentials {
    pub fn new(username: &str, password: &str) -> Self {
        Self {
            username: username.as_bytes().to_vec(),
            password: password.as_bytes().to_vec(),
        }
    }
}

pub(crate) trait TcpProxy {
    fn push_data(&mut self, event: IncomingDataEvent<'_>) -> Result<(), Error>;
    fn consume_data(&mut self, dir: OutgoingDirection, size: usize);
    fn peek_data(&mut self, dir: OutgoingDirection) -> OutgoingDataEvent;
    fn connection_established(&self) -> bool;
}

pub(crate) trait ConnectionManager {
    fn handles_connection(&self, connection: &Connection) -> bool;
    fn new_connection(
        &self,
        connection: &Connection,
        manager: Rc<dyn ConnectionManager>,
    ) -> Option<Box<dyn TcpProxy>>;
    fn close_connection(&self, connection: &Connection);
    fn get_server(&self) -> SocketAddr;
    fn get_credentials(&self) -> &Option<Credentials>;
}

#[derive(Default)]
pub struct Options {
    virtdns: Option<VirtualDns>,
}

impl Options {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn with_virtual_dns(mut self) -> Self {
        self.virtdns = Some(VirtualDns::new());
        self
    }
}
const TCP_TOKEN: Token = Token(0);
const UDP_TOKEN: Token = Token(1);

pub(crate) struct TunToProxy<'a> {
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
}

impl<'a> TunToProxy<'a> {
    pub(crate) fn new(interface: &str, options: Options) -> Result<Self, Error> {
        let tun = TunTapInterface::new(interface, Medium::Ip)?;
        let poll = Poll::new()?;
        poll.registry().register(
            &mut SourceFd(&tun.as_raw_fd()),
            TCP_TOKEN,
            Interest::READABLE,
        )?;

        let config = Config::new();
        let mut virt = VirtualTunDevice::new(tun.capabilities());
        let gateway4: Ipv4Addr = Ipv4Addr::from_str("0.0.0.1")?;
        let gateway6: Ipv6Addr = Ipv6Addr::from_str("::1")?;
        let mut iface = Interface::new(config, &mut virt);
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
            next_token: 2,
            token_to_connection: HashMap::default(),
            connection_managers: Vec::default(),
            sockets: SocketSet::new([]),
            device: virt,
            options,
            write_sockets: HashSet::default(),
        };
        Ok(tun)
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
        let e = "connection not exist";
        let mut conn = self.connections.remove(connection).ok_or(e)?;
        let token = &conn.token;
        self.token_to_connection.remove(token);
        self.poll.registry().deregister(&mut conn.mio_stream)?;
        info!("CLOSE {}", connection);
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

    fn tunsocket_read_and_forward(&mut self, connection: &Connection) -> Result<(), Error> {
        if let Some(state) = self.connections.get_mut(connection) {
            let closed = {
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

                match error {
                    Ok(_) => socket.state() == tcp::State::CloseWait,
                    Err(e) => {
                        log::error!("{e}");
                        true
                    }
                }
            };

            // Expect ACKs etc. from smoltcp sockets.
            self.expect_smoltcp_send()?;

            if closed {
                let e = "connection not exist";
                let connection_state = self.connections.get_mut(connection).ok_or(e)?;
                connection_state.mio_stream.shutdown(Both)?;
                self.remove_connection(connection)?;
            }
        }
        Ok(())
    }

    fn receive_tun(&mut self, frame: &mut [u8]) -> Result<(), Error> {
        if let Some((connection, first_packet, _payload_offset, _payload_size)) =
            connection_tuple(frame)
        {
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
            if resolved_conn.proto == IpProtocol::Tcp.into() {
                let cm = self.get_connection_manager(&resolved_conn);
                if cm.is_none() {
                    return Ok(());
                }
                let server = cm.ok_or("no connect manager")?.get_server();
                if first_packet {
                    for manager in self.connection_managers.iter_mut() {
                        if let Some(handler) =
                            manager.new_connection(&resolved_conn, manager.clone())
                        {
                            let mut socket = tcp::Socket::new(
                                tcp::SocketBuffer::new(vec![0; 4096]),
                                tcp::SocketBuffer::new(vec![0; 4096]),
                            );
                            socket.set_ack_delay(None);
                            let dst = SocketAddr::try_from(connection.dst)?;
                            socket.listen(dst)?;
                            let handle = self.sockets.add(socket);

                            let client = TcpStream::connect(server)?;

                            let token = Token(self.next_token);
                            self.next_token += 1;

                            let mut state = ConnectionState {
                                smoltcp_handle: handle,
                                mio_stream: client,
                                token,
                                handler,
                                smoltcp_socket_state: 0,
                            };

                            self.token_to_connection
                                .insert(token, resolved_conn.clone());
                            self.poll.registry().register(
                                &mut state.mio_stream,
                                token,
                                Interest::READABLE | Interest::WRITABLE,
                            )?;

                            self.connections.insert(resolved_conn.clone(), state);

                            info!("CONNECT {}", resolved_conn,);
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
                self.write_to_server(&resolved_conn);
            } else if resolved_conn.proto == IpProtocol::Udp.into() && resolved_conn.dst.port == 53
            {
                if let Some(virtual_dns) = &mut self.options.virtdns {
                    let payload = &frame[_payload_offset.._payload_offset + _payload_size];
                    if let Some(response) = virtual_dns.receive_query(payload) {
                        let rx_buffer =
                            udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY], vec![0; 4096]);
                        let tx_buffer =
                            udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY], vec![0; 4096]);
                        let mut socket = udp::Socket::new(rx_buffer, tx_buffer);
                        let dst = SocketAddr::try_from(connection.dst)?;
                        socket.bind(dst)?;
                        socket
                            .send_slice(response.as_slice(), resolved_conn.src.into())
                            .expect("failed to send DNS response");
                        let handle = self.sockets.add(socket);
                        self.expect_smoltcp_send()?;
                        self.sockets.remove(handle);
                    }
                }
                // Otherwise, UDP is not yet supported.
            }
        }
        Ok(())
    }

    fn write_to_server(&mut self, connection: &Connection) {
        if let Some(state) = self.connections.get_mut(connection) {
            let event = state.handler.peek_data(OutgoingDirection::ToServer);
            if event.buffer.is_empty() {
                return;
            }
            let result = state.mio_stream.write(event.buffer);
            match result {
                Ok(consumed) => {
                    state
                        .handler
                        .consume_data(OutgoingDirection::ToServer, consumed);
                }
                Err(error) if error.kind() != std::io::ErrorKind::WouldBlock => {
                    panic!("Error: {:?}", error);
                }
                _ => {
                    // println!("{:?}", result);
                }
            }
        }
    }

    fn write_to_client(&mut self, token: Token, connection: &Connection) -> Result<(), Error> {
        loop {
            if let Some(state) = self.connections.get_mut(connection) {
                let socket_state = state.smoltcp_socket_state;
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
                let socket = self.sockets.get_mut::<tcp::Socket>(socket_handle);
                if socket_state & WRITE_CLOSED != 0 && consumed == buflen {
                    socket.close();
                    self.expect_smoltcp_send()?;
                    self.write_sockets.remove(&token);
                    self.remove_connection(connection)?;
                    break;
                }
            }
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
                self.write_to_client(*token, &connection.clone())?;
            }
        }
        Ok(())
    }

    fn mio_socket_event(&mut self, event: &Event) -> Result<(), Error> {
        let e = "connection not found";
        let conn_ref = self.token_to_connection.get(&event.token());
        if conn_ref.is_none() {
            return Ok(());
        }
        let connection = conn_ref.ok_or(e)?.clone();
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
                            error!("READ from proxy: {}", error);
                        }
                        vecbuf.len()
                    }
                };

                if read == 0 {
                    {
                        let socket = self.sockets.get_mut::<tcp::Socket>(
                            self.connections.get(&connection).ok_or(e)?.smoltcp_handle,
                        );
                        socket.close();
                    }
                    self.expect_smoltcp_send()?;
                    self.remove_connection(&connection.clone())?;
                    return Ok(());
                }

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
                if event.is_read_closed() {
                    state.smoltcp_socket_state |= WRITE_CLOSED;
                }
            }

            // We have read from the proxy server and pushed the data to the connection handler.
            // Thus, expect data to be processed (e.g. decapsulated) and forwarded to the client.
            self.write_to_client(event.token(), &connection)?;
        }
        if event.is_writable() {
            self.write_to_server(&connection);
        }
        Ok(())
    }

    fn udp_event(&mut self, _event: &Event) {}

    pub(crate) fn run(&mut self) -> Result<(), Error> {
        let mut events = Events::with_capacity(1024);

        loop {
            self.poll.poll(&mut events, None)?;
            for event in events.iter() {
                match event.token() {
                    TCP_TOKEN => self.tun_event(event)?,
                    UDP_TOKEN => self.udp_event(event),
                    _ => self.mio_socket_event(event)?,
                }
            }
            self.send_to_smoltcp()?;
        }
    }
}
