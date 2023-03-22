use crate::error::Error;
use crate::virtdevice::VirtualTunDevice;
use log::{error, info};
use mio::event::Event;
use mio::net::TcpStream;
use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Token};
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, Medium, RxToken, TunTapInterface, TxToken};
use smoltcp::socket::tcp;
use smoltcp::time::Instant;
use smoltcp::wire::{
    IpAddress, IpCidr, Ipv4Address, Ipv4Packet, Ipv6Address, Ipv6Packet, TcpPacket, UdpPacket,
};
use std::collections::HashMap;
use std::convert::From;
use std::fmt::{Display, Formatter};
use std::io::{Read, Write};
use std::net::Shutdown::Both;
use std::net::{IpAddr, Shutdown, SocketAddr};
use std::os::unix::io::AsRawFd;

#[derive(Hash, Clone, Eq, PartialEq)]
pub enum DestinationHost {
    Address(IpAddr),
    Hostname(String),
}

impl ToString for DestinationHost {
    fn to_string(&self) -> String {
        match self {
            DestinationHost::Address(addr) => addr.to_string(),
            DestinationHost::Hostname(name) => name.clone(),
        }
    }
}

#[derive(Hash, Clone, Eq, PartialEq)]
pub(crate) struct Destination {
    pub(crate) host: DestinationHost,
    pub(crate) port: u16,
}

impl From<Destination> for SocketAddr {
    fn from(value: Destination) -> Self {
        SocketAddr::new(
            match value.host {
                DestinationHost::Address(addr) => addr,
                DestinationHost::Hostname(_) => {
                    panic!("Failed to convert hostname destination into socket address")
                }
            },
            value.port,
        )
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
        write!(f, "{}:{}", self.host.to_string(), self.port)
    }
}

#[derive(Hash, Clone, Eq, PartialEq)]
pub(crate) struct Connection {
    pub(crate) src: std::net::SocketAddr,
    pub(crate) dst: Destination,
    pub(crate) proto: u8,
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
    if proto == smoltcp::wire::IpProtocol::Udp.into() {
        match UdpPacket::new_checked(packet) {
            Ok(result) => Some((
                (result.src_port(), result.dst_port()),
                false,
                transport_offset + 8,
                packet.len() - 8,
            )),
            Err(_) => None,
        }
    } else if proto == smoltcp::wire::IpProtocol::Tcp.into() {
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

        if let Some((ports, first_packet, payload_offset, payload_size)) = get_transport_info(
            proto,
            packet.header_len().into(),
            &frame[packet.header_len().into()..],
        ) {
            let connection = Connection {
                src: SocketAddr::new(src_addr, ports.0),
                dst: SocketAddr::new(dst_addr, ports.1).into(),
                proto,
            };
            return Some((connection, first_packet, payload_offset, payload_size));
        } else {
            return None;
        }
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

struct ConnectionState {
    smoltcp_handle: SocketHandle,
    mio_stream: TcpStream,
    token: Token,
    handler: std::boxed::Box<dyn TcpProxy>,
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
        manager: std::rc::Rc<dyn ConnectionManager>,
    ) -> Option<std::boxed::Box<dyn TcpProxy>>;
    fn close_connection(&self, connection: &Connection);
    fn get_server(&self) -> SocketAddr;
    fn get_credentials(&self) -> &Option<Credentials>;
}

pub(crate) struct TunToProxy<'a> {
    tun: TunTapInterface,
    poll: Poll,
    tun_token: Token,
    udp_token: Token,
    iface: Interface,
    connections: HashMap<Connection, ConnectionState>,
    connection_managers: Vec<std::rc::Rc<dyn ConnectionManager>>,
    next_token: usize,
    token_to_connection: HashMap<Token, Connection>,
    sockets: SocketSet<'a>,
    device: VirtualTunDevice,
}

impl<'a> TunToProxy<'a> {
    pub(crate) fn new(interface: &str) -> Self {
        let tun_token = Token(0);
        let tun = TunTapInterface::new(interface, Medium::Ip).unwrap();
        let poll = Poll::new().unwrap();
        poll.registry()
            .register(
                &mut SourceFd(&tun.as_raw_fd()),
                tun_token,
                Interest::READABLE,
            )
            .unwrap();

        let config = Config::new();
        let mut virt = VirtualTunDevice::new(tun.capabilities());
        let mut iface = Interface::new(config, &mut virt);
        iface.update_ip_addrs(|ip_addrs| {
            ip_addrs
                .push(IpCidr::new(IpAddress::v4(0, 0, 0, 1), 0))
                .unwrap();
            ip_addrs
                .push(IpCidr::new(IpAddress::v6(0, 0, 0, 0, 0, 0, 0, 1), 0))
                .unwrap()
        });
        iface
            .routes_mut()
            .add_default_ipv4_route(Ipv4Address::new(0, 0, 0, 1))
            .unwrap();
        iface
            .routes_mut()
            .add_default_ipv6_route(Ipv6Address::new(0, 0, 0, 0, 0, 0, 0, 1))
            .unwrap();
        iface.set_any_ip(true);

        Self {
            tun,
            poll,
            tun_token,
            udp_token: Token(1),
            iface,
            connections: Default::default(),
            next_token: 2,
            token_to_connection: Default::default(),
            connection_managers: Default::default(),
            sockets: SocketSet::new([]),
            device: virt,
        }
    }

    pub(crate) fn add_connection_manager(&mut self, manager: std::rc::Rc<dyn ConnectionManager>) {
        self.connection_managers.push(manager);
    }

    fn expect_smoltcp_send(&mut self) {
        self.iface
            .poll(Instant::now(), &mut self.device, &mut self.sockets);

        while let Some(vec) = self.device.exfiltrate_packet() {
            let slice = vec.as_slice();

            // TODO: Actual write. Replace.
            self.tun
                .transmit(Instant::now())
                .unwrap()
                .consume(slice.len(), |buf| {
                    buf[..].clone_from_slice(slice);
                });
        }
    }

    fn remove_connection(&mut self, connection: &Connection) {
        let mut connection_state = self.connections.remove(connection).unwrap();
        self.token_to_connection.remove(&connection_state.token);
        self.poll
            .registry()
            .deregister(&mut connection_state.mio_stream)
            .unwrap();
        info!("CLOSE {}", connection);
    }

    fn get_connection_manager(
        &self,
        connection: &Connection,
    ) -> Option<std::rc::Rc<dyn ConnectionManager>> {
        for manager in self.connection_managers.iter() {
            if manager.handles_connection(connection) {
                return Some(manager.clone());
            }
        }
        None
    }

    fn tunsocket_read_and_forward(&mut self, connection: &Connection) {
        if let Some(state) = self.connections.get_mut(connection) {
            let closed = {
                // let socket = self.iface.get_socket::<TcpSocket>(state.smoltcp_handle);
                let socket = self.sockets.get_mut::<tcp::Socket>(state.smoltcp_handle);
                let mut error = Ok(());
                while socket.can_recv() && error.is_ok() {
                    socket
                        .recv(|data| {
                            let event = IncomingDataEvent {
                                direction: IncomingDirection::FromClient,
                                buffer: data,
                            };
                            error = state.handler.push_data(event);

                            (data.len(), ())
                        })
                        .unwrap();
                }

                match error {
                    Ok(_) => socket.state() == smoltcp::socket::tcp::State::CloseWait,
                    Err(e) => {
                        log::error!("{e}");
                        true
                    }
                }
            };

            if closed {
                let connection_state = self.connections.get_mut(connection).unwrap();
                connection_state
                    .mio_stream
                    .shutdown(Shutdown::Both)
                    .unwrap();
                self.remove_connection(connection);
            }
        }
    }

    fn receive_tun(&mut self, frame: &mut [u8]) {
        if let Some((connection, first_packet, _payload_offset, _payload_size)) =
            connection_tuple(frame)
        {
            if connection.proto == smoltcp::wire::IpProtocol::Tcp.into() {
                let cm = self.get_connection_manager(&connection);
                if cm.is_none() {
                    return;
                }
                let server = cm.unwrap().get_server();
                if first_packet {
                    for manager in self.connection_managers.iter_mut() {
                        if let Some(handler) = manager.new_connection(&connection, manager.clone())
                        {
                            let mut socket = smoltcp::socket::tcp::Socket::new(
                                smoltcp::socket::tcp::SocketBuffer::new(vec![0; 4096]),
                                smoltcp::socket::tcp::SocketBuffer::new(vec![0; 4096]),
                            );
                            socket.set_ack_delay(None);
                            let dst = connection.dst.clone();
                            socket
                                .listen(<Destination as Into<SocketAddr>>::into(dst))
                                .unwrap();
                            let handle = self.sockets.add(socket);

                            let client = TcpStream::connect(server).unwrap();

                            let token = Token(self.next_token);
                            self.next_token += 1;

                            let mut state = ConnectionState {
                                smoltcp_handle: handle,
                                mio_stream: client,
                                token,
                                handler,
                            };

                            self.token_to_connection.insert(token, connection.clone());
                            self.poll
                                .registry()
                                .register(
                                    &mut state.mio_stream,
                                    token,
                                    Interest::READABLE | Interest::WRITABLE,
                                )
                                .unwrap();

                            self.connections.insert(connection.clone(), state);

                            info!("CONNECT {}", connection,);
                            break;
                        }
                    }
                } else if !self.connections.contains_key(&connection) {
                    return;
                }

                // Inject the packet to advance the smoltcp socket state
                self.device.inject_packet(frame);

                // Having advanced the socket state, we expect the socket to ACK
                // Exfiltrate the response packets generated by the socket and inject them
                // into the tunnel interface.
                self.expect_smoltcp_send();

                // Read from the smoltcp socket and push the data to the connection handler.
                self.tunsocket_read_and_forward(&connection);

                // The connection handler builds up the connection or encapsulates the data.
                // Therefore, we now expect it to write data to the server.
                self.write_to_server(&connection);
            } else if connection.proto == smoltcp::wire::IpProtocol::Udp.into() {
                // UDP is not yet supported
                /*if _payload_offset > frame.len() || _payload_offset + _payload_offset > frame.len() {
                    return;
                }
                let payload = &frame[_payload_offset.._payload_offset + _payload_size];
                self.virtual_dns.add_query(payload);*/
            }
        }
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

    fn write_to_client(&mut self, connection: &Connection) {
        if let Some(state) = self.connections.get_mut(connection) {
            let event = state.handler.peek_data(OutgoingDirection::ToClient);
            let socket = self.sockets.get_mut::<tcp::Socket>(state.smoltcp_handle);
            if socket.may_send() {
                let consumed = socket.send_slice(event.buffer).unwrap();
                state
                    .handler
                    .consume_data(OutgoingDirection::ToClient, consumed);
            }
        }
    }

    fn tun_event(&mut self, event: &Event) {
        if event.is_readable() {
            while let Some((rx_token, _)) = self.tun.receive(Instant::now()) {
                rx_token.consume(|frame| {
                    self.receive_tun(frame);
                });
            }
        }
    }

    fn mio_socket_event(&mut self, event: &Event) {
        if let Some(conn_ref) = self.token_to_connection.get(&event.token()) {
            let connection = conn_ref.clone();
            if event.is_readable() {
                {
                    let state = self.connections.get_mut(&connection).unwrap();

                    let mut buf = [0u8; 4096];
                    let read_result = state.mio_stream.read(&mut buf);
                    let read = if let Ok(read_result) = read_result {
                        read_result
                    } else {
                        error!("READ from proxy: {}", read_result.as_ref().err().unwrap());
                        0
                    };

                    if read == 0 {
                        {
                            let socket = self.sockets.get_mut::<tcp::Socket>(
                                self.connections.get(&connection).unwrap().smoltcp_handle,
                            );
                            socket.close();
                        }
                        self.expect_smoltcp_send();
                        self.remove_connection(&connection.clone());
                        return;
                    }

                    let event = IncomingDataEvent {
                        direction: IncomingDirection::FromServer,
                        buffer: &buf[0..read],
                    };
                    if let Err(error) = state.handler.push_data(event) {
                        state.mio_stream.shutdown(Both).unwrap();
                        {
                            let socket = self.sockets.get_mut::<tcp::Socket>(
                                self.connections.get(&connection).unwrap().smoltcp_handle,
                            );
                            socket.close();
                        }
                        self.expect_smoltcp_send();
                        log::error! {"{error}"};
                        self.remove_connection(&connection.clone());
                        return;
                    }
                }

                // We have read from the proxy server and pushed the data to the connection handler.
                // Thus, expect data to be processed (e.g. decapsulated) and forwarded to the client.

                //self.expect_smoltcp_send();
                self.write_to_client(&connection);
                self.expect_smoltcp_send();
            }
            if event.is_writable() {
                self.write_to_server(&connection);
            }
        }
    }

    fn udp_event(&mut self, _event: &Event) {}

    pub(crate) fn run(&mut self) {
        let mut events = Events::with_capacity(1024);

        loop {
            self.poll.poll(&mut events, None).unwrap();
            for event in events.iter() {
                if event.token() == self.tun_token {
                    self.tun_event(event);
                } else if event.token() == self.udp_token {
                    self.udp_event(event);
                } else {
                    self.mio_socket_event(event);
                }
            }
        }
    }
}
