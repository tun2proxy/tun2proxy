use std::collections::{BTreeMap, HashMap};
use std::convert::From;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, Shutdown};
use std::os::unix::io::AsRawFd;

use mio::{Events, Interest, Poll, Token};
use mio::event::Event;
use mio::net::{TcpSocket as MioTcp, TcpStream};
use mio::unix::SourceFd;
use smoltcp::iface::{Interface, InterfaceBuilder, Routes};
use smoltcp::phy::{Device, Medium, RxToken, TunTapInterface, TxToken};
use smoltcp::socket::{SocketHandle, SocketSet, TcpSocket, TcpSocketBuffer};
use smoltcp::time::Instant;
use smoltcp::wire::{IpAddress, IpCidr, Ipv4Address, Ipv4Packet, TcpPacket, UdpPacket, Ipv6Packet};
use crate::virtdevice::VirtualTunDevice;
use std::net::Shutdown::Both;

pub struct ProxyError {
    message: String
}

impl ProxyError {
    pub fn new(message: String) -> Self {
        Self {
            message
        }
    }

    pub fn message(&self) -> String {
        self.message.clone()
    }
}

#[derive(Hash, Clone, Copy)]
pub struct Connection {
    pub src: std::net::SocketAddr,
    pub dst: std::net::SocketAddr,
    pub proto: u8
}

impl std::fmt::Display for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{} -> {}", self.src, self.dst)
    }
}

impl Eq for Connection {}

impl PartialEq<Self> for Connection {
    fn eq(&self, other: &Self) -> bool {
        return other.src == self.src && other.dst == self.dst && other.proto == self.proto;
    }
}

#[derive(Eq, PartialEq, Debug)]
pub(crate) enum IncomingDirection {
    FromServer,
    FromClient
}

#[derive(Eq, PartialEq, Debug)]
pub(crate) enum OutgoingDirection {
    ToServer,
    ToClient
}

#[allow(dead_code)]
pub(crate) enum ConnectionEvent<'a> {
    NewConnection(&'a Connection),
    ConnectionClosed(&'a Connection)
}

pub(crate) struct DataEvent<'a, T> {
    pub(crate) direction: T,
    pub(crate) buffer: &'a [u8]
}

pub(crate) type IncomingDataEvent<'a> = DataEvent<'a, IncomingDirection>;
pub(crate) type OutgoingDataEvent<'a> = DataEvent<'a, OutgoingDirection>;

fn get_transport_info(proto: u8, transport_offset: usize, packet: &[u8]) -> Option<((u16, u16), bool, usize, usize)> {
    if proto == smoltcp::wire::IpProtocol::Udp.into() {
        match UdpPacket::new_checked(packet) {
            Ok(result) => {
                Some(((result.src_port(), result.dst_port()), false, transport_offset + 8, packet.len() - 8))
            },
            Err(_) => None
        }
    } else if proto == smoltcp::wire::IpProtocol::Tcp.into() {
        match TcpPacket::new_checked(packet) {
            Ok(result) => {
                Some(((result.src_port(), result.dst_port()), result.syn() && !result.ack(),
                      transport_offset + result.header_len() as usize, packet.len()))
            },
            Err(_) => None
        }
    }
    else {
        None
    }
}

fn connection_tuple(frame: &[u8]) -> Option<(Connection, bool, usize, usize)> {
    match Ipv4Packet::new_checked(frame) {
        Ok(packet) => {
            let proto:u8 = packet.protocol().into();

            let mut a: [u8; 4] = Default::default();
            a.copy_from_slice(packet.src_addr().as_bytes());
            let src_addr = IpAddr::from(a);
            a.copy_from_slice(packet.dst_addr().as_bytes());
            let dst_addr = IpAddr::from(a);

            if let Some((ports, first_packet, payload_offset, payload_size))
            = get_transport_info(proto,packet.header_len().into(), &frame[packet.header_len().into()..]) {
                let connection = Connection {
                    src: SocketAddr::new(src_addr, ports.0),
                    dst: SocketAddr::new(dst_addr, ports.1),
                    proto
                };
                return Some((connection, first_packet, payload_offset, payload_size));
            } else {
                return None;
            }

        }
        _ => {  }
    }

    match Ipv6Packet::new_checked(frame) {
        Ok(packet) => {
            // TODO: Support extension headers.
            let proto:u8 = packet.next_header().into();

            let mut a: [u8; 16] = Default::default();
            a.copy_from_slice(packet.src_addr().as_bytes());
            let src_addr = IpAddr::from(a);
            a.copy_from_slice(packet.dst_addr().as_bytes());
            let dst_addr = IpAddr::from(a);

            if let Some((ports, first_packet, payload_offset, payload_size))
            = get_transport_info(proto,packet.header_len().into(), &frame[packet.header_len().into()..]) {
                let connection = Connection {
                    src: SocketAddr::new(src_addr, ports.0),
                    dst: SocketAddr::new(dst_addr, ports.1),
                    proto
                };
                Some((connection, first_packet, payload_offset, payload_size))
            } else {
                None
            }

        }
        _ => None
    }
}

struct ConnectionState {
    smoltcp_handle: SocketHandle,
    mio_stream: TcpStream,
    token: Token
}

pub(crate) trait TcpProxy {
    fn push_data(&mut self, event: IncomingDataEvent<'_>) -> Result<(), ProxyError>;
    fn consume_data(&mut self, dir: OutgoingDirection, size: usize);
    fn peek_data(&mut self, dir: OutgoingDirection) -> OutgoingDataEvent;
    fn connection_established(&self) -> bool;
}

pub(crate) trait ConnectionManager {
    fn handles_connection(&self, connection: &Connection) -> bool;
    fn new_connection(&mut self, connection: &Connection) -> Option<std::boxed::Box<dyn TcpProxy>>;
    fn close_connection(&mut self, connection: &Connection);
    fn get_server(&self) -> SocketAddr;
}

pub(crate) struct TunToProxy<'a> {
    tun: TunTapInterface,
    poll: Poll,
    tun_token: Token,
    udp_token: Token,
    iface: Interface<'a, VirtualTunDevice>,
    connections: HashMap<Connection, ConnectionState>,
    managers: HashMap<Connection, std::boxed::Box<dyn TcpProxy>>,
    connection_managers: Vec<std::boxed::Box<dyn ConnectionManager>>,
    next_token: usize,
    token_to_connection: HashMap<Token, Connection>,
    socketset: SocketSet<'a>
}

impl<'a> TunToProxy<'a> {

    pub(crate) fn new(interface: &str) -> Self {
        let tun_token = Token(0);
        let tun = TunTapInterface::new(interface, Medium::Ip).unwrap();
        let poll = Poll::new().unwrap();
        poll.registry().register(&mut SourceFd(&tun.as_raw_fd()), tun_token, Interest::READABLE).unwrap();

        let virt = VirtualTunDevice::new(tun.capabilities());
        let builder = InterfaceBuilder::new(virt);
        let ip_addrs = [
            IpCidr::new(IpAddress::v4(0, 0, 0, 1), 0),
        ];

        let mut routes = Routes::new(BTreeMap::new());
        routes.add_default_ipv4_route(Ipv4Address::new(0, 0, 0, 1)).unwrap();


        let iface = builder.any_ip(true)
            .ip_addrs(ip_addrs).routes(routes).finalize();


        Self {
            tun,
            poll,
            tun_token,
            udp_token: Token(1),
            iface,
            connections: Default::default(),
            next_token: 2,
            token_to_connection: Default::default(),
            socketset: SocketSet::new([]),
            managers: Default::default(),
            connection_managers: Default::default()
        }
    }

    pub(crate) fn add_connection_manager(&mut self, manager: Box<dyn ConnectionManager>) {
        self.connection_managers.push(manager);
    }

    fn expect_smoltcp_send(&mut self) {
        self.iface.poll(&mut self.socketset, Instant::now()).unwrap();

        while let Some(vec) = self.iface.device_mut().exfiltrate_packet() {
            let slice = vec.as_slice();

            // TODO: Actual write. Replace.
            self.tun.transmit().unwrap().consume(Instant::now(), slice.len(), |buf| {
                buf[..].clone_from_slice(slice);
                Ok(())
            }).unwrap();
        }
    }

    fn remove_connection(&mut self, connection: &Connection) {
        self.managers.remove(connection);
        let mut connection_state = self.connections.remove(connection).unwrap();
        self.token_to_connection.remove(&connection_state.token);
        self.poll.registry().deregister(&mut connection_state.mio_stream).unwrap();
        println!("[{:?}] CLOSE {}", chrono::offset::Local::now(), connection);
    }

    fn get_connection_manager(&self, connection: &Connection) -> Option<&Box<dyn ConnectionManager>>{
        for manager in self.connection_managers.iter() {
            if manager.handles_connection(connection) {
                return Some(manager);
            }
        }
        None
    }

    fn print_error(error: ProxyError) {
        println!("Error: {}", error.message());
    }

    fn tunsocket_read_and_forward(&mut self, connection: &Connection) {
        if let Some(handler) = self.managers.get_mut(&connection) {
            let closed = {
                let conn_info = self.connections.get_mut(&connection).unwrap();
                let mut socket = self.socketset.get::<TcpSocket>(conn_info.smoltcp_handle);
                let mut error = Ok(());
                while socket.can_recv() && error.is_ok() {
                    socket.recv(|data| {
                        let event = IncomingDataEvent {
                            direction: IncomingDirection::FromClient,
                            buffer: data,

                        };
                        error = handler.push_data(event);

                        (data.len(), ())
                    }).unwrap();
                }

                if error.is_err() {
                    Self::print_error(error.unwrap_err());
                    true
                } else {
                    socket.state() == smoltcp::socket::TcpState::CloseWait
                }
            };

            if closed {
                let connection_state = self.connections.get_mut(&connection).unwrap();
                connection_state.mio_stream.shutdown(Shutdown::Both).unwrap();
                self.remove_connection(&connection);
                return;
            }
        }
    }

    fn receive_tun(&mut self, frame: &mut [u8]) {
        if let Some((connection, first_packet, _payload_offset, _payload_size)) = connection_tuple(frame) {

            if connection.proto == smoltcp::wire::IpProtocol::Tcp.into() {
                let cm = self.get_connection_manager(&connection);
                if !cm.is_some() {
                    return;
                }
                let server = cm.unwrap().get_server();
                if first_packet {
                    let mut socket = TcpSocket::new(TcpSocketBuffer::new(vec![0; 4096]), TcpSocketBuffer::new(vec![0; 4096]));
                    socket.set_ack_delay(None);
                    socket.listen(connection.dst).unwrap();
                    let handle = self.socketset.add(socket);

                    let socket = if server.is_ipv4() {
                        MioTcp::new_v4().unwrap()
                    } else {
                        MioTcp::new_v6().unwrap()
                    };
                    let client = socket.connect(server).unwrap();

                    let token = Token(self.next_token);
                    self.next_token += 1;

                    let mut conn = ConnectionState {
                        smoltcp_handle: handle,
                        mio_stream: client,
                        token
                    };

                    self.token_to_connection.insert(token, connection);
                    self.poll.registry().register(&mut conn.mio_stream, token, Interest::READABLE | Interest::WRITABLE).unwrap();

                    self.connections.insert(connection, conn);

                    for manager in self.connection_managers.iter_mut() {
                        if let Some(handler) = manager.new_connection(&connection) {
                            self.managers.insert(connection, handler);
                            break;
                        }
                    }


                    println!("[{:?}] CONNECT {}", chrono::offset::Local::now(), connection);
                } else if !self.connections.contains_key(&connection) {
                    return;
                }

                // Inject the packet to advance the smoltcp socket state
                self.iface.device_mut().inject_packet(frame);

                // Having advanced the socket state, we expect the socket to ACK
                // Exfiltrate the response packets generated by the socket and inject them
                // into the tunnel interface.
                self.expect_smoltcp_send();

                // Read from the smoltcp socket and push the data to the connection handler.
                self.tunsocket_read_and_forward(&connection);

                // The connection handler builds up the connection or encapsulates the data.
                // Therefore, we now expect it to write data to the server.
                self.write_to_server(&connection);
            }
            else if connection.proto == smoltcp::wire::IpProtocol::Udp.into() {
                /* // UDP is not yet supported.
                if payload_offset > frame.len() || payload_offset + payload_offset > frame.len() {
                    return;
                }
                let payload = &frame[payload_offset..payload_offset+payload_size]; */
            }
        }
    }

    fn write_to_server(&mut self, connection: &Connection) {
        if let Some(handler) = self.managers.get_mut(&connection) {
            let event = handler.peek_data(OutgoingDirection::ToServer);
            if event.buffer.len() == 0 {
                return;
            }
            let connection_state = self.connections.get_mut(&connection).unwrap();
            let result = connection_state.mio_stream.write(event.buffer);
            match result {
                Ok(consumed) => {
                    handler.consume_data(OutgoingDirection::ToServer, consumed);
                }
                Err(error) if error.kind() != std::io::ErrorKind::WouldBlock  => {
                    panic!("Error: {:?}", error);
                }
                _ => {
                    // println!("{:?}", result);
                }
            }
        }
    }

    fn write_to_client(&mut self, connection: &Connection) {
        if let Some(handler) = self.managers.get_mut(&connection) {
            let event = handler.peek_data(OutgoingDirection::ToClient);
            let socket = &mut self.socketset.get::<TcpSocket>(self.connections.get(&connection).unwrap().smoltcp_handle);
            if socket.may_send() {
                let consumed = socket.send_slice(event.buffer).unwrap();
                handler.consume_data(OutgoingDirection::ToClient, consumed);
            }
        }
    }

    fn tun_event(&mut self, event: &Event) {
        if event.is_readable() {
            while let Some((rx_token, _)) = self.tun.receive() {
                if let Err(err) = rx_token.consume(Instant::now(), |frame| {
                    self.receive_tun(frame);
                    Ok(())
                }) {
                    panic!("Error: {}", err);
                }
            }
        }
    }

    fn mio_socket_event(&mut self, event: &Event) {
        let connection = *self.token_to_connection.get(&event.token()).unwrap();

        if event.is_readable() {
            {
                let conn = self.managers.get_mut(&connection).unwrap();
                let state = self.connections.get_mut(&connection).unwrap();

                let mut buf = [0u8; 4096];
                let read = state.mio_stream.read(&mut buf).unwrap();

                if read == 0 {
                    {
                        let mut socket = self.socketset.get::<TcpSocket>(self.connections.get(&connection).unwrap().smoltcp_handle);
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
                if let Err(error) = conn.push_data(event) {
                    state.mio_stream.shutdown(Both).unwrap();
                    {
                        let mut socket = self.socketset.get::<TcpSocket>(self.connections.get(&connection).unwrap().smoltcp_handle);
                        socket.close();
                    }
                    self.expect_smoltcp_send();
                    Self::print_error(error);
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

    fn udp_event(&mut self, _event: &Event) {

    }

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