#![allow(dead_code)]

use crate::{dns, error::Error, error::Result, virtdevice::VirtualTunDevice, NetworkInterface, Options};
#[cfg(target_family = "unix")]
use mio::unix::SourceFd;
use mio::{event::Event, net::TcpStream, net::UdpSocket, Events, Interest, Poll, Token};
#[cfg(not(target_family = "unix"))]
use smoltcp::phy::DeviceCapabilities;
#[cfg(any(target_os = "macos", target_os = "ios"))]
use smoltcp::phy::RawSocket;
#[cfg(any(target_os = "linux", target_os = "android"))]
use smoltcp::phy::TunTapInterface;
#[cfg(target_family = "unix")]
use smoltcp::phy::{Device, Medium, RxToken, TxToken};
use smoltcp::{
    iface::{Config, Interface, SocketHandle, SocketSet},
    socket::{tcp, tcp::State, udp, udp::UdpMetadata},
    time::Instant,
    wire::{IpCidr, IpProtocol, Ipv4Packet, Ipv6Packet, TcpPacket, UdpPacket, UDP_HEADER_LEN},
};
use socks5_impl::protocol::{Address, StreamOperation, UdpHeader};
use std::collections::LinkedList;
#[cfg(target_family = "unix")]
use std::os::unix::io::AsRawFd;
use std::{
    collections::{HashMap, HashSet},
    convert::{From, TryFrom},
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr},
    rc::Rc,
    str::FromStr,
};

#[derive(Hash, Clone, Eq, PartialEq, PartialOrd, Ord, Debug)]
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
    pub fn new(src: SocketAddr, dst: Address, protocol: IpProtocol) -> Self {
        Self { src, dst, protocol }
    }

    fn to_named(&self, name: String) -> Self {
        let mut result = self.clone();
        result.dst = Address::from((name, result.dst.port()));
        log::trace!("{} replace dst \"{}\" -> \"{}\"", self.protocol, self.dst, result.dst);
        result
    }
}

impl std::fmt::Display for ConnectionInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{} {} -> {}", self.protocol, self.src, self.dst)
    }
}

#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub(crate) enum IncomingDirection {
    FromServer,
    FromClient,
}

#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub(crate) enum OutgoingDirection {
    ToServer,
    ToClient,
}

#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub(crate) enum Direction {
    Incoming(IncomingDirection),
    Outgoing(OutgoingDirection),
}

#[derive(Clone, Eq, PartialEq, Debug)]
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
        let info = ConnectionInfo::new(
            SocketAddr::new(src_addr, ports.0),
            SocketAddr::new(dst_addr, ports.1).into(),
            protocol,
        );
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
        let info = ConnectionInfo::new(
            SocketAddr::new(src_addr, ports.0),
            SocketAddr::new(dst_addr, ports.1).into(),
            protocol,
        );
        return Ok((info, first_packet, payload_offset, payload_size));
    }
    Err("Neither IPv6 nor IPv4 packet".into())
}

const SERVER_WRITE_CLOSED: u8 = 1;
const CLIENT_WRITE_CLOSED: u8 = 2;

const UDP_ASSO_TIMEOUT: u64 = 10; // seconds
const DNS_PORT: u16 = 53;

struct ConnectionState {
    smoltcp_handle: SocketHandle,
    mio_stream: TcpStream,
    token: Token,
    proxy_handler: Box<dyn ProxyHandler>,
    close_state: u8,
    wait_read: bool,
    wait_write: bool,
    origin_dst: SocketAddr,
    udp_acco_expiry: Option<::std::time::Instant>,
    udp_socket: Option<UdpSocket>,
    udp_token: Option<Token>,
    udp_data_cache: LinkedList<Vec<u8>>,
    dns_over_tcp_expiry: Option<::std::time::Instant>,
}

pub(crate) trait ProxyHandler {
    fn get_connection_info(&self) -> &ConnectionInfo;
    fn push_data(&mut self, event: IncomingDataEvent<'_>) -> Result<(), Error>;
    fn consume_data(&mut self, dir: OutgoingDirection, size: usize);
    fn peek_data(&mut self, dir: OutgoingDirection) -> OutgoingDataEvent;
    fn connection_established(&self) -> bool;
    fn have_data(&mut self, dir: Direction) -> bool;
    fn reset_connection(&self) -> bool;
    fn get_udp_associate(&self) -> Option<SocketAddr>;
}

pub(crate) trait ConnectionManager {
    fn new_proxy_handler(&self, info: &ConnectionInfo, udp_associate: bool) -> Result<Box<dyn ProxyHandler>>;
    fn get_server_addr(&self) -> SocketAddr;
}

const TUN_TOKEN: Token = Token(0);
const PIPE_TOKEN: Token = Token(1);
const EXIT_TRIGGER_TOKEN: Token = Token(2);
const EXIT_TOKEN: Token = Token(10);

pub struct TunToProxy<'a> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    tun: TunTapInterface,
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    tun: RawSocket,
    poll: Poll,
    iface: Interface,
    connection_map: HashMap<ConnectionInfo, ConnectionState>,
    connection_manager: Option<Rc<dyn ConnectionManager>>,
    next_token_seed: usize,
    sockets: SocketSet<'a>,
    device: VirtualTunDevice,
    options: Options,
    write_sockets: HashSet<Token>,
    #[cfg(target_family = "unix")]
    exit_receiver: mio::unix::pipe::Receiver,
    #[cfg(target_family = "unix")]
    exit_trigger: Option<mio::unix::pipe::Sender>,
}

impl<'a> TunToProxy<'a> {
    pub fn new(_interface: &NetworkInterface, options: Options) -> Result<Self, Error> {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let tun = match _interface {
            NetworkInterface::Named(name) => TunTapInterface::new(name.as_str(), Medium::Ip)?,
            NetworkInterface::Fd(fd) => TunTapInterface::from_fd(*fd, Medium::Ip, options.mtu.unwrap_or(1500))?,
        };

        #[cfg(any(target_os = "macos", target_os = "ios"))]
        let tun = match _interface {
            NetworkInterface::Named(name) => RawSocket::new(name.as_str(), Medium::Ip)?,
            NetworkInterface::Fd(_fd) => panic!("Not supported"),
        };

        let poll = Poll::new()?;

        #[cfg(target_family = "unix")]
        poll.registry()
            .register(&mut SourceFd(&tun.as_raw_fd()), TUN_TOKEN, Interest::READABLE)?;

        #[cfg(target_family = "unix")]
        let (mut exit_trigger, mut exit_receiver) = mio::unix::pipe::new()?;

        #[cfg(target_family = "unix")]
        poll.registry()
            .register(&mut exit_trigger, EXIT_TRIGGER_TOKEN, Interest::WRITABLE)?;
        #[cfg(target_family = "unix")]
        poll.registry()
            .register(&mut exit_receiver, EXIT_TOKEN, Interest::READABLE)?;

        #[cfg(target_family = "unix")]
        let config = match tun.capabilities().medium {
            Medium::Ethernet => Config::new(smoltcp::wire::EthernetAddress([0x02, 0, 0, 0, 0, 0x01]).into()),
            Medium::Ip => Config::new(smoltcp::wire::HardwareAddress::Ip),
            Medium::Ieee802154 => todo!(),
        };
        #[cfg(not(target_family = "unix"))]
        let config = Config::new(smoltcp::wire::HardwareAddress::Ip);

        #[cfg(target_family = "unix")]
        let mut device = VirtualTunDevice::new(tun.capabilities());
        #[cfg(not(target_family = "unix"))]
        let mut device = VirtualTunDevice::new(DeviceCapabilities::default());

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
            #[cfg(target_family = "unix")]
            tun,
            poll,
            iface,
            connection_map: HashMap::default(),
            next_token_seed: usize::from(EXIT_TOKEN),
            connection_manager: None,
            sockets: SocketSet::new([]),
            device,
            options,
            write_sockets: HashSet::default(),
            #[cfg(target_family = "unix")]
            exit_receiver,
            #[cfg(target_family = "unix")]
            exit_trigger: Some(exit_trigger),
        };
        Ok(tun)
    }

    fn new_token(&mut self) -> Token {
        self.next_token_seed += 1;
        Token(self.next_token_seed)
    }

    pub(crate) fn set_connection_manager(&mut self, manager: Option<Rc<dyn ConnectionManager>>) {
        self.connection_manager = manager;
    }

    /// Read data from virtual device (remote server) and inject it into tun interface.
    fn expect_smoltcp_send(&mut self) -> Result<(), Error> {
        self.iface.poll(Instant::now(), &mut self.device, &mut self.sockets);

        while let Some(vec) = self.device.exfiltrate_packet() {
            let _slice = vec.as_slice();

            // TODO: Actual write. Replace.
            #[cfg(target_family = "unix")]
            self.tun
                .transmit(Instant::now())
                .ok_or("tx token not available")?
                .consume(_slice.len(), |buf| {
                    buf[..].clone_from_slice(_slice);
                });
        }
        Ok(())
    }

    fn find_info_by_token(&self, token: Token) -> Option<&ConnectionInfo> {
        self.connection_map
            .iter()
            .find_map(|(info, state)| if state.token == token { Some(info) } else { None })
    }

    fn find_info_by_udp_token(&self, token: Token) -> Option<&ConnectionInfo> {
        self.connection_map.iter().find_map(|(info, state)| {
            if let Some(udp_token) = state.udp_token {
                if udp_token == token {
                    return Some(info);
                }
            }
            None
        })
    }

    /// Destroy connection state machine
    fn remove_connection(&mut self, info: &ConnectionInfo) -> Result<(), Error> {
        if let Some(mut state) = self.connection_map.remove(info) {
            self.expect_smoltcp_send()?;

            {
                let handle = state.smoltcp_handle;
                let socket = self.sockets.get_mut::<tcp::Socket>(handle);
                socket.close();
                self.sockets.remove(handle);
            }

            if let Err(e) = self.poll.registry().deregister(&mut state.mio_stream) {
                // FIXME: The function `deregister` will frequently fail for unknown reasons.
                log::trace!("{}", e);
            }

            if let Some(mut udp_socket) = state.udp_socket {
                if let Err(e) = self.poll.registry().deregister(&mut udp_socket) {
                    log::trace!("{}", e);
                }
            }

            if let Err(err) = state.mio_stream.shutdown(Shutdown::Both) {
                log::trace!("Shutdown 0 {} error \"{}\"", info, err);
            }

            log::info!("Close {}", info);
        }
        Ok(())
    }

    fn get_connection_manager(&self) -> Option<Rc<dyn ConnectionManager>> {
        self.connection_manager.clone()
    }

    /// Scan connection state machine and check if any connection should be closed.
    fn check_change_close_state(&mut self, info: &ConnectionInfo) -> Result<(), Error> {
        let state = match self.connection_map.get_mut(info) {
            Some(state) => state,
            None => return Ok(()),
        };
        let mut closed_ends = 0;
        if (state.close_state & SERVER_WRITE_CLOSED) == SERVER_WRITE_CLOSED
            && !state
                .proxy_handler
                .have_data(Direction::Incoming(IncomingDirection::FromServer))
            && !state
                .proxy_handler
                .have_data(Direction::Outgoing(OutgoingDirection::ToClient))
        {
            // Close tun interface
            let socket = self.sockets.get_mut::<tcp::Socket>(state.smoltcp_handle);
            socket.close();

            closed_ends += 1;
        }

        if (state.close_state & CLIENT_WRITE_CLOSED) == CLIENT_WRITE_CLOSED
            && !state
                .proxy_handler
                .have_data(Direction::Incoming(IncomingDirection::FromClient))
            && !state
                .proxy_handler
                .have_data(Direction::Outgoing(OutgoingDirection::ToServer))
        {
            // Close remote server
            if let Err(err) = state.mio_stream.shutdown(Shutdown::Write) {
                log::trace!("Shutdown 1 {} error \"{}\"", info, err);
            }
            closed_ends += 1;
        }

        if closed_ends == 2 {
            // Close connection state machine
            self.remove_connection(info)?;
        }
        Ok(())
    }

    fn tunsocket_read_and_forward(&mut self, info: &ConnectionInfo) -> Result<(), Error> {
        // 1. Read data from tun and write to proxy handler (remote server).
        // Scope for mutable borrow of self.
        {
            let state = match self.connection_map.get_mut(info) {
                Some(state) => state,
                None => return Ok(()),
            };
            let socket = self.sockets.get_mut::<tcp::Socket>(state.smoltcp_handle);
            let mut error = Ok(());
            while socket.can_recv() && error.is_ok() {
                socket.recv(|data| {
                    let event = IncomingDataEvent {
                        direction: IncomingDirection::FromClient,
                        buffer: data,
                    };
                    error = state.proxy_handler.push_data(event);
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
        }
        // 2. Write data from proxy handler (remote server) to tun.
        // Expect ACKs etc. from smoltcp sockets.
        self.expect_smoltcp_send()?;

        self.check_change_close_state(info)?;

        Ok(())
    }

    fn update_mio_socket_interest(poll: &mut Poll, state: &mut ConnectionState) -> Result<()> {
        // Maybe we did not listen for any events before. Therefore, just swallow the error.
        if let Err(err) = poll.registry().deregister(&mut state.mio_stream) {
            log::trace!("{}", err);
        }

        // If we do not wait for read or write events, we do not need to register them.
        if !state.wait_read && !state.wait_write {
            return Ok(());
        }

        // This ugliness is due to the way Interest is implemented (as a NonZeroU8 wrapper).
        let interest = match (state.wait_read, state.wait_write) {
            (true, false) => Interest::READABLE,
            (false, true) => Interest::WRITABLE,
            _ => Interest::READABLE | Interest::WRITABLE,
        };

        poll.registry().register(&mut state.mio_stream, state.token, interest)?;
        Ok(())
    }

    fn preprocess_origin_connection_info(&mut self, info: ConnectionInfo) -> Result<ConnectionInfo> {
        let origin_dst = SocketAddr::try_from(&info.dst)?;
        let connection_info = match &mut self.options.virtual_dns {
            None => {
                let mut info = info;
                let port = origin_dst.port();
                if port == DNS_PORT && info.protocol == IpProtocol::Udp && dns::addr_is_private(&origin_dst) {
                    let dns_addr: SocketAddr = (self.options.dns_addr.ok_or("dns_addr")?, DNS_PORT).into();
                    info.dst = Address::from(dns_addr);
                }
                info
            }
            Some(virtual_dns) => {
                let dst_ip = origin_dst.ip();
                virtual_dns.touch_ip(&dst_ip);
                match virtual_dns.resolve_ip(&dst_ip) {
                    None => info,
                    Some(name) => info.to_named(name.clone()),
                }
            }
        };
        Ok(connection_info)
    }

    fn process_incoming_dns_over_tcp_packets(
        &mut self,
        manager: &Rc<dyn ConnectionManager>,
        info: &ConnectionInfo,
        origin_dst: SocketAddr,
        payload: &[u8],
    ) -> Result<()> {
        _ = dns::parse_data_to_dns_message(payload, false)?;

        if !self.connection_map.contains_key(info) {
            log::info!("DNS over TCP {} ({})", info, origin_dst);

            let proxy_handler = manager.new_proxy_handler(info, false)?;
            let server_addr = manager.get_server_addr();
            let state = self.create_new_tcp_connection_state(server_addr, origin_dst, proxy_handler, false)?;
            self.connection_map.insert(info.clone(), state);

            // TODO: Move this 3 lines to the function end?
            self.expect_smoltcp_send()?;
            self.tunsocket_read_and_forward(info)?;
            self.write_to_server(info)?;
        } else {
            log::trace!("DNS over TCP subsequent packet {} ({})", info, origin_dst);
        }

        // Insert the DNS message length in front of the payload
        let len = u16::try_from(payload.len())?;
        let mut buf = Vec::with_capacity(2 + usize::from(len));
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(payload);

        let err = "udp over tcp state not find";
        let state = self.connection_map.get_mut(info).ok_or(err)?;
        state.dns_over_tcp_expiry = Some(Self::common_udp_life_timeout());

        let data_event = IncomingDataEvent {
            direction: IncomingDirection::FromClient,
            buffer: &buf,
        };
        state.proxy_handler.push_data(data_event)?;
        Ok(())
    }

    fn receive_dns_over_tcp_packet_and_write_to_client(&mut self, info: &ConnectionInfo) -> Result<()> {
        let err = "udp connection state not found";
        let state = self.connection_map.get_mut(info).ok_or(err)?;
        assert!(state.dns_over_tcp_expiry.is_some());
        state.dns_over_tcp_expiry = Some(Self::common_udp_life_timeout());

        let mut vecbuf = vec![];
        Self::read_data_from_tcp_stream(&mut state.mio_stream, |data| {
            vecbuf.extend_from_slice(data);
            Ok(())
        })?;

        let data_event = IncomingDataEvent {
            direction: IncomingDirection::FromServer,
            buffer: &vecbuf,
        };
        if let Err(error) = state.proxy_handler.push_data(data_event) {
            log::error!("{}", error);
            self.remove_connection(&info.clone())?;
            return Ok(());
        }

        let dns_event = state.proxy_handler.peek_data(OutgoingDirection::ToClient);

        let mut buf = dns_event.buffer.to_vec();
        let mut to_send: LinkedList<Vec<u8>> = LinkedList::new();
        loop {
            if buf.len() < 2 {
                break;
            }
            let len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
            if buf.len() < len + 2 {
                break;
            }
            let data = buf[2..len + 2].to_vec();

            let mut message = dns::parse_data_to_dns_message(&data, false)?;

            let name = dns::extract_domain_from_dns_message(&message)?;
            let ip = dns::extract_ipaddr_from_dns_message(&message);
            log::trace!("DNS over TCP query result: {} -> {:?}", name, ip);

            state.proxy_handler.consume_data(OutgoingDirection::ToClient, len + 2);

            if !self.options.ipv6_enabled {
                dns::remove_ipv6_entries(&mut message);
            }

            to_send.push_back(message.to_vec()?);
            if len + 2 == buf.len() {
                break;
            }
            buf = buf[len + 2..].to_vec();
        }

        // Write to client
        let src = state.origin_dst;
        while let Some(packet) = to_send.pop_front() {
            self.send_udp_packet_to_client(src, info.src, &packet)?;
        }
        Ok(())
    }

    fn dns_over_tcp_timeout_expired(&self, info: &ConnectionInfo) -> bool {
        if let Some(state) = self.connection_map.get(info) {
            if let Some(expiry) = state.dns_over_tcp_expiry {
                return expiry < ::std::time::Instant::now();
            }
        }
        false
    }

    fn clearup_expired_dns_over_tcp(&mut self) -> Result<()> {
        let keys = self.connection_map.keys().cloned().collect::<Vec<_>>();
        for key in keys {
            if self.dns_over_tcp_timeout_expired(&key) {
                log::trace!("DNS over TCP timeout: {}", key);
                self.remove_connection(&key)?;
            }
        }
        Ok(())
    }

    fn process_incoming_udp_packets(
        &mut self,
        manager: &Rc<dyn ConnectionManager>,
        info: &ConnectionInfo,
        origin_dst: SocketAddr,
        payload: &[u8],
    ) -> Result<()> {
        if !self.connection_map.contains_key(info) {
            log::info!("UDP associate session {} ({})", info, origin_dst);
            let proxy_handler = manager.new_proxy_handler(info, true)?;
            let server_addr = manager.get_server_addr();
            let state = self.create_new_tcp_connection_state(server_addr, origin_dst, proxy_handler, true)?;
            self.connection_map.insert(info.clone(), state);

            self.expect_smoltcp_send()?;
            self.tunsocket_read_and_forward(info)?;
            self.write_to_server(info)?;
        } else {
            log::trace!("Subsequent udp packet {} ({})", info, origin_dst);
        }

        let err = "udp associate state not find";
        let state = self.connection_map.get_mut(info).ok_or(err)?;
        assert!(state.udp_acco_expiry.is_some());
        state.udp_acco_expiry = Some(Self::common_udp_life_timeout());

        // Add SOCKS5 UDP header to the incoming data
        let mut s5_udp_data = Vec::<u8>::new();
        UdpHeader::new(0, info.dst.clone()).write_to_stream(&mut s5_udp_data)?;
        s5_udp_data.extend_from_slice(payload);

        if let Some(udp_associate) = state.proxy_handler.get_udp_associate() {
            // UDP associate session has been established, we can send packets directly...
            if let Some(socket) = state.udp_socket.as_ref() {
                socket.send_to(&s5_udp_data, udp_associate)?;
            }
        } else {
            // UDP associate tunnel not ready yet, we must cache the packets...
            log::trace!("Cache udp packet {} ({})", info, origin_dst);
            state.udp_data_cache.push_back(s5_udp_data);
        }
        Ok(())
    }

    fn process_incoming_tcp_packets(
        &mut self,
        first_packet: bool,
        manager: &Rc<dyn ConnectionManager>,
        info: &ConnectionInfo,
        origin_dst: SocketAddr,
        frame: &[u8],
    ) -> Result<()> {
        if first_packet {
            let proxy_handler = manager.new_proxy_handler(info, false)?;
            let server = manager.get_server_addr();
            let state = self.create_new_tcp_connection_state(server, origin_dst, proxy_handler, false)?;
            self.connection_map.insert(info.clone(), state);

            log::info!("{} ({})", info, origin_dst);
        } else if !self.connection_map.contains_key(info) {
            log::trace!("Drop middle session {} ({})", info, origin_dst);
            return Ok(());
        } else {
            log::trace!("Subsequent packet {} ({})", info, origin_dst);
        }

        // Inject the packet to advance the remote proxy server smoltcp socket state
        self.device.inject_packet(frame);

        // Having advanced the socket state, we expect the socket to ACK
        // Exfiltrate the response packets generated by the socket and inject them
        // into the tunnel interface.
        self.expect_smoltcp_send()?;

        // Read from the smoltcp socket and push the data to the connection handler.
        self.tunsocket_read_and_forward(info)?;

        // The connection handler builds up the connection or encapsulates the data.
        // Therefore, we now expect it to write data to the server.
        self.write_to_server(info)?;
        Ok(())
    }

    // A raw packet was received on the tunnel interface.
    fn receive_tun(&mut self, frame: &mut [u8]) -> Result<(), Error> {
        let mut handler = || -> Result<(), Error> {
            let result = connection_tuple(frame);
            if let Err(error) = result {
                log::debug!("{}, ignored", error);
                return Ok(());
            }
            let (info, first_packet, payload_offset, payload_size) = result?;
            let origin_dst = SocketAddr::try_from(&info.dst)?;
            let info = self.preprocess_origin_connection_info(info)?;

            let manager = self.get_connection_manager().ok_or("get connection manager")?;

            if info.protocol == IpProtocol::Tcp {
                self.process_incoming_tcp_packets(first_packet, &manager, &info, origin_dst, frame)?;
            } else if info.protocol == IpProtocol::Udp {
                let port = info.dst.port();
                let payload = &frame[payload_offset..payload_offset + payload_size];
                if self.options.virtual_dns.is_some() && port == DNS_PORT {
                    log::info!("DNS query via virtual DNS {} ({})", info, origin_dst);
                    let virtual_dns = self.options.virtual_dns.as_mut().ok_or("")?;
                    let response = virtual_dns.receive_query(payload)?;
                    self.send_udp_packet_to_client(origin_dst, info.src, response.as_slice())?;
                } else if self.options.dns_over_tcp && port == DNS_PORT {
                    self.process_incoming_dns_over_tcp_packets(&manager, &info, origin_dst, payload)?;
                } else {
                    self.process_incoming_udp_packets(&manager, &info, origin_dst, payload)?;
                }
            } else {
                log::warn!("Unsupported protocol: {} ({})", info, origin_dst);
            }
            Ok::<(), Error>(())
        };
        if let Err(error) = handler() {
            log::error!("{}", error);
        }
        Ok(())
    }

    fn create_new_tcp_connection_state(
        &mut self,
        server_addr: SocketAddr,
        dst: SocketAddr,
        proxy_handler: Box<dyn ProxyHandler>,
        udp_associate: bool,
    ) -> Result<ConnectionState> {
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

        let expiry = if udp_associate {
            Some(Self::common_udp_life_timeout())
        } else {
            None
        };

        let (udp_socket, udp_token) = if udp_associate {
            let addr = (Ipv4Addr::UNSPECIFIED, 0).into();
            let mut socket = UdpSocket::bind(addr)?;
            let token = self.new_token();
            self.poll.registry().register(&mut socket, token, Interest::READABLE)?;
            (Some(socket), Some(token))
        } else {
            (None, None)
        };
        let state = ConnectionState {
            smoltcp_handle: handle,
            mio_stream: client,
            token,
            proxy_handler,
            close_state: 0,
            wait_read: true,
            wait_write: false,
            udp_acco_expiry: expiry,
            udp_socket,
            udp_token,
            origin_dst: dst,
            udp_data_cache: LinkedList::new(),
            dns_over_tcp_expiry: None,
        };
        Ok(state)
    }

    fn common_udp_life_timeout() -> ::std::time::Instant {
        ::std::time::Instant::now() + ::std::time::Duration::from_secs(UDP_ASSO_TIMEOUT)
    }

    fn udp_associate_timeout_expired(&self, info: &ConnectionInfo) -> bool {
        if let Some(state) = self.connection_map.get(info) {
            if let Some(expiry) = state.udp_acco_expiry {
                return expiry < ::std::time::Instant::now();
            }
        }
        false
    }

    fn clearup_expired_udp_associate(&mut self) -> Result<()> {
        let keys = self.connection_map.keys().cloned().collect::<Vec<_>>();
        for key in keys {
            if self.udp_associate_timeout_expired(&key) {
                log::trace!("UDP associate timeout: {}", key);
                self.remove_connection(&key)?;
            }
        }
        Ok(())
    }

    fn send_udp_packet_to_client(&mut self, src: SocketAddr, dst: SocketAddr, data: &[u8]) -> Result<()> {
        let rx_buffer = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY], vec![0; 4096]);
        let tx_buffer = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY], vec![0; 4096]);
        let mut socket = udp::Socket::new(rx_buffer, tx_buffer);
        socket.bind(src)?;
        socket.send_slice(data, UdpMetadata::from(dst))?;
        let handle = self.sockets.add(socket);
        self.expect_smoltcp_send()?;
        self.sockets.remove(handle);
        Ok(())
    }

    fn write_to_server(&mut self, info: &ConnectionInfo) -> Result<(), Error> {
        if let Some(state) = self.connection_map.get_mut(info) {
            let event = state.proxy_handler.peek_data(OutgoingDirection::ToServer);
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
                    state.proxy_handler.consume_data(OutgoingDirection::ToServer, written);
                    state.wait_write = written < buffer_size;
                    Self::update_mio_socket_interest(&mut self.poll, state)?;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    state.wait_write = true;
                    Self::update_mio_socket_interest(&mut self.poll, state)?;
                }
                Err(error) => {
                    return Err(error.into());
                }
            }
        }
        self.check_change_close_state(info)?;
        Ok(())
    }

    fn write_to_client(&mut self, token: Token, info: &ConnectionInfo) -> Result<(), Error> {
        while let Some(state) = self.connection_map.get_mut(info) {
            let event = state.proxy_handler.peek_data(OutgoingDirection::ToClient);
            let buflen = event.buffer.len();
            let consumed;
            {
                let socket = self.sockets.get_mut::<tcp::Socket>(state.smoltcp_handle);
                if socket.may_send() {
                    if let Some(virtual_dns) = &mut self.options.virtual_dns {
                        // Unwrapping is fine because every smoltcp socket is bound to an.
                        virtual_dns.touch_ip(&IpAddr::from(socket.local_endpoint().unwrap().addr));
                    }
                    consumed = socket.send_slice(event.buffer)?;
                    state.proxy_handler.consume_data(OutgoingDirection::ToClient, consumed);
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
            #[cfg(target_family = "unix")]
            while let Some((rx_token, _)) = self.tun.receive(Instant::now()) {
                rx_token.consume(|frame| self.receive_tun(frame))?;
            }
        }
        Ok(())
    }

    fn pipe_event(&mut self, _event: &Event) -> Result<(), Error> {
        Ok(())
    }

    fn send_to_smoltcp(&mut self) -> Result<(), Error> {
        for token in self.write_sockets.clone().into_iter() {
            if let Some(connection) = self.find_info_by_token(token) {
                let connection = connection.clone();
                if let Err(error) = self.write_to_client(token, &connection) {
                    log::error!("Write to client {}", error);
                    self.remove_connection(&connection)?;
                }
            }
        }
        Ok(())
    }

    fn receive_udp_packet_and_write_to_client(&mut self, info: &ConnectionInfo) -> Result<()> {
        let err = "udp connection state not found";
        let state = self.connection_map.get_mut(info).ok_or(err)?;
        assert!(state.udp_acco_expiry.is_some());
        state.udp_acco_expiry = Some(Self::common_udp_life_timeout());
        let mut to_send: LinkedList<Vec<u8>> = LinkedList::new();
        if let Some(udp_socket) = state.udp_socket.as_ref() {
            let mut buf = [0; 1 << 16];
            // Receive UDP packet from remote SOCKS5 server
            while let Ok((packet_size, _svr_addr)) = udp_socket.recv_from(&mut buf) {
                let buf = buf[..packet_size].to_vec();
                let header = UdpHeader::retrieve_from_stream(&mut &buf[..])?;

                let buf = if info.dst.port() == DNS_PORT {
                    let mut message = dns::parse_data_to_dns_message(&buf[header.len()..], false)?;
                    if !self.options.ipv6_enabled {
                        dns::remove_ipv6_entries(&mut message);
                    }
                    message.to_vec()?
                } else {
                    buf[header.len()..].to_vec()
                };

                // Escape the borrow checker madness
                to_send.push_back(buf);
            }
        }

        // Write to client
        let src = state.origin_dst;
        while let Some(packet) = to_send.pop_front() {
            self.send_udp_packet_to_client(src, info.src, &packet)?;
        }
        Ok(())
    }

    fn consume_cached_udp_packets(&mut self, info: &ConnectionInfo) -> Result<()> {
        // Try to send the first UDP packets to remote SOCKS5 server for UDP associate session
        if let Some(state) = self.connection_map.get_mut(info) {
            if let Some(udp_socket) = state.udp_socket.as_ref() {
                if let Some(addr) = state.proxy_handler.get_udp_associate() {
                    // Consume udp_data_cache data
                    while let Some(buf) = state.udp_data_cache.pop_front() {
                        udp_socket.send_to(&buf, addr)?;
                    }
                }
            }
        }
        Ok(())
    }

    fn mio_socket_event(&mut self, event: &Event) -> Result<(), Error> {
        if let Some(info) = self.find_info_by_udp_token(event.token()) {
            return self.receive_udp_packet_and_write_to_client(&info.clone());
        }

        let conn_info = match self.find_info_by_token(event.token()) {
            Some(conn_info) => conn_info.clone(),
            None => {
                // We may have closed the connection in an earlier iteration over the poll events,
                // e.g. because an event through the tunnel interface indicated that the connection
                // should be closed.
                log::trace!("Connection info not found");
                return Ok(());
            }
        };

        let e = "connection manager not found";
        let server = self.get_connection_manager().ok_or(e)?.get_server_addr();

        let mut block = || -> Result<(), Error> {
            if event.is_readable() || event.is_read_closed() {
                let established = self
                    .connection_map
                    .get(&conn_info)
                    .ok_or("")?
                    .proxy_handler
                    .connection_established();
                if self.options.dns_over_tcp && conn_info.dst.port() == DNS_PORT && established {
                    self.receive_dns_over_tcp_packet_and_write_to_client(&conn_info)?;
                    return Ok(());
                } else {
                    let e = "connection state not found";
                    let state = self.connection_map.get_mut(&conn_info).ok_or(e)?;

                    // TODO: Move this reading process to its own function.
                    let mut vecbuf = vec![];
                    Self::read_data_from_tcp_stream(&mut state.mio_stream, |data| {
                        vecbuf.extend_from_slice(data);
                        Ok(())
                    })?;

                    let data_event = IncomingDataEvent {
                        direction: IncomingDirection::FromServer,
                        buffer: &vecbuf,
                    };
                    if let Err(error) = state.proxy_handler.push_data(data_event) {
                        log::error!("{}", error);
                        self.remove_connection(&conn_info.clone())?;
                        return Ok(());
                    }

                    // The handler request for reset the server connection
                    if state.proxy_handler.reset_connection() {
                        if let Err(err) = self.poll.registry().deregister(&mut state.mio_stream) {
                            log::trace!("{}", err);
                        }
                        // Closes the connection with the proxy
                        if let Err(err) = state.mio_stream.shutdown(Shutdown::Both) {
                            log::trace!("Shutdown 2 error \"{}\"", err);
                        }

                        log::info!("RESET {}", conn_info);

                        state.mio_stream = TcpStream::connect(server)?;

                        state.wait_read = true;
                        state.wait_write = true;

                        Self::update_mio_socket_interest(&mut self.poll, state)?;

                        return Ok(());
                    }

                    if vecbuf.is_empty() || event.is_read_closed() {
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

                self.consume_cached_udp_packets(&conn_info)?;
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

    fn read_data_from_tcp_stream<F>(stream: &mut TcpStream, mut callback: F) -> Result<()>
    where
        F: FnMut(&mut [u8]) -> Result<()>,
    {
        let mut tmp: [u8; 4096] = [0_u8; 4096];
        loop {
            match stream.read(&mut tmp) {
                Ok(0) => {
                    // The tcp connection closed
                    break;
                }
                Ok(read_result) => {
                    callback(&mut tmp[0..read_result])?;
                }
                Err(error) => {
                    if error.kind() == std::io::ErrorKind::WouldBlock {
                        // We have read all available data.
                        break;
                    } else if error.kind() == std::io::ErrorKind::Interrupted {
                        // Hardware or software interrupt, continue polling.
                        continue;
                    } else {
                        return Err(error.into());
                    }
                }
            };
        }
        Ok(())
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn prepare_exiting_signal_trigger(&mut self) -> Result<()> {
        let mut exit_trigger = self.exit_trigger.take().ok_or("Already running")?;
        ctrlc::set_handler(move || {
            let mut count = 0;
            loop {
                match exit_trigger.write(b"EXIT") {
                    Ok(_) => {
                        log::trace!("Exit signal triggered successfully");
                        break;
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        if count > 5 {
                            log::error!("Send exit signal failed 5 times, exit anyway");
                            std::process::exit(1);
                        }
                        log::trace!("Send exit signal failed, retry in 1 second");
                        std::thread::sleep(std::time::Duration::from_secs(1));
                        count += 1;
                    }
                    Err(err) => {
                        println!("Failed to send exit signal: \"{}\"", err);
                        break;
                    }
                }
            }
        })?;
        Ok(())
    }

    pub fn run(&mut self) -> Result<(), Error> {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        self.prepare_exiting_signal_trigger()?;

        let mut events = Events::with_capacity(1024);
        loop {
            if let Err(err) = self.poll.poll(&mut events, None) {
                if err.kind() == std::io::ErrorKind::Interrupted {
                    log::debug!("Poll interrupted: \"{err}\", ignored, continue polling");
                    continue;
                }
                return Err(err.into());
            }
            for event in events.iter() {
                match event.token() {
                    EXIT_TOKEN => {
                        if self.exiting_event_handler()? {
                            return Ok(());
                        }
                    }
                    EXIT_TRIGGER_TOKEN => {
                        #[cfg(target_family = "unix")]
                        log::trace!("Exiting trigger is ready, {:?}", self.exit_trigger);
                    }
                    TUN_TOKEN => self.tun_event(event)?,
                    PIPE_TOKEN => self.pipe_event(event)?,
                    _ => self.mio_socket_event(event)?,
                }
            }
            self.send_to_smoltcp()?;
            self.clearup_expired_udp_associate()?;
            self.clearup_expired_dns_over_tcp()?;
        }
    }

    #[cfg(target_family = "unix")]
    fn exiting_event_handler(&mut self) -> Result<bool> {
        let mut buffer = vec![0; 100];
        match self.exit_receiver.read(&mut buffer) {
            Ok(size) => {
                log::trace!("Received exit signal: {:?}", &buffer[..size]);
                log::info!("Exiting tun2proxy...");
                Ok(true)
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                log::trace!("Exiting reciever is ready");
                Ok(false)
            }
            Err(err) => Err(err.into()),
        }
    }

    #[cfg(target_os = "windows")]
    fn exiting_event_handler(&mut self) -> Result<bool> {
        Ok(true)
    }

    #[cfg(target_family = "unix")]
    pub fn shutdown(&mut self) -> Result<(), Error> {
        log::debug!("Shutdown tun2proxy...");
        _ = self.exit_trigger.as_mut().ok_or("Already triggered")?.write(b"EXIT")?;
        Ok(())
    }
}
