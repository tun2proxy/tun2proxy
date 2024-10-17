use crate::error::Result;
use ipstack::stream::IpStackUdpStream;
use std::collections::VecDeque;
use std::hash::Hash;
use std::mem;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time::{sleep, Duration};

pub const UDPGW_MAX_CONNECTIONS: usize = 100;
pub const UDPGW_KEEPALIVE_TIME: tokio::time::Duration = std::time::Duration::from_secs(10);
pub const UDPGW_FLAG_KEEPALIVE: u8 = 0x01;
pub const UDPGW_FLAG_IPV6: u8 = 0x08;
pub const UDPGW_FLAG_DOMAIN: u8 = 0x10;
pub const UDPGW_FLAG_ERR: u8 = 0x20;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[repr(C)]
#[repr(packed(1))]
pub struct PackLenHeader {
    packet_len: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[repr(C)]
#[repr(packed(1))]
pub struct UdpgwHeader {
    pub flags: u8,
    pub conid: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[repr(C)]
#[repr(packed(1))]
pub struct UdpgwAddrIpv4 {
    pub addr_ip: u32,
    pub addr_port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[repr(C)]
#[repr(packed(1))]
pub struct UdpgwAddrIpv6 {
    pub addr_ip: [u8; 16],
    pub addr_port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum UdpgwAddr {
    IPV4(UdpgwAddrIpv4),
    IPV6(UdpgwAddrIpv6),
}

impl From<SocketAddr> for UdpgwAddr {
    fn from(addr: SocketAddr) -> Self {
        match addr {
            SocketAddr::V4(addr_v4) => {
                let ipv4_addr = addr_v4.ip().octets();
                let addr_ip = u32::from_be_bytes(ipv4_addr);
                UdpgwAddr::IPV4(UdpgwAddrIpv4 {
                    addr_ip,
                    addr_port: addr_v4.port(),
                })
            }
            SocketAddr::V6(addr_v6) => {
                let ipv6_addr = addr_v6.ip().octets();
                UdpgwAddr::IPV6(UdpgwAddrIpv6 {
                    addr_ip: ipv6_addr,
                    addr_port: addr_v6.port(),
                })
            }
        }
    }
}

impl From<UdpgwAddr> for SocketAddr {
    fn from(addr: UdpgwAddr) -> Self {
        match addr {
            UdpgwAddr::IPV4(addr_ipv4) => SocketAddrV4::new(Ipv4Addr::from(addr_ipv4.addr_ip), addr_ipv4.addr_port).into(),
            UdpgwAddr::IPV6(addr_ipv6) => SocketAddrV6::new(Ipv6Addr::from(addr_ipv6.addr_ip), addr_ipv6.addr_port, 0, 0).into(),
        }
    }
}

#[allow(dead_code)]
pub(crate) struct UdpGwData<'a> {
    flags: u8,
    conid: u16,
    remote_addr: SocketAddr,
    udpdata: &'a [u8],
}

impl<'a> UdpGwData<'a> {
    pub fn len(&self) -> usize {
        return self.udpdata.len();
    }
}

#[allow(dead_code)]
pub(crate) enum UdpGwResponse<'a> {
    KeepAlive,
    Error,
    Data(UdpGwData<'a>),
}

#[derive(Debug)]
pub(crate) struct UdpGwClientStream {
    inner: TcpStream,
    conid: u16,
    tmp_buf: Vec<u8>,
    send_buf: Vec<u8>,
    recv_buf: Vec<u8>,
    closed: bool,
    last_activity: std::time::Instant,
}

impl AsyncWrite for UdpGwClientStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<tokio::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl AsyncRead for UdpGwClientStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl UdpGwClientStream {
    pub async fn close(&mut self) -> Result<()> {
        self.inner.shutdown().await?;
        self.closed = true;
        Ok(())
    }
    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.inner.local_addr()?)
    }
    pub fn is_closed(&mut self) -> bool {
        self.closed
    }

    pub fn id(&mut self) -> u16 {
        self.conid
    }

    pub fn newid(&mut self) -> u16 {
        let next = self.conid;
        self.conid += 1;
        return next;
    }
    pub fn new(udp_mtu: u16, tcp_server_stream: TcpStream) -> Self {
        UdpGwClientStream {
            inner: tcp_server_stream,
            tmp_buf: vec![0; udp_mtu.into()],
            send_buf: vec![0; udp_mtu.into()],
            recv_buf: vec![0; udp_mtu.into()],
            last_activity: std::time::Instant::now(),
            closed: false,
            conid: 0,
        }
    }
}

#[derive(Debug)]
pub(crate) struct UdpGwClient {
    udp_mtu: u16,
    max_connections: usize,
    keepalive_time: Duration,
    udpgw_bind_addr: SocketAddr,
    keepalive_packet: Vec<u8>,
    server_connections: Mutex<VecDeque<UdpGwClientStream>>,
}

impl UdpGwClient {
    pub fn new(udp_mtu: u16, max_connections: usize, keepalive_time: Duration, udpgw_bind_addr: SocketAddr) -> Self {
        let mut keepalive_packet = vec![];
        keepalive_packet.extend_from_slice(&(std::mem::size_of::<UdpgwHeader>() as u16).to_le_bytes());
        keepalive_packet.extend_from_slice(&[UDPGW_FLAG_KEEPALIVE, 0, 0]);
        let server_connections = Mutex::new(VecDeque::new());
        return UdpGwClient {
            udp_mtu,
            max_connections,
            udpgw_bind_addr,
            keepalive_time,
            keepalive_packet,
            server_connections: server_connections,
        };
    }

    pub(crate) fn get_udp_mtu(&self) -> u16 {
        self.udp_mtu
    }

    pub(crate) async fn get_server_connection(&self) -> Option<UdpGwClientStream> {
        self.server_connections.lock().await.pop_front()
    }

    pub(crate) async fn release_server_connection(&self, stream: UdpGwClientStream) {
        if self.server_connections.lock().await.len() < self.max_connections {
            self.server_connections.lock().await.push_back(stream);
        }
    }

    pub(crate) fn get_udpgw_bind_addr(&self) -> SocketAddr {
        return self.udpgw_bind_addr;
    }

    pub(crate) async fn heartbeat_task(&self) {
        loop {
            sleep(self.keepalive_time).await;
            if let Some(mut stream) = self.get_server_connection().await {
                if stream.last_activity.elapsed() < self.keepalive_time {
                    self.release_server_connection(stream).await;
                    continue;
                }
                log::debug!("{:?}:{} send keepalive", stream.local_addr(), stream.id());
                if let Err(e) = stream.write_all(&self.keepalive_packet).await {
                    let _ = stream.close().await;
                    log::warn!("{:?}:{} Heartbeat failed: {}", stream.local_addr(), stream.id(), e);
                } else {
                    stream.last_activity = std::time::Instant::now();
                    match UdpGwClient::recv_udpgw_packet(self.udp_mtu, &mut stream).await {
                        Ok(UdpGwResponse::KeepAlive) => {
                            self.release_server_connection(stream).await;
                            continue;
                        }
                        //shoud not receive other
                        _ => {
                            continue;
                        }
                    }
                }
            }
        }
    }

    pub(crate) fn parse_udp_response(udp_mtu: u16, data_len: usize, data: &[u8]) -> Result<UdpGwResponse> {
        if data_len < mem::size_of::<UdpgwHeader>() {
            return Err("Invalid udpgw data".into());
        }
        let header_bytes = &data[..mem::size_of::<UdpgwHeader>()];
        let header = UdpgwHeader {
            flags: header_bytes[0],
            conid: u16::from_le_bytes([header_bytes[1], header_bytes[2]]),
        };

        let flags = header.flags;
        let conid = header.conid;

        // parse address
        let ip_data = &data[mem::size_of::<UdpgwHeader>()..];
        let mut data_len = data_len - mem::size_of::<UdpgwHeader>();

        if flags & UDPGW_FLAG_ERR != 0 {
            return Ok(UdpGwResponse::Error);
        }

        if flags & UDPGW_FLAG_ERR != 0 {
            return Ok(UdpGwResponse::KeepAlive);
        }

        if flags & UDPGW_FLAG_IPV6 != 0 {
            if data_len < mem::size_of::<UdpgwAddrIpv6>() {
                return Err("ipv6 Invalid UDP data".into());
            }
            let addr_ipv6_bytes = &ip_data[..mem::size_of::<UdpgwAddrIpv6>()];
            let addr_ipv6 = UdpgwAddrIpv6 {
                addr_ip: addr_ipv6_bytes[..16].try_into().map_err(|_| "Failed to convert slice to array")?,
                addr_port: u16::from_be_bytes([addr_ipv6_bytes[16], addr_ipv6_bytes[17]]),
            };
            data_len -= mem::size_of::<UdpgwAddrIpv6>();
            // check payload length
            if data_len > udp_mtu as usize {
                return Err("too much data".into());
            }
            return Ok(UdpGwResponse::Data(UdpGwData {
                flags,
                conid,
                remote_addr: UdpgwAddr::IPV6(addr_ipv6).into(),
                udpdata: &ip_data[mem::size_of::<UdpgwAddrIpv6>()..(data_len + mem::size_of::<UdpgwAddrIpv6>())],
            }));
        } else {
            if data_len < mem::size_of::<UdpgwAddrIpv4>() {
                return Err("ipv4 Invalid UDP data".into());
            }
            let addr_ipv4_bytes = &ip_data[..mem::size_of::<UdpgwAddrIpv4>()];
            let addr_ipv4 = UdpgwAddrIpv4 {
                addr_ip: u32::from_be_bytes([addr_ipv4_bytes[0], addr_ipv4_bytes[1], addr_ipv4_bytes[2], addr_ipv4_bytes[3]]),
                addr_port: u16::from_be_bytes([addr_ipv4_bytes[4], addr_ipv4_bytes[5]]),
            };
            data_len -= mem::size_of::<UdpgwAddrIpv4>();

            // check payload length
            if data_len > udp_mtu as usize {
                return Err("too much data".into());
            }
            return Ok(UdpGwResponse::Data(UdpGwData {
                flags,
                conid,
                remote_addr: UdpgwAddr::IPV4(addr_ipv4).into(),
                udpdata: &ip_data[mem::size_of::<UdpgwAddrIpv4>()..(data_len + mem::size_of::<UdpgwAddrIpv4>())],
            }));
        }
    }

    pub(crate) async fn recv_udp_packet(
        udp_stack: &mut IpStackUdpStream,
        stream: &mut UdpGwClientStream,
    ) -> std::result::Result<usize, std::io::Error> {
        return udp_stack.read(&mut stream.tmp_buf).await;
    }

    pub(crate) async fn send_udp_packet<'a>(
        packet: UdpGwData<'a>,
        udp_stack: &mut IpStackUdpStream,
    ) -> std::result::Result<(), std::io::Error> {
        return udp_stack.write_all(&packet.udpdata).await;
    }

    pub(crate) async fn recv_udpgw_packet(udp_mtu: u16, stream: &mut UdpGwClientStream) -> Result<UdpGwResponse> {
        stream.recv_buf.resize(2, 0);
        let result;
        match tokio::time::timeout(tokio::time::Duration::from_secs(10), stream.inner.read(&mut stream.recv_buf)).await {
            Ok(ret) => {
                result = ret;
            }
            Err(_e) => {
                let _ = stream.close().await;
                return Err(format!("{:?} wait tcp data timeout", stream.local_addr()).into());
            }
        };
        match result {
            Ok(0) => {
                let _ = stream.close().await;
                return Err(format!("{:?} tcp connection closed", stream.local_addr()).into());
            }
            Ok(n) => {
                if n < std::mem::size_of::<PackLenHeader>() {
                    return Err("received PackLenHeader error".into());
                }
                let packet_len = u16::from_le_bytes([stream.recv_buf[0], stream.recv_buf[1]]);
                if packet_len > udp_mtu {
                    return Err("packet too long".into());
                }
                stream.recv_buf.resize(udp_mtu as usize, 0);
                let mut left_len: usize = packet_len as usize;
                let mut recv_len = 0;
                while left_len > 0 {
                    if let Ok(len) = stream.inner.read(&mut stream.recv_buf[recv_len..left_len]).await {
                        if len == 0 {
                            let _ = stream.close().await;
                            return Err(format!("{:?} tcp connection closed", stream.local_addr()).into());
                        }
                        recv_len += len;
                        left_len -= len;
                    } else {
                        let _ = stream.close().await;
                        return Err(format!("{:?} tcp connection closed", stream.local_addr()).into());
                    }
                }
                stream.last_activity = std::time::Instant::now();
                return UdpGwClient::parse_udp_response(udp_mtu, packet_len as usize, &stream.recv_buf);
            }
            Err(_) => {
                let _ = stream.close().await;
                return Err(format!("{:?} tcp read error", stream.local_addr()).into());
            }
        }
    }

    pub(crate) async fn send_udpgw_packet(
        ipv6_enabled: bool,
        len: usize,
        remote_addr: SocketAddr,
        domain: Option<&String>,
        stream: &mut UdpGwClientStream,
    ) -> Result<()> {
        stream.send_buf.clear();
        let conid = stream.newid();
        let data = &stream.tmp_buf;
        let mut pack_len = std::mem::size_of::<UdpgwHeader>() + len;
        let packet = &mut stream.send_buf;
        let mut flags = 0;
        match domain {
            Some(domain) => {
                let addr_port = match remote_addr.into() {
                    UdpgwAddr::IPV4(addr_ipv4) => addr_ipv4.addr_port,
                    UdpgwAddr::IPV6(addr_ipv6) => addr_ipv6.addr_port,
                };
                pack_len += std::mem::size_of::<u16>();
                let domain_len = domain.len();
                if domain_len > 255 {
                    return Err("InvalidDomain".into());
                }
                pack_len += domain_len + 1;
                flags = UDPGW_FLAG_DOMAIN;
                packet.extend_from_slice(&(pack_len as u16).to_le_bytes());
                packet.extend_from_slice(&[flags]);
                packet.extend_from_slice(&conid.to_le_bytes());
                packet.extend_from_slice(&addr_port.to_be_bytes());
                packet.extend_from_slice(domain.as_bytes());
                packet.push(0);
                packet.extend_from_slice(&data[..len]);
            }
            None => match remote_addr.into() {
                UdpgwAddr::IPV4(addr_ipv4) => {
                    pack_len += std::mem::size_of::<UdpgwAddrIpv4>();
                    packet.extend_from_slice(&(pack_len as u16).to_le_bytes());
                    packet.extend_from_slice(&[flags]);
                    packet.extend_from_slice(&conid.to_le_bytes());
                    packet.extend_from_slice(&addr_ipv4.addr_ip.to_be_bytes());
                    packet.extend_from_slice(&addr_ipv4.addr_port.to_be_bytes());
                    packet.extend_from_slice(&data[..len]);
                }
                UdpgwAddr::IPV6(addr_ipv6) => {
                    if !ipv6_enabled {
                        return Err("ipv6 not support".into());
                    }
                    flags = UDPGW_FLAG_IPV6;
                    pack_len += std::mem::size_of::<UdpgwAddrIpv6>();
                    packet.extend_from_slice(&(pack_len as u16).to_le_bytes());
                    packet.extend_from_slice(&[flags]);
                    packet.extend_from_slice(&conid.to_le_bytes());
                    packet.extend_from_slice(&addr_ipv6.addr_ip);
                    packet.extend_from_slice(&addr_ipv6.addr_port.to_be_bytes());
                    packet.extend_from_slice(&data[..len]);
                }
            },
        }

        stream.inner.write_all(&packet).await?;

        stream.last_activity = std::time::Instant::now();

        Ok(())
    }
}
