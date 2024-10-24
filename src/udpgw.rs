use crate::error::Result;
use ipstack::stream::IpStackUdpStream;
use socks5_impl::protocol::{AsyncStreamOperation, BufMut, StreamOperation};
use std::{
    collections::VecDeque,
    hash::Hash,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    sync::atomic::Ordering::Relaxed,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{
        tcp::{OwnedReadHalf, OwnedWriteHalf},
        TcpStream,
    },
    sync::Mutex,
    time::{sleep, Duration},
};

pub const UDPGW_MAX_CONNECTIONS: usize = 100;
pub const UDPGW_KEEPALIVE_TIME: tokio::time::Duration = std::time::Duration::from_secs(10);
pub const UDPGW_FLAG_KEEPALIVE: u8 = 0x01;
pub const UDPGW_FLAG_IPV4: u8 = 0x00;
pub const UDPGW_FLAG_IPV6: u8 = 0x08;
pub const UDPGW_FLAG_DOMAIN: u8 = 0x10;
pub const UDPGW_FLAG_ERR: u8 = 0x20;

pub const UDPGW_LENGTH_FIELD_SIZE: usize = std::mem::size_of::<u16>();

static TCP_COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Packet {
    pub length: u16,
    pub header: UdpgwHeader,
    pub data: Vec<u8>,
}

impl From<Packet> for Vec<u8> {
    fn from(packet: Packet) -> Vec<u8> {
        (&packet).into()
    }
}

impl From<&Packet> for Vec<u8> {
    fn from(packet: &Packet) -> Vec<u8> {
        let mut bytes: Vec<u8> = vec![];
        packet.write_to_buf(&mut bytes);
        bytes
    }
}

impl TryFrom<&[u8]> for Packet {
    type Error = std::io::Error;

    fn try_from(value: &[u8]) -> std::result::Result<Self, Self::Error> {
        if value.len() < UDPGW_LENGTH_FIELD_SIZE {
            return Err(std::io::ErrorKind::InvalidData.into());
        }
        let length = u16::from_le_bytes([value[0], value[1]]);
        if value.len() < length as usize + UDPGW_LENGTH_FIELD_SIZE {
            return Err(std::io::ErrorKind::InvalidData.into());
        }
        let header = UdpgwHeader::try_from(&value[UDPGW_LENGTH_FIELD_SIZE..])?;
        let data = value[UDPGW_LENGTH_FIELD_SIZE + header.len()..].to_vec();
        Ok(Packet::new(header, data))
    }
}

impl Packet {
    pub fn new(header: UdpgwHeader, data: Vec<u8>) -> Self {
        let length = (header.len() + data.len()) as u16;
        Packet { length, header, data }
    }
}

impl StreamOperation for Packet {
    fn retrieve_from_stream<R>(stream: &mut R) -> std::io::Result<Self>
    where
        R: std::io::Read,
        Self: Sized,
    {
        let mut buf = [0; UDPGW_LENGTH_FIELD_SIZE];
        stream.read_exact(&mut buf)?;
        let length = u16::from_le_bytes(buf);
        let mut buf = [0; UdpgwHeader::static_len()];
        stream.read_exact(&mut buf)?;
        let header = UdpgwHeader::try_from(&buf[..])?;
        let mut data = vec![0; length as usize - header.len()];
        stream.read_exact(&mut data)?;
        Ok(Packet::new(header, data))
    }

    fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
        buf.put_u16_le(self.length);
        self.header.write_to_buf(buf);
        buf.put_slice(&self.data);
    }

    fn len(&self) -> usize {
        UDPGW_LENGTH_FIELD_SIZE + self.header.len() + self.data.len()
    }
}

#[async_trait::async_trait]
impl AsyncStreamOperation for Packet {
    async fn retrieve_from_async_stream<R>(r: &mut R) -> std::io::Result<Self>
    where
        R: tokio::io::AsyncRead + Unpin + Send,
        Self: Sized,
    {
        let mut buf = [0; 2];
        r.read_exact(&mut buf).await?;
        let length = u16::from_le_bytes(buf);
        let header = UdpgwHeader::retrieve_from_async_stream(r).await?;
        let mut data = vec![0; length as usize - header.len()];
        r.read_exact(&mut data).await?;
        Ok(Packet::new(header, data))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(C)]
#[repr(packed(1))]
pub struct UdpgwHeader {
    pub flags: u8,
    pub conn_id: u16,
}

impl StreamOperation for UdpgwHeader {
    fn retrieve_from_stream<R>(stream: &mut R) -> std::io::Result<Self>
    where
        R: std::io::Read,
        Self: Sized,
    {
        let mut buf = [0; UdpgwHeader::static_len()];
        stream.read_exact(&mut buf)?;
        UdpgwHeader::try_from(&buf[..])
    }

    fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
        let bytes: Vec<u8> = self.into();
        buf.put_slice(&bytes);
    }

    fn len(&self) -> usize {
        Self::static_len()
    }
}

#[async_trait::async_trait]
impl AsyncStreamOperation for UdpgwHeader {
    async fn retrieve_from_async_stream<R>(r: &mut R) -> std::io::Result<Self>
    where
        R: tokio::io::AsyncRead + Unpin + Send,
        Self: Sized,
    {
        let mut buf = [0; UdpgwHeader::static_len()];
        r.read_exact(&mut buf).await?;
        UdpgwHeader::try_from(&buf[..])
    }
}

impl UdpgwHeader {
    pub fn new(flags: u8, conn_id: u16) -> Self {
        UdpgwHeader { flags, conn_id }
    }

    pub const fn static_len() -> usize {
        std::mem::size_of::<UdpgwHeader>()
    }
}

impl TryFrom<&[u8]> for UdpgwHeader {
    type Error = std::io::Error;

    fn try_from(value: &[u8]) -> std::result::Result<Self, Self::Error> {
        if value.len() < UdpgwHeader::static_len() {
            return Err(std::io::ErrorKind::InvalidData.into());
        }
        Ok(UdpgwHeader {
            flags: value[0],
            conn_id: u16::from_le_bytes([value[1], value[2]]),
        })
    }
}

impl From<&UdpgwHeader> for Vec<u8> {
    fn from(header: &UdpgwHeader) -> Vec<u8> {
        let mut bytes = vec![0; header.len()];
        bytes[0] = header.flags;
        bytes[1..3].copy_from_slice(&header.conn_id.to_le_bytes());
        bytes
    }
}

#[allow(clippy::len_without_is_empty)]
#[derive(Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct BinSocketAddr(SocketAddr);

impl BinSocketAddr {
    pub fn len(&self) -> usize {
        match self.0 {
            SocketAddr::V4(_) => Self::static_len(false),
            SocketAddr::V6(_) => Self::static_len(true),
        }
    }

    pub fn static_len(is_ipv6: bool) -> usize {
        if is_ipv6 {
            std::mem::size_of::<Ipv6Addr>() + std::mem::size_of::<u16>()
        } else {
            std::mem::size_of::<Ipv4Addr>() + std::mem::size_of::<u16>()
        }
    }
}

impl From<&BinSocketAddr> for Vec<u8> {
    fn from(addr: &BinSocketAddr) -> Vec<u8> {
        socket_addr_to_binary(&addr.0)
    }
}

impl From<BinSocketAddr> for Vec<u8> {
    fn from(addr: BinSocketAddr) -> Vec<u8> {
        socket_addr_to_binary(&addr.0)
    }
}

impl TryFrom<&[u8]> for BinSocketAddr {
    type Error = std::io::Error;
    fn try_from(value: &[u8]) -> std::result::Result<Self, Self::Error> {
        Ok(BinSocketAddr(binary_to_socket_addr(value)?))
    }
}

impl From<SocketAddr> for BinSocketAddr {
    fn from(addr: SocketAddr) -> Self {
        BinSocketAddr(addr)
    }
}

impl From<BinSocketAddr> for SocketAddr {
    fn from(addr: BinSocketAddr) -> Self {
        addr.0
    }
}

fn socket_addr_to_binary(addr: &SocketAddr) -> Vec<u8> {
    match addr {
        SocketAddr::V4(addr_v4) => {
            let mut bytes = vec![0; std::mem::size_of::<SocketAddrV4>()];
            bytes[0..4].copy_from_slice(&addr_v4.ip().octets());
            bytes[4..6].copy_from_slice(&addr_v4.port().to_be_bytes());
            bytes
        }
        SocketAddr::V6(addr_v6) => {
            let mut bytes = vec![0; std::mem::size_of::<Ipv6Addr>() + std::mem::size_of::<u16>()];
            bytes[0..16].copy_from_slice(&addr_v6.ip().octets());
            bytes[16..18].copy_from_slice(&addr_v6.port().to_be_bytes());
            bytes
        }
    }
}

fn binary_to_socket_addr(bytes: &[u8]) -> std::io::Result<SocketAddr> {
    if bytes.len() == std::mem::size_of::<SocketAddrV4>() {
        let ip = Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]);
        let port = u16::from_be_bytes([bytes[4], bytes[5]]);
        Ok(SocketAddr::V4(SocketAddrV4::new(ip, port)))
    } else if bytes.len() == std::mem::size_of::<Ipv6Addr>() + std::mem::size_of::<u16>() {
        let mut ip = [0; 16];
        ip.copy_from_slice(&bytes[0..16]);
        let port = u16::from_be_bytes([bytes[16], bytes[17]]);
        Ok(SocketAddr::V6(SocketAddrV6::new(ip.into(), port, 0, 0)))
    } else {
        Err(std::io::ErrorKind::InvalidData.into())
    }
}

#[allow(dead_code)]
#[derive(Debug)]
pub(crate) struct UdpGwData<'a> {
    flags: u8,
    conn_id: u16,
    remote_addr: SocketAddr,
    udpdata: &'a [u8],
}

impl<'a> UdpGwData<'a> {
    pub fn len(&self) -> usize {
        self.udpdata.len()
    }
}

#[allow(dead_code)]
#[derive(Debug)]
pub(crate) enum UdpGwResponse<'a> {
    KeepAlive,
    Error,
    TcpClose,
    Data(UdpGwData<'a>),
}

#[derive(Debug)]
pub(crate) struct UdpGwClientStreamWriter {
    inner: OwnedWriteHalf,
    tmp_buf: Vec<u8>,
    send_buf: Vec<u8>,
}

#[derive(Debug)]
pub(crate) struct UdpGwClientStreamReader {
    inner: OwnedReadHalf,
    recv_buf: Vec<u8>,
}

#[derive(Debug)]
pub(crate) struct UdpGwClientStream {
    local_addr: String,
    writer: Option<UdpGwClientStreamWriter>,
    reader: Option<UdpGwClientStreamReader>,
    conn_id: u16,
    closed: bool,
    last_activity: std::time::Instant,
}

impl Drop for UdpGwClientStream {
    fn drop(&mut self) {
        TCP_COUNTER.fetch_sub(1, Relaxed);
    }
}

impl UdpGwClientStream {
    pub fn close(&mut self) {
        self.closed = true;
    }
    pub fn get_reader(&mut self) -> Option<UdpGwClientStreamReader> {
        self.reader.take()
    }

    pub fn set_reader(&mut self, mut reader: Option<UdpGwClientStreamReader>) {
        self.reader = reader.take();
    }

    pub fn set_writer(&mut self, mut writer: Option<UdpGwClientStreamWriter>) {
        self.writer = writer.take();
    }

    pub fn get_writer(&mut self) -> Option<UdpGwClientStreamWriter> {
        self.writer.take()
    }

    pub fn local_addr(&self) -> &String {
        &self.local_addr
    }

    pub fn update_activity(&mut self) {
        self.last_activity = std::time::Instant::now();
    }

    pub fn is_closed(&mut self) -> bool {
        self.closed
    }

    pub fn id(&mut self) -> u16 {
        self.conn_id
    }

    pub fn new_id(&mut self) -> u16 {
        self.conn_id += 1;
        self.conn_id
    }
    pub fn new(udp_mtu: u16, tcp_server_stream: TcpStream) -> Self {
        let local_addr = tcp_server_stream
            .local_addr()
            .unwrap_or_else(|_| "0.0.0.0:0".parse::<SocketAddr>().unwrap())
            .to_string();
        let (rx, tx) = tcp_server_stream.into_split();
        let writer = UdpGwClientStreamWriter {
            inner: tx,
            tmp_buf: vec![0; udp_mtu.into()],
            send_buf: vec![0; udp_mtu.into()],
        };
        let reader = UdpGwClientStreamReader {
            inner: rx,
            recv_buf: vec![0; udp_mtu.into()],
        };
        TCP_COUNTER.fetch_add(1, Relaxed);
        UdpGwClientStream {
            local_addr,
            reader: Some(reader),
            writer: Some(writer),
            last_activity: std::time::Instant::now(),
            closed: false,
            conn_id: 0,
        }
    }
}

#[derive(Debug)]
pub(crate) struct UdpGwClient {
    udp_mtu: u16,
    max_connections: u16,
    udp_timeout: u64,
    keepalive_time: Duration,
    server_addr: SocketAddr,
    keepalive_packet: Vec<u8>,
    server_connections: Mutex<VecDeque<UdpGwClientStream>>,
}

impl UdpGwClient {
    pub fn new(udp_mtu: u16, max_connections: u16, keepalive_time: Duration, udp_timeout: u64, server_addr: SocketAddr) -> Self {
        let keepalive_packet: Vec<u8> = Packet::new(UdpgwHeader::new(UDPGW_FLAG_KEEPALIVE, 0), vec![]).into();
        let server_connections = Mutex::new(VecDeque::with_capacity(max_connections as usize));
        UdpGwClient {
            udp_mtu,
            max_connections,
            udp_timeout,
            server_addr,
            keepalive_time,
            keepalive_packet,
            server_connections,
        }
    }

    pub(crate) fn get_udp_mtu(&self) -> u16 {
        self.udp_mtu
    }

    pub(crate) fn get_udp_timeout(&self) -> u64 {
        self.udp_timeout
    }

    pub(crate) fn is_full(&self) -> bool {
        TCP_COUNTER.load(Relaxed) >= self.max_connections as u32
    }

    pub(crate) async fn get_server_connection(&self) -> Option<UdpGwClientStream> {
        self.server_connections.lock().await.pop_front()
    }

    pub(crate) async fn release_server_connection(&self, stream: UdpGwClientStream) {
        if self.server_connections.lock().await.len() < self.max_connections as usize {
            self.server_connections.lock().await.push_back(stream);
        }
    }

    pub(crate) async fn release_server_connection_with_stream(
        &self,
        mut stream: UdpGwClientStream,
        reader: UdpGwClientStreamReader,
        writer: UdpGwClientStreamWriter,
    ) {
        if self.server_connections.lock().await.len() < self.max_connections as usize {
            stream.set_reader(Some(reader));
            stream.set_writer(Some(writer));
            self.server_connections.lock().await.push_back(stream);
        }
    }

    pub(crate) fn get_server_addr(&self) -> SocketAddr {
        self.server_addr
    }

    /// Heartbeat task asynchronous function to periodically check and maintain the active state of the server connection.
    pub(crate) async fn heartbeat_task(&self) {
        loop {
            sleep(self.keepalive_time).await;
            if let Some(mut stream) = self.get_server_connection().await {
                if stream.last_activity.elapsed() < self.keepalive_time {
                    self.release_server_connection(stream).await;
                    continue;
                }

                let Some(mut stream_reader) = stream.get_reader() else {
                    continue;
                };

                let Some(mut stream_writer) = stream.get_writer() else {
                    continue;
                };
                let local_addr = stream_writer.inner.local_addr();
                log::debug!("{:?}:{} send keepalive", local_addr, stream.id());
                if let Err(e) = stream_writer.inner.write_all(&self.keepalive_packet).await {
                    log::warn!("{:?}:{} send keepalive failed: {}", local_addr, stream.id(), e);
                } else {
                    match UdpGwClient::recv_udpgw_packet(self.udp_mtu, 10, &mut stream_reader).await {
                        Ok(UdpGwResponse::KeepAlive) => {
                            stream.update_activity();
                            self.release_server_connection_with_stream(stream, stream_reader, stream_writer)
                                .await;
                        }
                        Ok(v) => log::warn!("{:?}:{} keepalive unexpected response: {:?}", local_addr, stream.id(), v),
                        Err(e) => log::warn!("{:?}:{} keepalive no response, error \"{}\"", local_addr, stream.id(), e),
                    }
                }
            }
        }
    }

    /// Parses the UDP response data.
    pub(crate) fn parse_udp_response(udp_mtu: u16, data_len: usize, stream: &mut UdpGwClientStreamReader) -> Result<UdpGwResponse> {
        let data = &stream.recv_buf;
        let header_len = UdpgwHeader::static_len();
        if data_len < header_len {
            return Err("Invalid udpgw data".into());
        }
        let header_bytes = &data[..header_len];
        let header = UdpgwHeader {
            flags: header_bytes[0],
            conn_id: u16::from_le_bytes([header_bytes[1], header_bytes[2]]),
        };

        let flags = header.flags;
        let conn_id = header.conn_id;

        let ip_data = &data[header_len..];
        let mut data_len = data_len - header_len;

        if flags & UDPGW_FLAG_ERR != 0 {
            return Ok(UdpGwResponse::Error);
        }

        if flags & UDPGW_FLAG_KEEPALIVE != 0 {
            return Ok(UdpGwResponse::KeepAlive);
        }

        if flags & UDPGW_FLAG_IPV6 != 0 {
            let ipv6_addr_len = BinSocketAddr::static_len(true);
            if data_len < ipv6_addr_len {
                return Err("ipv6 Invalid UDP data".into());
            }
            let addr_ipv6 = BinSocketAddr::try_from(&ip_data[..ipv6_addr_len])?;
            data_len -= ipv6_addr_len;

            if data_len > udp_mtu as usize {
                return Err("too much data".into());
            }
            return Ok(UdpGwResponse::Data(UdpGwData {
                flags,
                conn_id,
                remote_addr: addr_ipv6.into(),
                udpdata: &ip_data[ipv6_addr_len..(data_len + ipv6_addr_len)],
            }));
        } else {
            let ipv4_addr_len = BinSocketAddr::static_len(false);
            if data_len < ipv4_addr_len {
                return Err("ipv4 Invalid UDP data".into());
            }
            let addr_ipv4 = BinSocketAddr::try_from(&ip_data[..ipv4_addr_len])?;
            data_len -= ipv4_addr_len;

            if data_len > udp_mtu as usize {
                return Err("too much data".into());
            }
            return Ok(UdpGwResponse::Data(UdpGwData {
                flags,
                conn_id,
                remote_addr: addr_ipv4.into(),
                udpdata: &ip_data[ipv4_addr_len..(data_len + ipv4_addr_len)],
            }));
        }
    }

    pub(crate) async fn recv_udp_packet(
        udp_stack: &mut IpStackUdpStream,
        stream: &mut UdpGwClientStreamWriter,
    ) -> std::result::Result<usize, std::io::Error> {
        udp_stack.read(&mut stream.tmp_buf).await
    }

    pub(crate) async fn send_udp_packet<'a>(
        packet: UdpGwData<'a>,
        udp_stack: &mut IpStackUdpStream,
    ) -> std::result::Result<(), std::io::Error> {
        udp_stack.write_all(packet.udpdata).await
    }

    /// Receives a UDP gateway packet.
    ///
    /// This function is responsible for receiving packets from the UDP gateway
    ///
    /// # Arguments
    /// - `udp_mtu`: The maximum transmission unit size for UDP packets.
    /// - `udp_timeout`: The timeout in seconds for receiving UDP packets.
    /// - `stream`: A mutable reference to the UDP gateway client stream reader.
    ///
    /// # Returns
    /// - `Result<UdpGwResponse>`: Returns a result type containing the parsed UDP gateway response, or an error if one occurs.
    pub(crate) async fn recv_udpgw_packet(udp_mtu: u16, udp_timeout: u64, stream: &mut UdpGwClientStreamReader) -> Result<UdpGwResponse> {
        let result = tokio::time::timeout(
            tokio::time::Duration::from_secs(udp_timeout + 2),
            stream.inner.read(&mut stream.recv_buf[..2]),
        )
        .await
        .map_err(std::io::Error::from)?;
        let n = result?;
        if n == 0 {
            return Ok(UdpGwResponse::TcpClose);
        }
        if n < UDPGW_LENGTH_FIELD_SIZE {
            return Err("received Packet Length field error".into());
        }
        let packet_len = u16::from_le_bytes([stream.recv_buf[0], stream.recv_buf[1]]);
        if packet_len > udp_mtu {
            return Err("packet too long".into());
        }
        let mut left_len: usize = packet_len as usize;
        let mut recv_len = 0;
        while left_len > 0 {
            let Ok(len) = stream.inner.read(&mut stream.recv_buf[recv_len..left_len]).await else {
                return Ok(UdpGwResponse::TcpClose);
            };
            if len == 0 {
                return Ok(UdpGwResponse::TcpClose);
            }
            recv_len += len;
            left_len -= len;
        }
        UdpGwClient::parse_udp_response(udp_mtu, packet_len as usize, stream)
    }

    /// Sends a UDP gateway packet.
    ///
    /// This function constructs and sends a UDP gateway packet based on the IPv6 enabled status, data length,
    /// remote address, domain (if any), connection ID, and the UDP gateway client writer stream.
    ///
    /// # Arguments
    ///
    /// * `ipv6_enabled` - Whether IPv6 is enabled
    /// * `len` - Length of the data packet
    /// * `remote_addr` - Remote address
    /// * `domain` - Target domain (optional)
    /// * `conn_id` - Connection ID
    /// * `stream` - UDP gateway client writer stream
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the packet is sent successfully, otherwise returns an error.
    pub(crate) async fn send_udpgw_packet(
        ipv6_enabled: bool,
        len: usize,
        remote_addr: SocketAddr,
        domain: Option<&String>,
        conn_id: u16,
        stream: &mut UdpGwClientStreamWriter,
    ) -> Result<()> {
        stream.send_buf.clear();
        let data = &stream.tmp_buf;
        let mut pack_len = UdpgwHeader::static_len() + len;
        let packet = &mut stream.send_buf;
        match domain {
            Some(domain) => {
                let addr_port = remote_addr.port();
                let domain_len = domain.len();
                if domain_len > 255 {
                    return Err("InvalidDomain".into());
                }
                pack_len += UDPGW_LENGTH_FIELD_SIZE;
                pack_len += domain_len + 1;
                packet.extend_from_slice(&(pack_len as u16).to_le_bytes());
                packet.extend_from_slice(&[UDPGW_FLAG_DOMAIN]);
                packet.extend_from_slice(&conn_id.to_le_bytes());
                packet.extend_from_slice(&addr_port.to_be_bytes());
                packet.extend_from_slice(domain.as_bytes());
                packet.push(0);
                packet.extend_from_slice(&data[..len]);
            }
            None => match remote_addr {
                SocketAddr::V4(_) => {
                    let addr_ipv4 = BinSocketAddr::from(remote_addr);
                    pack_len += addr_ipv4.len();
                    packet.extend_from_slice(&(pack_len as u16).to_le_bytes());
                    packet.extend_from_slice(&[UDPGW_FLAG_IPV4]);
                    packet.extend_from_slice(&conn_id.to_le_bytes());
                    let addr_ipv4_bin: Vec<u8> = addr_ipv4.into();
                    packet.extend_from_slice(&addr_ipv4_bin);
                    packet.extend_from_slice(&data[..len]);
                }
                SocketAddr::V6(_) => {
                    if !ipv6_enabled {
                        return Err("ipv6 not support".into());
                    }
                    let addr_ipv6 = BinSocketAddr::from(remote_addr);
                    pack_len += addr_ipv6.len();
                    packet.extend_from_slice(&(pack_len as u16).to_le_bytes());
                    packet.extend_from_slice(&[UDPGW_FLAG_IPV6]);
                    packet.extend_from_slice(&conn_id.to_le_bytes());
                    let addr_ipv6_bin: Vec<u8> = addr_ipv6.into();
                    packet.extend_from_slice(&addr_ipv6_bin);
                    packet.extend_from_slice(&data[..len]);
                }
            },
        }

        stream.inner.write_all(packet).await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{Packet, UdpgwHeader};
    use socks5_impl::protocol::StreamOperation;

    #[test]
    fn test_udpgw_header() {
        let header = UdpgwHeader::new(0x01, 0x1234);
        let mut bytes: Vec<u8> = vec![];
        let packet = Packet::new(header, vec![]);
        packet.write_to_buf(&mut bytes);

        let header2 = Packet::retrieve_from_stream(&mut bytes.as_slice()).unwrap().header;

        assert_eq!(header, header2);
    }
}
