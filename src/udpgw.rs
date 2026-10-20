use crate::error::Result;
use socks5_impl::{Address, AsyncStreamOperation, StreamOperation, protocol::BufMut};
use std::{collections::VecDeque, hash::Hash, net::SocketAddr, sync::atomic::Ordering::Relaxed};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{
        TcpStream,
        tcp::{OwnedReadHalf, OwnedWriteHalf},
    },
    sync::Mutex,
    time::{Duration, sleep},
};

pub(crate) const UDPGW_LENGTH_FIELD_SIZE: usize = std::mem::size_of::<u16>();
pub(crate) const UDPGW_MAX_CONNECTIONS: usize = 5;
pub(crate) const UDPGW_KEEPALIVE_TIME: tokio::time::Duration = std::time::Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UdpFlag(pub u8);

impl UdpFlag {
    pub const ZERO: UdpFlag = UdpFlag(0x00);
    pub const KEEPALIVE: UdpFlag = UdpFlag(0x01);
    pub const DATA: UdpFlag = UdpFlag(0x02);
    pub const CLOSE: UdpFlag = UdpFlag(0x04);
    pub const ERR: UdpFlag = UdpFlag(0x20);
}

impl std::fmt::Display for UdpFlag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let flag = match self.0 {
            0x00 => "ZERO",
            0x01 => "KEEPALIVE",
            0x02 => "DATA",
            0x04 => "CLOSE",
            0x20 => "ERR",
            n => return write!(f, "Unknown UdpFlag(0x{n:02X})"),
        };
        write!(f, "{flag}")
    }
}

impl std::ops::BitAnd for UdpFlag {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self::Output {
        UdpFlag(self.0 & rhs.0)
    }
}

impl std::ops::BitOr for UdpFlag {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self::Output {
        UdpFlag(self.0 | rhs.0)
    }
}

/// UDP Gateway Packet Format
///
/// The format is referenced from SOCKS5 packet format, with additional flags and connection ID fields.
///
/// `LEN`: This field is indicated the length of the packet, not including the length field itself.
///
/// `FLAGS`: This field is used to indicate the packet type. The flags are defined as follows:
/// - `0x01`: Keepalive packet without address and data
/// - `0x02`: Data packet with address and data
/// - `0x04`: Close packet without address and data
/// - `0x20`: Error packet without address and data
///
/// `CONN_ID`: This field is used to indicate the unique connection ID for the packet.
///
/// `ATYP` & `DST.ADDR` & `DST.PORT`: This fields are used to indicate the remote address and port.
/// It can be either an IPv4 address, an IPv6 address, or a domain name, depending on the `ATYP` field.
/// The address format directly uses the address format of the [SOCKS5](https://datatracker.ietf.org/doc/html/rfc1928#section-4) protocol.
/// - `ATYP`: Address Type, 1 byte, indicating the type of address ( 0x01-IPv4, 0x04-IPv6, or 0x03-domain name )
/// - `DST.ADDR`: Destination Address. If `ATYP` is 0x01 or 0x04, it is 4 or 16 bytes of IP address;
///   If `ATYP` is 0x03, it is a domain name, `DST.ADDR` is a variable length field,
///   it begins with a 1-byte length field and then the domain name without null-termination,
///   since the length field is 1 byte, the maximum length of the domain name is 255 bytes.
/// - `DST.PORT`: Destination Port, 2 bytes, the port number of the destination address.
///
/// `DATA`: The data field, a variable length field, the length is determined by the `LEN` field.
///
/// All the digits fields are in big-endian byte order.
///
/// ```plain
/// +-----+  +-------+---------+  +------+----------+----------+  +----------+
/// | LEN |  | FLAGS | CONN_ID |  | ATYP | DST.ADDR | DST.PORT |  |   DATA   |
/// +-----+  +-------+---------+  +------+----------+----------+  +----------+
/// |  2  |  |   1   |    2    |  |  1   | Variable |    2     |  | Variable |
/// +-----+  +-------+---------+  +------+----------+----------+  +----------+
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Packet {
    pub header: UdpgwHeader,
    pub address: Option<Address>,
    pub data: Vec<u8>,
}

impl std::fmt::Display for Packet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let addr = self.address.as_ref().map_or("None".to_string(), |addr| addr.to_string());
        let len = self.data.len();
        write!(f, "Packet {{ {}, address: {}, payload length: {} }}", self.header, addr, len)
    }
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
        use std::io::{Error, ErrorKind::InvalidData};
        if value.len() < UDPGW_LENGTH_FIELD_SIZE {
            return Err(Error::new(InvalidData, "frame too short"));
        }
        let length = u16::from_be_bytes([value[0], value[1]]) as usize;
        let total = length + UDPGW_LENGTH_FIELD_SIZE;
        if value.len() < total {
            return Err(Error::new(InvalidData, "incomplete frame"));
        }
        let mut iter = std::io::Cursor::new(&value[UDPGW_LENGTH_FIELD_SIZE..total]);
        let header = UdpgwHeader::retrieve_from_stream(&mut iter)?;
        let address = if header.flags & UdpFlag::DATA == UdpFlag::DATA {
            Some(Address::retrieve_from_stream(&mut iter)?)
        } else {
            None
        };
        let read_len = header.len() + address.as_ref().map_or(0, |addr| addr.len());
        if length < read_len {
            return Err(Error::new(InvalidData, "length field smaller than header and address length"));
        }
        use tokio_util::bytes::Buf;
        Ok(Packet::new(header, address, iter.chunk()))
    }
}

impl Packet {
    pub fn new(header: UdpgwHeader, address: Option<Address>, data: &[u8]) -> Self {
        let data = data.to_vec();
        Packet { header, address, data }
    }

    pub fn build_keepalive_packet(conn_id: u16) -> Self {
        Packet::new(UdpgwHeader::new(UdpFlag::KEEPALIVE, conn_id), None, &[])
    }

    pub fn build_close_packet(conn_id: u16) -> Self {
        Packet::new(UdpgwHeader::new(UdpFlag::CLOSE, conn_id), None, &[])
    }

    pub fn build_error_packet(conn_id: u16) -> Self {
        Packet::new(UdpgwHeader::new(UdpFlag::ERR, conn_id), None, &[])
    }

    pub fn build_packet_from_address(conn_id: u16, remote_addr: &Address, data: &[u8]) -> std::io::Result<Self> {
        let packet = match remote_addr {
            Address::SocketAddress(addr) => Packet::build_ip_packet(conn_id, *addr, data),
            Address::DomainAddress(domain, port) => Packet::build_domain_packet(conn_id, *port, domain, data)?,
        };
        if packet.len().saturating_sub(UDPGW_LENGTH_FIELD_SIZE) > u16::MAX as usize {
            use std::io::{Error, ErrorKind::InvalidInput};
            return Err(Error::new(InvalidInput, "udpgw packet exceeds maximum frame length"));
        }
        Ok(packet)
    }

    pub fn build_ip_packet(conn_id: u16, remote_addr: SocketAddr, data: &[u8]) -> Self {
        let addr: Address = remote_addr.into();
        Packet::new(UdpgwHeader::new(UdpFlag::DATA, conn_id), Some(addr), data)
    }

    pub fn build_domain_packet(conn_id: u16, port: u16, domain: &str, data: &[u8]) -> std::io::Result<Self> {
        use std::io::{Error, ErrorKind::InvalidInput};
        if domain.len() > 255 {
            return Err(Error::new(InvalidInput, "domain name exceeds 255 characters"));
        }
        let addr = Address::from((domain, port));
        let packet = Packet::new(UdpgwHeader::new(UdpFlag::DATA, conn_id), Some(addr), data);
        if packet.len().saturating_sub(UDPGW_LENGTH_FIELD_SIZE) > u16::MAX as usize {
            return Err(Error::new(InvalidInput, "udpgw packet exceeds maximum frame length"));
        }
        Ok(packet)
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
        let length = u16::from_be_bytes(buf) as usize;
        let header = UdpgwHeader::retrieve_from_stream(stream)?;
        let address = if header.flags & UdpFlag::DATA == UdpFlag::DATA {
            Some(Address::retrieve_from_stream(stream)?)
        } else {
            None
        };
        let read_len = header.len() + address.as_ref().map_or(0, |addr| addr.len());
        if length < read_len {
            return Err(std::io::ErrorKind::InvalidData.into());
        }
        let mut data = vec![0; length - read_len];
        stream.read_exact(&mut data)?;
        Ok(Packet::new(header, address, &data))
    }

    fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
        let len = self.len() - UDPGW_LENGTH_FIELD_SIZE;
        buf.put_u16(len as u16);
        self.header.write_to_buf(buf);
        if let Some(addr) = &self.address {
            addr.write_to_buf(buf);
        }
        buf.put_slice(&self.data);
    }

    fn len(&self) -> usize {
        UDPGW_LENGTH_FIELD_SIZE + self.header.len() + self.address.as_ref().map_or(0, |addr| addr.len()) + self.data.len()
    }
}

#[async_trait::async_trait]
impl AsyncStreamOperation for Packet {
    async fn retrieve_from_async_stream<R>(r: &mut R) -> std::io::Result<Self>
    where
        R: tokio::io::AsyncRead + Unpin + Send + ?Sized,
        Self: Sized,
    {
        let mut buf = [0; UDPGW_LENGTH_FIELD_SIZE];
        r.read_exact(&mut buf).await?;
        let length = u16::from_be_bytes(buf) as usize;
        let header = UdpgwHeader::retrieve_from_async_stream(r).await?;
        let address = if header.flags & UdpFlag::DATA == UdpFlag::DATA {
            Some(Address::retrieve_from_async_stream(r).await?)
        } else {
            None
        };
        let read_len = header.len() + address.as_ref().map_or(0, |addr| addr.len());
        if length < read_len {
            return Err(std::io::ErrorKind::InvalidData.into());
        }
        let mut data = vec![0; length - read_len];
        r.read_exact(&mut data).await?;
        Ok(Packet::new(header, address, &data))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UdpgwHeader {
    pub flags: UdpFlag,
    pub conn_id: u16,
}

impl std::fmt::Display for UdpgwHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} conn_id: {}", self.flags, self.conn_id)
    }
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
        R: tokio::io::AsyncRead + Unpin + Send + ?Sized,
        Self: Sized,
    {
        let mut buf = [0; UdpgwHeader::static_len()];
        r.read_exact(&mut buf).await?;
        UdpgwHeader::try_from(&buf[..])
    }
}

impl UdpgwHeader {
    pub fn new(flags: UdpFlag, conn_id: u16) -> Self {
        UdpgwHeader { flags, conn_id }
    }

    pub const fn static_len() -> usize {
        std::mem::size_of::<u8>() + std::mem::size_of::<u16>()
    }
}

impl TryFrom<&[u8]> for UdpgwHeader {
    type Error = std::io::Error;

    fn try_from(value: &[u8]) -> std::result::Result<Self, Self::Error> {
        if value.len() < UdpgwHeader::static_len() {
            return Err(std::io::ErrorKind::InvalidData.into());
        }
        let conn_id = u16::from_be_bytes([value[1], value[2]]);
        Ok(UdpgwHeader::new(UdpFlag(value[0]), conn_id))
    }
}

impl From<&UdpgwHeader> for Vec<u8> {
    fn from(header: &UdpgwHeader) -> Vec<u8> {
        let mut bytes = vec![0; header.len()];
        bytes[0] = header.flags.0;
        bytes[1..3].copy_from_slice(&header.conn_id.to_be_bytes());
        bytes
    }
}

#[allow(dead_code)]
#[derive(Debug)]
pub(crate) enum UdpGwResponse {
    KeepAlive,
    Error,
    TcpClose,
    Data(Packet),
}

impl std::fmt::Display for UdpGwResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UdpGwResponse::KeepAlive => write!(f, "KeepAlive"),
            UdpGwResponse::Error => write!(f, "Error"),
            UdpGwResponse::TcpClose => write!(f, "TcpClose"),
            UdpGwResponse::Data(packet) => write!(f, "Data({packet})"),
        }
    }
}

static SERIAL_NUMBER: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(1);

#[derive(Debug)]
pub(crate) struct UdpGwClientStream {
    local_addr: SocketAddr,
    writer: Option<OwnedWriteHalf>,
    reader: Option<OwnedReadHalf>,
    closed: bool,
    last_activity: std::time::Instant,
    serial_number: u16,
}

impl UdpGwClientStream {
    pub fn close(&mut self) {
        self.closed = true;
    }

    pub fn get_reader(&mut self) -> Option<OwnedReadHalf> {
        self.reader.take()
    }

    pub fn set_reader(&mut self, reader: Option<OwnedReadHalf>) {
        self.reader = reader;
    }

    pub fn set_writer(&mut self, writer: Option<OwnedWriteHalf>) {
        self.writer = writer;
    }

    pub fn get_writer(&mut self) -> Option<OwnedWriteHalf> {
        self.writer.take()
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn update_activity(&mut self) {
        self.last_activity = std::time::Instant::now();
    }

    pub fn is_closed(&self) -> bool {
        self.closed
    }

    pub fn serial_number(&self) -> u16 {
        self.serial_number
    }

    pub fn rotate_serial_number(&mut self) -> u16 {
        self.serial_number = SERIAL_NUMBER.fetch_add(1, Relaxed);
        self.serial_number
    }

    pub fn new(tcp_server_stream: TcpStream) -> Self {
        let default = "0.0.0.0:0".parse::<SocketAddr>().unwrap();
        let local_addr = tcp_server_stream.local_addr().unwrap_or(default);
        let (reader, writer) = tcp_server_stream.into_split();
        let serial_number = SERIAL_NUMBER.fetch_add(1, Relaxed);
        UdpGwClientStream {
            local_addr,
            reader: Some(reader),
            writer: Some(writer),
            last_activity: std::time::Instant::now(),
            closed: false,
            serial_number,
        }
    }
}

#[derive(Debug)]
pub(crate) struct UdpGwClient {
    udp_mtu: u16,
    max_connections: usize,
    udp_timeout: u64,
    keepalive_time: Duration,
    udpgw_server: SocketAddr,
    server_connections: Mutex<VecDeque<UdpGwClientStream>>,
}

impl UdpGwClient {
    pub fn new(udp_mtu: u16, max_connections: usize, keepalive_time: Duration, udp_timeout: u64, udpgw_server: SocketAddr) -> Self {
        let server_connections = Mutex::new(VecDeque::with_capacity(max_connections));
        UdpGwClient {
            udp_mtu,
            max_connections,
            udp_timeout,
            udpgw_server,
            keepalive_time,
            server_connections,
        }
    }

    pub(crate) fn get_udp_mtu(&self) -> u16 {
        self.udp_mtu
    }

    pub(crate) fn get_udp_timeout(&self) -> u64 {
        self.udp_timeout
    }

    pub(crate) async fn pop_server_connection_from_queue(&self) -> Option<UdpGwClientStream> {
        self.server_connections.lock().await.pop_front()
    }

    pub(crate) async fn store_server_connection(&self, stream: UdpGwClientStream) {
        let mut conns = self.server_connections.lock().await;
        if conns.len() < self.max_connections {
            conns.push_back(stream);
        }
    }

    pub(crate) async fn store_server_connection_full(&self, mut stream: UdpGwClientStream, reader: OwnedReadHalf, writer: OwnedWriteHalf) {
        let mut conns = self.server_connections.lock().await;
        if conns.len() < self.max_connections {
            stream.set_reader(Some(reader));
            stream.set_writer(Some(writer));
            conns.push_back(stream);
        }
    }

    pub(crate) fn get_udpgw_server_addr(&self) -> SocketAddr {
        self.udpgw_server
    }

    /// Heartbeat task asynchronous function to periodically check and maintain the active state of the server connection.
    pub(crate) async fn heartbeat_task(&self, shutdown_token: tokio_util::sync::CancellationToken) -> std::io::Result<()> {
        log::info!("udpgw: heartbeat task started");
        loop {
            tokio::select! {
                _ = shutdown_token.cancelled() => break,
                _ = sleep(self.keepalive_time) => {}
            };

            let mut streams = Vec::new();

            while let Some(stream) = self.pop_server_connection_from_queue().await {
                if !stream.is_closed() {
                    streams.push(stream);
                }
            }

            let (mut tx, mut rx) = (0, 0);

            for mut stream in streams {
                if stream.last_activity.elapsed() < self.keepalive_time {
                    self.store_server_connection(stream).await;
                    continue;
                }

                let Some(mut stream_reader) = stream.get_reader() else {
                    continue;
                };

                let Some(mut stream_writer) = stream.get_writer() else {
                    continue;
                };
                let local_addr = stream_writer.local_addr()?;
                let sn = stream.serial_number();
                let keepalive_packet: Vec<u8> = Packet::build_keepalive_packet(sn).into();
                tx += keepalive_packet.len();
                if let Err(e) = stream_writer.write_all(&keepalive_packet).await {
                    log::warn!("stream {sn} {local_addr:?} send keepalive failed: {e}");
                    continue;
                }
                loop {
                    match UdpGwClient::recv_udpgw_packet(self.udp_mtu, self.udp_timeout, &mut stream_reader).await {
                        Ok((len, UdpGwResponse::KeepAlive)) => {
                            stream.update_activity();
                            self.store_server_connection_full(stream, stream_reader, stream_writer).await;
                            log::trace!("stream {sn} {local_addr:?} send keepalive and recieve it successfully");
                            rx += len;
                            break;
                        }
                        Ok((len, UdpGwResponse::Data(data))) => {
                            let conn_id = data.header.conn_id;
                            log::trace!("stream {sn} {local_addr:?} keepalive ignored late data for conn_id {conn_id}");
                            rx += len;
                        }
                        Ok((len, UdpGwResponse::Error)) => {
                            log::trace!("stream {sn} {local_addr:?} keepalive ignored late error packet");
                            rx += len;
                        }
                        Ok((len, v)) => {
                            log::debug!("stream {sn} {local_addr:?} keepalive unexpected response: {v}");
                            rx += len;
                            break;
                        }
                        Err(e) => {
                            log::debug!("stream {sn} {local_addr:?} keepalive no response, error \"{e}\"");
                            break;
                        }
                    }
                }
            }
            crate::traffic_status::traffic_status_update(tx, rx)?;
        }
        log::info!("udpgw: heartbeat task exiting");
        Ok(())
    }

    /// Parses the UDP response data.
    pub(crate) fn parse_udp_response(udp_mtu: u16, packet: Packet) -> Result<UdpGwResponse> {
        let flags = packet.header.flags;
        if flags & UdpFlag::ERR == UdpFlag::ERR {
            return Ok(UdpGwResponse::Error);
        }
        if flags & UdpFlag::KEEPALIVE == UdpFlag::KEEPALIVE {
            return Ok(UdpGwResponse::KeepAlive);
        }
        if flags & UdpFlag::CLOSE == UdpFlag::CLOSE {
            return Ok(UdpGwResponse::TcpClose);
        }
        if packet.data.len() > udp_mtu as usize {
            return Err("too much data".into());
        }
        Ok(UdpGwResponse::Data(packet))
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
    pub(crate) async fn recv_udpgw_packet(udp_mtu: u16, udp_timeout: u64, stream: &mut OwnedReadHalf) -> Result<(usize, UdpGwResponse)> {
        let packet = tokio::time::timeout(
            tokio::time::Duration::from_secs(udp_timeout + 2),
            Packet::retrieve_from_async_stream(stream),
        )
        .await
        .map_err(std::io::Error::from)??;
        Ok((packet.len(), UdpGwClient::parse_udp_response(udp_mtu, packet)?))
    }

    /// Cancellation-safe frame reader.
    ///
    /// `recv_udpgw_packet` above is NOT cancellation safe: `read_exact` inside
    /// `Packet::retrieve_from_async_stream` may have already consumed socket
    /// bytes into the future's local buffer when the future is dropped by
    /// `tokio::select!` (the local-read branch wins whenever the app sends a
    /// datagram). Those bytes are lost and the next read starts mid-frame,
    /// which desynchronizes the parser ("Unsupported address type", "too much
    /// data").
    ///
    /// This variant keeps the partial frame in `acc`, a buffer owned by the
    /// caller (outside any future), and only ever awaits a plain `read()`,
    /// which is cancellation safe. Intended to be called in a `select!` loop
    /// with the same `acc` across iterations.
    pub(crate) async fn recv_udpgw_packet_csafe(
        udp_mtu: u16,
        udp_timeout: u64,
        stream: &mut OwnedReadHalf,
        acc: &mut Vec<u8>,
    ) -> Result<(usize, UdpGwResponse)> {
        use tokio_util::bytes::Buf;
        let mut chunk = [0u8; 8192];
        loop {
            if acc.len() >= UDPGW_LENGTH_FIELD_SIZE {
                let length = u16::from_be_bytes([acc[0], acc[1]]) as usize;
                if length >= 3 && acc.len() >= length + UDPGW_LENGTH_FIELD_SIZE {
                    let total = length + UDPGW_LENGTH_FIELD_SIZE;
                    let mut cur = std::io::Cursor::new(&acc[..total]);
                    let _ = cur.get_u16();
                    let header = UdpgwHeader::retrieve_from_stream(&mut cur)?;
                    let address = if header.flags & UdpFlag::DATA == UdpFlag::DATA {
                        Some(Address::retrieve_from_stream(&mut cur)?)
                    } else {
                        None
                    };
                    let read_len = header.len() + address.as_ref().map_or(0, |a| a.len());
                    if length < read_len {
                        return Err(std::io::Error::from(std::io::ErrorKind::InvalidData).into());
                    }
                    // `cur` spans the whole frame (length field included), so its
                    // position is already the absolute offset of the payload.
                    let data_start = cur.position() as usize;
                    let data = acc[data_start..total].to_vec();
                    acc.drain(..total);
                    let full = UDPGW_LENGTH_FIELD_SIZE + read_len + data.len();
                    let packet = Packet::new(header, address, &data);
                    return Ok((full, UdpGwClient::parse_udp_response(udp_mtu, packet)?));
                }
                if length < 3 {
                    return Err(std::io::Error::from(std::io::ErrorKind::InvalidData).into());
                }
            }
            let n = tokio::time::timeout(tokio::time::Duration::from_secs(udp_timeout + 2), stream.read(&mut chunk))
                .await
                .map_err(std::io::Error::from)??;
            if n == 0 {
                return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into());
            }
            acc.extend_from_slice(&chunk[..n]);
        }
    }

    /// Sends a UDP gateway packet.
    ///
    /// This function constructs and sends a UDP gateway packet based on the IPv6 enabled status, data length,
    /// remote address, domain (if any), connection ID, and the UDP gateway client writer stream.
    ///
    /// # Arguments
    ///
    /// * `ipv6_enabled` - Whether IPv6 is enabled
    /// * `data` - The data packet
    /// * `remote_addr` - Remote address
    /// * `conn_id` - Connection ID
    /// * `stream` - UDP gateway client writer stream
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the packet is sent successfully, otherwise returns an error.
    pub(crate) async fn send_udpgw_packet(
        ipv6_enabled: bool,
        data: &[u8],
        remote_addr: &socks5_impl::Address,
        conn_id: u16,
        stream: &mut OwnedWriteHalf,
    ) -> Result<()> {
        if !ipv6_enabled && remote_addr.get_type() == socks5_impl::AddressType::IPv6 {
            return Err("ipv6 not support".into());
        }
        let out_data: Vec<u8> = Packet::build_packet_from_address(conn_id, remote_addr, data)?.into();
        stream.write_all(&out_data).await?;

        Ok(())
    }

    /// Sends a UDP gateway close packet to notify the server to stop receiving data for `conn_id`.
    pub(crate) async fn send_udpgw_close_packet(conn_id: u16, stream: &mut OwnedWriteHalf) -> Result<usize> {
        let out_data: Vec<u8> = Packet::build_close_packet(conn_id).into();
        let len = out_data.len();
        stream.write_all(&out_data).await?;
        Ok(len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    /// The exact frame the udpgw server sends for a WireGuard handshake response:
    /// LEN=102, FLAGS=DATA, IPv4 address, 92-byte payload starting with type 0x02.
    fn handshake_response_frame(conn_id: u16, payload: &[u8]) -> Vec<u8> {
        let mut frame = Vec::new();
        let body_len = 3 + 7 + payload.len();
        frame.extend_from_slice(&(body_len as u16).to_be_bytes());
        frame.push(UdpFlag::DATA.0);
        frame.extend_from_slice(&conn_id.to_be_bytes());
        frame.push(0x01);
        frame.extend_from_slice(&[203, 0, 113, 9]);
        frame.extend_from_slice(&51820u16.to_be_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    async fn read_one_frame(frame: &[u8], split_at: Option<usize>) -> (usize, UdpGwResponse, Vec<u8>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (mut server_side, _) = listener.accept().await.unwrap();
        let (mut reader, _writer) = client.into_split();

        match split_at {
            Some(n) => {
                server_side.write_all(&frame[..n]).await.unwrap();
                server_side.flush().await.unwrap();
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                server_side.write_all(&frame[n..]).await.unwrap();
            }
            None => server_side.write_all(frame).await.unwrap(),
        }

        let mut acc = Vec::new();
        let (len, resp) = UdpGwClient::recv_udpgw_packet_csafe(10240, 10, &mut reader, &mut acc)
            .await
            .unwrap();
        (len, resp, acc)
    }

    #[tokio::test]
    async fn csafe_reader_returns_byte_exact_payload() {
        let mut payload: Vec<u8> = (0..92u8).collect();
        payload[0] = 0x02; // wg MESSAGE_HANDSHAKE_RESPONSE type byte
        let frame = handshake_response_frame(8, &payload);
        assert_eq!(frame.len(), 104);
        assert_eq!(payload[0], 0x02, "wg message type must stay at payload[0]");

        let (len, resp, acc) = read_one_frame(&frame, Some(40)).await;
        match resp {
            UdpGwResponse::Data(p) => {
                assert_eq!(p.header.conn_id, 8);
                assert_eq!(p.header.flags, UdpFlag::DATA);
                assert_eq!(p.data, payload, "payload must be delivered byte-exact");
            }
            other => panic!("unexpected response: {other}"),
        }
        assert_eq!(len, 104);
        assert!(acc.is_empty(), "frame fully consumed");
    }

    #[tokio::test]
    async fn csafe_reader_handles_addressless_frame() {
        let mut frame = Vec::new();
        frame.extend_from_slice(&3u16.to_be_bytes());
        frame.push(UdpFlag::KEEPALIVE.0);
        frame.extend_from_slice(&8u16.to_be_bytes());

        let (len, resp, acc) = read_one_frame(&frame, None).await;
        assert!(matches!(resp, UdpGwResponse::KeepAlive));
        assert_eq!(len, 5);
        assert!(acc.is_empty());

        let close_pkt = Packet::build_close_packet(9);
        let close_frame: Vec<u8> = (&close_pkt).into();
        assert_eq!(close_frame, vec![0x00, 0x03, UdpFlag::CLOSE.0, 0x00, 0x09]);
        assert_eq!(Packet::try_from(close_frame.as_slice()).unwrap(), close_pkt);
        let (len, resp, acc) = read_one_frame(&close_frame, None).await;
        assert!(matches!(resp, UdpGwResponse::TcpClose));
        assert_eq!(len, 5);
        assert!(acc.is_empty());
    }

    #[test]
    fn try_from_slice_ignores_trailing_bytes_and_rejects_truncated_header() {
        let addr: SocketAddr = "203.0.113.9:51820".parse().unwrap();
        let expected = Packet::build_ip_packet(8, addr, b"hello");
        let mut bytes: Vec<u8> = (&expected).into();
        bytes.extend_from_slice(b"trailing-next-frame-bytes");

        let parsed = Packet::try_from(bytes.as_slice()).unwrap();
        assert_eq!(parsed, expected);

        let malformed = [0x00, 0x01, UdpFlag::KEEPALIVE.0, 0x00, 0x08];
        assert!(Packet::try_from(&malformed[..]).is_err());
    }

    #[test]
    fn build_packet_from_address_rejects_frames_exceeding_u16_max() {
        let addr = Address::from("203.0.113.9:51820".parse::<SocketAddr>().unwrap());
        let max_payload = (u16::MAX as usize) - UdpgwHeader::static_len() - addr.len();
        assert!(Packet::build_packet_from_address(1, &addr, &vec![0u8; max_payload]).is_ok());
        assert!(Packet::build_packet_from_address(1, &addr, &vec![0u8; max_payload + 1]).is_err());
    }
}
