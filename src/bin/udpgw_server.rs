use std::mem;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::net::SocketAddrV4;
use std::net::ToSocketAddrs;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::ReadHalf;
use tokio::net::TcpListener;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::sync::mpsc::Sender;
pub use tun2proxy::udpgw::*;
use tun2proxy::ArgVerbosity;
use tun2proxy::Result;
pub(crate) const CLIENT_DISCONNECT_TIMEOUT: tokio::time::Duration = std::time::Duration::from_secs(30);

#[derive(Debug)]
struct UdpRequest {
    flags: u8,
    server_addr: SocketAddr,
    conid: u16,
    data: Vec<u8>,
}

#[derive(Debug)]
struct Client {
    #[allow(dead_code)]
    addr: SocketAddr,
    buf: Vec<u8>,
    last_activity: std::time::Instant,
}

#[derive(Debug, Clone, clap::Parser)]
pub struct UdpGwArgs {
    /// UDP mtu
    #[arg(long, value_name = "udp mtu", default_value = "10240")]
    pub udp_mtu: u16,

    /// Verbosity level
    #[arg(short, long, value_name = "level", value_enum, default_value = "info")]
    pub verbosity: ArgVerbosity,

    /// Daemonize for unix family or run as Windows service
    #[arg(long)]
    pub daemonize: bool,

    /// UDP timeout in seconds
    #[arg(long, value_name = "seconds", default_value = "3")]
    pub udp_timeout: u64,

    /// UDP gateway listen address
    #[arg(long, value_name = "IP:PORT", default_value = "127.0.0.1:7300")]
    pub listen_addr: SocketAddr,
}

impl UdpGwArgs {
    #[allow(clippy::let_and_return)]
    pub fn parse_args() -> Self {
        use clap::Parser;
        Self::parse()
    }
}
async fn send_error(tx: Sender<Vec<u8>>, con: &mut UdpRequest) {
    let mut error_packet = vec![];
    error_packet.extend_from_slice(&(std::mem::size_of::<UdpgwHeader>() as u16).to_le_bytes());
    error_packet.extend_from_slice(&[UDPGW_FLAG_ERR]);
    error_packet.extend_from_slice(&con.conid.to_le_bytes());
    if let Err(e) = tx.send(error_packet).await {
        log::error!("send error response error {:?}", e);
    }
}

async fn send_keepalive_response(tx: Sender<Vec<u8>>, keepalive_packet: &[u8]) {
    if let Err(e) = tx.send(keepalive_packet.to_vec()).await {
        log::error!("send keepalive response error {:?}", e);
    }
}

pub fn parse_udp(udp_mtu: u16, data_len: usize, data: &[u8]) -> Result<(&[u8], u8, u16, SocketAddr)> {
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

    // keepalive
    if flags & UDPGW_FLAG_KEEPALIVE != 0 {
        return Ok((data, flags, conid, SocketAddrV4::new(Ipv4Addr::from(0), 0).into()));
    }

    let ip_data = &data[mem::size_of::<UdpgwHeader>()..];
    let mut data_len = data_len - mem::size_of::<UdpgwHeader>();
    // port_len + min(ipv4/ipv6/(domain_len + 1))
    if data_len < mem::size_of::<u16>() + 2 {
        return Err("Invalid udpgw data".into());
    }
    if flags & UDPGW_FLAG_DOMAIN != 0 {
        let addr_port = u16::from_be_bytes([ip_data[0], ip_data[1]]);
        data_len -= 2;
        if let Some(end) = ip_data.iter().skip(2).position(|&x| x == 0) {
            let domain_slice = &ip_data[2..end + 2];
            match std::str::from_utf8(domain_slice) {
                Ok(domain) => {
                    let target_str = format!("{}:{}", domain, addr_port);
                    let target = target_str
                        .to_socket_addrs()?
                        .next()
                        .ok_or(format!("Invalid address {}", target_str))?;
                    if data_len < 2 + domain.len() {
                        return Err("Invalid udpgw data".into());
                    }
                    data_len -= domain.len() + 1;
                    if data_len > udp_mtu as usize {
                        return Err("too much data".into());
                    }
                    let udpdata = &ip_data[(2 + domain.len() + 1)..];
                    return Ok((udpdata, flags, conid, target));
                }
                Err(_) => {
                    return Err("Invalid UTF-8 sequence in domain".into());
                }
            }
        } else {
            return Err("missing domain name".into());
        }
    } else if flags & UDPGW_FLAG_IPV6 != 0 {
        if data_len < mem::size_of::<UdpgwAddrIpv6>() {
            return Err("Ipv6 Invalid UDP data".into());
        }
        let addr_ipv6_bytes = &ip_data[..mem::size_of::<UdpgwAddrIpv6>()];
        let addr_ipv6 = UdpgwAddrIpv6 {
            addr_ip: addr_ipv6_bytes[..16].try_into().map_err(|_| "Failed to convert slice to array")?,
            addr_port: u16::from_be_bytes([addr_ipv6_bytes[16], addr_ipv6_bytes[17]]),
        };
        data_len -= mem::size_of::<UdpgwAddrIpv6>();

        if data_len > udp_mtu as usize {
            return Err("too much data".into());
        }
        return Ok((
            &ip_data[mem::size_of::<UdpgwAddrIpv6>()..(data_len + mem::size_of::<UdpgwAddrIpv6>())],
            flags,
            conid,
            UdpgwAddr::IPV6(addr_ipv6).into(),
        ));
    } else {
        if data_len < mem::size_of::<UdpgwAddrIpv4>() {
            return Err("Ipv4 Invalid UDP data".into());
        }
        let addr_ipv4_bytes = &ip_data[..mem::size_of::<UdpgwAddrIpv4>()];
        let addr_ipv4 = UdpgwAddrIpv4 {
            addr_ip: u32::from_be_bytes([addr_ipv4_bytes[0], addr_ipv4_bytes[1], addr_ipv4_bytes[2], addr_ipv4_bytes[3]]),
            addr_port: u16::from_be_bytes([addr_ipv4_bytes[4], addr_ipv4_bytes[5]]),
        };
        data_len -= mem::size_of::<UdpgwAddrIpv4>();

        if data_len > udp_mtu as usize {
            return Err("too much data".into());
        }

        return Ok((
            &ip_data[mem::size_of::<UdpgwAddrIpv4>()..(data_len + mem::size_of::<UdpgwAddrIpv4>())],
            flags,
            conid,
            UdpgwAddr::IPV4(addr_ipv4).into(),
        ));
    }
}

async fn process_udp(addr: SocketAddr, udp_timeout: u64, tx: Sender<Vec<u8>>, con: &mut UdpRequest) -> Result<()> {
    let std_sock = std::net::UdpSocket::bind("0.0.0.0:0")?;
    std_sock.set_nonblocking(true)?;
    nix::sys::socket::setsockopt(&std_sock, nix::sys::socket::sockopt::ReuseAddr, &true)?;
    let socket = UdpSocket::from_std(std_sock)?;
    socket.send_to(&con.data, &con.server_addr).await?;
    con.data.resize(2048, 0);
    match tokio::time::timeout(tokio::time::Duration::from_secs(udp_timeout), socket.recv_from(&mut con.data)).await {
        Ok(ret) => {
            let (len, _addr) = ret?;
            let mut packet = vec![];
            let mut pack_len = mem::size_of::<UdpgwHeader>() + len;
            match con.server_addr.into() {
                UdpgwAddr::IPV4(addr_ipv4) => {
                    pack_len += mem::size_of::<UdpgwAddrIpv4>();
                    packet.extend_from_slice(&(pack_len as u16).to_le_bytes());
                    packet.extend_from_slice(&[con.flags]);
                    packet.extend_from_slice(&con.conid.to_le_bytes());
                    packet.extend_from_slice(&addr_ipv4.addr_ip.to_be_bytes());
                    packet.extend_from_slice(&addr_ipv4.addr_port.to_be_bytes());
                    packet.extend_from_slice(&con.data[..len]);
                }
                UdpgwAddr::IPV6(addr_ipv6) => {
                    pack_len += mem::size_of::<UdpgwAddrIpv6>();
                    packet.extend_from_slice(&(pack_len as u16).to_le_bytes());
                    packet.extend_from_slice(&[con.flags]);
                    packet.extend_from_slice(&con.conid.to_le_bytes());
                    packet.extend_from_slice(&addr_ipv6.addr_ip);
                    packet.extend_from_slice(&addr_ipv6.addr_port.to_be_bytes());
                    packet.extend_from_slice(&con.data[..len]);
                }
            }
            if let Err(e) = tx.send(packet).await {
                log::error!("client {} send udp response {}", addr, e);
            }
        }
        Err(e) => {
            log::warn!("client {} udp recv_from {}", addr, e);
        }
    }
    Ok(())
}

async fn process_client_udp_req<'a>(args: &UdpGwArgs, tx: Sender<Vec<u8>>, mut client: Client, mut tcp_read_stream: ReadHalf<'a>) {
    let mut buf = vec![0; args.udp_mtu as usize];
    let mut len_buf = [0; mem::size_of::<PackLenHeader>()];
    let udp_mtu = args.udp_mtu;
    let udp_timeout = args.udp_timeout;
    'out: loop {
        let result;
        match tokio::time::timeout(tokio::time::Duration::from_secs(2), tcp_read_stream.read(&mut len_buf)).await {
            Ok(ret) => {
                result = ret;
            }
            Err(_e) => {
                if client.last_activity.elapsed() >= CLIENT_DISCONNECT_TIMEOUT {
                    log::debug!("client {} last_activity elapsed", client.addr);
                    return;
                }
                continue;
            }
        };
        match result {
            Ok(0) => break, // Connection closed
            Ok(n) => {
                if n < mem::size_of::<PackLenHeader>() {
                    log::error!("client {} received PackLenHeader error", client.addr);
                    break;
                }
                let packet_len = u16::from_le_bytes([len_buf[0], len_buf[1]]);
                if packet_len > udp_mtu {
                    log::error!("client {} received packet too long", client.addr);
                    break;
                }
                log::debug!("client {} recvied packet len {}", client.addr, packet_len);
                client.buf.clear();
                let mut left_len: usize = packet_len as usize;
                while left_len > 0 {
                    if let Ok(len) = tcp_read_stream.read(&mut buf[..left_len]).await {
                        if len == 0 {
                            break 'out;
                        }
                        client.buf.extend_from_slice(&mut buf[..len]);
                        left_len -= len;
                    } else {
                        break 'out;
                    }
                }
                client.last_activity = std::time::Instant::now();
                let ret = parse_udp(udp_mtu, client.buf.len(), &client.buf);
                if let Ok((udpdata, flags, conid, reqaddr)) = ret {
                    if flags & UDPGW_FLAG_KEEPALIVE != 0 {
                        log::debug!("client {} send keepalive", client.addr);
                        send_keepalive_response(tx.clone(), udpdata).await;
                        continue;
                    }
                    log::debug!(
                        "client {} received udp data,flags:{},conid:{},addr:{:?},data len:{}",
                        client.addr,
                        flags,
                        conid,
                        reqaddr,
                        udpdata.len()
                    );
                    let mut req = UdpRequest {
                        server_addr: reqaddr,
                        conid,
                        flags,
                        data: udpdata.to_vec(),
                    };
                    let tx1 = tx.clone();
                    let tx2 = tx.clone();
                    tokio::spawn(async move {
                        if let Err(e) = process_udp(client.addr, udp_timeout, tx1, &mut req).await {
                            send_error(tx2, &mut req).await;
                            log::error!("client {} process_udp {}", client.addr, e);
                        }
                    });
                } else {
                    log::error!("client {} parse_udp_data {:?}", client.addr, ret.err());
                }
            }
            Err(_) => {
                log::error!("client {} tcp_read_stream error", client.addr);
                break;
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Arc::new(UdpGwArgs::parse_args());

    let tcp_listener = TcpListener::bind(args.listen_addr).await?;

    let default = format!("{:?}", args.verbosity);

    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(default)).init();

    log::info!("UDP GW Server started");

    #[cfg(unix)]
    if args.daemonize {
        let stdout = std::fs::File::create("/tmp/udpgw.out")?;
        let stderr = std::fs::File::create("/tmp/udpgw.err")?;
        let daemonize = daemonize::Daemonize::new()
            .working_directory("/tmp")
            .umask(0o777)
            .stdout(stdout)
            .stderr(stderr)
            .privileged_action(|| "Executed before drop privileges");
        let _ = daemonize
            .start()
            .map_err(|e| format!("Failed to daemonize process, error:{:?}", e))?;
    }

    #[cfg(target_os = "windows")]
    if args.daemonize {
        tun2proxy::win_svc::start_service()?;
        return Ok(());
    }

    loop {
        let (mut tcp_stream, addr) = tcp_listener.accept().await?;
        let client = Client {
            addr,
            buf: vec![],
            last_activity: std::time::Instant::now(),
        };
        log::info!("client {} connected", addr);
        let params = Arc::clone(&args);
        tokio::spawn(async move {
            let (tx, mut rx) = mpsc::channel::<Vec<u8>>(100);
            let (tcp_read_stream, mut tcp_write_stream) = tcp_stream.split();
            tokio::select! {
                _ = process_client_udp_req(&params, tx, client, tcp_read_stream) =>{}
                _ = async {
                    loop
                    {
                        if let Some(udp_response) = rx.recv().await {
                            log::debug!("send udp_response len {}",udp_response.len());
                            let _ = tcp_write_stream.write(&udp_response).await;
                        }
                    }
                } => {}
            }
            log::info!("client {} disconnected", addr);
        });
    }
}
