use socks5_impl::protocol::AsyncStreamOperation;
use std::net::SocketAddr;
use tokio::{
    io::AsyncWriteExt,
    net::{
        tcp::{ReadHalf, WriteHalf},
        UdpSocket,
    },
    sync::mpsc::{Receiver, Sender},
};
use tun2proxy::{
    udpgw::{Packet, UdpFlag},
    ArgVerbosity, BoxError, Error, Result,
};

pub(crate) const CLIENT_DISCONNECT_TIMEOUT: tokio::time::Duration = std::time::Duration::from_secs(60);

#[derive(Debug, Clone)]
pub struct Client {
    addr: SocketAddr,
    last_activity: std::time::Instant,
}

impl Client {
    pub fn new(addr: SocketAddr) -> Self {
        let last_activity = std::time::Instant::now();
        Self { addr, last_activity }
    }
}

#[derive(Debug, Clone, clap::Parser)]
#[command(author, version, about = "UDP Gateway Server for tun2proxy", long_about = None)]
pub struct UdpGwArgs {
    /// UDP gateway listen address
    #[arg(short, long, value_name = "IP:PORT", default_value = "127.0.0.1:7300")]
    pub listen_addr: SocketAddr,

    /// UDP mtu
    #[arg(short = 'm', long, value_name = "udp mtu", default_value = "10240")]
    pub udp_mtu: u16,

    /// UDP timeout in seconds
    #[arg(short = 't', long, value_name = "seconds", default_value = "3")]
    pub udp_timeout: u64,

    /// Daemonize for unix family or run as Windows service
    #[cfg(unix)]
    #[arg(short, long)]
    pub daemonize: bool,

    /// Verbosity level
    #[arg(short, long, value_name = "level", value_enum, default_value = "info")]
    pub verbosity: ArgVerbosity,
}

impl UdpGwArgs {
    pub fn parse_args() -> Self {
        <Self as ::clap::Parser>::parse()
    }
}

async fn send_error_response(tx: Sender<Packet>, conn_id: u16) {
    let error_packet = Packet::build_error_packet(conn_id);
    if let Err(e) = tx.send(error_packet).await {
        log::error!("send error response error {:?}", e);
    }
}

async fn send_keepalive_response(tx: Sender<Packet>, conn_id: u16) {
    let keepalive_packet = Packet::build_keepalive_packet(conn_id);
    if let Err(e) = tx.send(keepalive_packet).await {
        log::error!("send keepalive response error {:?}", e);
    }
}

/// Send data field of packet from client to destination server and receive response,
/// then wrap response data to the packet's data field and send packet back to client.
async fn process_udp(udp_mtu: u16, udp_timeout: u64, tx: Sender<Packet>, mut packet: Packet) -> Result<()> {
    let Some(dst_addr) = &packet.address else {
        return Err(std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, "udp request address is None").into());
    };
    use std::net::ToSocketAddrs;
    let Some(dst_addr) = dst_addr.to_socket_addrs()?.next() else {
        return Err(std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, "to_socket_addrs").into());
    };
    let std_sock = match dst_addr {
        std::net::SocketAddr::V6(_) => std::net::UdpSocket::bind("[::]:0")?,
        std::net::SocketAddr::V4(_) => std::net::UdpSocket::bind("0.0.0.0:0")?,
    };
    std_sock.set_nonblocking(true)?;
    #[cfg(unix)]
    nix::sys::socket::setsockopt(&std_sock, nix::sys::socket::sockopt::ReuseAddr, &true)?;
    let socket = UdpSocket::from_std(std_sock)?;
    // 1. send udp data to destination server
    socket.send_to(&packet.data, &dst_addr).await?;
    // 2. receive response from destination server
    let mut buf = vec![0u8; udp_mtu as usize];
    let (len, _addr) = tokio::time::timeout(tokio::time::Duration::from_secs(udp_timeout), socket.recv_from(&mut buf))
        .await
        .map_err(std::io::Error::from)??;
    packet.data = buf[..len].to_vec();
    // 3. send response back to client
    use std::io::{Error, ErrorKind::BrokenPipe};
    tx.send(packet).await.map_err(|e| Error::new(BrokenPipe, e))?;
    Ok(())
}

fn mask_ip(ip: &str) -> String {
    if ip.len() <= 2 {
        return ip.to_string();
    }
    let mut masked_ip = String::new();
    for (i, c) in ip.chars().enumerate() {
        if i == 0 || i == ip.len() - 1 || c == '.' || c == ':' {
            masked_ip.push(c);
        } else {
            masked_ip.push('*');
        }
    }
    masked_ip
}

fn mask_socket_addr(socket_addr: std::net::SocketAddr) -> String {
    match socket_addr {
        std::net::SocketAddr::V4(addr) => {
            let masked_ip = mask_ip(&addr.ip().to_string());
            format!("{}:{}", masked_ip, addr.port())
        }
        std::net::SocketAddr::V6(addr) => {
            let masked_ip = mask_ip(&addr.ip().to_string());
            format!("[{}]:{}", masked_ip, addr.port())
        }
    }
}

async fn process_client_udp_req(args: &UdpGwArgs, tx: Sender<Packet>, mut client: Client, mut reader: ReadHalf<'_>) -> std::io::Result<()> {
    let udp_timeout = args.udp_timeout;
    let udp_mtu = args.udp_mtu;

    let masked_addr = mask_socket_addr(client.addr);

    loop {
        let masked_addr = masked_addr.clone();
        // 1. read udpgw packet from client
        let res = tokio::time::timeout(tokio::time::Duration::from_secs(2), Packet::retrieve_from_async_stream(&mut reader)).await;
        let packet = match res {
            Ok(Ok(packet)) => packet,
            Ok(Err(e)) => {
                log::debug!("client {} retrieve_from_async_stream \"{}\"", masked_addr, e);
                break;
            }
            Err(e) => {
                if client.last_activity.elapsed() >= CLIENT_DISCONNECT_TIMEOUT {
                    log::debug!("client {} last_activity elapsed \"{e}\"", masked_addr);
                    break;
                }
                continue;
            }
        };
        client.last_activity = std::time::Instant::now();

        let flags = packet.header.flags;
        let conn_id = packet.header.conn_id;
        if flags & UdpFlag::KEEPALIVE == UdpFlag::KEEPALIVE {
            log::trace!("client {} send keepalive", masked_addr);
            // 2. if keepalive packet, do nothing, send keepalive response to client
            send_keepalive_response(tx.clone(), conn_id).await;
            continue;
        }
        log::trace!("client {} received udp data {}", masked_addr, packet);

        // 3. process client udpgw packet in a new task
        let tx = tx.clone();
        tokio::spawn(async move {
            if let Err(e) = process_udp(udp_mtu, udp_timeout, tx.clone(), packet).await {
                send_error_response(tx, conn_id).await;
                log::debug!("client {} process udp function \"{e}\"", masked_addr);
            }
        });
    }
    Ok(())
}

async fn write_to_client(addr: SocketAddr, mut writer: WriteHalf<'_>, mut rx: Receiver<Packet>) -> std::io::Result<()> {
    let masked_addr = mask_socket_addr(addr);
    loop {
        use std::io::{Error, ErrorKind::BrokenPipe};
        let packet = rx.recv().await.ok_or(Error::new(BrokenPipe, "recv error"))?;
        log::trace!("send response to client {} with {}", masked_addr, packet);
        let data: Vec<u8> = packet.into();
        let _r = writer.write(&data).await?;
    }
}

async fn main_async(args: UdpGwArgs) -> Result<(), BoxError> {
    log::info!("{} {} starting...", module_path!(), env!("CARGO_PKG_VERSION"));
    log::info!("UDP Gateway Server running at {}", args.listen_addr);

    let shutdown_token = tokio_util::sync::CancellationToken::new();
    let main_loop_handle = tokio::spawn(run(args, shutdown_token.clone()));

    let ctrlc_fired = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let ctrlc_fired_clone = ctrlc_fired.clone();
    let ctrlc_handel = ctrlc2::set_async_handler(async move {
        log::info!("Ctrl-C received, exiting...");
        ctrlc_fired_clone.store(true, std::sync::atomic::Ordering::SeqCst);
        shutdown_token.cancel();
    })
    .await;

    let _ = main_loop_handle.await?;

    if ctrlc_fired.load(std::sync::atomic::Ordering::SeqCst) {
        log::info!("Ctrl-C fired, waiting the handler to finish...");
        ctrlc_handel.await.map_err(|err| err.to_string())?;
    }

    Ok(())
}

pub async fn run(args: UdpGwArgs, shutdown_token: tokio_util::sync::CancellationToken) -> crate::Result<()> {
    let tcp_listener = tokio::net::TcpListener::bind(args.listen_addr).await?;
    loop {
        let (mut tcp_stream, addr) = tokio::select! {
            v = tcp_listener.accept() => v?,
            _ = shutdown_token.cancelled() => break,
        };
        let client = Client::new(addr);
        let masked_addr = mask_socket_addr(addr);
        log::info!("client {} connected", masked_addr);
        let params = args.clone();
        tokio::spawn(async move {
            let (tx, rx) = tokio::sync::mpsc::channel::<Packet>(100);
            let (tcp_read_stream, tcp_write_stream) = tcp_stream.split();
            let res = tokio::select! {
                v = process_client_udp_req(&params, tx, client, tcp_read_stream) => v,
                v = write_to_client(addr, tcp_write_stream, rx) => v,
            };
            log::info!("client {} disconnected with {:?}", masked_addr, res);
        });
    }
    Ok::<(), Error>(())
}

fn main() -> Result<(), BoxError> {
    dotenvy::dotenv().ok();
    let args = UdpGwArgs::parse_args();

    let default = format!("{:?}", args.verbosity);
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(default)).init();

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

    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    rt.block_on(main_async(args))
}
