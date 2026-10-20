use socks5_impl::{Address, AsyncStreamOperation, StreamOperation};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use tokio::{
    io::{AsyncRead, AsyncWriteExt},
    net::{
        UdpSocket,
        tcp::{ReadHalf, WriteHalf},
    },
    sync::Mutex,
    sync::mpsc::{Receiver, Sender},
};
use tokio_util::sync::CancellationToken;
use tun2proxy::{
    BoxError, Error, Result,
    udpgw::{Packet, UdpFlag},
};

pub(crate) const CLIENT_DISCONNECT_TIMEOUT: tokio::time::Duration = std::time::Duration::from_secs(60);

#[derive(Debug, Clone)]
pub struct Client {
    addr: SocketAddr,
    last_activity: Arc<AtomicU64>,
}

impl Client {
    pub fn new(addr: SocketAddr) -> Self {
        let last_activity = Arc::new(AtomicU64::new(now_millis()));
        Self { addr, last_activity }
    }
}

fn about_info() -> &'static str {
    concat!("UDP Gateway Server for tun2proxy\nVersion: ", tun2proxy::version_info!())
}

#[derive(Debug, Clone, clap::Parser)]
#[command(author, version = tun2proxy::version_info!(), about = about_info(), long_about = None)]
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

    /// Verbosity level, possible values are "off", "error", "warn", "info", "debug", "trace"
    #[arg(short, long, value_name = "level", default_value = "info")]
    pub verbosity: log::LevelFilter,
}

impl UdpGwArgs {
    pub fn parse_args() -> Self {
        <Self as ::clap::Parser>::parse()
    }
}

fn now_millis() -> u64 {
    static START_INSTANT: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    START_INSTANT.get_or_init(Instant::now).elapsed().as_millis() as u64
}

fn packet_address(addr: SocketAddr) -> Address {
    Address::SocketAddress(addr)
}

/// A per-(conn_id) UDP relay session within a single client TCP connection.
struct Session {
    sock: Arc<UdpSocket>,
    dst: SocketAddr,
    req_addr: Address,
    generation: u64,
    sent: Arc<AtomicU64>,
    last_act: Arc<AtomicU64>,
    stop: CancellationToken,
}

type SessionMap = Arc<Mutex<HashMap<u16, Session>>>;
type GenerationMap = Arc<Mutex<HashMap<u16, u64>>>;
static NEXT_GENERATION: AtomicU64 = AtomicU64::new(1);

#[derive(Clone)]
struct ClientSessions {
    sessions: SessionMap,
    generations: GenerationMap,
    delivery_lock: Arc<Mutex<()>>,
}

impl ClientSessions {
    fn new() -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            generations: Arc::new(Mutex::new(HashMap::new())),
            delivery_lock: Arc::new(Mutex::new(())),
        }
    }

    async fn replace_generation(&self, conn_id: u16) -> u64 {
        let _delivery_guard = self.delivery_lock.lock().await;
        let generation = NEXT_GENERATION.fetch_add(1, Ordering::Relaxed);
        self.generations.lock().await.insert(conn_id, generation);
        if let Some(old) = self.sessions.lock().await.remove(&conn_id) {
            old.stop.cancel();
        }
        generation
    }

    async fn close_session(&self, conn_id: u16) -> bool {
        let _delivery_guard = self.delivery_lock.lock().await;
        self.generations.lock().await.remove(&conn_id);
        if let Some(old) = self.sessions.lock().await.remove(&conn_id) {
            old.stop.cancel();
            true
        } else {
            false
        }
    }
}

struct OutboundItem {
    packet: Packet,
    generation: Option<u64>,
}

async fn send_error_response(tx: Sender<OutboundItem>, conn_id: u16, generation: u64) {
    let error_packet = Packet::build_error_packet(conn_id);
    if let Err(e) = tx
        .send(OutboundItem {
            packet: error_packet,
            generation: Some(generation),
        })
        .await
    {
        log::error!("send error response error {e:?}");
    }
}

async fn send_keepalive_response(tx: Sender<OutboundItem>, conn_id: u16) {
    let keepalive_packet = Packet::build_keepalive_packet(conn_id);
    if let Err(e) = tx
        .send(OutboundItem {
            packet: keepalive_packet,
            generation: None,
        })
        .await
    {
        log::error!("send keepalive response error {e:?}");
    }
}

async fn send_udp_datagram(sock: &UdpSocket, data: &[u8], dst: SocketAddr) -> std::io::Result<()> {
    tokio::time::timeout(std::time::Duration::from_secs(1), sock.send_to(data, dst))
        .await
        .map_err(std::io::Error::from)??;
    Ok(())
}

/// Send data field of packet from client to destination server.
///
/// Unlike the stock implementation this keeps a persistent relay socket per
/// conn_id (and destination), so replies from the destination keep flowing to
/// the client for the whole lifetime of the session instead of being limited
/// to a single response per client datagram.
async fn process_udp(
    udp_mtu: u16,
    udp_timeout: u64,
    state: ClientSessions,
    client_activity: Arc<AtomicU64>,
    tx: Sender<OutboundItem>,
    packet: Packet,
) -> std::result::Result<(), (u64, Error)> {
    let conn_id = packet.header.conn_id;
    let Some(req_addr) = packet.address.clone() else {
        let generation = state.replace_generation(conn_id).await;
        return Err((
            generation,
            std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, "udp request address is None").into(),
        ));
    };

    if packet.data.len() > udp_mtu as usize {
        let generation = state.replace_generation(conn_id).await;
        return Err((
            generation,
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "udp request exceeds configured MTU").into(),
        ));
    }

    // Fast path: if the request address matches the existing session's request address,
    // reuse it directly without re-running DNS resolution or invalidating in-flight replies.
    {
        let map = state.sessions.lock().await;
        if let Some(s) = map.get(&conn_id)
            && s.req_addr == req_addr
        {
            let n = s.sent.fetch_add(1, Ordering::SeqCst) + 1;
            s.last_act.store(now_millis(), Ordering::SeqCst);
            let sock = s.sock.clone();
            let dst_addr = s.dst;
            let generation = s.generation;
            drop(map);
            if n == 1 || n % 500 == 0 {
                log::info!("session {conn_id} reuse #{n} -> {dst_addr}");
            }
            send_udp_datagram(&sock, &packet.data, dst_addr)
                .await
                .map_err(|e| (generation, e.into()))?;
            return Ok(());
        }
    }

    // Advance the generation and invalidate any existing session for this conn_id
    // before async DNS resolution so queued responses from the old destination cannot
    // be written while resolving, and any error from this request is versioned.
    let generation = state.replace_generation(conn_id).await;

    let mut resolved = tokio::time::timeout(std::time::Duration::from_secs(10), req_addr.resolve_using_tokio())
        .await
        .map_err(std::io::Error::from)
        .and_then(|res| res)
        .map_err(|e| (generation, e.into()))?;
    let Some(dst_addr) = resolved.next() else {
        return Err((
            generation,
            std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, "resolve_using_tokio").into(),
        ));
    };

    let delivery_guard = state.delivery_lock.lock().await;

    // Create a new session after resolving the destination.
    let std_sock = match dst_addr {
        SocketAddr::V6(_) => std::net::UdpSocket::bind("[::]:0"),
        SocketAddr::V4(_) => std::net::UdpSocket::bind("0.0.0.0:0"),
    }
    .map_err(|e| (generation, e.into()))?;
    std_sock.set_nonblocking(true).map_err(|e| (generation, e.into()))?;
    #[cfg(unix)]
    {
        use nix::sys::socket::{setsockopt, sockopt};
        let _ = setsockopt(&std_sock, sockopt::ReuseAddr, &true);
        let _ = setsockopt(&std_sock, sockopt::RcvBuf, &(4 * 1024 * 1024));
    }
    let socket = Arc::new(UdpSocket::from_std(std_sock).map_err(|e| (generation, e.into()))?);
    let local_port = socket.local_addr().map(|a| a.port()).unwrap_or(0);
    log::info!("session {conn_id} (gen {generation}) created: local 0.0.0.0:{local_port} -> {dst_addr}");
    let sent = Arc::new(AtomicU64::new(1));
    let last_act = Arc::new(AtomicU64::new(now_millis()));
    let stop = CancellationToken::new();

    state.sessions.lock().await.insert(
        conn_id,
        Session {
            sock: socket.clone(),
            dst: dst_addr,
            req_addr,
            generation,
            sent,
            last_act: last_act.clone(),
            stop: stop.clone(),
        },
    );

    if let Err(e) = send_udp_datagram(&socket, &packet.data, dst_addr).await {
        let mut map = state.sessions.lock().await;
        if map.get(&conn_id).is_some_and(|session| session.generation == generation) {
            map.remove(&conn_id);
        }
        return Err((generation, e.into()));
    }
    drop(delivery_guard);

    // 3. relay every reply from the destination back to the client
    let rsock = socket.clone();
    let rtx = tx.clone();
    let last_act_map = last_act.clone();
    let stop_flag = stop.clone();
    let sessions_cleanup = state.sessions.clone();
    let idle_ms = udp_timeout.max(1).saturating_mul(1000);
    let max_frame_payload =
        (u16::MAX as usize).saturating_sub(tun2proxy::udpgw::UdpgwHeader::static_len() + packet_address(dst_addr).len());
    let effective_mtu = (udp_mtu as usize).min(max_frame_payload);
    tokio::spawn(async move {
        let mut buf = vec![0u8; u16::MAX as usize];
        let mut responses: u64 = 0;
        let mut next_log: u64 = 1;
        loop {
            let received = tokio::select! {
                biased;
                _ = stop_flag.cancelled() => {
                    log::info!("session {conn_id} relay exit (replaced) after {responses} responses, port {local_port}");
                    break;
                }
                received = tokio::time::timeout(std::time::Duration::from_secs(1), rsock.recv_from(&mut buf)) => received,
            };
            match received {
                Ok(Ok((_len, source))) if source != dst_addr => {
                    log::debug!("session {conn_id} ignored UDP packet from unexpected source {source}, expected {dst_addr}");
                    let expired = {
                        let mut map = sessions_cleanup.lock().await;
                        let idle_for = map.get(&conn_id).and_then(|session| {
                            (session.generation == generation).then(|| now_millis().saturating_sub(session.last_act.load(Ordering::SeqCst)))
                        });
                        if idle_for.is_some_and(|idle| idle >= idle_ms) {
                            map.remove(&conn_id);
                            true
                        } else {
                            false
                        }
                    };
                    if expired {
                        log::info!("session {conn_id} relay exit (idle-timeout) after {responses} responses, port {local_port}");
                        break;
                    }
                }
                Ok(Ok((len, _addr))) => {
                    if stop_flag.is_cancelled() {
                        log::info!("session {conn_id} relay exit (replaced) after {responses} responses, port {local_port}");
                        break;
                    }
                    let now = now_millis();
                    last_act_map.store(now, Ordering::SeqCst);
                    client_activity.store(now, Ordering::SeqCst);
                    responses += 1;
                    if responses >= next_log {
                        log::info!("session {conn_id} relayed {responses} responses (last {len}B)");
                        next_log = responses + 500;
                    }
                    let packet = if len > effective_mtu {
                        log::debug!("session {conn_id} dropped oversized UDP response ({len}B > MTU {effective_mtu})");
                        Packet::build_error_packet(conn_id)
                    } else {
                        match Packet::build_packet_from_address(conn_id, &packet_address(dst_addr), &buf[..len]) {
                            Ok(packet) => packet,
                            Err(e) => {
                                log::debug!("session {conn_id} build response error {e}");
                                continue;
                            }
                        }
                    };
                    let item = OutboundItem {
                        packet,
                        generation: Some(generation),
                    };
                    let sent = tokio::select! {
                        biased;
                        _ = stop_flag.cancelled() => {
                            log::info!("session {conn_id} relay exit (replaced) after {responses} responses, port {local_port}");
                            break;
                        }
                        sent = rtx.send(item) => sent,
                    };
                    if sent.is_err() {
                        log::info!("session {conn_id} relay exit (client-gone) after {responses} responses, port {local_port}");
                        break;
                    }
                }
                Ok(Err(e)) => {
                    log::info!("session {conn_id} relay exit (recv error {e}) after {responses} responses, port {local_port}");
                    break;
                }
                Err(_) => {
                    let (still_current, idle_expired) = {
                        let mut map = sessions_cleanup.lock().await;
                        let idle_ms_now = now_millis();
                        let idle_for = map.get(&conn_id).and_then(|session| {
                            (session.generation == generation).then(|| idle_ms_now.saturating_sub(session.last_act.load(Ordering::SeqCst)))
                        });
                        match idle_for {
                            Some(idle) if idle >= idle_ms => {
                                if let Some(s) = map.remove(&conn_id) {
                                    s.stop.cancel();
                                }
                                (true, true)
                            }
                            Some(_) => (true, false),
                            None => (false, false),
                        }
                    };
                    if idle_expired {
                        log::info!("session {conn_id} relay exit (idle-timeout) after {responses} responses, port {local_port}");
                        break;
                    }
                    if !still_current {
                        break;
                    }
                }
            }
        }
        let mut map = sessions_cleanup.lock().await;
        if let Some(s) = map.get(&conn_id)
            && s.generation == generation
        {
            s.stop.cancel();
            map.remove(&conn_id);
        }
    });

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

async fn process_client_udp_req(
    args: &UdpGwArgs,
    state: ClientSessions,
    tx: Sender<OutboundItem>,
    client: Client,
    mut reader: ReadHalf<'_>,
) -> std::io::Result<()> {
    let udp_timeout = args.udp_timeout;
    let udp_mtu = args.udp_mtu;

    let masked_addr = mask_socket_addr(client.addr);

    loop {
        let masked_addr = masked_addr.clone();
        // 1. read udpgw packet from client
        let packet = match retrieve_packet_or_disconnect(&mut reader, &client.last_activity).await {
            Ok(packet) => packet,
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                log::debug!("client {masked_addr} last_activity elapsed \"{e}\"");
                break;
            }
            Err(e) => {
                log::debug!("client {masked_addr} retrieve_from_async_stream \"{e}\"");
                break;
            }
        };
        client.last_activity.store(now_millis(), Ordering::SeqCst);

        let flags = packet.header.flags;
        let conn_id = packet.header.conn_id;
        if flags == UdpFlag::KEEPALIVE {
            log::trace!("client {masked_addr} send keepalive");
            // 2. if keepalive packet, do nothing, send keepalive response to client
            send_keepalive_response(tx.clone(), conn_id).await;
            continue;
        }
        if flags == UdpFlag::CLOSE {
            let closed = state.close_session(conn_id).await;
            log::debug!("client {masked_addr} close session {conn_id} (active: {closed})");
            continue;
        }
        if flags != UdpFlag::DATA {
            log::debug!("client {masked_addr} unexpected packet flags {flags} for conn_id {conn_id}");
            let generation = state.replace_generation(conn_id).await;
            send_error_response(tx.clone(), conn_id, generation).await;
            continue;
        }
        log::trace!("client {masked_addr} received udp data {packet}");

        // 3. process the client udpgw packet inline to preserve ordering
        if let Err((generation, e)) = process_udp(
            udp_mtu,
            udp_timeout,
            state.clone(),
            client.last_activity.clone(),
            tx.clone(),
            packet,
        )
        .await
        {
            send_error_response(tx.clone(), conn_id, generation).await;
            log::debug!("client {masked_addr} process udp function \"{e}\"");
        }
    }
    Ok(())
}

async fn retrieve_packet_or_disconnect<R>(reader: &mut R, last_activity: &AtomicU64) -> std::io::Result<Packet>
where
    R: AsyncRead + Unpin + Send + ?Sized,
{
    let disconnect_ms = CLIENT_DISCONNECT_TIMEOUT.as_millis() as u64;
    let packet_read = Packet::retrieve_from_async_stream(reader);
    tokio::pin!(packet_read);
    loop {
        tokio::select! {
            result = &mut packet_read => return result,
            _ = tokio::time::sleep(std::time::Duration::from_secs(2)) => {
                if now_millis().saturating_sub(last_activity.load(Ordering::SeqCst)) >= disconnect_ms {
                    return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "client inactivity timeout"));
                }
            }
        }
    }
}

async fn write_to_client(
    addr: SocketAddr,
    generations: GenerationMap,
    delivery_lock: Arc<Mutex<()>>,
    client_activity: Arc<AtomicU64>,
    mut writer: WriteHalf<'_>,
    mut rx: Receiver<OutboundItem>,
) -> std::io::Result<()> {
    let masked_addr = mask_socket_addr(addr);
    loop {
        use std::io::{Error, ErrorKind::BrokenPipe};
        let item = rx.recv().await.ok_or(Error::new(BrokenPipe, "recv error"))?;
        let _delivery_guard = delivery_lock.lock().await;
        if let Some(generation) = item.generation {
            let conn_id = item.packet.header.conn_id;
            let is_current = generations
                .lock()
                .await
                .get(&conn_id)
                .is_some_and(|&current_gen| current_gen == generation);
            if !is_current {
                log::trace!("client {masked_addr} dropped stale response for conn_id {conn_id} (gen {generation})");
                continue;
            }
        }
        let packet = item.packet;
        log::trace!("send response to client {masked_addr} with {packet}");
        let data: Vec<u8> = packet.into();
        // write_all: a partial write() would corrupt the udpgw frame stream
        // and desynchronize the client-side packet parser.
        tokio::time::timeout(CLIENT_DISCONNECT_TIMEOUT, writer.write_all(&data))
            .await
            .map_err(std::io::Error::from)??;
        client_activity.store(now_millis(), Ordering::SeqCst);
    }
}

async fn main_async(args: UdpGwArgs) -> Result<(), BoxError> {
    log::info!("{} {} starting...", module_path!(), tun2proxy::version_info!());
    log::info!("UDP Gateway Server running at {}", args.listen_addr);

    let shutdown_token = CancellationToken::new();
    let main_loop_handle = tokio::spawn(run(args, shutdown_token.clone()));

    let ctrlc_fired = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let ctrlc_fired_clone = ctrlc_fired.clone();
    let ctrlc_handel = ctrlc2::AsyncCtrlC::new(move || {
        log::info!("Ctrl-C received, exiting...");
        ctrlc_fired_clone.store(true, std::sync::atomic::Ordering::SeqCst);
        shutdown_token.cancel();
        true
    })?;

    let _ = main_loop_handle.await?;

    if ctrlc_fired.load(std::sync::atomic::Ordering::SeqCst) {
        log::info!("Ctrl-C fired, waiting the handler to finish...");
        ctrlc_handel.await?;
    }

    Ok(())
}

pub async fn run(args: UdpGwArgs, shutdown_token: CancellationToken) -> crate::Result<()> {
    let tcp_listener = tokio::net::TcpListener::bind(args.listen_addr).await?;
    let mut client_tasks = tokio::task::JoinSet::new();
    loop {
        let (mut tcp_stream, addr) = tokio::select! {
            biased;
            _ = shutdown_token.cancelled() => break,
            Some(result) = client_tasks.join_next(), if !client_tasks.is_empty() => {
                if let Err(e) = result {
                    log::warn!("client task join error: {e}");
                }
                continue;
            }
            accepted = tcp_listener.accept() => accepted?,
        };
        let client = Client::new(addr);
        let state = ClientSessions::new();
        let masked_addr = mask_socket_addr(addr);
        log::info!("client {masked_addr} connected");
        let params = args.clone();
        let client_shutdown = shutdown_token.clone();
        client_tasks.spawn(async move {
            let (tx, rx) = tokio::sync::mpsc::channel::<OutboundItem>(1024);
            let (tcp_read_stream, tcp_write_stream) = tcp_stream.split();
            let writer_generations = state.generations.clone();
            let writer_delivery_lock = state.delivery_lock.clone();
            let cleanup_sessions = state.sessions.clone();
            let writer_activity = client.last_activity.clone();
            let res = tokio::select! {
                _ = client_shutdown.cancelled() => Ok(()),
                v = process_client_udp_req(&params, state, tx, client, tcp_read_stream) => v,
                v = write_to_client(addr, writer_generations, writer_delivery_lock, writer_activity, tcp_write_stream, rx) => v,
            };
            let mut map = cleanup_sessions.lock().await;
            for (_, session) in map.drain() {
                session.stop.cancel();
            }
            log::info!("client {masked_addr} disconnected with {res:?}");
        });
    }
    while let Some(result) = client_tasks.join_next().await {
        if let Err(e) = result {
            log::warn!("client task join error during shutdown: {e}");
        }
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
        let _ = daemonize.start().map_err(|e| format!("Failed to daemonize process, error:{e:?}"))?;
    }

    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    rt.block_on(main_async(args))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn partial_packet_read_survives_timeout_check() {
        let expected = Packet::build_keepalive_packet(42);
        let frame: Vec<u8> = expected.clone().into();
        let (mut client, mut server) = tokio::io::duplex(64);
        client.write_all(&frame[..1]).await.unwrap();
        let last_activity = AtomicU64::new(now_millis());

        let read = retrieve_packet_or_disconnect(&mut server, &last_activity);
        tokio::pin!(read);
        tokio::select! {
            result = &mut read => panic!("partial frame unexpectedly completed: {result:?}"),
            _ = tokio::time::sleep(std::time::Duration::from_millis(2100)) => {}
        }

        client.write_all(&frame[1..]).await.unwrap();
        assert_eq!(read.await.unwrap(), expected);
    }

    #[tokio::test]
    async fn generation_filter_drops_aba_and_stale_error_packets() {
        let conn_id = 7;
        let idle_expired_conn_id = 8;
        let dst_a: SocketAddr = "127.0.0.1:10001".parse().unwrap();
        let state = ClientSessions::new();
        let client_activity = Arc::new(AtomicU64::new(now_millis()));
        let (tx, rx) = tokio::sync::mpsc::channel::<OutboundItem>(16);

        // Request 1 for conn_id fails before session creation (e.g. MTU error) and queues an error.
        let bad_packet = Packet::new(
            tun2proxy::udpgw::UdpgwHeader::new(UdpFlag::DATA, conn_id),
            Some(Address::SocketAddress(dst_a)),
            &[0u8; 32],
        );
        let (failed_req_gen, _) = process_udp(8, 5, state.clone(), client_activity.clone(), tx.clone(), bad_packet)
            .await
            .unwrap_err();
        send_error_response(tx.clone(), conn_id, failed_req_gen).await;

        // Replacement session for conn_id advances the generation, invalidating both earlier data and request 1's error.
        let active_gen = state.replace_generation(conn_id).await;

        // Idle-expired session is removed from `sessions`, but its generation remains valid until `conn_id` is reassigned.
        let idle_gen = state.replace_generation(idle_expired_conn_id).await;

        let stale_data = Packet::build_packet_from_address(conn_id, &Address::SocketAddress(dst_a), b"old-a").unwrap();
        let queued_before_idle_expiry =
            Packet::build_packet_from_address(idle_expired_conn_id, &Address::SocketAddress(dst_a), b"queued-before-idle").unwrap();
        let current_data = Packet::build_packet_from_address(conn_id, &Address::SocketAddress(dst_a), b"new-a").unwrap();

        tx.send(OutboundItem {
            packet: stale_data,
            generation: Some(failed_req_gen),
        })
        .await
        .unwrap();
        tx.send(OutboundItem {
            packet: queued_before_idle_expiry.clone(),
            generation: Some(idle_gen),
        })
        .await
        .unwrap();
        tx.send(OutboundItem {
            packet: current_data.clone(),
            generation: Some(active_gen),
        })
        .await
        .unwrap();
        drop(tx);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (accept_res, connect_res) = tokio::join!(listener.accept(), tokio::net::TcpStream::connect(addr));
        let mut client_stream = connect_res.unwrap();
        let mut server_stream = accept_res.unwrap().0;

        let (_, server_write) = server_stream.split();
        let _ = write_to_client(dst_a, state.generations, state.delivery_lock, client_activity, server_write, rx).await;
        drop(server_stream);

        let first = Packet::retrieve_from_async_stream(&mut client_stream).await.unwrap();
        assert_eq!(first, queued_before_idle_expiry);
        let second = Packet::retrieve_from_async_stream(&mut client_stream).await.unwrap();
        assert_eq!(second, current_data);
        assert!(Packet::retrieve_from_async_stream(&mut client_stream).await.is_err());
    }

    #[tokio::test]
    async fn close_packet_stops_session_and_drops_queued_responses() {
        let echo_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_sock.local_addr().unwrap();

        let args = UdpGwArgs {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            udp_mtu: 1500,
            udp_timeout: 30,
            #[cfg(unix)]
            daemonize: false,
            verbosity: log::LevelFilter::Off,
        };
        let state = ClientSessions::new();
        let (tx, rx) = tokio::sync::mpsc::channel::<OutboundItem>(16);
        let client = Client::new("127.0.0.1:50000".parse().unwrap());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (accept_res, connect_res) = tokio::join!(listener.accept(), tokio::net::TcpStream::connect(addr));
        let mut client_stream = connect_res.unwrap();
        let mut server_stream = accept_res.unwrap().0;
        let (server_read, server_write) = server_stream.split();

        // Send DATA(conn_id=1) followed immediately by CLOSE(conn_id=1) and KEEPALIVE(conn_id=1).
        let data_pkt = Packet::build_ip_packet(1, echo_addr, b"ping");
        let close_pkt = Packet::build_close_packet(1);
        let keepalive_pkt = Packet::build_keepalive_packet(1);

        let mut wire: Vec<u8> = (&data_pkt).into();
        let close_bytes: Vec<u8> = (&close_pkt).into();
        let keepalive_bytes: Vec<u8> = (&keepalive_pkt).into();
        wire.extend_from_slice(&close_bytes);
        wire.extend_from_slice(&keepalive_bytes);
        client_stream.write_all(&wire).await.unwrap();
        client_stream.shutdown().await.unwrap();

        process_client_udp_req(&args, state.clone(), tx.clone(), client.clone(), server_read)
            .await
            .unwrap();

        // Active session and generation for conn_id=1 must be removed after CLOSE.
        assert!(!state.sessions.lock().await.contains_key(&1));
        assert!(!state.generations.lock().await.contains_key(&1));

        // Even if a late response with generation 1 was queued before CLOSE completed, write_to_client drops it.
        let late_resp = Packet::build_ip_packet(1, echo_addr, b"late-pong");
        tx.send(OutboundItem {
            packet: late_resp,
            generation: Some(1),
        })
        .await
        .unwrap();
        drop(tx);

        let _ = write_to_client(
            echo_addr,
            state.generations,
            state.delivery_lock,
            client.last_activity,
            server_write,
            rx,
        )
        .await;
        drop(server_stream);

        // Only the keepalive response should arrive on the client stream.
        let received = Packet::retrieve_from_async_stream(&mut client_stream).await.unwrap();
        assert_eq!(received, keepalive_pkt);
        assert!(Packet::retrieve_from_async_stream(&mut client_stream).await.is_err());
    }
}
