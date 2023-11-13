use mio::{event, windows::NamedPipe, Interest, Registry, Token};
use smoltcp::wire::IpCidr;
use smoltcp::{
    phy::{self, Device, DeviceCapabilities, Medium},
    time::Instant,
};
use std::{
    cell::RefCell,
    fs::OpenOptions,
    io::{self, Read, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    os::windows::prelude::{FromRawHandle, IntoRawHandle, OpenOptionsExt},
    rc::Rc,
    sync::{Arc, Mutex},
    thread::JoinHandle,
    vec::Vec,
};
use windows::{
    core::{GUID, PWSTR},
    Win32::{
        Foundation::{ERROR_BUFFER_OVERFLOW, WIN32_ERROR},
        NetworkManagement::{
            IpHelper::{
                GetAdaptersAddresses, SetInterfaceDnsSettings, DNS_INTERFACE_SETTINGS, DNS_INTERFACE_SETTINGS_VERSION1,
                DNS_SETTING_NAMESERVER, GAA_FLAG_INCLUDE_GATEWAYS, GAA_FLAG_INCLUDE_PREFIX, IF_TYPE_ETHERNET_CSMACD, IF_TYPE_IEEE80211,
                IP_ADAPTER_ADDRESSES_LH,
            },
            Ndis::IfOperStatusUp,
        },
        Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6},
        Storage::FileSystem::FILE_FLAG_OVERLAPPED,
    },
};

fn server() -> io::Result<(NamedPipe, String)> {
    use rand::Rng;
    let num: u64 = rand::thread_rng().gen();
    let name = format!(r"\\.\pipe\my-pipe-{}", num);
    let pipe = NamedPipe::new(&name)?;
    Ok((pipe, name))
}

fn client(name: &str) -> io::Result<NamedPipe> {
    let mut opts = OpenOptions::new();
    opts.read(true).write(true).custom_flags(FILE_FLAG_OVERLAPPED.0);
    let file = opts.open(name)?;
    unsafe { Ok(NamedPipe::from_raw_handle(file.into_raw_handle())) }
}

pub(crate) fn pipe() -> io::Result<(NamedPipe, NamedPipe)> {
    let (pipe, name) = server()?;
    Ok((pipe, client(&name)?))
}

/// A virtual TUN (IP) interface.
pub struct WinTunInterface {
    wintun_session: Arc<wintun::Session>,
    mtu: usize,
    medium: Medium,
    pipe_server: Rc<RefCell<NamedPipe>>,
    pipe_server_cache: Rc<RefCell<Vec<u8>>>,
    pipe_client: Arc<Mutex<NamedPipe>>,
    pipe_client_cache: Arc<Mutex<Vec<u8>>>,
    wintun_reader_thread: Option<JoinHandle<()>>,
    old_gateway: Option<IpAddr>,
}

impl event::Source for WinTunInterface {
    fn register(&mut self, registry: &Registry, token: Token, interests: Interest) -> io::Result<()> {
        self.pipe_server.borrow_mut().register(registry, token, interests)?;
        Ok(())
    }

    fn reregister(&mut self, registry: &Registry, token: Token, interests: Interest) -> io::Result<()> {
        self.pipe_server.borrow_mut().reregister(registry, token, interests)?;
        Ok(())
    }

    fn deregister(&mut self, registry: &Registry) -> io::Result<()> {
        self.pipe_server.borrow_mut().deregister(registry)?;
        Ok(())
    }
}

impl WinTunInterface {
    pub fn new(tun_name: &str, medium: Medium) -> io::Result<WinTunInterface> {
        let wintun = unsafe { wintun::load() }.map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        let guid = 324435345345345345_u128;
        let adapter = match wintun::Adapter::open(&wintun, tun_name) {
            Ok(a) => a,
            Err(_) => {
                wintun::Adapter::create(&wintun, tun_name, tun_name, Some(guid)).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?
            }
        };

        let session = adapter
            .start_session(wintun::MAX_RING_CAPACITY)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        let wintun_session = Arc::new(session);

        let (pipe_server, pipe_client) = pipe()?;

        let pipe_client = Arc::new(Mutex::new(pipe_client));
        let pipe_client_cache = Arc::new(Mutex::new(Vec::new()));

        let mtu = adapter.get_mtu().map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        let reader_session = wintun_session.clone();
        let pipe_client_clone = pipe_client.clone();
        let pipe_client_cache_clone = pipe_client_cache.clone();
        let reader_thread = std::thread::spawn(move || {
            let block = || -> Result<(), Box<dyn std::error::Error>> {
                loop {
                    // Take the old data from pipe_client_cache and append the new data
                    let cached_data = pipe_client_cache_clone.lock()?.drain(..).collect::<Vec<u8>>();
                    let bytes = if cached_data.len() >= mtu {
                        // if the cached data is greater than mtu, then sleep 1ms and return the data
                        std::thread::sleep(std::time::Duration::from_millis(1));
                        cached_data
                    } else {
                        // read data from tunnel interface
                        let packet = reader_session.receive_blocking()?;
                        let bytes = packet.bytes().to_vec();
                        // and append to the end of cached data
                        cached_data.into_iter().chain(bytes).collect::<Vec<u8>>()
                    };

                    if bytes.is_empty() {
                        continue;
                    }
                    let len = bytes.len();

                    // write data to named pipe_server
                    let result = { pipe_client_clone.lock()?.write(&bytes) };
                    match result {
                        Ok(n) => {
                            if n < len {
                                log::trace!("Wintun pipe_client write data {} less than buffer {}", n, len);
                                pipe_client_cache_clone.lock()?.extend_from_slice(&bytes[n..]);
                            }
                        }
                        Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                            log::trace!("Wintun pipe_client write WouldBlock (1) len {}", len);
                            pipe_client_cache_clone.lock()?.extend_from_slice(&bytes);
                        }
                        Err(err) => log::error!("Wintun pipe_client write data len {} error \"{}\"", len, err),
                    }
                }
            };
            if let Err(err) = block() {
                log::trace!("Reader {}", err);
            }
        });

        Ok(WinTunInterface {
            wintun_session,
            mtu,
            medium,
            pipe_server: Rc::new(RefCell::new(pipe_server)),
            pipe_server_cache: Rc::new(RefCell::new(Vec::new())),
            pipe_client,
            pipe_client_cache,
            wintun_reader_thread: Some(reader_thread),
            old_gateway: None,
        })
    }

    pub fn pipe_client(&self) -> Arc<Mutex<NamedPipe>> {
        self.pipe_client.clone()
    }

    pub fn pipe_client_event(&self, event: &event::Event) -> Result<(), io::Error> {
        if event.is_readable() {
            self.pipe_client_event_readable()
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        } else if event.is_writable() {
            self.pipe_client_event_writable()
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        }
        Ok(())
    }

    fn pipe_client_event_readable(&self) -> Result<(), Box<dyn std::error::Error + '_>> {
        let mut reader = self.pipe_client.lock()?;
        let mut buffer = vec![0; self.mtu];
        loop {
            // some data arieved to pipe_client from pipe_server
            match reader.read(&mut buffer[..]) {
                Ok(len) => match self.wintun_session.allocate_send_packet(len as u16) {
                    Ok(mut write_pack) => {
                        write_pack.bytes_mut().copy_from_slice(&buffer[..len]);
                        // write data to tunnel interface
                        self.wintun_session.send_packet(write_pack);
                    }
                    Err(err) => {
                        log::error!("Wintun: failed to allocate send packet: {}", err);
                    }
                },
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
                Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                Err(err) => return Err(err.into()),
            }
        }
        Ok(())
    }

    fn pipe_client_event_writable(&self) -> Result<(), Box<dyn std::error::Error + '_>> {
        let cache = self.pipe_client_cache.lock()?.drain(..).collect::<Vec<u8>>();
        if cache.is_empty() {
            return Ok(());
        }
        let len = cache.len();
        let result = self.pipe_client.lock()?.write(&cache[..]);
        match result {
            Ok(n) => {
                if n < len {
                    log::trace!("Wintun pipe_client write data {} less than buffer {}", n, len);
                    self.pipe_client_cache.lock()?.extend_from_slice(&cache[n..]);
                }
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                log::trace!("Wintun pipe_client write WouldBlock (2) len {}", len);
                self.pipe_client_cache.lock()?.extend_from_slice(&cache);
            }
            Err(err) => log::error!("Wintun pipe_client write data len {} error \"{}\"", len, err),
        }
        Ok(())
    }

    pub fn setup_config<'a>(
        &mut self,
        bypass_ips: impl IntoIterator<Item = &'a IpCidr>,
        dns_addr: Option<IpAddr>,
    ) -> Result<(), io::Error> {
        let adapter = self.wintun_session.get_adapter();

        // Setup the adapter's address/mask/gateway
        let address = "10.1.0.33".parse::<IpAddr>().unwrap();
        let mask = "255.255.255.0".parse::<IpAddr>().unwrap();
        let gateway = "10.1.0.1".parse::<IpAddr>().unwrap();
        adapter
            .set_network_addresses_tuple(address, mask, Some(gateway))
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        // 1. Setup the adapter's DNS
        let interface = GUID::from(adapter.get_guid());
        let dns = dns_addr.unwrap_or("8.8.8.8".parse::<IpAddr>().unwrap());
        let dns2 = "8.8.4.4".parse::<IpAddr>().unwrap();
        set_interface_dns_settings(interface, &[dns, dns2])?;

        // 2. Route all traffic to the adapter, here the destination is adapter's gateway
        // command: `route add 0.0.0.0 mask 0.0.0.0 10.1.0.1 metric 6`
        let unspecified = Ipv4Addr::UNSPECIFIED.to_string();
        let gateway = gateway.to_string();
        let args = &["add", &unspecified, "mask", &unspecified, &gateway, "metric", "6"];
        run_command("route", args)?;
        log::info!("route {:?}", args);

        let old_gateways = get_active_network_interface_gateways()?;
        // find ipv4 gateway address, or error return
        let old_gateway = old_gateways
            .iter()
            .find(|addr| addr.is_ipv4())
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "No ipv4 gateway found"))?;
        let old_gateway = old_gateway.ip();
        self.old_gateway = Some(old_gateway);

        // 3. route the bypass ip to the old gateway
        // command: `route add bypass_ip old_gateway metric 1`
        for bypass_ip in bypass_ips {
            let args = &["add", &bypass_ip.to_string(), &old_gateway.to_string(), "metric", "1"];
            run_command("route", args)?;
            log::info!("route {:?}", args);
        }

        Ok(())
    }

    pub fn restore_config(&mut self) -> Result<(), io::Error> {
        if self.old_gateway.is_none() {
            return Ok(());
        }
        let unspecified = Ipv4Addr::UNSPECIFIED.to_string();

        // 1. Remove current adapter's route
        // command: `route delete 0.0.0.0 mask 0.0.0.0`
        let args = &["delete", &unspecified, "mask", &unspecified];
        run_command("route", args)?;

        // 2. Add back the old gateway route
        // command: `route add 0.0.0.0 mask 0.0.0.0 old_gateway metric 200`
        let old_gateway = self.old_gateway.take().unwrap().to_string();
        let args = &["add", &unspecified, "mask", &unspecified, &old_gateway, "metric", "200"];
        run_command("route", args)?;

        Ok(())
    }
}

impl Drop for WinTunInterface {
    fn drop(&mut self) {
        if let Err(e) = self.restore_config() {
            log::error!("Faild to unsetup config: {}", e);
        }
        if let Err(e) = self.wintun_session.shutdown() {
            log::error!("phy: failed to shutdown interface: {}", e);
        }
        if let Some(thread) = self.wintun_reader_thread.take() {
            if let Err(e) = thread.join() {
                log::error!("phy: failed to join reader thread: {:?}", e);
            }
        }
    }
}

impl Device for WinTunInterface {
    type RxToken<'a> = RxToken;
    type TxToken<'a> = TxToken;

    fn capabilities(&self) -> DeviceCapabilities {
        let mut v = DeviceCapabilities::default();
        v.max_transmission_unit = self.mtu;
        v.medium = self.medium;
        v
    }

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let mut buffer = vec![0; self.mtu];
        match self.pipe_server.borrow_mut().read(&mut buffer[..]) {
            Ok(size) => {
                buffer.resize(size, 0);
                let rx = RxToken { buffer };
                let tx = TxToken {
                    pipe_server: self.pipe_server.clone(),
                    pipe_server_cache: self.pipe_server_cache.clone(),
                };
                Some((rx, tx))
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => None,
            Err(err) => panic!("{}", err),
        }
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(TxToken {
            pipe_server: self.pipe_server.clone(),
            pipe_server_cache: self.pipe_server_cache.clone(),
        })
    }
}

#[doc(hidden)]
pub struct RxToken {
    buffer: Vec<u8>,
}

impl phy::RxToken for RxToken {
    fn consume<R, F>(mut self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        f(&mut self.buffer[..])
    }
}

#[doc(hidden)]
pub struct TxToken {
    pipe_server: Rc<RefCell<NamedPipe>>,
    pipe_server_cache: Rc<RefCell<Vec<u8>>>,
}

impl phy::TxToken for TxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = vec![0; len];
        let result = f(&mut buffer);

        let buffer = self.pipe_server_cache.borrow_mut().drain(..).chain(buffer).collect::<Vec<_>>();
        if buffer.is_empty() {
            // log::trace!("Wintun TxToken (pipe_server) is empty");
            return result;
        }
        let len = buffer.len();

        match self.pipe_server.borrow_mut().write(&buffer[..]) {
            Ok(n) => {
                if n < len {
                    log::trace!("Wintun TxToken (pipe_server) sent {} less than buffer len {}", n, len);
                    self.pipe_server_cache.borrow_mut().extend_from_slice(&buffer[n..]);
                }
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                self.pipe_server_cache.borrow_mut().extend_from_slice(&buffer[..]);
                log::trace!("Wintun TxToken (pipe_server) WouldBlock data len: {}", len)
            }
            Err(err) => log::error!("Wintun TxToken (pipe_server) len {} error \"{}\"", len, err),
        }
        result
    }
}

pub struct NamedPipeSource(pub Arc<Mutex<NamedPipe>>);

impl event::Source for NamedPipeSource {
    fn register(&mut self, registry: &Registry, token: Token, interests: Interest) -> io::Result<()> {
        self.0
            .lock()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?
            .register(registry, token, interests)
    }

    fn reregister(&mut self, registry: &Registry, token: Token, interests: Interest) -> io::Result<()> {
        self.0
            .lock()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?
            .reregister(registry, token, interests)
    }

    fn deregister(&mut self, registry: &Registry) -> io::Result<()> {
        self.0
            .lock()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?
            .deregister(registry)
    }
}

pub(crate) fn run_command(command: &str, args: &[&str]) -> io::Result<()> {
    let out = std::process::Command::new(command).args(args).output()?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(if out.stderr.is_empty() { &out.stdout } else { &out.stderr });
        let info = format!("{} failed with: \"{}\"", command, err);
        return Err(std::io::Error::new(std::io::ErrorKind::Other, info));
    }
    Ok(())
}

pub(crate) fn set_interface_dns_settings(interface: GUID, dns: &[IpAddr]) -> io::Result<()> {
    // format L"1.1.1.1 8.8.8.8", or L"1.1.1.1,8.8.8.8".
    let dns = dns.iter().map(|ip| ip.to_string()).collect::<Vec<_>>().join(",");
    let dns = dns.encode_utf16().chain(std::iter::once(0)).collect::<Vec<_>>();

    let settings = DNS_INTERFACE_SETTINGS {
        Version: DNS_INTERFACE_SETTINGS_VERSION1,
        Flags: DNS_SETTING_NAMESERVER as _,
        NameServer: PWSTR(dns.as_ptr() as _),
        ..DNS_INTERFACE_SETTINGS::default()
    };

    unsafe { SetInterfaceDnsSettings(interface, &settings as *const _)? };
    Ok(())
}

pub(crate) fn get_active_network_interface_gateways() -> io::Result<Vec<SocketAddr>> {
    let mut addrs = vec![];
    get_adapters_addresses(|adapter| {
        if adapter.OperStatus == IfOperStatusUp && [IF_TYPE_ETHERNET_CSMACD, IF_TYPE_IEEE80211].contains(&adapter.IfType) {
            let mut current_gateway = adapter.FirstGatewayAddress;
            while !current_gateway.is_null() {
                let gateway = unsafe { &*current_gateway };
                {
                    let sockaddr_ptr = gateway.Address.lpSockaddr;
                    let sockaddr = unsafe { &*(sockaddr_ptr as *const SOCKADDR) };
                    let a = unsafe { sockaddr_to_socket_addr(sockaddr) }?;
                    addrs.push(a);
                }
                current_gateway = gateway.Next;
            }
        }
        Ok(())
    })?;
    Ok(addrs)
}

pub(crate) fn get_adapters_addresses<F>(mut callback: F) -> io::Result<()>
where
    F: FnMut(IP_ADAPTER_ADDRESSES_LH) -> io::Result<()>,
{
    let mut size = 0;
    let flags = GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_INCLUDE_GATEWAYS;
    let family = AF_UNSPEC.0 as u32;

    // Make an initial call to GetAdaptersAddresses to get the
    // size needed into the size variable
    let result = unsafe { GetAdaptersAddresses(family, flags, None, None, &mut size) };

    if WIN32_ERROR(result) != ERROR_BUFFER_OVERFLOW {
        WIN32_ERROR(result).ok()?;
    }
    // Allocate memory for the buffer
    let mut addresses: Vec<u8> = vec![0; (size + 4) as usize];

    // Make a second call to GetAdaptersAddresses to get the actual data we want
    let result = unsafe {
        let addr = Some(addresses.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH);
        GetAdaptersAddresses(family, flags, None, addr, &mut size)
    };

    WIN32_ERROR(result).ok()?;

    // If successful, output some information from the data we received
    let mut current_addresses = addresses.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
    while !current_addresses.is_null() {
        unsafe {
            callback(*current_addresses)?;
            current_addresses = (*current_addresses).Next;
        }
    }
    Ok(())
}

pub(crate) unsafe fn sockaddr_to_socket_addr(sock_addr: *const SOCKADDR) -> io::Result<SocketAddr> {
    let address = match (*sock_addr).sa_family {
        AF_INET => sockaddr_in_to_socket_addr(&*(sock_addr as *const SOCKADDR_IN)),
        AF_INET6 => sockaddr_in6_to_socket_addr(&*(sock_addr as *const SOCKADDR_IN6)),
        _ => return Err(io::Error::new(io::ErrorKind::Other, "Unsupported address type")),
    };
    Ok(address)
}

pub(crate) unsafe fn sockaddr_in_to_socket_addr(sockaddr_in: &SOCKADDR_IN) -> SocketAddr {
    let ip = Ipv4Addr::new(
        sockaddr_in.sin_addr.S_un.S_un_b.s_b1,
        sockaddr_in.sin_addr.S_un.S_un_b.s_b2,
        sockaddr_in.sin_addr.S_un.S_un_b.s_b3,
        sockaddr_in.sin_addr.S_un.S_un_b.s_b4,
    );
    let port = u16::from_be(sockaddr_in.sin_port);
    SocketAddr::new(ip.into(), port)
}

pub(crate) unsafe fn sockaddr_in6_to_socket_addr(sockaddr_in6: &SOCKADDR_IN6) -> SocketAddr {
    let ip = IpAddr::V6(Ipv6Addr::new(
        u16::from_be(sockaddr_in6.sin6_addr.u.Word[0]),
        u16::from_be(sockaddr_in6.sin6_addr.u.Word[1]),
        u16::from_be(sockaddr_in6.sin6_addr.u.Word[2]),
        u16::from_be(sockaddr_in6.sin6_addr.u.Word[3]),
        u16::from_be(sockaddr_in6.sin6_addr.u.Word[4]),
        u16::from_be(sockaddr_in6.sin6_addr.u.Word[5]),
        u16::from_be(sockaddr_in6.sin6_addr.u.Word[6]),
        u16::from_be(sockaddr_in6.sin6_addr.u.Word[7]),
    ));
    let port = u16::from_be(sockaddr_in6.sin6_port);
    SocketAddr::new(ip, port)
}
