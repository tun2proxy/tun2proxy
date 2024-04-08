use crate::{Error, Result};
use socks5_impl::protocol::UserKey;

#[cfg(target_os = "linux")]
use std::ffi::OsString;

use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

#[derive(Debug, Clone, clap::Parser)]
#[command(author, version, about = "Tunnel interface to proxy.", long_about = None)]
pub struct Args {
    /// Proxy URL in the form proto://[username[:password]@]host:port,
    /// where proto is one of socks4, socks5, http. For example:
    /// socks5://myname:password@127.0.0.1:1080
    #[arg(short, long, value_parser = ArgProxy::from_url, value_name = "URL")]
    pub proxy: ArgProxy,

    /// Name of the tun interface, such as tun0, utun4, etc.
    /// If this option is not provided, the OS will generate a random one.
    #[arg(short, long, value_name = "name", conflicts_with = "tun_fd", value_parser = validate_tun)]
    pub tun: Option<String>,

    /// File descriptor of the tun interface
    #[arg(long, value_name = "fd", conflicts_with = "tun")]
    pub tun_fd: Option<i32>,

    /// Create a tun interface in a newly created unprivileged namespace
    /// while maintaining proxy connectivity via the global network namespace.
    #[cfg(target_os = "linux")]
    #[arg(long)]
    pub unshare: bool,

    /// File descriptor for UNIX datagram socket meant to transfer
    /// network sockets from global namespace to the new one.
    /// See `unshare(1)`, `namespaces(7)`, `sendmsg(2)`, `unix(7)`.
    #[cfg(target_os = "linux")]
    #[arg(long, value_name = "fd", hide(true))]
    pub socket_transfer_fd: Option<i32>,

    /// Specify a command to run with root-like capabilities in the new namespace
    /// when using `--unshare`.
    /// This could be useful to start additional daemons, e.g. `openvpn` instance.
    #[cfg(target_os = "linux")]
    #[arg(requires = "unshare")]
    pub admin_command: Vec<OsString>,

    /// IPv6 enabled
    #[arg(short = '6', long)]
    pub ipv6_enabled: bool,

    /// Routing and system setup, which decides whether to setup the routing and system configuration.
    /// This option is only available on Linux and requires root-like privileges. See `capabilities(7)`.
    #[arg(short, long, default_value = if cfg!(target_os = "linux") { "false" } else { "true" })]
    pub setup: bool,

    /// DNS handling strategy
    #[arg(short, long, value_name = "strategy", value_enum, default_value = "direct")]
    pub dns: ArgDns,

    /// DNS resolver address
    #[arg(long, value_name = "IP", default_value = "8.8.8.8")]
    pub dns_addr: IpAddr,

    /// IPs used in routing setup which should bypass the tunnel
    #[arg(short, long, value_name = "IP")]
    pub bypass: Vec<IpAddr>,

    /// TCP timeout in seconds
    #[arg(long, value_name = "seconds", default_value = "600")]
    pub tcp_timeout: u64,

    /// UDP timeout in seconds
    #[arg(long, value_name = "seconds", default_value = "10")]
    pub udp_timeout: u64,

    /// Verbosity level
    #[arg(short, long, value_name = "level", value_enum, default_value = "info")]
    pub verbosity: ArgVerbosity,
}

fn validate_tun(p: &str) -> Result<String> {
    #[cfg(target_os = "macos")]
    if p.len() <= 4 || &p[..4] != "utun" {
        return Err(Error::from("Invalid tun interface name, please use utunX"));
    }
    Ok(p.to_string())
}

impl Default for Args {
    fn default() -> Self {
        #[cfg(target_os = "linux")]
        let setup = false;
        #[cfg(not(target_os = "linux"))]
        let setup = true;
        Args {
            proxy: ArgProxy::default(),
            tun: None,
            tun_fd: None,
            #[cfg(target_os = "linux")]
            unshare: false,
            #[cfg(target_os = "linux")]
            socket_transfer_fd: None,
            #[cfg(target_os = "linux")]
            admin_command: Vec::new(),
            ipv6_enabled: false,
            setup,
            dns: ArgDns::default(),
            dns_addr: "8.8.8.8".parse().unwrap(),
            bypass: vec![],
            tcp_timeout: 600,
            udp_timeout: 10,
            verbosity: ArgVerbosity::Info,
        }
    }
}

impl Args {
    #[allow(clippy::let_and_return)]
    pub fn parse_args() -> Self {
        use clap::Parser;
        let args = Self::parse();
        #[cfg(target_os = "linux")]
        if !args.setup && args.tun.is_none() {
            eprintln!("Missing required argument, '--tun' must present when '--setup' is not used.");
            std::process::exit(-1);
        }
        args
    }

    pub fn proxy(&mut self, proxy: ArgProxy) -> &mut Self {
        self.proxy = proxy;
        self
    }

    pub fn dns(&mut self, dns: ArgDns) -> &mut Self {
        self.dns = dns;
        self
    }

    pub fn tun_fd(&mut self, tun_fd: Option<i32>) -> &mut Self {
        self.tun_fd = tun_fd;
        self
    }

    pub fn verbosity(&mut self, verbosity: ArgVerbosity) -> &mut Self {
        self.verbosity = verbosity;
        self
    }

    pub fn tun(&mut self, tun: String) -> &mut Self {
        self.tun = Some(tun);
        self
    }

    pub fn dns_addr(&mut self, dns_addr: IpAddr) -> &mut Self {
        self.dns_addr = dns_addr;
        self
    }

    pub fn bypass(&mut self, bypass: IpAddr) -> &mut Self {
        self.bypass.push(bypass);
        self
    }

    pub fn ipv6_enabled(&mut self, ipv6_enabled: bool) -> &mut Self {
        self.ipv6_enabled = ipv6_enabled;
        self
    }

    pub fn setup(&mut self, setup: bool) -> &mut Self {
        self.setup = setup;
        self
    }
}

#[repr(C)]
#[derive(Default, Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, clap::ValueEnum)]
pub enum ArgVerbosity {
    Off = 0,
    Error,
    Warn,
    #[default]
    Info,
    Debug,
    Trace,
}

#[cfg(target_os = "android")]
impl TryFrom<jni::sys::jint> for ArgVerbosity {
    type Error = Error;
    fn try_from(value: jni::sys::jint) -> Result<Self> {
        match value {
            0 => Ok(ArgVerbosity::Off),
            1 => Ok(ArgVerbosity::Error),
            2 => Ok(ArgVerbosity::Warn),
            3 => Ok(ArgVerbosity::Info),
            4 => Ok(ArgVerbosity::Debug),
            5 => Ok(ArgVerbosity::Trace),
            _ => Err(Error::from("Invalid verbosity level")),
        }
    }
}

impl From<ArgVerbosity> for log::LevelFilter {
    fn from(verbosity: ArgVerbosity) -> Self {
        match verbosity {
            ArgVerbosity::Off => log::LevelFilter::Off,
            ArgVerbosity::Error => log::LevelFilter::Error,
            ArgVerbosity::Warn => log::LevelFilter::Warn,
            ArgVerbosity::Info => log::LevelFilter::Info,
            ArgVerbosity::Debug => log::LevelFilter::Debug,
            ArgVerbosity::Trace => log::LevelFilter::Trace,
        }
    }
}

impl From<log::Level> for ArgVerbosity {
    fn from(level: log::Level) -> Self {
        match level {
            log::Level::Error => ArgVerbosity::Error,
            log::Level::Warn => ArgVerbosity::Warn,
            log::Level::Info => ArgVerbosity::Info,
            log::Level::Debug => ArgVerbosity::Debug,
            log::Level::Trace => ArgVerbosity::Trace,
        }
    }
}

impl std::fmt::Display for ArgVerbosity {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ArgVerbosity::Off => write!(f, "off"),
            ArgVerbosity::Error => write!(f, "error"),
            ArgVerbosity::Warn => write!(f, "warn"),
            ArgVerbosity::Info => write!(f, "info"),
            ArgVerbosity::Debug => write!(f, "debug"),
            ArgVerbosity::Trace => write!(f, "trace"),
        }
    }
}

/// DNS query handling strategy
/// - Virtual: Use a virtual DNS server to handle DNS queries, also known as Fake-IP mode
/// - OverTcp: Use TCP to send DNS queries to the DNS server
/// - Direct: Do not handle DNS by relying on DNS server bypassing
#[repr(C)]
#[derive(Default, Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, clap::ValueEnum)]
pub enum ArgDns {
    Virtual = 0,
    OverTcp,
    #[default]
    Direct,
}

#[cfg(target_os = "android")]
impl TryFrom<jni::sys::jint> for ArgDns {
    type Error = Error;
    fn try_from(value: jni::sys::jint) -> Result<Self> {
        match value {
            0 => Ok(ArgDns::Virtual),
            1 => Ok(ArgDns::OverTcp),
            2 => Ok(ArgDns::Direct),
            _ => Err(Error::from("Invalid DNS strategy")),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ArgProxy {
    pub proxy_type: ProxyType,
    pub addr: SocketAddr,
    pub credentials: Option<UserKey>,
}

impl Default for ArgProxy {
    fn default() -> Self {
        ArgProxy {
            proxy_type: ProxyType::Socks5,
            addr: "127.0.0.1:1080".parse().unwrap(),
            credentials: None,
        }
    }
}

impl std::fmt::Display for ArgProxy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let auth = match &self.credentials {
            Some(creds) => format!("{}", creds),
            None => "".to_owned(),
        };
        if auth.is_empty() {
            write!(f, "{}://{}", &self.proxy_type, &self.addr)
        } else {
            write!(f, "{}://{}@{}", &self.proxy_type, auth, &self.addr)
        }
    }
}

impl ArgProxy {
    pub fn from_url(s: &str) -> Result<ArgProxy> {
        if s == "none" {
            return Ok(ArgProxy {
                proxy_type: ProxyType::None,
                addr: "0.0.0.0:0".parse().unwrap(),
                credentials: None,
            });
        }

        let e = format!("`{s}` is not a valid proxy URL");
        let url = url::Url::parse(s).map_err(|_| Error::from(&e))?;
        let e = format!("`{s}` does not contain a host");
        let host = url.host_str().ok_or(Error::from(e))?;

        let mut url_host = String::from(host);
        let e = format!("`{s}` does not contain a port");
        let port = url.port().ok_or(Error::from(&e))?;
        url_host.push(':');
        url_host.push_str(port.to_string().as_str());

        let e = format!("`{host}` could not be resolved");
        let mut addr_iter = url_host.to_socket_addrs().map_err(|_| Error::from(&e))?;

        let e = format!("`{host}` does not resolve to a usable IP address");
        let addr = addr_iter.next().ok_or(Error::from(&e))?;

        let credentials = if url.username() == "" && url.password().is_none() {
            None
        } else {
            use percent_encoding::percent_decode;
            let username = percent_decode(url.username().as_bytes()).decode_utf8().unwrap();
            let password = percent_decode(url.password().unwrap_or("").as_bytes()).decode_utf8().unwrap();
            Some(UserKey::new(username, password))
        };

        let scheme = url.scheme();

        let proxy_type = match url.scheme().to_ascii_lowercase().as_str() {
            "socks4" => Some(ProxyType::Socks4),
            "socks5" => Some(ProxyType::Socks5),
            "http" => Some(ProxyType::Http),
            _ => None,
        }
        .ok_or(Error::from(&format!("`{scheme}` is an invalid proxy type")))?;

        Ok(ArgProxy {
            proxy_type,
            addr,
            credentials,
        })
    }
}

#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
pub enum ProxyType {
    Http = 0,
    Socks4,
    #[default]
    Socks5,
    None,
}

impl std::fmt::Display for ProxyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProxyType::Socks4 => write!(f, "socks4"),
            ProxyType::Socks5 => write!(f, "socks5"),
            ProxyType::Http => write!(f, "http"),
            ProxyType::None => write!(f, "none"),
        }
    }
}
