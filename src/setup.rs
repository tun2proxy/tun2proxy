use crate::error::Error;
use smoltcp::wire::IpCidr;
use std::ffi::{CString, OsStr};
use std::io::{BufRead, Write};
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::FromRawFd;
use std::process::{Command, Output};
use std::ptr::null;
use std::str::FromStr;

#[derive(Clone)]
pub struct Setup {
    routes: Vec<IpCidr>,
    proxy_addr: IpAddr,
    tun: String,
    set_up: bool,
}

pub fn get_default_cidrs() -> [IpCidr; 4] {
    [
        IpCidr::new(Ipv4Addr::from_str("0.0.0.0").unwrap().into(), 1),
        IpCidr::new(Ipv4Addr::from_str("128.0.0.0").unwrap().into(), 1),
        IpCidr::new(Ipv6Addr::from_str("::").unwrap().into(), 1),
        IpCidr::new(Ipv6Addr::from_str("8000::").unwrap().into(), 1),
    ]
}

fn run_iproute<I, S>(args: I, error: &str, require_success: bool) -> Result<Output, Error>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut command = Command::new("");
    for (i, arg) in args.into_iter().enumerate() {
        if i == 0 {
            command = Command::new(arg);
        } else {
            command.arg(arg);
        }
    }

    let e = Error::from(error);
    let output = command.output().map_err(|_| e)?;
    if !require_success || output.status.success() {
        Ok(output)
    } else {
        let mut args: Vec<&str> = command.get_args().map(|x| x.to_str().unwrap()).collect();
        let program = command.get_program().to_str().unwrap();
        let mut cmdline = Vec::<&str>::new();
        cmdline.push(program);
        cmdline.append(&mut args);
        let command = cmdline.as_slice().join(" ");
        match String::from_utf8(output.stderr.clone()) {
            Ok(output) => Err(format!("Command `{}` failed: {}", command, output).into()),
            Err(_) => Err(format!(
                "Command `{:?}` failed with exit code {}",
                command,
                output.status.code().unwrap()
            )
            .into()),
        }
    }
}

fn ipv4_addr_is_shared(addr: &Ipv4Addr) -> bool {
    addr.octets()[0] == 100 && (addr.octets()[1] & 0b1100_0000 == 0b0100_0000)
}

fn ipv4_addr_is_benchmarking(addr: &Ipv4Addr) -> bool {
    addr.octets()[0] == 198 && (addr.octets()[1] & 0xfe) == 18
}

fn ipv4_addr_is_reserved(addr: &Ipv4Addr) -> bool {
    addr.octets()[0] & 240 == 240 && !addr.is_broadcast()
}

fn ipv4_addr_is_global(addr: &Ipv4Addr) -> bool {
    !(addr.octets()[0] == 0 // "This network"
        || addr.is_private()
        || ipv4_addr_is_shared(addr)
        || addr.is_loopback()
        || addr.is_link_local()
        // addresses reserved for future protocols (`192.0.0.0/24`)
        ||(addr.octets()[0] == 192 && addr.octets()[1] == 0 && addr.octets()[2] == 0)
        || addr.is_documentation()
        || ipv4_addr_is_benchmarking(addr)
        || ipv4_addr_is_reserved(addr)
        || addr.is_broadcast())
}

fn ipv6_addr_is_documentation(addr: &Ipv6Addr) -> bool {
    (addr.segments()[0] == 0x2001) && (addr.segments()[1] == 0xdb8)
}

fn ipv6_addr_is_unique_local(addr: &Ipv6Addr) -> bool {
    (addr.segments()[0] & 0xfe00) == 0xfc00
}

fn ipv6_addr_is_unicast_link_local(addr: &Ipv6Addr) -> bool {
    (addr.segments()[0] & 0xffc0) == 0xfe80
}

fn ipv6_addr_is_global(addr: &Ipv6Addr) -> bool {
    !(addr.is_unspecified()
        || addr.is_loopback()
        // IPv4-mapped Address (`::ffff:0:0/96`)
        || matches!(addr.segments(), [0, 0, 0, 0, 0, 0xffff, _, _])
        // IPv4-IPv6 Translat. (`64:ff9b:1::/48`)
        || matches!(addr.segments(), [0x64, 0xff9b, 1, _, _, _, _, _])
        // Discard-Only Address Block (`100::/64`)
        || matches!(addr.segments(), [0x100, 0, 0, 0, _, _, _, _])
        // IETF Protocol Assignments (`2001::/23`)
        || (matches!(addr.segments(), [0x2001, b, _, _, _, _, _, _] if b < 0x200)
        && !(
        // Port Control Protocol Anycast (`2001:1::1`)
        u128::from_be_bytes(addr.octets()) == 0x2001_0001_0000_0000_0000_0000_0000_0001
            // Traversal Using Relays around NAT Anycast (`2001:1::2`)
            || u128::from_be_bytes(addr.octets()) == 0x2001_0001_0000_0000_0000_0000_0000_0002
            // AMT (`2001:3::/32`)
            || matches!(addr.segments(), [0x2001, 3, _, _, _, _, _, _])
            // AS112-v6 (`2001:4:112::/48`)
            || matches!(addr.segments(), [0x2001, 4, 0x112, _, _, _, _, _])
            // ORCHIDv2 (`2001:20::/28`)
            || matches!(addr.segments(), [0x2001, b, _, _, _, _, _, _] if (0x20..=0x2F).contains(&b))
    ))
        || ipv6_addr_is_documentation(addr)
        || ipv6_addr_is_unique_local(addr)
        || ipv6_addr_is_unicast_link_local(addr))
}

impl Setup {
    pub fn new(
        tun: impl Into<String>,
        proxy_addr: &IpAddr,
        routes: impl IntoIterator<Item = IpCidr>,
    ) -> Self {
        let routes_cidr = routes.into_iter().collect();
        Self {
            tun: tun.into(),
            proxy_addr: *proxy_addr,
            routes: routes_cidr,
            set_up: false,
        }
    }

    fn clone_default_route(&mut self) -> Result<(), Error> {
        let route_show_args = if self.proxy_addr.is_ipv6() {
            ["ip", "-6", "route", "show"]
        } else {
            ["ip", "-4", "route", "show"]
        };

        let routes = run_iproute(route_show_args, "failed to get routing table", true)?;

        // Equivalent of `ip route | grep '^default' | cut -d ' ' -f 2-`
        let mut default_route_args = Vec::<String>::new();
        for result in routes.stdout.lines() {
            let line = result.unwrap();
            let split = line.split_whitespace();
            for (i, route_component) in split.enumerate() {
                if i == 0 && route_component != "default" {
                    break;
                } else if i == 0 {
                    continue;
                }
                default_route_args.push(String::from(route_component));
            }
            if !default_route_args.is_empty() {
                break;
            }
        }

        let mut proxy_route = vec!["ip".into(), "route".into(), "add".into()];
        proxy_route.push(self.proxy_addr.to_string());
        proxy_route.extend(default_route_args.into_iter());
        run_iproute(
            proxy_route,
            "failed to clone default route for proxy",
            false,
        )?;
        Ok(())
    }

    fn setup_resolv_conf() -> Result<(), Error> {
        unsafe {
            let fd = libc::open(
                CString::new("/tmp/tun2proxy-resolv.conf")?.as_ptr(),
                libc::O_RDWR | libc::O_CLOEXEC | libc::O_CREAT,
            );
            if fd == -1 {
                return Err("Failed to create temporary file".into());
            }
            let mut f = std::fs::File::from_raw_fd(fd);
            f.write_all("nameserver 198.18.0.1\n".as_bytes())?;
            mem::forget(f);
            if libc::fchmod(fd, 0o444) == -1 {
                return Err("Failed to change ownership of /etc/resolv.conf".into());
            }
            let fd_path = format!("/proc/self/fd/{}", fd);
            if libc::mount(
                CString::new(fd_path)?.as_ptr(),
                CString::new("/etc/resolv.conf")?.as_ptr(),
                CString::new("resolvconf")?.as_ptr(),
                libc::MS_BIND,
                null(),
            ) == -1
            {
                return Err("Failed to mount /etc/resolv.conf".into());
            }
        }
        Ok(())
    }

    fn add_tunnel_routes(&self) -> Result<(), Error> {
        for route in &self.routes {
            run_iproute(
                [
                    "ip",
                    "route",
                    "add",
                    route.to_string().as_str(),
                    "dev",
                    self.tun.as_str(),
                ],
                "failed to add route",
                true,
            )?;
        }
        Ok(())
    }

    fn shutdown(&self) {
        if !self.set_up {
            return;
        }
        Self::shutdown_with_args(&self.tun, self.proxy_addr);
    }

    fn shutdown_with_args(tun_name: &str, proxy_ip: IpAddr) {
        log::info!("Restoring network configuration");
        let _ = Command::new("ip").args(["link", "del", tun_name]).output();
        let _ = Command::new("ip")
            .args(["route", "del", proxy_ip.to_string().as_str()])
            .output();
        unsafe {
            let umount_path = CString::new("/etc/resolv.conf").unwrap();
            libc::umount(umount_path.as_ptr());
        }
    }

    pub fn setup(&mut self) -> Result<(), Error> {
        unsafe {
            if libc::getuid() != 0 {
                return Err("Automatic setup requires root privileges".into());
            }
        }

        let global = match self.proxy_addr {
            IpAddr::V4(addr) => ipv4_addr_is_global(&addr),
            IpAddr::V6(addr) => ipv6_addr_is_global(&addr),
        };

        if !global {
            return Err(format!("The proxy address {} is not a global address. Please specify the setup IP address manually", self.proxy_addr)
            .into());
        }

        run_iproute(
            [
                "ip",
                "tuntap",
                "add",
                "name",
                self.tun.as_str(),
                "mode",
                "tun",
            ],
            "failed to create tunnel device",
            true,
        )?;

        self.set_up = true;
        let tun_name = self.tun.clone();
        let proxy_ip = self.proxy_addr;
        // TODO: This is not optimal.
        ctrlc::set_handler(move || {
            Self::shutdown_with_args(&tun_name, proxy_ip);
            std::process::exit(0);
        })?;

        run_iproute(
            ["ip", "link", "set", self.tun.as_str(), "up"],
            "failed to bring up tunnel device",
            true,
        )?;

        self.clone_default_route()?;
        Self::setup_resolv_conf()?;
        self.add_tunnel_routes()?;

        Ok(())
    }
}

impl Drop for Setup {
    fn drop(&mut self) {
        self.shutdown();
    }
}
