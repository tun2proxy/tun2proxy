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
    tunnel_bypass_addr: IpAddr,
    allow_private: bool,
    tun: String,
    set_up: bool,
    delete_proxy_route: bool,
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

impl Setup {
    pub fn new(
        tun: impl Into<String>,
        tunnel_bypass_addr: &IpAddr,
        routes: impl IntoIterator<Item = IpCidr>,
        allow_private: bool,
    ) -> Self {
        let routes_cidr = routes.into_iter().collect();
        Self {
            tun: tun.into(),
            tunnel_bypass_addr: *tunnel_bypass_addr,
            allow_private,
            routes: routes_cidr,
            set_up: false,
            delete_proxy_route: false,
        }
    }

    fn route_proxy_address(&mut self) -> Result<bool, Error> {
        let route_show_args = if self.tunnel_bypass_addr.is_ipv6() {
            ["ip", "-6", "route", "show"]
        } else {
            ["ip", "-4", "route", "show"]
        };

        let routes = run_iproute(route_show_args, "failed to get routing table", true)?;

        let mut route_info = Vec::<(IpCidr, Vec<String>)>::new();

        for line in routes.stdout.lines() {
            if line.is_err() {
                break;
            }
            let line = line.unwrap();
            if line.starts_with([' ', '\t']) {
                continue;
            }

            let mut split = line.split_whitespace();
            let mut dst_str = split.next().unwrap();
            if dst_str == "default" {
                dst_str = if self.tunnel_bypass_addr.is_ipv6() {
                    "::/0"
                } else {
                    "0.0.0.0/0"
                }
            }

            let (addr_str, prefix_len_str) = dst_str.split_once(['/']).unwrap();

            let cidr: IpCidr = IpCidr::new(
                std::net::IpAddr::from_str(addr_str).unwrap().into(),
                u8::from_str(prefix_len_str).unwrap(),
            );
            let route_components: Vec<String> = split.map(String::from).collect();
            route_info.push((cidr, route_components))
        }

        // Sort routes by prefix length, the most specific route comes first.
        route_info.sort_by(|entry1, entry2| entry2.0.prefix_len().cmp(&entry1.0.prefix_len()));

        for (cidr, route_components) in route_info {
            if !cidr.contains_addr(&smoltcp::wire::IpAddress::from(self.tunnel_bypass_addr)) {
                continue;
            }

            // The IP address is routed through a more specific route than the default route.
            // In this case, there is nothing to do.
            if cidr.prefix_len() != 0 {
                break;
            }

            let mut proxy_route = vec!["ip".into(), "route".into(), "add".into()];
            proxy_route.push(self.tunnel_bypass_addr.to_string());
            proxy_route.extend(route_components.into_iter());
            run_iproute(proxy_route, "failed to clone route for proxy", false)?;
            return Ok(true);
        }
        Ok(false)
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
        Self::shutdown_with_args(&self.tun, self.tunnel_bypass_addr, self.delete_proxy_route);
    }

    fn shutdown_with_args(tun_name: &str, proxy_ip: IpAddr, delete_proxy_route: bool) {
        log::info!("Restoring network configuration");
        let _ = Command::new("ip").args(["link", "del", tun_name]).output();
        if delete_proxy_route {
            let _ = Command::new("ip")
                .args(["route", "del", proxy_ip.to_string().as_str()])
                .output();
        }
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

        if self.tunnel_bypass_addr.is_loopback() && !self.allow_private {
            log::warn!(
                "The proxy address {} is a loopback address. You may need to manually \
                provide --setup-ip to specify the server IP bypassing the tunnel",
                self.tunnel_bypass_addr
            )
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
        let proxy_ip = self.tunnel_bypass_addr;

        run_iproute(
            ["ip", "link", "set", self.tun.as_str(), "up"],
            "failed to bring up tunnel device",
            true,
        )?;
        
        let delete_proxy_route = self.route_proxy_address()?;
        self.delete_proxy_route = delete_proxy_route;
        ctrlc::set_handler(move || {
            Self::shutdown_with_args(&tun_name, proxy_ip, delete_proxy_route);
            std::process::exit(0);
        })?;
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
