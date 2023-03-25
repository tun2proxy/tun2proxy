use crate::error::Error;
use smoltcp::wire::IpCidr;
use std::ffi::CString;
use std::io::{BufRead, Write};
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::FromRawFd;
use std::process::Command;
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
            Vec::from(["-6", "route", "show"])
        } else {
            Vec::from(["-4", "route", "show"])
        };

        let e = Error::from("failed to get routing table");
        let routes = Command::new("ip")
            .args(route_show_args.as_slice())
            .output()
            .map_err(|_| e)?;

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

        let e = Error::from("failed to clone default route for proxy");
        let mut proxy_route = vec!["route".to_string(), "add".to_string()];
        proxy_route.push(self.proxy_addr.to_string());
        proxy_route.extend(default_route_args.clone());
        Command::new("ip")
            .args(proxy_route)
            .output()
            .map_err(|_| e)?;
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
            if libc::fchmod(fd, 0o644) == -1 {
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
            let e = Error::from(format!(
                "failed to set up routing of {} through {}",
                route, self.tun
            ));
            Command::new("ip")
                .args([
                    "route",
                    "add",
                    route.to_string().as_str(),
                    "dev",
                    self.tun.as_str(),
                ])
                .output()
                .map_err(|_| e)?;
        }
        Ok(())
    }

    fn shutdown(tun_name: String) {
        let _ = Command::new("ip")
            .args(["link", "del", tun_name.as_str()])
            .output();
        unsafe {
            let umount_path = CString::new("/etc/resolv.conf").unwrap();
            libc::umount(umount_path.as_ptr());
        }
    }

    pub fn setup(&mut self) -> Result<(), Error> {
        self.set_up = true;

        unsafe {
            if libc::getuid() != 0 {
                return Err("Automatic setup requires root privileges".into());
            }
        }

        let tun_name = self.tun.clone();
        // TODO: This is not optimal.
        ctrlc::set_handler(move || {
            Self::shutdown(tun_name.clone());
            std::process::exit(0);
        })?;

        let e = Error::from("failed to create tunnel device");
        Command::new("ip")
            .args(["tuntap", "add", "name", self.tun.as_str(), "mode", "tun"])
            .output()
            .map_err(|_| e)?;

        let e = Error::from("failed to bring up tunnel device");
        Command::new("ip")
            .args(["link", "set", self.tun.as_str(), "up"])
            .output()
            .map_err(|_| e)?;

        self.clone_default_route()?;
        Self::setup_resolv_conf()?;
        self.add_tunnel_routes()?;

        Ok(())
    }
}
