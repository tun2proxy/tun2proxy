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
