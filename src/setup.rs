use crate::error::Error;
use smoltcp::wire::IpCidr;
use std::convert::TryFrom;

use std::ffi::OsStr;
use std::io::BufRead;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use std::os::fd::RawFd;

use std::process::{Command, Output};

use std::str::FromStr;

use fork::Fork;

#[derive(Clone)]
pub struct Setup {
    routes: Vec<IpCidr>,
    tunnel_bypass_addr: IpAddr,
    allow_private: bool,
    tun: String,
    set_up: bool,
    delete_proxy_route: bool,
    child: libc::pid_t,
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
            Ok(output) => Err(format!(
                "[{}] Command `{}` failed: {}",
                nix::unistd::getpid(),
                command,
                output
            )
            .into()),
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
            child: 0,
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

            let (addr_str, prefix_len_str) = match dst_str.split_once(['/']) {
                None => (
                    dst_str,
                    if self.tunnel_bypass_addr.is_ipv6() {
                        "128"
                    } else {
                        "32"
                    },
                ),
                Some((addr_str, prefix_len_str)) => (addr_str, prefix_len_str),
            };

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
        let fd = nix::fcntl::open(
            "/tmp/tun2proxy-resolv.conf",
            nix::fcntl::OFlag::O_RDWR | nix::fcntl::OFlag::O_CLOEXEC | nix::fcntl::OFlag::O_CREAT,
            nix::sys::stat::Mode::from_bits(0o644_u32).unwrap(),
        )?;
        let data = "nameserver 198.18.0.1\n".as_bytes();
        let mut written = 0;
        loop {
            if written >= data.len() {
                break;
            }
            written += nix::unistd::write(fd, &data[written..])?;
        }
        nix::sys::stat::fchmod(fd, nix::sys::stat::Mode::from_bits(0o444_u32).unwrap())?;
        let source = format!("/proc/self/fd/{}", fd);
        nix::mount::mount(
            source.as_str().into(),
            "/etc/resolv.conf",
            "".into(),
            nix::mount::MsFlags::MS_BIND,
            "".into(),
        )?;
        nix::unistd::close(fd)?;
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

    fn shutdown(&mut self) -> Result<(), Error> {
        self.set_up = false;
        log::info!(
            "[{}] Restoring network configuration",
            nix::unistd::getpid()
        );
        let _ = Command::new("ip")
            .args(["link", "del", self.tun.as_str()])
            .output();
        if self.delete_proxy_route {
            let _ = Command::new("ip")
                .args(["route", "del", self.tunnel_bypass_addr.to_string().as_str()])
                .output();
        }
        nix::mount::umount("/etc/resolv.conf")?;
        Ok(())
    }

    fn setup_and_handle_signals(&mut self, read_from_child: RawFd, write_to_parent: RawFd) {
        if let Err(e) = (|| -> Result<(), Error> {
            nix::unistd::close(read_from_child)?;
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
            let _tun_name = self.tun.clone();
            let _proxy_ip = self.tunnel_bypass_addr;

            run_iproute(
                ["ip", "link", "set", self.tun.as_str(), "up"],
                "failed to bring up tunnel device",
                true,
            )?;

            let delete_proxy_route = self.route_proxy_address()?;
            self.delete_proxy_route = delete_proxy_route;
            Self::setup_resolv_conf()?;
            self.add_tunnel_routes()?;

            // Signal to child that we are done setting up everything.
            if nix::unistd::write(write_to_parent, &[1])? != 1 {
                return Err("Failed to write to pipe".into());
            }
            nix::unistd::close(write_to_parent)?;

            // Now wait for the termination signals.
            let mut mask = nix::sys::signal::SigSet::empty();
            mask.add(nix::sys::signal::SIGINT);
            mask.add(nix::sys::signal::SIGTERM);
            mask.add(nix::sys::signal::SIGQUIT);
            mask.thread_block().unwrap();

            let mut fd = nix::sys::signalfd::SignalFd::new(&mask).unwrap();
            loop {
                let res = fd.read_signal().unwrap().unwrap();
                let signo = nix::sys::signal::Signal::try_from(res.ssi_signo as i32).unwrap();
                if signo == nix::sys::signal::SIGINT
                    || signo == nix::sys::signal::SIGTERM
                    || signo == nix::sys::signal::SIGQUIT
                {
                    break;
                }
            }

            self.shutdown()?;
            Ok(())
        })() {
            log::error!("{e}");
            self.shutdown().unwrap();
        };
    }

    pub fn drop_privileges(&self) -> Result<(), Error> {
        // 65534 is usually the nobody user. Even in cases it is not, it is safer to use this ID
        // than running with UID and GID 0.
        nix::unistd::setgid(nix::unistd::Gid::from_raw(65534))?;
        nix::unistd::setuid(nix::unistd::Uid::from_raw(65534))?;

        Ok(())
    }

    pub fn configure(&mut self) -> Result<(), Error> {
        log::info!(
            "[{}] Setting up network configuration",
            nix::unistd::getpid()
        );
        if nix::unistd::getuid() != 0.into() {
            return Err("Automatic setup requires root privileges".into());
        }

        if self.tunnel_bypass_addr.is_loopback() && !self.allow_private {
            log::warn!(
                "The proxy address {} is a loopback address. You may need to manually \
                provide --setup-ip to specify the server IP bypassing the tunnel",
                self.tunnel_bypass_addr
            )
        }

        let (read_from_child, write_to_parent) = nix::unistd::pipe()?;
        match fork::fork() {
            Ok(Fork::Child) => {
                prctl::set_death_signal(nix::sys::signal::SIGINT as isize).unwrap();
                self.setup_and_handle_signals(read_from_child, write_to_parent);
                std::process::exit(0);
            }
            Ok(Fork::Parent(child)) => {
                self.child = child;
                nix::unistd::close(write_to_parent)?;
                let mut buf = [0];
                if nix::unistd::read(read_from_child, &mut buf)? != 1 {
                    return Err("Failed to read from pipe".into());
                }
                nix::unistd::close(read_from_child)?;

                Ok(())
            }
            _ => Err("Failed to fork".into()),
        }
    }

    pub fn restore(&mut self) -> Result<(), Error> {
        nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(self.child),
            nix::sys::signal::SIGINT,
        )?;
        nix::sys::wait::waitpid(nix::unistd::Pid::from_raw(self.child), None)?;
        Ok(())
    }
}
