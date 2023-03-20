#[cfg(test)]
mod tests {
    extern crate reqwest;

    use fork::Fork;
    use nix::sys::signal;
    use nix::unistd::Pid;
    use std::env;
    use std::io::BufRead;
    use std::net::{SocketAddr, ToSocketAddrs};
    use std::process::Command;
    use std::string::ToString;
    use tun2proxy::{main_entry, ProxyType};

    static TUN_TEST_DEVICE: &str = "tun0";
    static ALL_ROUTES: [&str; 4] = ["0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"];

    #[derive(Clone, Copy)]
    struct Test {
        env: &'static str,
        proxy_type: ProxyType,
    }

    static TESTS: [Test; 2] = [
        Test {
            env: "SOCKS5_SERVER",
            proxy_type: ProxyType::Socks5,
        },
        Test {
            env: "HTTP_SERVER",
            proxy_type: ProxyType::Http,
        },
    ];

    #[cfg(test)]
    #[ctor::ctor]
    fn init() {
        routes_setup();
    }

    #[cfg(test)]
    #[ctor::dtor]
    fn cleanup() {
        Command::new("ip")
            .args(["link", "del", TUN_TEST_DEVICE])
            .output()
            .expect("failed to delete tun device");
    }

    fn parse_server_addr(string: String) -> SocketAddr {
        return string.to_socket_addrs().unwrap().next().unwrap();
    }

    fn routes_setup() {
        let mut all_servers: Vec<SocketAddr> = Vec::new();

        for test in TESTS {
            if let Ok(server) = env::var(test.env) {
                all_servers.push(parse_server_addr(server));
            }
        }

        Command::new("ip")
            .args(["tuntap", "add", "name", TUN_TEST_DEVICE, "mode", "tun"])
            .output()
            .expect("failed to create tun device");

        Command::new("ip")
            .args(["link", "set", TUN_TEST_DEVICE, "up"])
            .output()
            .expect("failed to bring up tun device");

        let routes = Command::new("ip")
            .args(["route", "show"])
            .output()
            .expect("failed to get routing table");

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
            if default_route_args.len() > 0 {
                break;
            }
        }

        for server in all_servers {
            let mut proxy_route = vec!["route".to_string(), "add".to_string()];
            proxy_route.push(server.ip().to_string());
            proxy_route.extend(default_route_args.clone());
            Command::new("ip")
                .args(proxy_route)
                .output()
                .expect("failed to get routing table");
        }

        for route in ALL_ROUTES {
            Command::new("ip")
                .args(["route", "add", route, "dev", TUN_TEST_DEVICE])
                .output()
                .expect("failed to add route");
        }
    }

    fn run_test<F>(filter: F)
    where
        F: Fn(&Test) -> bool,
    {
        for test in TESTS {
            if !filter(&test) {
                continue;
            }
            let env_var = env::var(test.env).expect(
                format!(
                    "this test requires the {} environment variable to be set",
                    test.env
                )
                .as_str(),
            );
            let address = parse_server_addr(env_var);

            match fork::fork() {
                Ok(Fork::Parent(child)) => {
                    reqwest::blocking::get("https://1.1.1.1")
                        .expect("failed to issue HTTP request");
                    signal::kill(Pid::from_raw(child), signal::SIGKILL)
                        .expect("failed to kill child");
                    nix::sys::wait::waitpid(Pid::from_raw(child), None)
                        .expect("failed to wait for child");
                }
                Ok(Fork::Child) => {
                    prctl::set_death_signal(signal::SIGKILL as isize).unwrap(); // 9 == SIGKILL
                    main_entry(TUN_TEST_DEVICE, address, ProxyType::Socks5);
                }
                Err(_) => assert!(false),
            }
        }
    }

    #[test]
    fn test_socks5() {
        run_test(|test| test.proxy_type == ProxyType::Socks5)
    }

    #[test]
    fn test_http() {
        run_test(|test| test.proxy_type == ProxyType::Http)
    }
}
