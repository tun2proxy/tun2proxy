#[cfg(test)]
mod tests {
    extern crate reqwest;

    use std::env;
    use std::io::BufRead;
    use std::net::SocketAddr;
    use std::process::Command;
    use std::string::ToString;

    use fork::Fork;
    use nix::sys::signal;
    use nix::unistd::Pid;
    use serial_test::serial;

    use tun2proxy::tun2proxy::Options;
    use tun2proxy::{main_entry, Proxy, ProxyType};

    static TUN_TEST_DEVICE: &str = "tun0";
    static ALL_ROUTES: [&str; 4] = ["0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"];

    #[derive(Clone, Debug)]
    struct Test {
        proxy: Proxy,
    }

    fn proxy_from_env(env_var: &str) -> Result<Proxy, String> {
        let url =
            env::var(env_var).map_err(|_| format!("{env_var} environment variable not found"))?;
        Proxy::from_url(url.as_str()).map_err(|_| format!("{env_var} URL cannot be parsed"))
    }

    fn test_from_env(env_var: &str) -> Result<Test, String> {
        let proxy = proxy_from_env(env_var)?;
        Ok(Test { proxy })
    }

    fn tests() -> [Result<Test, String>; 2] {
        [test_from_env("SOCKS5_SERVER"), test_from_env("HTTP_SERVER")]
    }

    #[cfg(test)]
    #[ctor::ctor]
    fn init() {
        dotenvy::dotenv().ok();
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

    fn routes_setup() {
        let mut all_servers: Vec<SocketAddr> = Vec::new();

        for test in tests() {
            if test.is_err() {
                continue;
            }
            all_servers.push(test.unwrap().proxy.addr);
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
            if !default_route_args.is_empty() {
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

    fn request_ip_host_http() {
        reqwest::blocking::get("http://1.1.1.1").expect("failed to issue HTTP request");
    }

    fn request_example_https() {
        reqwest::blocking::get("https://example.org").expect("failed to issue HTTPs request");
    }

    fn run_test<F, T>(filter: F, test_function: T)
    where
        F: Fn(&Test) -> bool,
        T: Fn(),
    {
        for potential_test in tests() {
            match potential_test {
                Ok(test) => {
                    if filter(&test) {
                        continue;
                    }

                    match fork::fork() {
                        Ok(Fork::Parent(child)) => {
                            test_function();
                            signal::kill(Pid::from_raw(child), signal::SIGKILL)
                                .expect("failed to kill child");
                            nix::sys::wait::waitpid(Pid::from_raw(child), None)
                                .expect("failed to wait for child");
                        }
                        Ok(Fork::Child) => {
                            prctl::set_death_signal(signal::SIGKILL as isize).unwrap(); // 9 == SIGKILL
                            main_entry(TUN_TEST_DEVICE, test.proxy, Options::new());
                        }
                        Err(_) => panic!(),
                    }
                }
                Err(_) => {
                    continue;
                }
            }
        }
    }

    fn require_var(var: &str) {
        env::var(var).unwrap_or_else(|_| panic!("{}", "{var} environment variable required"));
    }

    #[serial]
    #[test]
    fn test_socks5() {
        require_var("SOCKS5_SERVER");
        run_test(
            |test| test.proxy.proxy_type == ProxyType::Socks5,
            request_ip_host_http,
        )
    }

    #[serial]
    #[test]
    fn test_http() {
        require_var("HTTP_SERVER");
        run_test(
            |test| test.proxy.proxy_type == ProxyType::Http,
            request_ip_host_http,
        )
    }

    #[serial]
    #[test]
    fn test_socks5_dns() {
        require_var("SOCKS5_SERVER");
        run_test(
            |test| test.proxy.proxy_type == ProxyType::Socks5,
            request_example_https,
        )
    }

    #[serial]
    #[test]
    fn test_http_dns() {
        require_var("HTTP_SERVER");
        run_test(
            |test| test.proxy.proxy_type == ProxyType::Http,
            request_example_https,
        )
    }
}
