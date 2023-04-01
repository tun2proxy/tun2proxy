#[cfg(test)]
mod tests {
    extern crate reqwest;

    use std::env;

    use fork::Fork;
    use nix::sys::signal;
    use nix::unistd::Pid;
    use serial_test::serial;

    use tun2proxy::setup::{get_default_cidrs, Setup};
    use tun2proxy::{main_entry, Options, Proxy, ProxyType};

    #[derive(Clone, Debug)]
    struct Test {
        proxy: Proxy,
    }

    static TUN_TEST_DEVICE: &str = "tun0";

    fn proxy_from_env(env_var: &str) -> Result<Proxy, String> {
        let url =
            env::var(env_var).map_err(|_| format!("{env_var} environment variable not found"))?;
        Proxy::from_url(url.as_str()).map_err(|_| format!("{env_var} URL cannot be parsed"))
    }

    fn test_from_env(env_var: &str) -> Result<Test, String> {
        let proxy = proxy_from_env(env_var)?;
        Ok(Test { proxy })
    }

    fn tests() -> [Result<Test, String>; 3] {
        [
            test_from_env("SOCKS4_SERVER"),
            test_from_env("SOCKS5_SERVER"),
            test_from_env("HTTP_SERVER"),
        ]
    }

    #[cfg(test)]
    #[ctor::ctor]
    fn init() {
        dotenvy::dotenv().ok();
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
                    if !filter(&test) {
                        continue;
                    }

                    let mut setup = Setup::new(
                        TUN_TEST_DEVICE,
                        &test.proxy.addr.ip(),
                        get_default_cidrs(),
                        false,
                    );
                    setup.configure().unwrap();

                    match fork::fork() {
                        Ok(Fork::Parent(child)) => {
                            test_function();
                            signal::kill(Pid::from_raw(child), signal::SIGINT)
                                .expect("failed to kill child");
                            setup.restore().unwrap();
                        }
                        Ok(Fork::Child) => {
                            prctl::set_death_signal(signal::SIGINT as isize).unwrap();
                            let _ = main_entry(
                                TUN_TEST_DEVICE,
                                &test.proxy,
                                Options::new().with_virtual_dns(),
                            );
                            std::process::exit(0);
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
        env::var(var).unwrap_or_else(|_| panic!("{} environment variable required", var));
    }

    #[serial]
    #[test_log::test]
    fn test_socks4() {
        require_var("SOCKS4_SERVER");
        run_test(
            |test| test.proxy.proxy_type == ProxyType::Socks4,
            request_ip_host_http,
        )
    }

    #[serial]
    #[test_log::test]
    fn test_socks5() {
        require_var("SOCKS5_SERVER");
        run_test(
            |test| test.proxy.proxy_type == ProxyType::Socks5,
            request_ip_host_http,
        )
    }

    #[serial]
    #[test_log::test]
    fn test_http() {
        require_var("HTTP_SERVER");
        run_test(
            |test| test.proxy.proxy_type == ProxyType::Http,
            request_ip_host_http,
        )
    }

    #[serial]
    #[test_log::test]
    fn test_socks4_dns() {
        require_var("SOCKS4_SERVER");
        run_test(
            |test| test.proxy.proxy_type == ProxyType::Socks4,
            request_example_https,
        )
    }

    #[serial]
    #[test_log::test]
    fn test_socks5_dns() {
        require_var("SOCKS5_SERVER");
        run_test(
            |test| test.proxy.proxy_type == ProxyType::Socks5,
            request_example_https,
        )
    }

    #[serial]
    #[test_log::test]
    fn test_http_dns() {
        require_var("HTTP_SERVER");
        run_test(
            |test| test.proxy.proxy_type == ProxyType::Http,
            request_example_https,
        )
    }
}
