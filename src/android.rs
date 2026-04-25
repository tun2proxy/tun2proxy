#![cfg(target_os = "android")]

use crate::{
    Args,
    args::ArgProxy,
    error::{Error, Result},
};
use jni::{
    Env, EnvUnowned,
    objects::{JClass, JString},
    sys::{jboolean, jchar, jint},
};

/// # Safety
///
/// Running tun2proxy with some arguments
/// Parameters:
/// - proxy_url: the proxy url, e.g. "socks5://127.0.0.1:1080"
/// - tun_fd: the tun file descriptor, it will be owned by tun2proxy
/// - close_fd_on_drop: whether close the tun_fd on drop
/// - tun_mtu: the tun mtu
/// - dns_strategy: the dns strategy, see ArgDns enum
/// - verbosity: the verbosity level, see ArgVerbosity enum
/// - udpgw_server: optional udpgw server address (e.g. "198.18.0.1:7300"),
///   empty string to disable. When set, UDP packets are forwarded via the
///   udpgw protocol through a TCP connection to this address.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_com_github_shadowsocks_bg_Tun2proxy_run(
    mut env: EnvUnowned<'_>,
    _clazz: JClass<'_>,
    proxy_url: JString<'_>,
    tun_fd: jint,
    close_fd_on_drop: jboolean,
    tun_mtu: jchar,
    verbosity: jint,
    dns_strategy: jint,
    udpgw_server: JString<'_>,
) -> jint {
    let dns = dns_strategy.try_into().unwrap();
    let verbosity = verbosity.try_into().unwrap();
    let filter_str = &format!("off,tun2proxy={verbosity}");
    let filter = android_logger::FilterBuilder::new().parse(filter_str).build();
    android_logger::init_once(
        android_logger::Config::default()
            .with_tag("tun2proxy")
            .with_max_level(log::LevelFilter::Trace)
            .with_filter(filter),
    );
    env.with_env(|env: &mut Env| -> Result<jint> {
        let proxy_url = get_java_string(env, &proxy_url).unwrap();
        let proxy = ArgProxy::try_from(proxy_url.as_str()).unwrap();

        let mut args = Args::default();
        args.proxy(proxy)
            .tun_fd(Some(tun_fd))
            .close_fd_on_drop(close_fd_on_drop)
            .dns(dns)
            .verbosity(verbosity);

        #[cfg(feature = "udpgw")]
        {
            let udpgw_str = get_java_string(env, &udpgw_server).unwrap_or_default();
            if !udpgw_str.is_empty() {
                if let Ok(addr) = udpgw_str.parse::<std::net::SocketAddr>() {
                    args.udpgw_server(addr);
                    log::info!("udpgw_server={}", addr);
                }
            }
        }

        let v = crate::general_api::general_run_for_api(args, tun_mtu, false);
        Ok::<jint, Error>(v)
    })
    .resolve::<jni::errors::LogErrorAndDefault>()
}

/// # Safety
///
/// Shutdown tun2proxy
#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_com_github_shadowsocks_bg_Tun2proxy_stop(_env: EnvUnowned<'_>, _: JClass<'_>) -> jint {
    crate::general_api::tun2proxy_stop_internal()
}

fn get_java_string(env: &Env, string: &JString) -> Result<String, Error> {
    string.try_to_string(env).map_err(|e| e.into())
}
