#![cfg(target_os = "android")]

use crate::{
    args::ArgProxy,
    error::{Error, Result},
    Args,
};
use jni::{
    objects::{JClass, JString},
    sys::{jboolean, jchar, jint},
    JNIEnv,
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
#[no_mangle]
pub unsafe extern "C" fn Java_com_github_shadowsocks_bg_Tun2proxy_run(
    mut env: JNIEnv,
    _clazz: JClass,
    proxy_url: JString,
    tun_fd: jint,
    close_fd_on_drop: jboolean,
    tun_mtu: jchar,
    verbosity: jint,
    dns_strategy: jint,
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
    let proxy_url = get_java_string(&mut env, &proxy_url).unwrap();
    let proxy = ArgProxy::try_from(proxy_url.as_str()).unwrap();
    let close_fd_on_drop = close_fd_on_drop != 0;

    let mut args = Args::default();
    args.proxy(proxy)
        .tun_fd(Some(tun_fd))
        .close_fd_on_drop(close_fd_on_drop)
        .dns(dns)
        .verbosity(verbosity);
    crate::general_api::general_run_for_api(args, tun_mtu, false)
}

/// # Safety
///
/// Shutdown tun2proxy
#[no_mangle]
pub unsafe extern "C" fn Java_com_github_shadowsocks_bg_Tun2proxy_stop(_env: JNIEnv, _: JClass) -> jint {
    crate::general_api::tun2proxy_stop_internal()
}

fn get_java_string(env: &mut JNIEnv, string: &JString) -> Result<String, Error> {
    Ok(env.get_string(string)?.into())
}
