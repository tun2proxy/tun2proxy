#![cfg(target_os = "android")]

use crate::{error::Error, main_entry, shutdown, NetworkInterface, Options, Proxy};
use jni::{
    objects::{JClass, JString},
    sys::{jboolean, jint},
    JNIEnv,
};

/// # Safety
///
/// Running tun2proxy
#[no_mangle]
pub unsafe extern "C" fn Java_com_github_shadowsocks_bg_Tun2proxy_run(
    mut env: JNIEnv,
    _clazz: JClass,
    proxy_url: JString,
    tun_fd: jint,
    tun_mtu: jint,
    verbose: jboolean,
) -> jint {
    let log_level = if verbose != 0 { "trace" } else { "info" };
    let filter_str = &format!("off,tun2proxy={log_level}");
    let filter = android_logger::FilterBuilder::new()
        .parse(filter_str)
        .build();
    android_logger::init_once(
        android_logger::Config::default()
            .with_tag("tun2proxy")
            .with_max_level(log::LevelFilter::Trace)
            .with_filter(filter),
    );

    let mut block = || -> Result<(), Error> {
        let proxy_url = get_java_string(&mut env, &proxy_url)?;
        let proxy = Proxy::from_url(proxy_url)?;

        let addr = proxy.addr;
        let proxy_type = proxy.proxy_type;
        log::info!("Proxy {proxy_type} server: {addr}");

        let options = Options::new().with_virtual_dns().with_mtu(tun_mtu as usize);

        let interface = NetworkInterface::Fd(tun_fd);
        _ = main_entry(&interface, &proxy, options)?;
        Ok::<(), Error>(())
    };
    if let Err(error) = block() {
        log::error!("failed to run tun2proxy with error: {:?}", error);
    }
    0
}

/// # Safety
///
/// Shutdown tun2proxy
#[no_mangle]
pub unsafe extern "C" fn Java_com_github_shadowsocks_bg_Tun2proxy_stop(
    _env: JNIEnv,
    _clazz: JClass,
) -> jint {
    if let Err(e) = shutdown() {
        log::error!("failed to shutdown tun2proxy with error: {:?}", e);
        1
    } else {
        0
    }
}

unsafe fn get_java_string<'a>(env: &'a mut JNIEnv, string: &'a JString) -> Result<&'a str, Error> {
    let str_ptr = env.get_string(string)?.as_ptr();
    let s: &str = std::ffi::CStr::from_ptr(str_ptr).to_str()?;
    Ok(s)
}
