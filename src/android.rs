#![cfg(target_os = "android")]

use crate::{
    args::{ArgDns, ArgProxy},
    error::{Error, Result},
    ArgVerbosity, Args,
};
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
    dns_over_tcp: jboolean,
) -> jint {
    let dns = if dns_over_tcp != 0 { ArgDns::OverTcp } else { ArgDns::Direct };
    let verbosity = if verbose != 0 { ArgVerbosity::Trace } else { ArgVerbosity::Info };
    let filter_str = &format!("off,tun2proxy={verbosity}");
    let filter = android_logger::FilterBuilder::new().parse(filter_str).build();
    android_logger::init_once(
        android_logger::Config::default()
            .with_tag("tun2proxy")
            .with_max_level(log::LevelFilter::Trace)
            .with_filter(filter),
    );
    let proxy_url = get_java_string(&mut env, &proxy_url).unwrap();
    let proxy = ArgProxy::from_url(proxy_url).unwrap();

    let args = Args::new(Some(tun_fd), proxy, dns, verbosity);
    crate::api::tun2proxy_internal_run(args, tun_mtu as _)
}

/// # Safety
///
/// Shutdown tun2proxy
#[no_mangle]
pub unsafe extern "C" fn Java_com_github_shadowsocks_bg_Tun2proxy_stop(_env: JNIEnv, _: JClass) -> jint {
    crate::api::tun2proxy_internal_stop()
}

unsafe fn get_java_string<'a>(env: &'a mut JNIEnv, string: &'a JString) -> Result<&'a str, Error> {
    let str_ptr = env.get_string(string)?.as_ptr();
    let s: &str = std::ffi::CStr::from_ptr(str_ptr).to_str()?;
    Ok(s)
}
