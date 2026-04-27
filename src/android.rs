#![cfg(target_os = "android")]

use crate::{
    Args,
    error::{Error, Result},
};
use jni::{
    Env, EnvUnowned,
    objects::{JClass, JString},
    sys::{jchar, jint},
};

/// # Safety
///
/// Running tun2proxy with some arguments
/// Parameters:
/// - cli_args: The command line arguments,
///   e.g. `tun2proxy-bin --tun-fd 43 --close-fd-on-drop false --proxy socks5://127.0.0.1:1080 --dns over-tcp --verbosity trace`
/// - tun_mtu: The MTU of the TUN device, e.g. 1500
#[unsafe(no_mangle)]
pub unsafe extern "C" fn Java_com_github_shadowsocks_bg_Tun2proxy_run(
    mut env: EnvUnowned<'_>,
    _clazz: JClass<'_>,
    cli_args: JString<'_>,
    tun_mtu: jchar,
) -> jint {
    env.with_env(|env: &mut Env| -> Result<jint> {
        let cli_args = get_java_string(env, &cli_args)?;
        let tokens = shlex::split(&cli_args).ok_or_else(|| Error::from("Failed to split CLI args"))?;
        let tokens_clone = tokens.clone();
        let args = <Args as ::clap::Parser>::try_parse_from(tokens).map_err(|err| Error::from(format!("Parse CLI args: {err}")))?;

        let filter_str = format!("off,tun2proxy={}", args.verbosity);
        let filter = android_logger::FilterBuilder::new().parse(&filter_str).build();
        android_logger::init_once(
            android_logger::Config::default()
                .with_tag("tun2proxy")
                .with_max_level(log::LevelFilter::Trace)
                .with_filter(filter),
        );

        if !tokens_clone
            .iter()
            .any(|token| token == "--dns" || token.starts_with("--dns=") || token == "-d" || token.starts_with("-d"))
        {
            log::error!("--dns is required for Android");
            return Err(Error::from("--dns is required for Android"));
        }

        if args.tun_fd.is_none() {
            log::error!("tun_fd is required for Android");
            return Err(Error::from("tun_fd is required for Android"));
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
