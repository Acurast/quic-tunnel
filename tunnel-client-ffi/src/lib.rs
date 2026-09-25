//! uniffi-based FFI for `tunnel-client`.
//!
//! Produces `libtunnel_client_ffi.so` (and matching iOS/desktop variants)
//! consumed by the Android `tunnel-client` library and other foreign-language
//! clients. All foreign-facing surface lives in [`ffi`].

// `test` joins the list so the foreign surface can be unit-tested on the host.
#[cfg(any(target_os = "android", target_os = "ios", test))]
uniffi::setup_scaffolding!();

#[cfg(any(target_os = "android", target_os = "ios", test))]
pub mod ffi;

/// JNI entry point that wires `android_logger` to logcat; invoke once before
/// any tunnel operation. `filter_spec` is an env_logger-style filter string
/// (e.g. `"tunnel_client=trace,hyper=info"`), falling back to `"info"`.
#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_acurast_tunnel_TunnelClient_initAndroid(
    mut env: jni::JNIEnv,
    _class: jni::objects::JClass,
    filter_spec: jni::objects::JString,
) {
    let spec: String = env
        .get_string(&filter_spec)
        .map(|s| s.into())
        .unwrap_or_else(|_| "info".to_string());

    let max_level = max_level_from_filter_spec(&spec).unwrap_or(log::LevelFilter::Info);

    android_logger::init_once(
        android_logger::Config::default()
            .with_max_level(max_level)
            .with_tag("tunnel_client_ffi")
            // env_logger-style spec, so transitive crates can be throttled individually.
            .with_filter(android_logger::FilterBuilder::new().parse(&spec).build()),
    );
    // android_logger only sets this when it actually installs the logger.
    log::set_max_level(max_level);
    log::info!(
        "tunnel-client-ffi: logger initialized (filter={}, max_level={:?})",
        spec,
        max_level
    );
}

/// Most verbose level mentioned in an env_logger-style filter, or `None` if it
/// names no recognisable level.
#[cfg(target_os = "android")]
fn max_level_from_filter_spec(spec: &str) -> Option<log::LevelFilter> {
    use log::LevelFilter::*;
    let parse = |s: &str| match s.trim().to_ascii_lowercase().as_str() {
        "off" => Some(Off),
        "error" => Some(Error),
        "warn" => Some(Warn),
        "info" => Some(Info),
        "debug" => Some(Debug),
        "trace" => Some(Trace),
        _ => None,
    };
    let mut max = Off;
    for part in spec.split(',') {
        let level_str = part.rsplit('=').next().unwrap_or(part);
        if let Some(level) = parse(level_str) {
            if level > max {
                max = level;
            }
        }
    }
    if max == Off { None } else { Some(max) }
}
