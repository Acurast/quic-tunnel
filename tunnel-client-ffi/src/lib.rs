//! uniffi-based FFI for `tunnel-client`.
//!
//! Produces `libtunnel_client_ffi.so` (and matching iOS/desktop variants)
//! consumed by the Android `tunnel-client` library and other foreign-language
//! clients. All foreign-facing surface lives in [`ffi`].

#[cfg(any(target_os = "android", target_os = "ios"))]
uniffi::setup_scaffolding!();

#[cfg(any(target_os = "android", target_os = "ios"))]
pub mod ffi;

/// JNI entry point that initializes `rustls-platform-verifier` with the
/// hosting Android app's `Context`. Must be invoked once before any tunnel
/// operation; both `instant-acme` (HTTPS to Let's Encrypt) and `quinn`
/// (relay TLS) drive cert validation through the platform verifier, which
/// panics on first use otherwise.
///
/// Called from the Kotlin wrapper (e.g. `TunnelClient.initAndroid(context)`).
#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_acurast_tunnel_TunnelClient_initAndroid(
    mut env: jni::JNIEnv,
    _class: jni::objects::JClass,
    context: jni::objects::JObject,
) {
    android_logger::init_once(
        android_logger::Config::default()
            .with_max_level(log::LevelFilter::Debug)
            .with_tag("tunnel_client_ffi")
            // Wide-open module filter so transitive crates (hyper, quinn,
            // instant-acme, rustls, tunnel_client) also emit through logcat.
            .with_filter(
                android_logger::FilterBuilder::new()
                    .parse("debug")
                    .build(),
            ),
    );
    // Force-set the log crate's max level after init_once. android_logger only
    // sets it when it actually installs the logger (first call); a no-op call
    // would otherwise leave the runtime filter at its previous value.
    log::set_max_level(log::LevelFilter::Debug);
    log::info!("tunnel-client-ffi: logger initialized");

    if let Err(e) = rustls_platform_verifier::android::init_with_env(&mut env, context) {
        log::error!("rustls-platform-verifier init failed: {e}");
    } else {
        log::info!("rustls-platform-verifier: initialized");
    }
}
