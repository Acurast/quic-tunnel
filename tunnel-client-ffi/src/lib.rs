//! uniffi-based FFI for `tunnel-client`.
//!
//! Produces `libtunnel_client_ffi.so` (and matching iOS/desktop variants)
//! consumed by the Android `tunnel-client` library and other foreign-language
//! clients. All foreign-facing surface lives in [`ffi`].

#[cfg(any(target_os = "android", target_os = "ios"))]
uniffi::setup_scaffolding!();

#[cfg(any(target_os = "android", target_os = "ios"))]
pub mod ffi;
