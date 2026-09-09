//! Source distribution and CMake build integration for `libddwaf`.
//!
//! This crate builds the native library but intentionally provides no Rust
//! bindings. Its build script exports `root`, `include`, and `lib` metadata for
//! an immediate dependent such as `libddwaf-sys`.

/// Version of the bundled native `libddwaf` sources.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
