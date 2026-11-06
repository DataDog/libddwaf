use std::ffi::{c_char, CStr};

unsafe extern "C" {
    fn ddwaf_get_version() -> *const c_char;
}

fn main() {
    let version = unsafe {
        let version = ddwaf_get_version();
        assert!(!version.is_null());
        CStr::from_ptr(version)
    };

    assert_eq!(version.to_bytes(), libddwaf_src::VERSION.as_bytes());
    println!("libddwaf version: {}", version.to_string_lossy());
}
