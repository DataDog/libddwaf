use std::ffi::CStr;
use std::os::raw::c_char;

#[no_mangle]
pub extern "C" fn check_string(c_string: *const c_char) -> bool {
    let c_str = unsafe {
        assert!(!c_string.is_null());
        CStr::from_ptr(c_string)
    };

    c_str.to_str().unwrap() == "/etc/passwd"
}
