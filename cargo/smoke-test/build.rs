use std::env;

fn main() {
    let lib_dir = env::var("DEP_DDWAF_SRC_LIB")
        .expect("libddwaf-src did not export its native library directory");
    assert_eq!(
        env::var("DEP_DDWAF_SRC_STATIC").as_deref(),
        Ok("true"),
        "the smoke test expects a static libddwaf build"
    );

    let target = env::var("TARGET").expect("Cargo did not provide TARGET");
    let (library, uses_gnu_abi) = if target.contains("-linux-") {
        ("ddwaf", true)
    } else if target.contains("-apple-") {
        ("ddwaf", false)
    } else if target.ends_with("-windows-msvc") {
        ("ddwaf_static", false)
    } else if target.ends_with("-windows-gnu") {
        ("ddwaf", true)
    } else {
        panic!("unsupported smoke-test target: {target}");
    };
    println!("cargo::rustc-link-search=native={lib_dir}");
    println!("cargo::rustc-link-lib=static={library}");

    if target.contains("-linux-") {
        for library in ["stdc++", "pthread", "rt", "dl", "m"] {
            println!("cargo::rustc-link-lib=dylib={library}");
        }
    } else if target.contains("-apple-") {
        println!("cargo::rustc-link-lib=dylib=c++");
    } else if uses_gnu_abi {
        println!("cargo::rustc-link-lib=c++");
    }
    if target.contains("-windows-") {
        println!("cargo::rustc-link-lib=ws2_32"); // for inet_pton()
    }
}
