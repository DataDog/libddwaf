use std::env;
use std::fs;
use std::path::{Path, PathBuf};

const UNKNOWN_GIT_COMMIT: &str = "0000000000000000000000000000000000000000";

fn main() {
    let source_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());

    verify_package_version(&source_dir);
    emit_rerun_instructions(&source_dir);

    let build_static = env::var_os("CARGO_FEATURE_STATIC").is_some();
    let build_shared = env::var_os("CARGO_FEATURE_SHARED").is_some();
    assert_ne!(
        build_static, build_shared,
        "enable exactly one of the `static` or `shared` features"
    );

    let git_commit =
        package_git_commit(&source_dir).unwrap_or_else(|| UNKNOWN_GIT_COMMIT.to_owned());
    let install_dir = cmake::Config::new(&source_dir)
        .define("CMAKE_INSTALL_INCLUDEDIR", "include")
        .define("CMAKE_INSTALL_LIBDIR", "lib")
        .define("GIT_COMMIT", git_commit)
        .define("LIBDDWAF_BUILD_SHARED", cmake_bool(build_shared))
        .define("LIBDDWAF_BUILD_STATIC", cmake_bool(build_static))
        .define("LIBDDWAF_TESTING", "OFF")
        .build();

    let include_dir = install_dir.join("include");
    let lib_dir = install_dir.join("lib");
    assert!(
        include_dir.join("ddwaf.h").is_file(),
        "libddwaf did not install ddwaf.h under {}",
        include_dir.display()
    );
    assert!(
        lib_dir.is_dir(),
        "libddwaf did not install its libraries under {}",
        lib_dir.display()
    );

    emit_link_instructions(&lib_dir, build_static);
    println!("cargo::metadata=root={}", install_dir.display());
    println!("cargo::metadata=include={}", include_dir.display());
    println!("cargo::metadata=lib={}", lib_dir.display());
    println!("cargo::metadata=static={build_static}");
    println!("cargo::metadata=shared={build_shared}");
}

fn emit_link_instructions(lib_dir: &Path, build_static: bool) {
    let target_os = env::var("CARGO_CFG_TARGET_OS").expect("Cargo did not provide target OS");
    let target_env =
        env::var("CARGO_CFG_TARGET_ENV").expect("Cargo did not provide target environment");
    let library = if build_static && target_os == "windows" && target_env == "msvc" {
        "ddwaf_static"
    } else {
        "ddwaf"
    };
    let library_kind = if build_static { "static" } else { "dylib" };

    println!("cargo::rustc-link-search=native={}", lib_dir.display());
    println!("cargo::rustc-link-lib={library_kind}={library}");

    if !build_static {
        return;
    }

    match target_os.as_str() {
        "linux" => {
            for library in ["pthread", "rt", "dl", "m"] {
                println!("cargo::rustc-link-lib=dylib={library}");
            }
        }
        "windows" => println!("cargo::rustc-link-lib=ws2_32"),
        "macos" => {}
        _ => panic!("unsupported libddwaf target OS: {target_os}"),
    }
}

fn package_git_commit(source_dir: &Path) -> Option<String> {
    let vcs_info = fs::read_to_string(source_dir.join(".cargo_vcs_info.json")).ok()?;
    let sha_prefix = "\"sha1\": \"";
    let sha_start = vcs_info.find(sha_prefix)? + sha_prefix.len();
    let sha = vcs_info.get(sha_start..sha_start + 40)?;

    sha.bytes()
        .all(|byte| byte.is_ascii_hexdigit())
        .then(|| sha.to_owned())
}

fn verify_package_version(source_dir: &Path) {
    let native_version = fs::read_to_string(source_dir.join("version"))
        .expect("failed to read the native libddwaf version");
    assert_eq!(
        native_version.trim(),
        env!("CARGO_PKG_VERSION"),
        "Cargo.toml and the native libddwaf version file disagree"
    );
}

fn emit_rerun_instructions(source_dir: &Path) {
    for path in [
        "CMakeLists.txt",
        "build.rs",
        "cmake",
        "include",
        "libddwaf.def",
        "libddwaf.version",
        "src",
        "third_party/CMakeLists.txt",
        "version",
    ] {
        println!("cargo::rerun-if-changed={path}");
    }
    if source_dir.join(".cargo_vcs_info.json").is_file() {
        println!("cargo::rerun-if-changed=.cargo_vcs_info.json");
    }
}

fn cmake_bool(value: bool) -> &'static str {
    if value {
        "ON"
    } else {
        "OFF"
    }
}
