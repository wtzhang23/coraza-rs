use std::path::PathBuf;

fn main() {
    let crate_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let go = PathBuf::from(std::env::var("GO").unwrap_or("go".to_string()));

    println!("cargo:rerun-if-changed=go/libcoraza/libcoraza/go.mod");
    println!("cargo:rerun-if-changed=go/libcoraza/libcoraza/go.sum");
    println!("cargo:rerun-if-changed=go/libcoraza/libcoraza/coraza.go");
    println!("cargo:rerun-if-changed=go/libcoraza/libcoraza/log.go");
    println!("cargo:rerun-if-changed=go/libcoraza/libcoraza/libcoraza_types.h");

    let build_dir = out_dir.join("build");
    let src_dir = crate_dir.join("go/libcoraza").canonicalize().unwrap();

    // clean build directory
    std::fs::remove_dir_all(&build_dir).unwrap_or_else(|e| {
        println!("Failed to clean build directory: {}", e);
    });
    std::fs::create_dir_all(&build_dir).unwrap();

    // build headers
    let status = std::process::Command::new(&go)
        .current_dir(&build_dir)
        .arg("tool")
        .arg("cgo")
        .arg("-exportheader")
        .arg(build_dir.join("coraza.h"))
        .arg(src_dir.join("libcoraza/coraza.go"))
        .arg(src_dir.join("libcoraza/log.go"))
        .status()
        .expect("Failed to build headers");
    if !status.success() {
        panic!("Failed to build headers");
    }

    // build coraza
    let status = std::process::Command::new(&go)
        .current_dir(&build_dir)
        .arg("build")
        .arg("-buildmode=c-archive")
        .arg("-o")
        .arg(build_dir.join("libcoraza.a"))
        .arg(src_dir.join("libcoraza/coraza.go"))
        .arg(src_dir.join("libcoraza/log.go"))
        .status()
        .expect("Failed to build coraza");
    if !status.success() {
        panic!("Failed to build coraza");
    }

    // generate bindings
    let bindings = bindgen::Builder::default()
        .header(build_dir.join("coraza.h").to_string_lossy())
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .allowlist_function("coraza_.*")
        .allowlist_type("coraza_.*")
        .allowlist_var("coraza_.*")
        .derive_debug(true)
        .derive_default(true)
        .derive_eq(true)
        .derive_copy(true)
        .derive_ord(true)
        .derive_partialeq(true)
        .derive_partialord(true)
        .derive_hash(true)
        .rustified_enum("coraza_debug_log_level_t")
        .rustified_enum("coraza_severity_t")
        .generate()
        .expect("Unable to generate bindings");
    let out_path = out_dir.join("bindings.rs");
    bindings
        .write_to_file(out_path)
        .expect("Couldn't write bindings!");

    // link
    println!("cargo:rustc-link-search=native={}", build_dir.display());
    println!("cargo:rustc-link-lib=static=coraza");
}
