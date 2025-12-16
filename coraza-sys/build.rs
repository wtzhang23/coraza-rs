use std::path::PathBuf;

fn main() {
    let dst = autotools::Config::new("libcoraza")
        .reconf("--install")
        .make_target("all")
        .build();
    println!(
        "cargo:rustc-link-search=native={}",
        dst.join("build").display()
    );
    println!("cargo:rustc-link-lib=static=coraza");

    let header = dst.join("build/coraza/coraza.h");
    let bindings = bindgen::Builder::default()
        .header(header.to_string_lossy())
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .allowlist_function("coraza_.*")
        .allowlist_type("coraza_.*")
        .allowlist_var("coraza_.*")
        .generate()
        .expect("Unable to generate bindings");
    let out_path = PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("bindings.rs");
    bindings
        .write_to_file(out_path)
        .expect("Couldn't write bindings!");
}
