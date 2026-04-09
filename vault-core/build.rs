//! Build script for vault-core
//!
//! Generates C header bindings using cbindgen when the FFI feature is enabled.

fn main() {
    // Only generate C bindings when FFI feature is enabled
    #[cfg(feature = "ffi")]
    {
        use std::env;
        use std::path::PathBuf;

        let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
        let out_dir = PathBuf::from(&crate_dir).join("bindings");

        // Ensure bindings directory exists
        std::fs::create_dir_all(&out_dir).expect("Failed to create bindings directory");

        let config = cbindgen::Config::from_file("cbindgen.toml")
            .expect("Failed to read cbindgen.toml");

        cbindgen::Builder::new()
            .with_crate(&crate_dir)
            .with_config(config)
            .generate()
            .expect("Failed to generate C bindings")
            .write_to_file(out_dir.join("vault-core.h"));

        println!("cargo:rerun-if-changed=src/");
        println!("cargo:rerun-if-changed=cbindgen.toml");
    }

    // Link to system libraries on Windows for Sequoia CNG backend
    #[cfg(windows)]
    {
        println!("cargo:rustc-link-lib=bcrypt");
        println!("cargo:rustc-link-lib=ncrypt");
    }
}
