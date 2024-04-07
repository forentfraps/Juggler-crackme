use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let asm_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("asm");

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    Command::new("nasm")
        .arg("-f")
        .arg("win64")
        .args(&[asm_dir.join("tricks.asm").to_str().unwrap(), "-o"])
        .arg(out_dir.join("tricks.o").to_str().unwrap())
        .status()
        .unwrap();
    Command::new("lib")
        .args(&["/OUT:tricks.lib", "tricks.o"])
        .current_dir(&out_dir)
        .status()
        .unwrap();
    // Tell cargo to tell rustc to link the object file
    println!(
        "cargo:rustc-link-search=native={}",
        out_dir.to_str().unwrap()
    );
    println!("cargo:rustc-link-lib=static=tricks");

    // Tell cargo to invalidate the built crate whenever the assembly file changes
    println!("cargo:rerun-if-changed=asm/tricks.asm");
}
