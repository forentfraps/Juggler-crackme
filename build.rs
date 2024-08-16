use std::env;
use std::path::PathBuf;
use std::process::Command;
// extern crate embed_resource;

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
    Command::new("c_aes/make_microsoft_no_crt.bat")
        .status()
        .unwrap();
    Command::new("c_verification/make_microsoft_no_crt.bat")
        .status()
        .unwrap();
    /*    embed_resource::compile("c_aes/res1.rc");
    embed_resource::compile("c_verification/res2.rc"); */
    println!("cargo:rustc-link-lib=static=tricks");

    // Tell cargo to invalidate the built crate whenever the assembly file changes
    println!("cargo:rerun-if-changed=asm/tricks.asm");
    println!("cargo:rerun-if-changed=c_aes/aes_dll.c");
    println!("cargo:rerun-if-changed=c_verification/verification.c");
    /*println!("cargo:rerun-if-changed=c_verification/res2.rc");
    println!("cargo:rerun-if-changed=c_aes/res1.rc");*/
}
