mod asm_macros;
mod winapi_cs;
use std::arch::asm;

use winapi::shared::minwindef::{BYTE, DWORD, HMODULE, ULONG, WORD};
use winapi::shared::ntdef::{LPCSTR, LPCWSTR, PVOID, ULONGLONG, UNICODE_STRING};
use winapi_cs::core::*;

type func = fn() -> ();

fn main() {
    let s = String::from("C:\\Windows\\System32\\ntdll.dll");
    let (_s2, ps2) = string_to_lpcstr(String::from("DbgBreakPoint"));
    let (_ws, pws) = string_to_lpcwstr(s);
    unsafe {
        //hide!();
        let ntdll: HMODULE = GetModuleHandle(pws).unwrap();
        //hide!();
        let f_ptr: func = GetProcAddress(ntdll, ps2).unwrap();
        f_ptr();
    }
    println!("Hello, world!");
}
