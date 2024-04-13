mod asm_macros;
mod winapi_cs;

use std::arch::asm;
use std::collections::HashSet;
use std::io;
use std::ptr::{null_mut, read_volatile, write_volatile};
use std::sync::atomic::{compiler_fence, Ordering};
use std::time::Duration;
use winapi::shared::basetsd::SIZE_T;
use winapi::shared::minwindef::{BYTE, DWORD, HMODULE, HRSRC__, LPARAM};
use winapi::shared::ntdef::{LPCSTR, PVOID};
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::libloaderapi::{
    FindResourceExW, GetModuleHandleW, GetProcAddress, LoadResource, LockResource, SizeofResource,
};
use winapi::um::winbase::EnumResourceNamesA;
use winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PAGE_READWRITE};
use winapi::um::winuser::{MAKEINTRESOURCEW, RT_RCDATA};
use winapi_cs::core::*;

use crate::winapi_cs::reflective_dll::*;
fn decoy(data: &mut i32) {
    unsafe {
        let temp = core::ptr::read_volatile(data);
        core::ptr::write_volatile(data, temp);
    }
}
unsafe extern "system" fn enum_names_proc(
    _h_module: HMODULE,
    _lpsz_type: LPCSTR,
    lpsz_name: *mut i8,
    _l_param: LPARAM,
) -> winapi::shared::minwindef::BOOL {
    println!("Resource Name: {:?}", lpsz_name);
    true.into()
}

unsafe extern "system" fn enum_types_proc(
    h_module: HMODULE,
    lpsz_type: *mut i8,
    l_param: LPARAM,
) -> winapi::shared::minwindef::BOOL {
    EnumResourceNamesA(h_module, lpsz_type, Some(enum_names_proc), l_param);
    true.into()
}
fn sieve_of_eratosthenes(n: usize) -> HashSet<usize> {
    let mut primes = vec![true; n + 1];
    let mut result = HashSet::new();

    for p in 2..=n {
        if primes[p] {
            result.insert(p);
            let mut multiple = p * p;
            while multiple <= n {
                primes[multiple] = false;
                multiple += p;
            }
        }
    }
    result
}

type pVirtualAlloc = fn(PVOID, SIZE_T, DWORD, DWORD) -> *mut BYTE;
type pVirtualProtect = fn(PVOID, SIZE_T, DWORD, *mut DWORD) -> bool;
fn main() {
    let mut user_input = String::new();
    match io::stdin().read_line(&mut user_input) {
        Ok(_) => (),
        Err(e) => println!("Error reading from stdin {:?}", e),
    }
    let (_ntdllstrw, pntdllstrw) =
        string_to_lpcwstr(String::from("C:\\Windows\\System32\\ntdll.dll"));
    let (_ker32strw, pker32strw) =
        string_to_lpcwstr(String::from("C:\\Windows\\System32\\kernel32.dll"));
    let (_virtAllocStr, pvirtAllocStr) = string_to_lpcstr(String::from("VirtualAlloc"));
    let (_virtProtStr, pvirtProtStr) = string_to_lpcstr(String::from("VirtualProtect"));
    let (_DBreakStr, pDBreakStr) = string_to_lpcstr(String::from("DbgBreakPoint"));
    let (_DRemoteStr, pDRemoteStr) = string_to_lpcstr(String::from("RtlUserThreadStart"));
    let (_userStr, puserStr) = string_to_lpcstr(user_input);
    unsafe {
        //hide!();
        let _ntdll: HMODULE = GetModuleHandle(pntdllstrw).unwrap();
        let _kernel32: HMODULE = GetModuleHandle(pker32strw).unwrap();
        let aes_ptr = include_bytes!("../c_aes/aes_dll_nocrt.dll");
        let VirtualProtect: pVirtualProtect = GetProcAddress_(_kernel32, pvirtProtStr).unwrap();
        let VirtualAlloc: pVirtualAlloc = GetProcAddress_(_kernel32, pvirtAllocStr).unwrap();

        let mut status: *mut u64 = GetProcAddress_(_ntdll, pDBreakStr).unwrap();
        let mut workAddress: *mut *const u8 = GetProcAddress_(_ntdll, pDRemoteStr).unwrap();
        let verif_data_sec = include_bytes!("../c_verification/mod2.dll.enc");
        let mut _oldProtect: DWORD = 0;
        VirtualProtect(
            status as PVOID,
            8,
            PAGE_EXECUTE_READWRITE,
            &mut _oldProtect as *mut u32,
        );
        VirtualProtect(
            workAddress as PVOID,
            8,
            PAGE_EXECUTE_READWRITE,
            &mut _oldProtect as *mut u32,
        );
        VirtualProtect(
            verif_data_sec.as_ptr() as PVOID,
            verif_data_sec.len(),
            PAGE_READWRITE,
            &mut _oldProtect as *mut u32,
        );
        ReflectiveLoadDll(aes_ptr.as_ptr() as *mut u8);
        *status = 0;
        compiler_fence(Ordering::SeqCst);
        for i in 0..(verif_data_sec.len() / 16) {
            println!("{}", i);
            *workAddress = verif_data_sec.as_ptr().offset(i as isize * 16);
            *status = 1;
            while read_volatile(status) == 1 {}
        }
        compiler_fence(Ordering::SeqCst);
        *workAddress = puserStr as *const u8;
        println!("Ended decryption");
        ReflectiveLoadDll(verif_data_sec.as_ptr() as *mut u8);
        //hide!();
    }
}
