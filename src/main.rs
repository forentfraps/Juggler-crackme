mod asm_macros;
mod winapi_cs;

use std::arch::asm;
use std::collections::HashSet;
use std::mem::transmute;
use std::ptr::{null_mut, read_volatile, write_volatile};
use std::sync::atomic::{compiler_fence, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;
use std::{io, thread};
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

struct warden_args {
    status: *mut Arc<Mutex<bool>>,
    workAddress: *mut Arc<Mutex<PVOID>>,
}
#[derive(Debug)]
enum StatusEnum {
    Idle,
    Work,
    Phase2,
}
unsafe fn warden(
    status: *mut Arc<(Mutex<StatusEnum>, Condvar)>,
    _workAddress: *mut Arc<(Mutex<u64>, Condvar)>,
) {
    let workAddress: *mut Arc<(Mutex<*mut *mut u8>, Condvar)> = transmute(_workAddress);
    let (_ntStr, pntStr) = string_to_lpcwstr(String::from("C:\\Windows\\System32\\ntdll.dll"));
    let (_ker32strw, pker32strw) =
        string_to_lpcwstr(String::from("C:\\Windows\\System32\\kernel32.dll"));
    let (_virtProtStr, pvirtProtStr) = string_to_lpcstr(String::from("VirtualProtect"));
    let ntdll = GetModuleHandle(pntStr).unwrap();
    let (_DBreakStr, pDBreakStr) = string_to_lpcstr(String::from("DbgBreakPoint"));
    let (_DRemoteStr, pDRemoteStr) = string_to_lpcstr(String::from("RtlUserThreadStart"));
    let _kernel32: HMODULE = GetModuleHandle(pker32strw).unwrap();
    let VirtualProtect: pVirtualProtect = GetProcAddress_(_kernel32, pvirtProtStr).unwrap();
    let mut Cstatus: *mut u64 = GetProcAddress_(ntdll, pDBreakStr).unwrap();
    let mut CworkAddress: *mut *const u8 = GetProcAddress_(ntdll, pDRemoteStr).unwrap();
    let mut _oldProtect: DWORD = 0;
    VirtualProtect(
        Cstatus as PVOID,
        8,
        PAGE_EXECUTE_READWRITE,
        &mut _oldProtect as *mut u32,
    );
    VirtualProtect(
        CworkAddress as PVOID,
        8,
        PAGE_EXECUTE_READWRITE,
        &mut _oldProtect as *mut u32,
    );
    *Cstatus = 0;
    'mainloop: loop {
        let (status_lock, cvar) = &**status;
        {
            let mut status = status_lock.lock().unwrap();

            loop {
                status = match *status {
                    StatusEnum::Idle => cvar.wait(status).unwrap(),
                    StatusEnum::Work => {
                        break;
                    }
                    StatusEnum::Phase2 => {
                        break 'mainloop;
                    }
                };
            }

            let (data_lock, _) = &**workAddress;
            let work_address = data_lock.lock().unwrap();

            *CworkAddress = **work_address as *const u8;
            *Cstatus = 1;
            *status = StatusEnum::Idle;
        }
        while *Cstatus == 1 {
            decoy(&mut (Cstatus as u64));
        }

        cvar.notify_one();
    }
    let (status_lock, cvar) = &**status;

    let (data_lock, _) = &**workAddress;
    {
        let work_address = data_lock.lock().unwrap();
        let mut status = status_lock.lock().unwrap();
        *status = StatusEnum::Idle;
        *CworkAddress = **work_address;
    }
    *Cstatus = 2;

    cvar.notify_one();
}

fn decoy(data: &mut u64) {
    unsafe {
        let temp = core::ptr::read_volatile(data);
        core::ptr::write_volatile(data, temp);
    }
}
unsafe extern "system" fn exception_handler(_exception_info: *mut *mut u32) -> i32 {
    // Return EXCEPTION_CONTINUE_SEARCH to allow other handlers to process this exception,
    // or EXCEPTION_EXECUTE_HANDLER to execute the exception handler.

    1
}

type pVirtualAlloc = fn(PVOID, SIZE_T, DWORD, DWORD) -> *mut BYTE;
type pVirtualProtect = fn(PVOID, SIZE_T, DWORD, *mut DWORD) -> bool;
fn main() {
    //{7h3_h4nd_0f_90d_h0v321n9_480v3}

    let (_ker32strw, pker32strw) =
        string_to_lpcwstr(String::from("C:\\Windows\\System32\\kernel32.dll"));
    let (_virtProtStr, pvirtProtStr) = string_to_lpcstr(String::from("VirtualProtect"));

    unsafe {
        //hide!();
        let _kernel32: HMODULE = GetModuleHandle(pker32strw).unwrap();
        let aes_ptr = include_bytes!("../c_aes/aes_dll_nocrt.dll");
        let VirtualProtect: pVirtualProtect = GetProcAddress_(_kernel32, pvirtProtStr).unwrap();
        let verif_data_sec = include_bytes!("../c_verification/mod2.dll.enc");
        let mut _oldProtect: DWORD = 0;
        let mut data = Arc::new((Mutex::new(0 as u64), Condvar::new()));
        let mut status = Arc::new((Mutex::new(StatusEnum::Idle), Condvar::new()));
        VirtualProtect(
            verif_data_sec.as_ptr() as PVOID,
            verif_data_sec.len() * 2,
            PAGE_READWRITE,
            &mut _oldProtect as *mut u32,
        );
        let mut user_input = String::new();
        match io::stdin().read_line(&mut user_input) {
            Ok(_) => (),
            Err(e) => {
                println!("Error reading from stdin {:?}", e);
                return;
            }
        }
        let mut data_th2 = data.clone();
        let mut status_th2 = status.clone();
        thread::spawn(move || {
            warden(
                &mut status_th2 as *mut Arc<(Mutex<StatusEnum>, Condvar)>,
                &mut data_th2 as *mut Arc<(Mutex<u64>, Condvar)>,
            )
        });
        let (_userStr, puserStr) = string_to_lpcstr(user_input);
        ReflectiveLoadDll(aes_ptr.as_ptr() as *mut u8);
        let (data_lock, _) = &*data;
        let (status_lock, cvar) = &*status;
        for i in 0..(verif_data_sec.len() / 16) {
            let data_ptr = verif_data_sec.as_ptr().offset(i as isize * 16) as *const u8;
            {
                let mut mut_work_mutex = data_lock.lock().unwrap();

                *mut_work_mutex = transmute::<*const *const u8, u64>(&data_ptr as *const *const u8);
            }
            {
                let mut status_mutex = status_lock.lock().unwrap();
                *status_mutex = StatusEnum::Work;
            }
            cvar.notify_one();
            {
                let mut status_mutex = status_lock.lock().unwrap();

                status_mutex = match *status_mutex {
                    StatusEnum::Work => cvar.wait(status_mutex).unwrap(),
                    _ => status_mutex,
                };
            }
        }

        let mut data_ptr = puserStr as *const u8;
        {
            let mut work_mutex = data_lock.lock().unwrap();
            *work_mutex = transmute::<*const *const u8, u64>(&data_ptr as *const *const u8);
        }
        {
            let mut status_mutex = status_lock.lock().unwrap();
            *status_mutex = StatusEnum::Phase2;
        }
        cvar.notify_one();
        {
            let mut status_mutex = status_lock.lock().unwrap();
            status_mutex = match *status_mutex {
                StatusEnum::Phase2 => cvar.wait(status_mutex).unwrap(),
                _ => status_mutex,
            };
        }
        ReflectiveLoadDll(verif_data_sec.as_ptr() as *mut u8);
    }
}
