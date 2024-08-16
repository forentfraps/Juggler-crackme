use std::mem::{transmute, transmute_copy};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};

use std::arch::asm;
use std::thread;
use winapi::shared::basetsd::SIZE_T;
use winapi::shared::minwindef::{DWORD, HMODULE};
use winapi::shared::ntdef::PVOID;

use winapi::um::winnt::PAGE_EXECUTE_READWRITE;

use crate::winapi_cs::core::*;
type pVirtualProtect = fn(PVOID, SIZE_T, DWORD, *mut DWORD) -> bool;

#[repr(C)]
pub struct warden_args {
    pub f: *const fn(),
    pub status: *mut Arc<(Mutex<StatusEnum>, Condvar)>,
    pub _workAddress: *mut Arc<(Mutex<u64>, Condvar)>,
}

extern "C" {

    pub fn wardenCallback(arg: *mut u8);
}

#[derive(Debug)]
pub enum StatusEnum {
    Idle,
    Work,
    Phase2,
}
macro_rules! wait_for_zero {
    ($ptr:expr) => {{
        let ptr = $ptr as *mut i32;
        unsafe {
            asm!(
                "2:",
                "mov rax, 0", // Load a non-zero value into EAX
                "lock cmpxchg [{0}], rax", // Compare and exchange with a locked bus, but don't change the value
                "jnz 2b", // Jump back to the start of the loop if *ptr was not zero
                in(reg) ptr,
                out("rax") _,
                options(nostack )
            );
        }
    }};
}
static DECOY: AtomicUsize = AtomicUsize::new(0);
unsafe extern "stdcall" fn warden_spawner(args: *mut warden_args) {
    if DECOY.fetch_and(1, Ordering::SeqCst) == 1 {
        let status: u64 = transmute_copy(&((*args).status));
        let workAddress: u64 = transmute_copy(&((*args)._workAddress));
        thread::spawn(move || warden(status, workAddress));
    }
}

pub unsafe fn warden(_status: u64, _workAddress: u64) {
    let status: *mut Arc<(Mutex<StatusEnum>, Condvar)> = transmute(_status);
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
    let Cstatus: *mut u64 = GetProcAddress_(ntdll, pDBreakStr).unwrap();
    let CworkAddress: *mut *const u8 = GetProcAddress_(ntdll, pDRemoteStr).unwrap();
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
    while *CworkAddress != 1 as *const u8 {
        decoy(&mut (*CworkAddress as u64));
    }

    // C thread initialised => notifying main thread it can proceed
    let (_, cvar) = &**status;
    cvar.notify_one();
    'mainloop: loop {
        let (status_lock, cvar) = &**status;
        {
            let mut status = status_lock.lock().unwrap();

            // Waiting for the status to become work to decrypt stuff or Phase2 To exit
            loop {
                status = match *status {
                    StatusEnum::Idle => cvar.wait(status).unwrap(),
                    StatusEnum::Work => {
                        //Notification recieved and we can send the data to C code
                        break;
                    }
                    StatusEnum::Phase2 => {
                        break 'mainloop;
                    }
                };
            }

            let (data_lock, _) = &**workAddress;
            let work_address = data_lock.lock().unwrap();

            // Putting the work address in
            *CworkAddress = **work_address as *const u8;
            // Setting the status (This is a mutex for C code)
            *Cstatus = 1;
            wait_for_zero!(Cstatus);
            //upon receiving work set status back to idle
            *status = StatusEnum::Idle;
        }
        //notify the main thread that the block is decyprted

        cvar.notify_one();
    }
    // This is only reached when Phase2 Starts

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
