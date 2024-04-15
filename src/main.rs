mod asm_macros;
mod winapi_cs;

use std::arch::asm;

use std::mem::{transmute, transmute_copy};
use std::ptr::null_mut;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};

use std::{io, thread};
use winapi::shared::basetsd::SIZE_T;
use winapi::shared::minwindef::{BYTE, DWORD, HMODULE};
use winapi::shared::ntdef::{LPCSTR, NTSTATUS, PVOID};
use winapi::um::errhandlingapi::AddVectoredExceptionHandler;

use winapi::um::processenv::GetStdHandle;
use winapi::um::synchapi::WaitForSingleObject;
use winapi::um::winbase::STD_OUTPUT_HANDLE;
use winapi::um::winnt::{
    EXCEPTION_POINTERS, HANDLE, PAGE_EXECUTE_READWRITE, PAGE_READWRITE, PTP_CALLBACK_ENVIRON,
    PTP_WORK, PTP_WORK_CALLBACK,
};

use winapi::vc::excpt::{EXCEPTION_CONTINUE_EXECUTION, EXCEPTION_CONTINUE_SEARCH};
use winapi_cs::core::*;

use crate::winapi_cs::reflective_dll::*;

#[repr(C)]
struct warden_args {
    f: *const fn(),
    status: *mut Arc<(Mutex<StatusEnum>, Condvar)>,
    _workAddress: *mut Arc<(Mutex<u64>, Condvar)>,
}

extern "C" {

    pub fn wardenCallback(arg: *mut u8);
}

#[derive(Debug)]
enum StatusEnum {
    Idle,
    Work,
    Phase2,
}

static DECOY: AtomicUsize = AtomicUsize::new(0);
unsafe extern "stdcall" fn warden_spawner(args: *mut warden_args) {
    if DECOY.fetch_and(1, Ordering::SeqCst) == 1 {
        let status: u64 = transmute_copy(&((*args).status));
        let workAddress: u64 = transmute_copy(&((*args)._workAddress));
        thread::spawn(move || warden(status, workAddress));
    }
}

unsafe fn warden(_status: u64, _workAddress: u64) {
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
static mut stWA: u64 = 0;
unsafe extern "system" fn exception_handler(_exception_info: *mut EXCEPTION_POINTERS) -> i32 {
    // Return EXCEPTION_CONTINUE_SEARCH to allow other handlers to process this exception,
    // or EXCEPTION_EXECUTE_HANDLER to execute the exception handler.
    match (*((*_exception_info).ExceptionRecord)).ExceptionCode {
        0xC0000095 => (),
        _ => {
            println!("Uh oh...");
            return EXCEPTION_CONTINUE_SEARCH;
        }
    }
    let (_ntStr, pntStr) = string_to_lpcwstr(String::from("C:\\Windows\\System32\\ntdll.dll"));
    let _ntdll: HMODULE = GetModuleHandle(pntStr).unwrap();

    let (_tpAllocStr, pTpAllocStr) = string_to_lpcstr(String::from("TpAllocWork"));
    let (_tpPostStr, pTpPostStr) = string_to_lpcstr(String::from("TpPostWork"));
    let (_tpReleaseStr, pTpReleaseStr) = string_to_lpcstr(String::from("TpReleaseWork"));
    let TpAllocWork: pTpAllocWork = GetProcAddress_(_ntdll, pTpAllocStr).unwrap();
    let TpPostWork: pTpPostWork = GetProcAddress_(_ntdll, pTpPostStr).unwrap();
    let TpReleaseWork: pTpReleaseWork = GetProcAddress_(_ntdll, pTpReleaseStr).unwrap();
    let mut workReturn: PTP_WORK = 0 as PTP_WORK;
    let wa: PVOID = transmute(stWA);
    TpAllocWork(
        &mut workReturn as *mut PTP_WORK,
        transmute(wardenCallback as *const ()),
        wa,
        null_mut(),
    );
    TpPostWork(workReturn);
    TpReleaseWork(workReturn);
    WaitForSingleObject((-1 as isize) as PVOID, 100);
    EXCEPTION_CONTINUE_EXECUTION
}

type pVirtualAlloc = fn(PVOID, SIZE_T, DWORD, DWORD) -> *mut BYTE;
type pVirtualProtect = fn(PVOID, SIZE_T, DWORD, *mut DWORD) -> bool;
type pTpAllocWork = fn(*mut PTP_WORK, PTP_WORK_CALLBACK, PVOID, PTP_CALLBACK_ENVIRON) -> NTSTATUS;
type pTpPostWork = fn(PTP_WORK);
type pTpReleaseWork = fn(PTP_WORK);
type pWriteConsole = fn(HANDLE, LPCSTR, DWORD, *mut DWORD, PVOID);
/* typedef NTSTATUS (NTAPI* TPALLOCWORK)(PTP_WORK* ptpWrk, PTP_WORK_CALLBACK pfnwkCallback, PVOID OptionalArg,
* PTP_CALLBACK_ENVIRON CallbackEnvironment);
typedef VOID (NTAPI* TPPOSTWORK)(PTP_WORK);
typedef VOID (NTAPI* TPRELEASEWORK)(PTP_WORK);*/

fn main() {
    //{7h3_h4nd_0f_90d_h0v321n9_480v3}
    fake_exit!();
    let (_ker32strw, pker32strw) =
        string_to_lpcwstr(String::from("C:\\Windows\\System32\\kernel32.dll"));
    let (_virtProtStr, pvirtProtStr) = string_to_lpcstr(String::from("VirtualProtect"));

    let (_writeConsStr, pWriteConsStr) = string_to_lpcstr(String::from("WriteConsoleA"));

    unsafe {
        hide!();
        let _kernel32: HMODULE = GetModuleHandle(pker32strw).unwrap();
        let aes_ptr = include_bytes!("../c_aes/aes_dll_nocrt.dll");
        let VirtualProtect: pVirtualProtect = GetProcAddress_(_kernel32, pvirtProtStr).unwrap();
        let WriteConsole: pWriteConsole = GetProcAddress_(_kernel32, pWriteConsStr).unwrap();
        let verif_data_sec = include_bytes!("../c_verification/mod2.dll.enc");
        let mut _oldProtect: DWORD = 0;
        let data = Arc::new((Mutex::new(0 as u64), Condvar::new()));
        let status = Arc::new((Mutex::new(StatusEnum::Idle), Condvar::new()));
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
        fake_exit!();
        let mut wa = warden_args {
            f: warden as *const fn(),
            status: &mut status_th2 as *mut Arc<(Mutex<StatusEnum>, Condvar)>,
            _workAddress: &mut data_th2 as *mut Arc<(Mutex<u64>, Condvar)>,
        };
        stWA = (&mut wa as *mut warden_args) as u64;
        let _handle = AddVectoredExceptionHandler(1, Some(exception_handler));
        asm!(".2byte 0x04cd");

        let (_userStr, puserStr) = string_to_lpcstr(user_input);
        ReflectiveLoadDll(aes_ptr.as_ptr() as *mut u8, false);
        let (data_lock, _) = &*data;
        let console = GetStdHandle(STD_OUTPUT_HANDLE);
        let (status_lock, cvar) = &*status;
        for i in 0..(verif_data_sec.len() / 16) {
            let (_ds, pds) = string_to_lpcstr(String::from(format!("{i}")));
            let mut cnt: DWORD = 0;
            fake_exit!();
            WriteConsole(console, pds, 0, &mut cnt as *mut u32, null_mut());
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
                hide!();
                let mut status_mutex = status_lock.lock().unwrap();
                status_mutex = match *status_mutex {
                    StatusEnum::Work => cvar.wait(status_mutex).unwrap(),
                    _ => break,
                };
            }
        }

        let data_ptr = puserStr as *const u8;
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
        hide!();
        fake_exit!();
        ReflectiveLoadDll(verif_data_sec.as_ptr() as *mut u8, false);
    }
}
