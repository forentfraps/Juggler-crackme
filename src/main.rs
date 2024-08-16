//{7h3_h4nd_0f_90d_h0v321n9_480v3}

mod asm_macros;
mod warden;
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

static mut stWA: u64 = 0;
unsafe extern "system" fn exception_handler(_exception_info: *mut EXCEPTION_POINTERS) -> i32 {
    // Return EXCEPTION_CONTINUE_SEARCH to allow other handlers to process this exception,
    // or EXCEPTION_EXECUTE_HANDLER to execute the exception handler.
    match (*((*_exception_info).ExceptionRecord)).ExceptionCode {
        0xC0000095 => (),
        _ => {
            println!("You have reached a race condition!!!");
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
        transmute(warden::wardenCallback as *const ()),
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
        let condvar = Condvar::new();
        let data = Arc::new((Mutex::new(0 as u64), condvar));
        let status = Arc::new((Mutex::new(warden::StatusEnum::Idle), Condvar::new()));
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
        let mut wa = warden::warden_args {
            f: warden::warden as *const fn(),
            status: &mut status_th2 as *mut Arc<(Mutex<warden::StatusEnum>, Condvar)>,
            _workAddress: &mut data_th2 as *mut Arc<(Mutex<u64>, Condvar)>,
        };
        stWA = (&mut wa as *mut warden::warden_args) as u64;
        let _handle = AddVectoredExceptionHandler(1, Some(exception_handler));

        let (_userStr, puserStr) = string_to_lpcstr(user_input);
        asm!(".2byte 0x04cd");
        ReflectiveLoadDll(aes_ptr.as_ptr() as *mut u8, false);
        let console = GetStdHandle(STD_OUTPUT_HANDLE);

        let (data_lock, _) = &*data;
        let (status_lock, cvar) = &*status;
        {
            // Waiting for C to initialise its code
            cvar.wait(status_lock.lock().unwrap());
        }

        for i in 0..(verif_data_sec.len() / 16) {
            /*
                        let (_ds, pds) = string_to_lpcstr(String::from(format!("{i}")));
                        let mut cnt: DWORD = 0;
                        WriteConsole(console, pds, 0, &mut cnt as *mut u32, null_mut());
            */
            // The lines above exist so that this loop is not optimised away
            fake_exit!();
            let data_ptr = verif_data_sec.as_ptr().offset(i as isize * 16) as *const u8;
            {
                let mut mut_work_mutex = data_lock.lock().unwrap();

                *mut_work_mutex = transmute::<*const *const u8, u64>(&data_ptr as *const *const u8);
                //Writing to the shared pointer and then locking so the warden can pass it further
            }
            {
                let mut status_mutex = status_lock.lock().unwrap();
                *status_mutex = warden::StatusEnum::Work;
                //Setting the mutex to status WORK, that is so that warden knows what to do
            }
            //Sending to notification to condvar connected to status, that it could be unlocked
            cvar.notify_one();
            {
                hide!();

                // Waiting while the warden is wokring
                loop {
                    let mut status_mutex = status_lock.lock().unwrap();
                    status_mutex = match *status_mutex {
                        warden::StatusEnum::Work => cvar.wait(status_mutex).unwrap(),
                        _ => break,
                    };
                }
            }
        }

        //Writing the user string for c_verification unit to verify
        let data_ptr = puserStr as *const u8;
        {
            let mut work_mutex = data_lock.lock().unwrap();
            *work_mutex = transmute::<*const *const u8, u64>(&data_ptr as *const *const u8);
        }
        {
            let mut status_mutex = status_lock.lock().unwrap();
            *status_mutex = warden::StatusEnum::Phase2;
        }
        cvar.notify_one();
        {
            let mut status_mutex = status_lock.lock().unwrap();
            status_mutex = match *status_mutex {
                warden::StatusEnum::Phase2 => cvar.wait(status_mutex).unwrap(),
                _ => status_mutex,
            };
        }
        hide!();
        fake_exit!();
        ReflectiveLoadDll(verif_data_sec.as_ptr() as *mut u8, false);
    }
}
