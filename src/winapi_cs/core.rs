#![allow(non_snake_case, non_camel_case_types)]
use super::utils::*;
use std::arch::asm;
use winapi::shared::minwindef::{BYTE, DWORD, FARPROC, HINSTANCE__, HMODULE, ULONG, WORD};
use winapi::shared::ntdef::{HANDLE, LPCSTR, LPCWSTR, NULL, PVOID, ULONGLONG, UNICODE_STRING};
use winapi::um::winnt::IMAGE_DATA_DIRECTORY;

pub fn string_to_lpcwstr(s: String) -> (Vec<u16>, *const u16) {
    let mut wide_chars: Vec<u16> = s.encode_utf16().collect();
    wide_chars.push(0);
    let lpcwstr = wide_chars.as_ptr();
    (wide_chars, lpcwstr)
}

pub fn string_to_lpcstr(s: String) -> (Vec<u8>, LPCSTR) {
    let mut bytes = s.into_bytes();
    bytes.push(0);
    let lpcstr = bytes.as_ptr();
    (bytes, lpcstr as LPCSTR)
}

#[allow(asm_sub_register)]
fn read_peb() -> *mut PEB {
    let mut raw_peb_pointer: *mut PEB;
    unsafe {
        asm!(
            ".8byte 0x0060250c8b4865",
            ".byte 0x00",
            out("rcx") raw_peb_pointer,
            options(nostack)
        );
    }
    raw_peb_pointer
}

pub unsafe fn GetModuleHandle(lModuleName: LPCWSTR) -> Option<HMODULE> {
    crate::fake_exit!();
    let PPEB = read_peb();
    let PLDR = (*PPEB).Ldr;
    let PModuleList = (&mut (*PLDR).InMemoryOrderModuleList) as *mut LIST_ENTRY;
    let PStartListEntry = (*PModuleList).Flink;
    let mut PEntry: *mut LDR_DATA_TABLE_ENTRY;
    let mut PListEntry = PStartListEntry;

    while PListEntry != PModuleList {
        // 16 is the size of LIST_ENTRY
        PEntry = ((PListEntry as *mut BYTE).wrapping_offset(-16)) as *mut LDR_DATA_TABLE_ENTRY;
        if wcscmp_case_insens((*PEntry).FullDllName.Buffer, lModuleName) {
            return Some((*PEntry).DllBase as HMODULE);
        }
        PListEntry = (*PListEntry).Flink;
    }
    None
}

pub unsafe fn GetProcAddress<F>(hModule: HMODULE, lpProcName: LPCSTR) -> Option<F>
where
    F: 'static,
{
    crate::fake_exit!();
    let dosHeader = hModule as *const IMAGE_DOS_HEADER;
    let ntHeaders = (hModule as *const BYTE).wrapping_offset((*dosHeader).e_lfanew as isize)
        as *const IMAGE_NT_HEADERS64;
    let exportDirectory = (hModule as *const BYTE)
        .wrapping_offset(((*ntHeaders).OptionalHeader.DataDirectory[0]).VirtualAddress as isize)
        as *const IMAGE_EXPORT_DIRECTORY;
    let addressOfFuntions: *const DWORD = (hModule as *const BYTE)
        .wrapping_offset((*exportDirectory).AddressOfFunctions as isize)
        as *const DWORD;
    let addressOfNameOrdinals: *const WORD = (hModule as *const BYTE)
        .wrapping_offset((*exportDirectory).AddressOfNameOrdinals as isize)
        as *const WORD;
    let addressOfNames: *const DWORD = (hModule as *const BYTE)
        .wrapping_offset((*exportDirectory).AddressOfNames as isize)
        as *const DWORD;
    for i in 0..(*exportDirectory).NumberOfNames {
        if strcmp_case_insens(
            lpProcName,
            (hModule as *const BYTE).wrapping_offset(*(addressOfNames.add(i as usize)) as isize)
                as LPCSTR,
        ) {
            return Some(std::mem::transmute_copy(
                &(hModule as *const BYTE).wrapping_offset(
                    *addressOfFuntions.add(*addressOfNameOrdinals.add(i as usize) as usize)
                        as isize,
                ),
            ));
        }
    }
    None
}

pub unsafe fn GetProcAddressNative<F>(lpProcName: LPCSTR) -> Option<F>
where
    F: 'static,
{
    crate::fake_exit!();
    let (_s, ps) = string_to_lpcwstr(String::from("C:\\Windows\\System32\\ntdll.dll"));
    let hModuleOPT = GetModuleHandle(ps);
    if hModuleOPT.is_none() {
        return None;
    }
    let hModule = hModuleOPT.unwrap();

    let dosHeader = hModule as *const IMAGE_DOS_HEADER;
    let ntHeaders = (hModule as *const BYTE).wrapping_offset((*dosHeader).e_lfanew as isize)
        as *const IMAGE_NT_HEADERS64;
    let exportDirectory = (hModule as *const BYTE)
        .wrapping_offset(((*ntHeaders).OptionalHeader.DataDirectory[0]).VirtualAddress as isize)
        as *const IMAGE_EXPORT_DIRECTORY;
    let addressOfFuntions: *const DWORD = (hModule as *const BYTE)
        .wrapping_offset((*exportDirectory).AddressOfFunctions as isize)
        as *const DWORD;
    let addressOfNameOrdinals: *const WORD = (hModule as *const BYTE)
        .wrapping_offset((*exportDirectory).AddressOfNameOrdinals as isize)
        as *const WORD;
    let addressOfNames: *const DWORD = (hModule as *const BYTE)
        .wrapping_offset((*exportDirectory).AddressOfNames as isize)
        as *const DWORD;
    for i in 0..(*exportDirectory).NumberOfNames {
        if strcmp_case_insens(
            lpProcName,
            (hModule as *const BYTE).wrapping_offset(*(addressOfNames.add(i as usize)) as isize)
                as LPCSTR,
        ) {
            return Some(std::mem::transmute_copy(
                &(hModule as *const BYTE).wrapping_offset(
                    *addressOfFuntions.add(*addressOfNameOrdinals.add(i as usize) as usize)
                        as isize,
                ),
            ));
        }
    }
    None
}

type pRtlInitUnicodeString = fn(*mut UNICODE_STRING, LPCWSTR);
type pLdrLoadDll = fn(LPCWSTR, ULONG, *mut UNICODE_STRING, *mut HMODULE);
pub unsafe fn LoadLibrary(lpFileName: LPCWSTR) -> Option<HMODULE> {
    let mut ustrModule: UNICODE_STRING;
    let mut hModule: HMODULE = 0 as *mut HINSTANCE__;
    let (_s, ps) = string_to_lpcstr(String::from("RtlInitUnicodeString"));
    let (_s1, ps1) = string_to_lpcstr(String::from("LdrLoadDll"));
    let RtlInitUnicodeString: pRtlInitUnicodeString = match GetProcAddressNative(ps) {
        Some(proc) => proc,
        None => return None,
    };
    RtlInitUnicodeString(&mut ustrModule as *mut UNICODE_STRING, lpFileName);
    let LdrLoadDll: pLdrLoadDll = match GetProcAddressNative(ps1) {
        Some(proc) => proc,
        None => return None,
    };
    LdrLoadDll(
        0 as *const u16,
        0,
        &mut ustrModule as *mut UNICODE_STRING,
        &mut hModule as *mut HMODULE,
    );
    Some(hModule)
}
