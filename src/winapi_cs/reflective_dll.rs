#![allow(non_snake_case, non_camel_case_types)]
use super::core::*;
use super::utils::*;
use std::any::Any;
use std::arch::asm;
use std::mem;
use std::mem::transmute;
use std::ptr::copy_nonoverlapping;
use winapi::shared::basetsd::SIZE_T;
use winapi::shared::minwindef::HINSTANCE;
use winapi::shared::minwindef::{BYTE, DWORD, FARPROC, HINSTANCE__, HMODULE, ULONG, WORD};
use winapi::shared::ntdef::{HANDLE, LPCSTR, LPCWSTR, NULL, PVOID, ULONGLONG, UNICODE_STRING};
use winapi::um::libloaderapi::LoadLibraryA;
use winapi::um::winnt::DLL_PROCESS_ATTACH;
use winapi::um::winnt::MEM_COMMIT;
use winapi::um::winnt::MEM_RESERVE;
use winapi::um::winnt::PAGE_EXECUTE_READWRITE;

type pVirtualAlloc = fn(PVOID, SIZE_T, DWORD, DWORD) -> *mut BYTE;
type pDllEntry = fn(HINSTANCE, DWORD, PVOID) -> bool;

fn image_first_section(ntheader: *const IMAGE_NT_HEADERS64) -> *const IMAGE_SECTION_HEADER {
    unsafe {
        let optional_header_offset = mem::offset_of!(IMAGE_NT_HEADERS64, OptionalHeader) as isize;
        let size_of_optional_header = (*ntheader).FileHeader.SizeOfOptionalHeader as isize;

        (ntheader as *const u8).offset(optional_header_offset + size_of_optional_header)
            as *const IMAGE_SECTION_HEADER
    }
}
unsafe fn ReflectiveLoadDll(dllBytes: *mut BYTE, run: bool) -> Option<*mut BYTE> {
    let dosHeaders = dllBytes as *const IMAGE_DOS_HEADER;
    let ntHeaders =
        dllBytes.wrapping_offset((*dosHeaders).e_lfanew as isize) as *const IMAGE_NT_HEADERS64;
    let dllImageSize = (*ntHeaders).OptionalHeader.SizeOfImage;
    let (_ker32strw, pker32strw) = string_to_lpcwstr(String::from("kernel32.dll"));
    let (_virtAllocStr, pvirtAllocStr) = string_to_lpcstr(String::from("VirtualAlloc"));
    let kernel32: HMODULE = match GetModuleHandle(pker32strw) {
        Some(module) => module,
        None => return None,
    };
    let VirtualAlloc: pVirtualAlloc = match GetProcAddress(kernel32, pvirtAllocStr) {
        Some(proc) => proc,
        None => return None,
    };
    let dllBase = VirtualAlloc(
        (*ntHeaders).OptionalHeader.ImageBase,
        dllImageSize as usize,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_EXECUTE_READWRITE,
    );
    let deltaImageBase =
        dllBase.offset_from(((*ntHeaders).OptionalHeader.ImageBase as *const BYTE));
    copy_nonoverlapping(dllBytes, dllBase, dllImageSize as usize);
    let mut section = image_first_section(ntHeaders);
    let mut sectionDestination;
    let mut sectionBytes;
    for i in 0..(*ntHeaders).FileHeader.NumberOfSections {
        sectionDestination = (dllBase as *const DWORD)
            .wrapping_offset((*section).VirtualAddress as isize)
            as *mut u32;
        sectionBytes = (dllBytes as *const DWORD)
            .wrapping_offset((*section).PointerToRawData as isize)
            as *mut u32;
        copy_nonoverlapping(
            sectionDestination,
            sectionBytes,
            (*section).SizeOfRawData as usize,
        );
        section = section.wrapping_offset(1);
    }
    let relocationTable = (((*ntHeaders).OptionalHeader.DataDirectory[5]).VirtualAddress
        as *mut DWORD)
        .wrapping_offset(dllBase as isize);
    let mut relocationProcessed: u32 = 0;
    let mut relocationBlock;
    let mut relocationCount: u32;
    let mut relocationEntries;
    let mut relocationRVA;
    let mut addressToPatch;

    while relocationProcessed < ((*ntHeaders).OptionalHeader.DataDirectory[5]).Size {
        relocationBlock = (relocationTable.wrapping_offset(relocationProcessed as isize))
            as *mut BASE_RELOCATION_BLOCK;
        relocationProcessed += 8;
        relocationCount = ((*relocationBlock).BlockSize - 8) / 2;
        relocationEntries = relocationTable.wrapping_offset(relocationProcessed as isize)
            as *mut BASE_RELOCATION_ENTRY;
        for i in 0..relocationCount {
            relocationProcessed += 2;
            if (*(relocationEntries.wrapping_offset(i as isize))).type_() == 0 {
                continue;
            }
            relocationRVA = ((*relocationBlock).PageAddress as *mut BYTE)
                .wrapping_offset(relocationEntries.wrapping_offset(i as isize) as isize);
            addressToPatch = 0 as *mut DWORD;
            copy_nonoverlapping(
                (dllBase as *mut DWORD).wrapping_offset(relocationRVA as isize),
                (&mut addressToPatch as *mut *mut DWORD) as *mut DWORD,
                8,
            );
            addressToPatch = addressToPatch.wrapping_offset(deltaImageBase);
            copy_nonoverlapping(
                (&mut addressToPatch as *mut *mut DWORD) as *mut DWORD,
                (dllBase as *mut DWORD).wrapping_offset(relocationRVA as isize),
                8,
            );
        }
    }
    let mut importDescrtiptor = (((*ntHeaders).OptionalHeader.DataDirectory[1]).VirtualAddress
        + dllBase as u32) as *mut IMAGE_IMPORT_DESCRIPTOR;
    let mut libraryName: LPCSTR;
    let mut library: HMODULE;
    let mut thunk: *mut IMAGE_THUNK_DATA;
    let mut functionOrdinal: LPCSTR;
    let mut functionName: *mut IMAGE_IMPORT_BY_NAME;
    let mut functionAddress: *mut DWORD;
    while (*importDescrtiptor).Name != 0 {
        libraryName = ((*importDescrtiptor).Name + dllBase as u32) as LPCSTR;
        // TODO convert LPCSTR -> LPCWSTR and use my lib
        // concerns include path shenanigans, although they should not matter
        library = LoadLibraryA(libraryName);
        if library != 0 as HMODULE {
            thunk = (dllBase as *mut DWORD)
                .wrapping_offset((*importDescrtiptor).FirstThunk as isize)
                as *mut IMAGE_THUNK_DATA;
            while (*thunk).Ordinal != 0 {
                if ((*thunk).Ordinal & 0x8000000000000000) != 0 {
                    functionOrdinal = ((*thunk).Ordinal & 0xffff) as LPCSTR;
                    (*thunk).Ordinal = GetProcAddress(library, functionOrdinal).unwrap();
                } else {
                    functionName = (dllBase as *mut DWORD)
                        .wrapping_offset((*thunk).Ordinal as isize)
                        as *mut IMAGE_IMPORT_BY_NAME;
                    functionAddress =
                        GetProcAddress(library, &mut ((*functionName).Name[0]) as LPCSTR).unwrap();
                    (*thunk).Ordinal = functionAddress as ULONGLONG;
                }
                thunk = thunk.wrapping_offset(1);
            }
        }
        importDescrtiptor = importDescrtiptor.wrapping_offset(1);
    }
    let DllEntry: pDllEntry = transmute(
        (dllBase as *mut DWORD)
            .wrapping_offset((*ntHeaders).OptionalHeader.AddressOfEntryPoint as isize),
    );
    DllEntry(dllBase as HINSTANCE, DLL_PROCESS_ATTACH, 0 as PVOID);

    None
}
