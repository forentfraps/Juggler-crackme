#![allow(non_snake_case, non_camel_case_types)]

use super::core::*;
use super::utils::*;
use std::arch::asm;
use std::mem;
use std::ptr::copy;
use winapi::shared::basetsd::DWORD_PTR;
use winapi::shared::basetsd::SIZE_T;
use winapi::shared::minwindef::HINSTANCE;
use winapi::shared::minwindef::{BYTE, DWORD, FARPROC, HINSTANCE__, HMODULE, ULONG, WORD};
use winapi::shared::ntdef::{HANDLE, LPCSTR, LPCWSTR, NULL, PVOID, ULONGLONG, UNICODE_STRING};
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::errhandlingapi::SetLastError;
use winapi::um::libloaderapi::GetProcAddress;
use winapi::um::libloaderapi::LoadLibraryA;
use winapi::um::winnt::DLL_PROCESS_ATTACH;
use winapi::um::winnt::IMAGE_ORDINAL64;
use winapi::um::winnt::IMAGE_SNAP_BY_ORDINAL64;
use winapi::um::winnt::IMAGE_THUNK_DATA64;
use winapi::um::winnt::MEM_COMMIT;
use winapi::um::winnt::MEM_RESERVE;
use winapi::um::winnt::PAGE_EXECUTE_READWRITE;
use winapi::um::winuser::MAKEINTRESOURCEA;

type pVirtualAlloc = fn(PVOID, SIZE_T, DWORD, DWORD) -> *mut BYTE;
type pDllEntry = extern "system" fn(HINSTANCE, DWORD, PVOID) -> bool;

fn image_first_section(ntheader: *const IMAGE_NT_HEADERS64) -> *const IMAGE_SECTION_HEADER {
    unsafe {
        let optional_header_offset = mem::offset_of!(IMAGE_NT_HEADERS64, OptionalHeader) as isize;
        let size_of_optional_header = (*ntheader).FileHeader.SizeOfOptionalHeader as isize;

        (ntheader as *const u8).offset(optional_header_offset + size_of_optional_header)
            as *const IMAGE_SECTION_HEADER
    }
}
pub unsafe fn ReflectiveLoadDll(dllBytes: *mut BYTE) -> Option<*mut BYTE> {
    let dosHeaders = dllBytes as *const IMAGE_DOS_HEADER;
    let ntHeaders =
        dllBytes.wrapping_offset((*dosHeaders).e_lfanew as isize) as *const IMAGE_NT_HEADERS64;
    println!("Reached headers elfanew {:?}", (*dosHeaders).e_lfanew);
    let dllImageSize = (*ntHeaders).OptionalHeader.SizeOfImage;
    println!("2");
    let (_ker32strw, pker32strw) =
        string_to_lpcwstr(String::from("C:\\Windows\\System32\\kernel32.dll"));
    let (_virtAllocStr, pvirtAllocStr) = string_to_lpcstr(String::from("VirtualAlloc"));
    let kernel32: HMODULE = match GetModuleHandle(pker32strw) {
        Some(module) => module,
        None => return None,
    };
    println!("Allocating, imagesize {:?}", dllImageSize);
    let VirtualAlloc: pVirtualAlloc = std::mem::transmute(GetProcAddress(kernel32, pvirtAllocStr));
    let mut dllBase = VirtualAlloc(
        0 as PVOID,
        dllImageSize as usize * 2,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_EXECUTE_READWRITE,
    );

    println!("dllbase {dllBase:?} error {}", GetLastError());
    let deltaImageBase = dllBase as usize - (*ntHeaders).OptionalHeader.ImageBase as usize;
    println!("Before copying deltaimagebase {deltaImageBase:x}");
    copy(dllBytes, dllBase, dllImageSize as usize);
    println!("After copying");
    let mut section = image_first_section(ntHeaders);
    let mut sectionDestination;
    let mut sectionBytes;
    for _ in 0..(*ntHeaders).FileHeader.NumberOfSections {
        sectionDestination = ((dllBase as usize) + (*section).VirtualAddress as usize) as *mut u8;
        sectionBytes = ((dllBytes as usize) + (*section).PointerToRawData as usize) as *mut u8;

        copy(
            sectionBytes,
            sectionDestination,
            (*section).SizeOfRawData as usize,
        );
        section = section.offset(1);
    }
    println!("checkpoint");
    let relocationTable = (((*ntHeaders).OptionalHeader.DataDirectory[5]).VirtualAddress
        as DWORD_PTR)
        + dllBase as usize;
    let mut relocationProcessed: u32 = 0;
    while relocationProcessed < ((*ntHeaders).OptionalHeader.DataDirectory[5]).Size {
        let relocationBlock =
            (relocationTable + relocationProcessed as usize) as *const BASE_RELOCATION_BLOCK;
        let blockSize = (*relocationBlock).BlockSize as usize;
        let entryCount = (blockSize - std::mem::size_of::<BASE_RELOCATION_BLOCK>())
            / std::mem::size_of::<BASE_RELOCATION_ENTRY>();

        let relocationEntries = relocationBlock.offset(1) as *const BASE_RELOCATION_ENTRY; // Immediately after the block

        for i in 0..entryCount as isize {
            let entry = relocationEntries.offset(i);
            if (*entry).type_() == 0 {
                continue;
            }

            let patchAddress = dllBase
                .offset((*relocationBlock).PageAddress as isize + ((*entry).offset() as isize));
            let valueAtAddress = patchAddress as *mut u32;
            *valueAtAddress = (*valueAtAddress) + (deltaImageBase as u32);
        }

        relocationProcessed += blockSize as u32;
    }
    println!("After basic relocs\n");
    let mut importDescriptor = (dllBase
        .offset((*ntHeaders).OptionalHeader.DataDirectory[1].VirtualAddress as isize))
        as *mut IMAGE_IMPORT_DESCRIPTOR;

    while (*importDescriptor).Name != 0 {
        let libraryNamePtr = dllBase.offset((*importDescriptor).Name as isize);
        print_lpcstr(libraryNamePtr as *const i8);
        let library = LoadLibraryA(libraryNamePtr as *const i8);
        println!("lib loaded {:?}", library);

        if !library.is_null() {
            let mut thunk =
                dllBase.offset((*importDescriptor).FirstThunk as isize) as *mut IMAGE_THUNK_DATA64;
            while *(*thunk).u1.AddressOfData() != 0 {
                let functionAddress = if IMAGE_SNAP_BY_ORDINAL64(*((*thunk).u1.Ordinal())) {
                    GetProcAddress(library, IMAGE_ORDINAL64(*(*thunk).u1.Ordinal()) as LPCSTR)
                } else {
                    let importByName = (dllBase as usize + (*(*thunk).u1.AddressOfData()) as usize)
                        as *const IMAGE_IMPORT_BY_NAME;
                    GetProcAddress(library, (*importByName).Name.as_ptr() as *const i8)
                };

                if !functionAddress.is_null() {
                    *(*thunk).u1.Function_mut() = functionAddress as u64;
                } else {
                    println!("Proc not found");
                }

                thunk = thunk.offset(1);
            }
        } else {
            println!("Lib not loaded")
        }

        importDescriptor = importDescriptor.offset(1);
    }
    let entry_point_rva = (*ntHeaders).OptionalHeader.AddressOfEntryPoint as isize;
    let DllEntry: pDllEntry = std::mem::transmute(dllBase.offset(entry_point_rva));

    println!("Calling dllEntry\n");
    //asm!("int 3");
    DllEntry(dllBase as HINSTANCE, DLL_PROCESS_ATTACH, 0 as PVOID);
    println!("SUCCESS");
    Some(dllBase)
}
