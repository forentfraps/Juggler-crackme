#![allow(non_snake_case, non_camel_case_types)]

use crc32fast::Hasher;

use std::ffi::{CStr, OsString};
use std::os::windows::ffi::OsStringExt;

use winapi::shared::minwindef::{BYTE, DWORD, ULONG, WORD};
use winapi::shared::ntdef::{CHAR, LONG, LPCSTR, LPCWSTR, PVOID, ULONGLONG, UNICODE_STRING};
use winapi::um::winnt::SHORT;

#[repr(C)]
pub struct PEB {
    pub Reserved1: [BYTE; 2],
    pub BeingDebugged: BYTE,
    pub Reserved2: [BYTE; 1],
    pub Reserved3: [PVOID; 2],
    pub Ldr: *mut PEB_LDR_DATA,
    pub ProcessParameters: PVOID,
    pub Reserved4: [PVOID; 3],
    pub AtlThunkSListPtr: PVOID,
    pub Reserved5: PVOID,
    pub Reserved6: ULONG,
    pub Reserved7: PVOID,
    pub Reserved8: ULONG,
    pub AtlThunkSListPtr32: ULONG,
    pub Reserved9: [PVOID; 45],
    pub Reserved10: [BYTE; 96],
    pub PostProcessInitRoutine: PVOID,
    pub Reserved11: [BYTE; 128],
    pub Reserved12: [PVOID; 1],
    pub SessionId: ULONG,
}

#[repr(C)]
pub struct PEB_LDR_DATA {
    pub Reserved1: [BYTE; 8],
    pub Reserved2: [PVOID; 3],
    pub InMemoryOrderModuleList: LIST_ENTRY,
}

#[repr(C)]
pub struct LIST_ENTRY {
    pub Flink: *mut LIST_ENTRY,
    pub Blink: *mut LIST_ENTRY,
}

#[repr(C)]
pub struct LDR_DATA_TABLE_ENTRY {
    pub Reserved1: [PVOID; 2],
    pub InMemoryOrderLinks: LIST_ENTRY,
    pub Reserved2: [PVOID; 2],
    pub DllBase: PVOID,
    pub EntryPoint: PVOID,
    pub Reserved3: PVOID,
    pub FullDllName: UNICODE_STRING,
    pub Reserved4: [BYTE; 8],
    pub Reserved5: [PVOID; 3],
    pub CheckSum_Reserved6: PVOID,
    pub TimeDateStamp: ULONG,
}

const IMAGE_NUMBEROF_DIRECTORY_ENTRIES: usize = 16;

#[repr(C)]
pub struct IMAGE_DOS_HEADER {
    pub e_magic: WORD,
    pub e_cblp: WORD,
    pub e_cp: WORD,
    pub e_crlc: WORD,
    pub e_cparhdr: WORD,
    pub e_minalloc: WORD,
    pub e_maxalloc: WORD,
    pub e_ss: WORD,
    pub e_sp: WORD,
    pub e_csum: WORD,
    pub e_ip: WORD,
    pub e_cs: WORD,
    pub e_lfarlc: WORD,
    pub e_ovno: WORD,
    pub e_res: [WORD; 4],
    pub e_oemid: WORD,
    pub e_oeminfo: WORD,
    pub e_res2: [WORD; 10],
    pub e_lfanew: LONG,
}

#[repr(C)]
pub struct IMAGE_NT_HEADERS64 {
    pub Signature: DWORD,
    pub FileHeader: IMAGE_FILE_HEADER,
    pub OptionalHeader: IMAGE_OPTIONAL_HEADER64,
}

#[repr(C)]
pub struct IMAGE_FILE_HEADER {
    pub Machine: WORD,
    pub NumberOfSections: WORD,
    pub TimeDateStamp: DWORD,
    pub PointerToSymbolTable: DWORD,
    pub NumberOfSymbols: DWORD,
    pub SizeOfOptionalHeader: WORD,
    pub Characteristics: WORD,
}

#[repr(C)]
pub struct IMAGE_OPTIONAL_HEADER64 {
    pub Magic: WORD,
    pub MajorLinkerVersion: BYTE,
    pub MinorLinkerVersion: BYTE,
    pub SizeOfCode: DWORD,
    pub SizeOfInitializedData: DWORD,
    pub SizeOfUninitializedData: DWORD,
    pub AddressOfEntryPoint: DWORD,
    pub BaseOfCode: DWORD,
    pub ImageBase: PVOID,
    pub SectionAlignment: DWORD,
    pub FileAlignment: DWORD,
    pub MajorOperatingSystemVersion: WORD,
    pub MinorOperatingSystemVersion: WORD,
    pub MajorImageVersion: WORD,
    pub MinorImageVersion: WORD,
    pub MajorSubsystemVersion: WORD,
    pub MinorSubsystemVersion: WORD,
    pub Win32VersionValue: DWORD,
    pub SizeOfImage: DWORD,
    pub SizeOfHeaders: DWORD,
    pub CheckSum: DWORD,
    pub Subsystem: WORD,
    pub DllCharacteristics: WORD,
    pub SizeOfStackReserve: ULONGLONG,
    pub SizeOfStackCommit: ULONGLONG,
    pub SizeOfHeapReserve: ULONGLONG,
    pub SizeOfHeapCommit: ULONGLONG,
    pub LoaderFlags: DWORD,
    pub NumberOfRvaAndSizes: DWORD,
    pub DataDirectory: [IMAGE_DATA_DIRECTORY; IMAGE_NUMBEROF_DIRECTORY_ENTRIES],
}

#[repr(C)]
pub struct IMAGE_DATA_DIRECTORY {
    pub VirtualAddress: DWORD,
    pub Size: DWORD,
}
#[repr(C)]
pub struct IMAGE_EXPORT_DIRECTORY {
    pub Characteristics: DWORD,
    pub TimeDateStamp: DWORD,
    pub MajorVersion: WORD,
    pub MinorVersion: WORD,
    pub Name: DWORD,
    pub Base: DWORD,
    pub NumberOfFunctions: DWORD,
    pub NumberOfNames: DWORD,
    pub AddressOfFunctions: DWORD,
    pub AddressOfNames: DWORD,
    pub AddressOfNameOrdinals: DWORD,
}

const IMAGE_SIZEOF_SHORT_NAME: usize = 8;

#[repr(C)]
pub struct IMAGE_SECTION_HEADER {
    pub Name: [BYTE; IMAGE_SIZEOF_SHORT_NAME],
    pub Misc: DWORD, // Represents the union as a DWORD directly.
    pub VirtualAddress: DWORD,
    pub SizeOfRawData: DWORD,
    pub PointerToRawData: DWORD,
    pub PointerToRelocations: DWORD,
    pub PointerToLinenumbers: DWORD,
    pub NumberOfRelocations: WORD,
    pub NumberOfLinenumbers: WORD,
    pub Characteristics: DWORD,
}
#[repr(C)]
pub struct BASE_RELOCATION_BLOCK {
    pub PageAddress: DWORD,
    pub BlockSize: DWORD,
}
#[repr(C)]
pub struct BASE_RELOCATION_ENTRY {
    pub data: SHORT,
}

impl BASE_RELOCATION_ENTRY {
    pub fn offset(&self) -> SHORT {
        self.data & 0x0FFF
    }

    pub fn type_(&self) -> SHORT {
        (self.data >> 12) & 0xF
    }
}

#[repr(C)]
pub struct IMAGE_IMPORT_DESCRIPTOR {
    // Directly using DWORD to substitute the union
    pub OriginalFirstThunk: DWORD,
    pub TimeDateStamp: DWORD,
    pub ForwarderChain: DWORD,
    pub Name: DWORD,
    pub FirstThunk: DWORD,
}

pub struct IMAGE_IMPORT_BY_NAME {
    pub Hint: WORD,
    pub Name: [CHAR; 1],
}

#[allow(unused)]
unsafe fn print_lpcwstr(lpcwstr: *const u16) {
    let mut len = 0;
    while *lpcwstr.offset(len) != 0 {
        len += 1;
    }
    let slice = std::slice::from_raw_parts(lpcwstr, len as usize);
    let os_string = OsString::from_wide(slice);
    if let Some(string) = os_string.to_str() {
        println!("{}", string);
    } else {
        eprintln!("Failed to convert LPCWSTR to a String");
    }
}

#[allow(unused)]
pub unsafe fn print_lpcstr(lpcstr: *const i8) {
    if lpcstr.is_null() {
        println!("Null pointer!");
        return;
    }

    // Convert the LPCSTR (pointer to a null-terminated string) to a CStr.
    let c_str = CStr::from_ptr(lpcstr);

    // Convert the CStr to a Rust string slice (&str) for printing.
    // This step checks the string for valid UTF-8 encoding.
    match c_str.to_str() {
        Ok(str_slice) => println!("{}", str_slice),
        Err(e) => println!("Failed to convert LPCSTR to a Rust string: {:?}", e),
    }
}
fn crc32(bytes: &[u8]) -> u32 {
    let mut hasher = Hasher::new();
    hasher.update(bytes);
    hasher.finalize()
}

pub fn wcscmp_case_insens(str1: LPCWSTR, str2: LPCWSTR) -> bool {
    let bytes1 = unsafe { lpcwstr_to_bytes_lowercase(str1) };
    let bytes2 = unsafe { lpcwstr_to_bytes_lowercase(str2) };
    let crc1 = crc32(&bytes1);
    let crc2 = crc32(&bytes2);
    crc1 == crc2
}
pub fn strcmp_case_insens(str1: LPCSTR, str2: LPCSTR) -> bool {
    let bytes1 = unsafe { lpcstr_to_bytes_lowercase(str1) };
    let bytes2 = unsafe { lpcstr_to_bytes_lowercase(str2) };
    let crc1 = crc32(&bytes1);
    let crc2 = crc32(&bytes2);
    crc1 == crc2
}
unsafe fn lpcwstr_to_bytes_lowercase(input: LPCWSTR) -> Vec<u8> {
    let mut wide_chars = Vec::new();
    let mut offset = 0;
    while *input.offset(offset) != 0 {
        let wide_char = *input.offset(offset);
        let char = std::char::from_u32(wide_char as u32)
            .map(|c| {
                if c.is_ascii_alphabetic() {
                    c.to_ascii_lowercase()
                } else {
                    c
                }
            })
            .unwrap_or('\u{0}')
            .encode_utf16(&mut [0u16; 2])[0];

        wide_chars.push(char);
        offset += 1;
    }
    wide_chars
        .iter()
        .flat_map(|&wide_char| vec![(wide_char >> 8) as u8, (wide_char & 0xFF) as u8])
        .collect()
}
unsafe fn lpcstr_to_bytes_lowercase(input: LPCSTR) -> Vec<u8> {
    let mut result = Vec::new();
    let mut offset = 0;

    while *input.offset(offset) != 0 {
        let c = *input.offset(offset) as u8;

        let lowercase_c = if c.is_ascii_alphabetic() {
            c.to_ascii_lowercase()
        } else {
            c
        };

        result.push(lowercase_c);
        offset += 1;
    }

    result
}
