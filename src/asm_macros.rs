#[allow(dead_code)]
extern "C" {
    pub fn appendByte2Rip();
}
#[macro_export]
macro_rules! hide {
    () => {
        asm!("call appendByte2Rip", ".byte 0x9a", options(nostack));
    };
}

#[macro_export]
macro_rules! fake_exit{
    () => {
        unsafe {
        asm!(
        ".byte 0xe8",
        ".2byte 0x0002",
        ".2byte 0x0000",
        ".2byte 0x8e7d",
        "pop rax",
        "add rax, 29",
        "xor r9, 0xf8145",
        "push rax",
        "ret",
        ".8byte 0xcccccccccccccccc",
        ".4byte 0xCCCCCCCC",
        ".byte 0x9a",
        out("rax") _,
        out("r9") _
        )
        }
    }
}
