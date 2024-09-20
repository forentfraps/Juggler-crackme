//! By convention, root.zig is the root source file when making a library. If
//! you are making an executable, the convention is to delete this file and
//! start with main.zig instead.
const std = @import("std");
const testing = std.testing;
const win = @import("std").os.windows;

const THREADENTRY32 = struct {
    dwSize: win.DWORD,
    cntUsage: win.DWORD,
    th32ThreadID: win.DWORD,
    th32OwnerProcessID: win.DWORD,
    tpBasePri: win.DWORD,
    tpDeltaPri: win.DWORD,
    dwFlags: win.DWORD,
};
const OPT_ARG = struct {
    arg1: win.DWORD,
    arg2: win.DWORD,
    arg3: u64,
    arg4: u64,
};
const _Thread32First = *const fn (win.HANDLE, *THREADENTRY32) c_int;
const _Thread32Next = *const fn (win.HANDLE, *THREADENTRY32) c_int;
const _OpenThread = *const fn (win.DWORD, c_int, win.DWORD) win.HANDLE;
const _SuspendThread = *const fn (win.HANDLE) win.DWORD;
const _ResumeThread = *const fn (win.HANDLE) win.DWORD;
const _GetThreadContext = *const fn (win.HANDLE, *win.CONTEXT) c_int;

extern fn unlock_thread(u64) void;

pub fn NtContinueExPatcher() !void {
    asm volatile (
        \\ 2:
        \\jmp 2b
        \\ret
        \\.byte 0xcc
        \\.word 0xcccc
        \\.word 0x48cc
    );
    const current_thread_id = std.Thread.getCurrentId();
    const current_process_id = win.GetCurrentProcessId();
    const kernel32_s = "kernel32.dll";
    var buf: [kernel32_s.len + 1]u16 = undefined;
    for (0..kernel32_s.len + 1) |i| {
        buf[i] = @as(u16, @intCast(kernel32_s[i]));
    }

    const kernel32 = win.kernel32.GetModuleHandleW(@as([*:0]u16, @ptrCast(buf[0..].ptr))).?;
    const ntdll_s = "ntdll.dll";
    var buf2: [ntdll_s.len + 1]u16 = undefined;
    for (0..ntdll_s.len + 1) |i| {
        buf2[i] = @as(u16, @intCast(ntdll_s[i]));
    }

    const ntdll = win.kernel32.GetModuleHandleW(@as([*:0]u16, @ptrCast(buf2[0..].ptr))).?;

    const Thread32First: _Thread32First = @ptrCast(win.kernel32.GetProcAddress(kernel32, "Thread32First").?);
    const Thread32Next: _Thread32Next = @ptrCast(win.kernel32.GetProcAddress(kernel32, "Thread32Next").?);
    const OpenThread: _OpenThread = @ptrCast(win.kernel32.GetProcAddress(kernel32, "OpenThread").?);
    const SuspendThread: _SuspendThread = @ptrCast(win.kernel32.GetProcAddress(kernel32, "SuspendThread").?);
    const NtContinueEx: [*]u8 = @ptrCast(win.kernel32.GetProcAddress(ntdll, "ZwContinueEx").?);
    const ResumeThread: _ResumeThread = @ptrCast(win.kernel32.GetProcAddress(kernel32, "ResumeThread").?);
    const GetThreadContext: _GetThreadContext = @ptrCast(win.kernel32.GetProcAddress(kernel32, "GetThreadContext").?);

    // Take a snapshot of all threads in the system.
    const TH32CS_SNAPTHREAD = 0x00000004;
    const hSnapshot = win.kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

    if (hSnapshot == win.INVALID_HANDLE_VALUE) {
        return;
    }

    var te32: THREADENTRY32 = undefined;
    te32.dwSize = @sizeOf(THREADENTRY32);

    // Iterate over the threads.
    if (Thread32First(hSnapshot, &te32) == 0) {
        win.CloseHandle(hSnapshot);
        return;
    }

    var found_thread_id: win.DWORD = 0;

    while (true) {
        // Check if the thread belongs to the current process and is not the current thread.
        if (te32.th32OwnerProcessID == current_process_id and te32.th32ThreadID != current_thread_id) {
            found_thread_id = te32.th32ThreadID;
            break;
        }
        if (Thread32Next(hSnapshot, &te32) == 0) {
            // No more threads to iterate over.
            break;
        }
    }

    // Clean up handles.
    win.CloseHandle(hSnapshot);

    const THREAD_SUSPEND_RESUME = 0x0002;
    const THREAD_GET_CONTEXT = 0x0008;
    const target_thread_handle = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT, 0, found_thread_id);

    const allocator = std.heap.page_allocator;
    var opt_arg: *OPT_ARG = try allocator.create(OPT_ARG);
    opt_arg.arg1 = 0;
    opt_arg.arg2 = 0;
    var thr_context: *win.CONTEXT = try allocator.create(win.CONTEXT);
    thr_context.ContextFlags = 0x0010001F;
    const suspend_count = SuspendThread(target_thread_handle);
    _ = GetThreadContext(target_thread_handle, thr_context);
    opt_arg.arg3 = suspend_count;

    _ = ResumeThread(target_thread_handle);
    const RIP: [*]u8 = @ptrFromInt(thr_context.Rip);
    const KeyAddr: [*]u8 = @ptrFromInt(thr_context.Rax);
    for (0..16) |_i| {
        const i: u8 = @intCast(_i);
        KeyAddr[i] = ((i ^ (i + 127)) | 60) - 60;
    }
    thr_context.Rax = 0;
    const syscall_number = NtContinueEx[4];
    opt_arg.arg4 = @as(u64, @intCast(win.peb().BeingDebugged & 1));
    var nt_continue_ex_payload: [26]u8 = [_]u8{ 0x66, 0xB8, 0x02, 0x01, 0x49, 0xBA, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x48, 0xBA, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x0F, 0x05 };
    // mov ax, syscall_number
    // movabs r10, context_ptr
    // movabs rdx, opt_arg
    // syscall
    const syscall_number_ptr: *align(1) u16 = @ptrCast(nt_continue_ex_payload[2..].ptr);
    const context_ptr: *align(1) u64 = @ptrCast(nt_continue_ex_payload[6..].ptr);
    const optional_arg_ptr: *align(1) u64 = @ptrCast(nt_continue_ex_payload[16..].ptr);
    syscall_number_ptr.* = syscall_number;
    context_ptr.* = @intFromPtr(thr_context);
    optional_arg_ptr.* = @intFromPtr(opt_arg);

    //Find the start of 0xcc block
    var offset: usize = 0;
    while (RIP[offset] != 0xc3) {
        offset += 1;
    }
    offset += 1;

    @memcpy(@as([*]u8, @ptrFromInt(thr_context.Rip + offset))[0..26], nt_continue_ex_payload[0..26]);
    const old_rip = thr_context.Rip;
    thr_context.Rip = thr_context.Rip + offset + 2048;

    unlock_thread(old_rip);
    return;
}
pub export fn DllMain(
    _: ?win.HINSTANCE,
    fdwReason: u32,
    _: win.LPVOID,
) c_int {
    const DLL_PROCESS_DETACH = 0;
    const DLL_PROCESS_ATTACH = 1;
    const DLL_THREAD_ATTACH = 2;
    const DLL_THREAD_DETACH = 3;

    const allocator = std.heap.page_allocator;
    switch (fdwReason) {
        DLL_PROCESS_ATTACH => {
            const thread = std.Thread.spawn(.{ .allocator = allocator }, NtContinueExPatcher, .{}) catch {
                return 0;
            };
            thread.detach();
        },
        DLL_PROCESS_DETACH => {},
        DLL_THREAD_ATTACH => {},
        DLL_THREAD_DETACH => {},
        else => {},
    }
    return 1; // Return true to indicate success
}
