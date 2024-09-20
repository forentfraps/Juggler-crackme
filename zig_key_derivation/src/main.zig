const std = @import("std");
const win = @import("std").os.windows;
//Testing utils
pub fn main() !void {
    const s = "zig_key_derivation.dll";
    var buf: [s.len + 1]u16 = undefined;
    for (0..s.len + 1) |i| {
        buf[i] = @as(u16, @intCast(s[i]));
    }
    _ = win.kernel32.LoadLibraryW(@as([*:0]u16, @ptrCast(buf[0..].ptr)));
    var x: u8 = 0;
    while (true) {
        x ^= 1;
    }
}
