const std = @import("std");
const libbpf = @cImport({
    @cInclude("libbpf.h");
});
const bpf_prog = @embedFile("@bpf_prog");

pub fn main() !void {
    std.debug.print("All your {s} are belong to us.\n", .{"codebase"});

    const Enum = enum { case1, case2 };
    const e: Enum = .case1;

    const t = @tagName(e);
    std.debug.print("Enum tag: {s}\n", .{t});

    std.debug.print("Embedded BPF program size: {d} bytes\n", .{bpf_prog.len});
}
