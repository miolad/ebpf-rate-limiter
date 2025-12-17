const std = @import("std");

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const libbpf_dep = b.dependency("libbpf", .{
        .target = target,
        .optimize = optimize,
    });

    const exe = b.addExecutable(.{
        .name = "ebpf_rate_limiter",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    exe.root_module.linkLibrary(libbpf_dep.artifact("bpf"));
    b.installArtifact(exe);

    const vmlinux_dep = b.dependency("vmlinux", .{});
    var buf: [32]u8 = undefined; // Large enough to account for any arch
    const vmlinux_path = vmlinux_dep.path(try std.fmt.bufPrint(&buf, "include/{s}", .{@tagName(target.result.cpu.arch)}));

    const obj = b.addObject(.{
        .name = "bpf_prog",
        .root_module = b.createModule(.{
            .target = b.resolveTargetQuery(.{
                .cpu_arch = switch (target.result.cpu.arch.endian()) {
                    .little => .bpfel,
                    .big => .bpfeb,
                },
                .os_tag = .freestanding,
            }),
            .optimize = .ReleaseFast,
            .strip = false, // Don't strip BTF section!
        }),
    });
    obj.root_module.addCSourceFile(.{ .file = b.path("src/bpf/prog.bpf.c") });
    obj.root_module.addIncludePath(vmlinux_path);
    obj.root_module.addSystemIncludePath(.{ .cwd_relative = "/usr/include" });
    exe.root_module.addAnonymousImport("@bpf_prog", .{
        .root_source_file = obj.getEmittedBin(),
    });
}
