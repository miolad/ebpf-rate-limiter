const std = @import("std");
const clap = @import("clap");
const libbpf = @cImport({
    @cInclude("libbpf.h");
});
var bpf_prog = @embedFile("@bpf_prog").*;

const loader_section_name = "veryverylongsectionnametobelongerthananyotherrealisticsectionnameusedinpractice";
const bpf = std.os.linux.BPF;

pub fn main() !void {
    // Using the C allocator since we are already linking with libc (due to libbpf)
    const allocator = std.heap.c_allocator;

    // Setup clap
    const params = comptime clap.parseParamsComptime(
        \\-h, --help            Display this help message and exit.
        \\-o, --object <str>    Path to eBPF object file to rate limit.
        \\-n, --name <str>      Name of the eBPF program in the provided object file to rate limit.
    );
    var diag = clap.Diagnostic{};
    var res = clap.parse(clap.Help, &params, clap.parsers.default, .{
        .allocator = allocator,
    }) catch |err| {
        try diag.reportToFile(.stderr(), err);
        return err;
    };
    defer res.deinit();

    if (res.args.help != 0) {
        var buf: [64]u8 = undefined;
        var writer = std.fs.File.stdout().writer(&buf);
        try writer.interface.print("Usage: ", .{});
        try writer.interface.flush();
        try clap.usageToFile(.stdout(), clap.Help, &params);
        try writer.interface.print("\n\n", .{});
        try writer.interface.flush();
        try clap.helpToFile(.stdout(), clap.Help, &params, .{});
        return;
    }
    if (res.args.object == null or res.args.name == null)
        return error.MissingRequiredArguments;

    // Open client eBPF object
    const client_obj = libbpf.bpf_object__open_file(
        res.args.object.?.ptr,
        null,
    ) orelse return error.OpenBpfObjectFailed;
    defer libbpf.bpf_object__close(client_obj);

    // Fetch client program
    const client_prog = libbpf.bpf_object__find_program_by_name(
        client_obj,
        res.args.name.?.ptr,
    ) orelse return error.FindProgramFailed;

    const auto_load = libbpf.bpf_program__autoload(client_prog);
    const auto_attach = libbpf.bpf_program__autoattach(client_prog);
    const client_prog_type: bpf.ProgType = @enumFromInt(libbpf.bpf_program__type(client_prog));
    const client_prog_attach_type: bpf.AttachType = @enumFromInt(libbpf.bpf_program__get_expected_attach_type(client_prog));
    std.debug.print(
        "Client eBPF program '{s}' opened successfully.\n\tAuto-load: {}\n\tAuto-attach: {}\n\tProgram type: {}\n\tAttach type: {}\n",
        .{ res.args.name.?, auto_load, auto_attach, client_prog_type, client_prog_attach_type },
    );

    // Update loader eBPF program's section name to match the client's
    const client_program_section_name: [*:0]const u8 = libbpf.bpf_program__section_name(client_prog);
    {
        var last_index: usize = 0;
        while (std.mem.indexOf(u8, bpf_prog[last_index..], loader_section_name)) |index| {
            const b = try std.fmt.bufPrintZ(
                bpf_prog[last_index..][index..(index + loader_section_name.len)],
                "{s}",
                .{client_program_section_name},
            );
            last_index = index + b.len + 1;
        }
    }

    // Open loader eBPF object
    const loader_obj = libbpf.bpf_object__open_mem(
        &bpf_prog,
        bpf_prog.len,
        null,
    ) orelse return error.OpenBpfObjectFailed;
    defer libbpf.bpf_object__close(loader_obj);

    // Fetch loader program
    const loader_prog = libbpf.bpf_object__find_program_by_name(
        loader_obj,
        "loader",
    ) orelse return error.FindProgramFailed;

    // // Set loader program type and attach type to match client program
    // if (libbpf.bpf_program__set_type(loader_prog, @intFromEnum(client_prog_type)) != 0) return error.SetProgramTypeFailed;
    // if (libbpf.bpf_program__set_expected_attach_type(loader_prog, @intFromEnum(client_prog_attach_type)) != 0) return error.SetProgramAttachTypeFailed;

    // if (client_prog_type == .tracing) {
    //     // For tracing programs, we need to set the attach target as well.
    //     // Retrieve the attach target of the client from its ELF section name.
    //     const client_elf_sec_name = std.mem.span(libbpf.bpf_program__section_name(client_prog));
    //     var iter = std.mem.splitScalar(u8, client_elf_sec_name, '/');
    //     _ = iter.next(); // Skip attach type
    //     const attach_target = iter.next() orelse return error.InvalidElfSectionName;

    //     if (libbpf.bpf_program__set_attach_target(loader_prog, 0, attach_target.ptr) != 0)
    //         return error.SetProgramAttachTargetFailed;
    // }

    // Load client and loader programs
    if (libbpf.bpf_object__load(client_obj) != 0) return error.LoadBpfObjectFailed;
    if (libbpf.bpf_object__load(loader_obj) != 0) return error.LoadBpfObjectFailed;

    // Insert client program into loader's prog_array map
    const prog_array_map = libbpf.bpf_object__find_map_by_name(loader_obj, "prog_array") orelse return error.FindMapFailed;
    const client_prog_fd = libbpf.bpf_program__fd(client_prog);
    if (client_prog_fd < 0) return error.GetProgramFdFailed;
    const zero: u32 = 0;
    if (libbpf.bpf_map__update_elem(
        prog_array_map,
        &zero,
        4,
        &client_prog_fd,
        4,
        bpf.ANY,
    ) < 0) return error.UpdateMapFailed;

    const loader_link = libbpf.bpf_program__attach(loader_prog) orelse return error.AttachProgramFailed;
    defer _ = libbpf.bpf_link__destroy(loader_link);

    // Wait for user input before exiting
    {
        var inbuf: [1024]u8 = undefined;
        var outbuf: [1024]u8 = undefined;

        var stdin = std.fs.File.stdin().reader(&inbuf);
        var output = std.Io.Writer.fixed(&outbuf);

        _ = stdin.interface.streamDelimiterLimit(&output, '\n', .unlimited) catch {};
    }
}
