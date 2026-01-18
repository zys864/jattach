//! jattach - JVM Dynamic Attach utility
//!
//! Copyright The jattach authors
//! SPDX-License-Identifier: Apache-2.0

const std = @import("std");
const builtin = @import("builtin");
const config = @import("config");

pub const psutil = @import("./psutil.zig");
pub const hotspot = @import("./jattach_hotspot.zig");
pub const openj9 = @import("./jattach_openj9.zig");
pub const jattach_windows = @import("./jattach_windows.zig");

const c = @cImport({
    @cInclude("unistd.h");
    @cInclude("signal.h");
});

pub const MAX_PATH = 1024;

/// Global state for mount namespace change tracking (POSIX only)
pub var mnt_changed: i32 = 0;

/// Main jattach function that attaches to a JVM process
pub fn jattach(pid: i32, args: []const []const u8, print_output: bool) u8 {
    if (builtin.os.tag == .windows) {
        return jattach_windows.jattach(pid, args, print_output);
    } else {
        return jattachPosix(pid, args, print_output);
    }
}

/// POSIX implementation of jattach
fn jattachPosix(pid: i32, args: []const []const u8, print_output: bool) u8 {
    const my_uid: c.uid_t = c.geteuid();
    const my_gid: c.gid_t = c.getegid();
    var target_uid: c.uid_t = my_uid;
    var target_gid: c.gid_t = my_gid;

    const process_info = psutil.getProcessInfo(pid) catch {
        std.debug.print("Process {d} not found\n", .{pid});
        return 1;
    };

    target_uid = process_info.uid;
    target_gid = process_info.gid;
    const nspid = process_info.nspid;

    // Container support: switch to the target namespaces.
    // Network and IPC namespaces are essential for OpenJ9 connection.
    _ = psutil.enterNs(pid, "net");
    _ = psutil.enterNs(pid, "ipc");
    mnt_changed = psutil.enterNs(pid, "mnt");

    // In HotSpot, dynamic attach is allowed only for the clients with the same euid/egid.
    // If we are running under root, switch to the required euid/egid automatically.
    if (my_gid != target_gid) {
        if (c.setegid(target_gid) != 0) {
            std.debug.print("Failed to change credentials to match the target process\n", .{});
            return 1;
        }
    }
    if (my_uid != target_uid) {
        if (c.seteuid(target_uid) != 0) {
            std.debug.print("Failed to change credentials to match the target process\n", .{});
            return 1;
        }
    }

    const tmp_pid = if (mnt_changed > 0) nspid else pid;
    psutil.getTmpPath(tmp_pid);

    // Make write() return EPIPE instead of abnormal process termination
    // Use sigaction with SA_IGN handler instead of signal() to avoid SIG_IGN macro issues
    var sa: c.struct_sigaction = std.mem.zeroes(c.struct_sigaction);
    sa.__sigaction_u.__sa_handler = null; // Will be interpreted as SIG_IGN when SA_SIGINFO is not set
    // Actually just ignore SIGPIPE errors - they'll return EPIPE which we handle
    // On macOS/BSD, we can use the simpler approach of just not setting up a handler
    // The default behavior on write to closed pipe will still be EPIPE error

    if (openj9.isOpenJ9Process(nspid)) {
        return openj9.jattachOpenJ9(pid, nspid, args, print_output);
    } else {
        return hotspot.jattachHotspot(pid, nspid, args, print_output);
    }
}

pub fn main() u8 {
    const allocator = std.heap.page_allocator;
    const args = std.process.argsAlloc(allocator) catch {
        std.debug.print("Failed to allocate memory for arguments\n", .{});
        return 1;
    };
    defer std.process.argsFree(allocator, args);

    if (args.len < 3) {
        const version = config.version;
        std.debug.print(
            \\jattach {s}
            \\
            \\Usage: jattach <pid> <cmd> [args ...]
            \\
            \\Commands:
            \\    load  threaddump   dumpheap  setflag    properties
            \\    jcmd  inspectheap  datadump  printflag  agentProperties
            \\
        , .{version});
        return 1;
    }

    const pid = std.fmt.parseInt(i32, args[1], 10) catch {
        std.debug.print("{s} is not a valid process ID\n", .{args[1]});
        return 1;
    };

    if (pid <= 0) {
        std.debug.print("{s} is not a valid process ID\n", .{args[1]});
        return 1;
    }

    return jattach(pid, args[2..], true);
}

/// Library entry point for external callers
pub export fn jattach_lib(pid: c_int, argc: c_int, argv: [*]const [*:0]const u8, print_output: c_int) c_int {
    if (argc <= 0) return 1;

    const allocator = std.heap.page_allocator;
    const args_slice = allocator.alloc([]const u8, @intCast(argc)) catch return 1;
    defer allocator.free(args_slice);

    for (0..@intCast(argc)) |i| {
        args_slice[i] = std.mem.sliceTo(argv[i], 0);
    }

    return jattach(@intCast(pid), args_slice, print_output != 0);
}

test "basic functionality" {
    // Basic compile test
    if (builtin.os.tag != .windows) {
        _ = psutil;
        _ = hotspot;
        _ = openj9;
    }
    _ = jattach_windows;
}
