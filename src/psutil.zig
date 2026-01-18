//! Process utilities for jattach
//!
//! Copyright The jattach authors
//! SPDX-License-Identifier: Apache-2.0

const std = @import("std");
const builtin = @import("builtin");
const main = @import("./main.zig");

const c = @cImport({
    @cInclude("unistd.h");
    @cInclude("sys/types.h");
    @cInclude("sys/stat.h");
    @cInclude("fcntl.h");
    @cInclude("dirent.h");
    @cInclude("string.h");
    @cInclude("stdlib.h");
    @cInclude("stdio.h");
});

pub const MAX_PATH = main.MAX_PATH;

/// Global tmp_path buffer
var tmp_path_buf: [MAX_PATH - 100]u8 = undefined;
var tmp_path_len: usize = 0;

/// Get the current tmp_path as a slice
pub fn getTmpPathSlice() []const u8 {
    return tmp_path_buf[0..tmp_path_len];
}

/// Process information structure
pub const ProcessInfo = struct {
    uid: c.uid_t,
    gid: c.gid_t,
    nspid: i32,
};

/// Gets /tmp path of the specified process
pub fn getTmpPath(pid: i32) void {
    // Try user-provided alternative path first
    if (c.getenv("JATTACH_PATH")) |jattach_path| {
        const path_slice = std.mem.sliceTo(jattach_path, 0);
        if (path_slice.len < tmp_path_buf.len) {
            @memcpy(tmp_path_buf[0..path_slice.len], path_slice);
            tmp_path_len = path_slice.len;
            return;
        }
    }

    if (getTmpPathR(pid)) |path| {
        tmp_path_len = path.len;
    } else {
        const default = "/tmp";
        @memcpy(tmp_path_buf[0..default.len], default);
        tmp_path_len = default.len;
    }
}

/// The reentrant version of getTmpPath
fn getTmpPathR(pid: i32) ?[]const u8 {
    switch (builtin.os.tag) {
        .linux => {
            const path = std.fmt.bufPrint(&tmp_path_buf, "/proc/{d}/root/tmp", .{pid}) catch return null;
            // Check if the remote /tmp can be accessed via /proc/[pid]/root
            var path_z: [MAX_PATH]u8 = undefined;
            @memcpy(path_z[0..path.len], path);
            path_z[path.len] = 0;

            var stats: c.struct_stat = undefined;
            if (c.stat(&path_z, &stats) == 0) {
                return path;
            }
            return null;
        },
        .macos => {
            // macOS has a secure per-user temporary directory
            const result = c.confstr(c._CS_DARWIN_USER_TEMP_DIR, &tmp_path_buf, tmp_path_buf.len);
            if (result > 0 and result <= tmp_path_buf.len) {
                const len = result - 1; // confstr includes null terminator in count
                return tmp_path_buf[0..len];
            }
            return null;
        },
        .freebsd => {
            // Use default /tmp path on FreeBSD
            return null;
        },
        else => return null,
    }
}

/// Gets process information (uid, gid, nspid)
pub fn getProcessInfo(pid: i32) !ProcessInfo {
    switch (builtin.os.tag) {
        .linux => return getProcessInfoLinux(pid),
        .macos => return getProcessInfoMacOS(pid),
        .freebsd => return getProcessInfoFreeBSD(pid),
        else => @compileError("Unsupported platform"),
    }
}

fn getProcessInfoLinux(pid: i32) !ProcessInfo {
    var path_buf: [64]u8 = undefined;
    const path = std.fmt.bufPrint(&path_buf, "/proc/{d}/status", .{pid}) catch return error.PathTooLong;

    var path_z: [64]u8 = undefined;
    @memcpy(path_z[0..path.len], path);
    path_z[path.len] = 0;

    const file = c.fopen(&path_z, "r");
    if (file == null) {
        return error.ProcessNotFound;
    }
    defer _ = c.fclose(file);

    var result = ProcessInfo{
        .uid = 0,
        .gid = 0,
        .nspid = pid,
    };

    var nspid_found = false;
    var line_buf: [1024]u8 = undefined;

    while (c.fgets(&line_buf, line_buf.len, file) != null) {
        const line = std.mem.sliceTo(&line_buf, 0);

        if (std.mem.startsWith(u8, line, "Uid:")) {
            // Parse: Uid:\t<real>\t<effective>\t...
            var it = std.mem.tokenizeAny(u8, line[4..], "\t ");
            _ = it.next(); // Skip real UID
            if (it.next()) |effective_uid| {
                result.uid = std.fmt.parseInt(c.uid_t, effective_uid, 10) catch 0;
            }
        } else if (std.mem.startsWith(u8, line, "Gid:")) {
            // Parse: Gid:\t<real>\t<effective>\t...
            var it = std.mem.tokenizeAny(u8, line[4..], "\t ");
            _ = it.next(); // Skip real GID
            if (it.next()) |effective_gid| {
                result.gid = std.fmt.parseInt(c.gid_t, effective_gid, 10) catch 0;
            }
        } else if (std.mem.startsWith(u8, line, "NStgid:")) {
            // PID namespaces can be nested; the last one is the innermost one
            var it = std.mem.tokenizeAny(u8, line[7..], "\t \n");
            while (it.next()) |nspid_str| {
                result.nspid = std.fmt.parseInt(i32, nspid_str, 10) catch result.nspid;
            }
            nspid_found = true;
        }
    }

    if (!nspid_found) {
        result.nspid = altLookupNspid(pid);
    }

    return result;
}

/// Alternative lookup for nspid on older Linux kernels
fn altLookupNspid(pid: i32) i32 {
    var path_buf: [300]u8 = undefined;
    const ns_path = std.fmt.bufPrint(&path_buf, "/proc/{d}/ns/pid", .{pid}) catch return pid;

    var ns_path_z: [300]u8 = undefined;
    @memcpy(ns_path_z[0..ns_path.len], ns_path);
    ns_path_z[ns_path.len] = 0;

    var oldns_stat: c.struct_stat = undefined;
    var newns_stat: c.struct_stat = undefined;

    // Don't bother looking for container PID if we are already in the same PID namespace
    if (c.stat("/proc/self/ns/pid", &oldns_stat) == 0 and c.stat(&ns_path_z, &newns_stat) == 0) {
        if (oldns_stat.st_ino == newns_stat.st_ino) {
            return pid;
        }
    }

    // Browse all PIDs in the namespace of the target process
    var proc_path_buf: [300]u8 = undefined;
    const proc_path = std.fmt.bufPrint(&proc_path_buf, "/proc/{d}/root/proc", .{pid}) catch return pid;

    var proc_path_z: [300]u8 = undefined;
    @memcpy(proc_path_z[0..proc_path.len], proc_path);
    proc_path_z[proc_path.len] = 0;

    const dir = c.opendir(&proc_path_z);
    if (dir == null) return pid;
    defer _ = c.closedir(dir);

    while (c.readdir(dir)) |entry| {
        const name = std.mem.sliceTo(&entry.*.d_name, 0);
        if (name.len > 0 and name[0] >= '1' and name[0] <= '9') {
            // Check if /proc/<container-pid>/sched points back to <host-pid>
            var sched_path_buf: [300]u8 = undefined;
            const sched_path = std.fmt.bufPrint(&sched_path_buf, "/proc/{d}/root/proc/{s}/sched", .{ pid, name }) catch continue;

            if (schedGetHostPid(sched_path) == pid) {
                return std.fmt.parseInt(i32, name, 10) catch pid;
            }
        }
    }

    return pid;
}

/// Parse host PID from sched file
fn schedGetHostPid(path: []const u8) i32 {
    var path_z: [300]u8 = undefined;
    if (path.len >= path_z.len) return -1;
    @memcpy(path_z[0..path.len], path);
    path_z[path.len] = 0;

    const file = c.fopen(&path_z, "r");
    if (file == null) return -1;
    defer _ = c.fclose(file);

    var line_buf: [256]u8 = undefined;
    if (c.fgets(&line_buf, line_buf.len, file) == null) return -1;

    const line = std.mem.sliceTo(&line_buf, 0);

    // The first line looks like: java (1234, #threads: 12)
    if (std.mem.lastIndexOf(u8, line, "(")) |paren_pos| {
        const after_paren = line[paren_pos + 1 ..];
        var it = std.mem.tokenizeAny(u8, after_paren, ", ");
        if (it.next()) |pid_str| {
            return std.fmt.parseInt(i32, pid_str, 10) catch -1;
        }
    }

    return -1;
}

fn getProcessInfoMacOS(pid: i32) !ProcessInfo {
    const sysctl_c = @cImport({
        @cInclude("sys/sysctl.h");
    });

    var mib = [_]c_int{ sysctl_c.CTL_KERN, sysctl_c.KERN_PROC, sysctl_c.KERN_PROC_PID, pid };
    var info: sysctl_c.struct_kinfo_proc = undefined;
    var len: usize = @sizeOf(@TypeOf(info));

    const result = sysctl_c.sysctl(&mib, 4, &info, &len, null, 0);
    if (result < 0 or len == 0) {
        return error.ProcessNotFound;
    }

    return ProcessInfo{
        .uid = info.kp_eproc.e_ucred.cr_uid,
        .gid = info.kp_eproc.e_pcred.p_rgid,
        .nspid = pid,
    };
}

fn getProcessInfoFreeBSD(pid: i32) !ProcessInfo {
    const sysctl_c = @cImport({
        @cInclude("sys/sysctl.h");
        @cInclude("sys/user.h");
    });

    var mib = [_]c_int{ sysctl_c.CTL_KERN, sysctl_c.KERN_PROC, sysctl_c.KERN_PROC_PID, pid };
    var info: sysctl_c.struct_kinfo_proc = undefined;
    var len: usize = @sizeOf(@TypeOf(info));

    const result = sysctl_c.sysctl(&mib, 4, &info, &len, null, 0);
    if (result < 0 or len == 0) {
        return error.ProcessNotFound;
    }

    return ProcessInfo{
        .uid = info.ki_uid,
        .gid = info.ki_groups[0],
        .nspid = pid,
    };
}

/// Tries to enter the namespace of the target process
/// Returns 1 if namespace changed, 0 if same namespace, -1 on failure
pub fn enterNs(pid: i32, ns_type: []const u8) i32 {
    switch (builtin.os.tag) {
        .linux => return enterNsLinux(pid, ns_type),
        else => return 0, // No namespace support on other platforms
    }
}

fn enterNsLinux(pid: i32, ns_type: []const u8) i32 {
    const linux = std.os.linux;

    var path_buf: [64]u8 = undefined;
    var selfpath_buf: [64]u8 = undefined;

    const path = std.fmt.bufPrint(&path_buf, "/proc/{d}/ns/{s}", .{ pid, ns_type }) catch return -1;
    const selfpath = std.fmt.bufPrint(&selfpath_buf, "/proc/self/ns/{s}", .{ns_type}) catch return -1;

    var path_z: [64]u8 = undefined;
    var selfpath_z: [64]u8 = undefined;
    @memcpy(path_z[0..path.len], path);
    path_z[path.len] = 0;
    @memcpy(selfpath_z[0..selfpath.len], selfpath);
    selfpath_z[selfpath.len] = 0;

    var oldns_stat: c.struct_stat = undefined;
    var newns_stat: c.struct_stat = undefined;

    if (c.stat(&selfpath_z, &oldns_stat) != 0) return -1;
    if (c.stat(&path_z, &newns_stat) != 0) return -1;

    // Don't try to call setns() if we're in the same namespace already
    if (oldns_stat.st_ino == newns_stat.st_ino) {
        return 0;
    }

    const newns_fd = c.open(&path_z, c.O_RDONLY);
    if (newns_fd < 0) return -1;
    defer _ = c.close(newns_fd);

    // Call setns syscall
    const result = linux.syscall2(.setns, @as(usize, @intCast(newns_fd)), 0);
    if (@as(isize, @bitCast(result)) < 0) {
        return -1;
    }

    return 1;
}

test "getTmpPath sets default" {
    getTmpPath(1);
    const path = getTmpPathSlice();
    try std.testing.expect(path.len > 0);
}
