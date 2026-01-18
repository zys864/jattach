//! HotSpot JVM Dynamic Attach implementation
//!
//! Copyright The jattach authors
//! SPDX-License-Identifier: Apache-2.0

const std = @import("std");
const builtin = @import("builtin");
const main = @import("./main.zig");
const psutil = @import("./psutil.zig");

const c = @cImport({
    @cInclude("unistd.h");
    @cInclude("sys/socket.h");
    @cInclude("sys/un.h");
    @cInclude("sys/stat.h");
    @cInclude("fcntl.h");
    @cInclude("signal.h");
    @cInclude("time.h");
    @cInclude("string.h");
    @cInclude("errno.h");
});

const MAX_PATH = main.MAX_PATH;

/// Check if remote JVM has already opened socket for Dynamic Attach
fn checkSocket(pid: i32) bool {
    var path_buf: [MAX_PATH]u8 = undefined;
    const tmp_path = psutil.getTmpPathSlice();
    const path = std.fmt.bufPrint(&path_buf, "{s}/.java_pid{d}", .{ tmp_path, pid }) catch return false;

    var path_z: [MAX_PATH]u8 = undefined;
    @memcpy(path_z[0..path.len], path);
    path_z[path.len] = 0;

    var stats: c.struct_stat = undefined;
    if (c.stat(&path_z, &stats) != 0) {
        return false;
    }

    // Check if it's a socket
    return (stats.st_mode & c.S_IFMT) == c.S_IFSOCK;
}

/// Get owner uid of a file
fn getFileOwner(path: []const u8) c.uid_t {
    var path_z: [MAX_PATH]u8 = undefined;
    if (path.len >= path_z.len) return @bitCast(@as(i32, -1));
    @memcpy(path_z[0..path.len], path);
    path_z[path.len] = 0;

    var stats: c.struct_stat = undefined;
    if (c.stat(&path_z, &stats) == 0) {
        return stats.st_uid;
    }
    return @bitCast(@as(i32, -1));
}

/// Force remote JVM to start Attach listener
fn startAttachMechanism(pid: i32, nspid: i32) !void {
    var path_buf: [MAX_PATH]u8 = undefined;
    const tmp_path = psutil.getTmpPathSlice();

    const effective_pid = if (main.mnt_changed > 0) nspid else pid;

    // Try to create attach trigger in process cwd first
    var path = std.fmt.bufPrint(&path_buf, "/proc/{d}/cwd/.attach_pid{d}", .{ effective_pid, nspid }) catch return error.PathTooLong;

    var file_created = false;
    var final_path: []const u8 = path;

    var path_z: [MAX_PATH]u8 = undefined;
    @memcpy(path_z[0..path.len], path);
    path_z[path.len] = 0;

    const fd = c.creat(&path_z, 0o660);
    if (fd != -1) {
        _ = c.close(fd);
        // Check if file ownership is correct
        const owner = getFileOwner(path);
        if (owner != c.geteuid()) {
            // Ownership changed, remove and try /tmp
            _ = c.unlink(&path_z);
        } else {
            file_created = true;
        }
    }

    if (!file_created) {
        // Failed to create attach trigger in current directory. Retry in /tmp
        path = std.fmt.bufPrint(&path_buf, "{s}/.attach_pid{d}", .{ tmp_path, nspid }) catch return error.PathTooLong;
        final_path = path;

        @memcpy(path_z[0..path.len], path);
        path_z[path.len] = 0;

        const fd2 = c.creat(&path_z, 0o660);
        if (fd2 == -1) {
            return error.CreateFileFailed;
        }
        _ = c.close(fd2);
    }

    // Will clean up the file when done
    var cleanup_path_z: [MAX_PATH]u8 = undefined;
    @memcpy(cleanup_path_z[0..final_path.len], final_path);
    cleanup_path_z[final_path.len] = 0;

    defer _ = c.unlink(&cleanup_path_z);

    // Send SIGQUIT to the target process to trigger attach listener
    _ = c.kill(pid, c.SIGQUIT);

    // Wait for socket to appear with exponential backoff
    // Start with 20 ms sleep and increment delay each iteration. Total timeout is ~6000 ms
    var ts = c.timespec{ .tv_sec = 0, .tv_nsec = 20000000 };

    while (ts.tv_nsec < 500000000) {
        _ = c.nanosleep(&ts, null);

        if (checkSocket(nspid)) {
            return;
        }

        // Check if process is still alive
        if (c.kill(pid, 0) != 0) {
            return error.ProcessDied;
        }

        ts.tv_nsec += 20000000;
    }

    return error.Timeout;
}

/// Connect to UNIX domain socket created by JVM for Dynamic Attach
fn connectSocket(pid: i32) !c_int {
    var path_buf: [MAX_PATH]u8 = undefined;
    const tmp_path = psutil.getTmpPathSlice();
    const path = std.fmt.bufPrint(&path_buf, "{s}/.java_pid{d}", .{ tmp_path, pid }) catch return error.PathTooLong;

    const fd = c.socket(c.PF_UNIX, c.SOCK_STREAM, 0);
    if (fd == -1) {
        return error.SocketFailed;
    }
    errdefer _ = c.close(fd);

    var addr: c.sockaddr_un = undefined;
    addr.sun_family = c.AF_UNIX;
    @memset(&addr.sun_path, 0);

    // Copy path to address
    const path_len = @min(path.len, addr.sun_path.len - 1);
    for (0..path_len) |i| {
        addr.sun_path[i] = @intCast(path[i]);
    }

    if (c.connect(fd, @ptrCast(&addr), @sizeOf(c.sockaddr_un)) == -1) {
        _ = c.close(fd);
        return error.ConnectFailed;
    }

    return fd;
}

/// Send command with arguments to socket
fn writeCommand(fd: c_int, args: []const []const u8) !void {
    var buf: [8192]u8 = undefined;
    var pos: usize = 0;

    // jcmd has 2 arguments maximum; merge excessive arguments into one
    const cmd_args: usize = if (args.len >= 2 and std.mem.eql(u8, args[0], "jcmd"))
        2
    else if (args.len >= 4)
        4
    else
        args.len;

    // Protocol version "1"
    buf[pos] = '1';
    pos += 1;
    buf[pos] = 0;
    pos += 1;

    var i: usize = 0;
    while (i < args.len and pos < buf.len) : (i += 1) {
        if (i >= cmd_args and pos > 0) {
            // Merge with previous argument using space
            pos -= 1; // Remove null terminator
            buf[pos] = ' ';
            pos += 1;
        }

        const arg = args[i];
        const copy_len = @min(arg.len, buf.len - pos - 1);
        @memcpy(buf[pos .. pos + copy_len], arg[0..copy_len]);
        pos += copy_len;
        buf[pos] = 0;
        pos += 1;
    }

    // Pad with null terminators to have at least 4 arguments
    while (i < 4 and pos < buf.len) : (i += 1) {
        buf[pos] = 0;
        pos += 1;
    }

    // Write all data to socket
    var written: usize = 0;
    while (written < pos) {
        const n = c.write(fd, &buf[written], pos - written);
        if (n <= 0) {
            return error.WriteFailed;
        }
        written += @intCast(n);
    }
}

/// Mirror response from remote JVM to stdout
fn readResponse(fd: c_int, args: []const []const u8, print_output: bool) u8 {
    var buf: [8192]u8 = undefined;

    const bytes_read_signed = c.read(fd, &buf, buf.len - 1);
    if (bytes_read_signed <= 0) {
        if (bytes_read_signed == 0) {
            std.debug.print("Unexpected EOF reading response\n", .{});
        } else {
            std.debug.print("Error reading response\n", .{});
        }
        return 1;
    }

    var bytes_read: usize = @intCast(bytes_read_signed);

    // First line of response is the command result code
    buf[bytes_read] = 0;

    // Find the result code (first number in buffer)
    var result: u8 = 0;
    var code_end: usize = 0;
    while (code_end < bytes_read and buf[code_end] >= '0' and buf[code_end] <= '9') : (code_end += 1) {}
    if (code_end > 0) {
        result = std.fmt.parseInt(u8, buf[0..code_end], 10) catch 0;
    }

    // Special treatment of 'load' command
    if (args.len > 0 and std.mem.eql(u8, args[0], "load")) {
        // Read the entire output of the 'load' command
        var total: usize = bytes_read;
        while (total < buf.len - 1) {
            const n = c.read(fd, &buf[total], buf.len - 1 - total);
            if (n <= 0) break;
            total += @intCast(n);
        }
        bytes_read = total;
        buf[bytes_read] = 0;

        // Parse the return code of Agent_OnAttach
        if (result == 0 and bytes_read >= 2) {
            const rest = buf[2..bytes_read];
            if (std.mem.startsWith(u8, rest, "return code: ")) {
                // JDK 9+: Agent_OnAttach result comes on the second line after "return code: "
                var end: usize = 13;
                while (end < rest.len and rest[end] >= '0' and rest[end] <= '9') : (end += 1) {}
                result = std.fmt.parseInt(u8, rest[13..end], 10) catch 0;
            } else if (rest.len > 0 and ((rest[0] >= '0' and rest[0] <= '9') or rest[0] == '-')) {
                // JDK 8: Agent_OnAttach result comes on the second line alone
                var end: usize = 0;
                if (rest[0] == '-') end = 1;
                while (end < rest.len and rest[end] >= '0' and rest[end] <= '9') : (end += 1) {}
                const val = std.fmt.parseInt(i16, rest[0..end], 10) catch 0;
                result = if (val < 0) 255 else @intCast(val);
            } else {
                // JDK 21+: load command always returns 0; the rest of output is an error message
                result = 255; // -1 as unsigned
            }
        }

        // Duplicate an error message passed from the JVM
        if (result == 255 and !print_output) {
            if (std.mem.indexOf(u8, buf[0..bytes_read], "\n")) |cr_pos| {
                if (cr_pos + 1 < bytes_read) {
                    std.debug.print("{s}", .{buf[cr_pos + 1 .. bytes_read]});
                }
            } else if (args.len > 1) {
                std.debug.print("Target JVM failed to load {s}\n", .{args[1]});
            }
        }
    }

    if (print_output) {
        std.debug.print("JVM response code = ", .{});

        // Write initial buffer
        std.debug.print("{s}", .{buf[0..bytes_read]});

        // Continue reading and writing
        while (true) {
            const n = c.read(fd, &buf, buf.len);
            if (n <= 0) break;
            std.debug.print("{s}", .{buf[0..@intCast(n)]});
        }

        std.debug.print("\n", .{});
    }

    return result;
}

/// Main HotSpot attach function
pub fn jattachHotspot(pid: i32, nspid: i32, args: []const []const u8, print_output: bool) u8 {
    if (!checkSocket(nspid)) {
        startAttachMechanism(pid, nspid) catch {
            std.debug.print("Could not start attach mechanism\n", .{});
            return 1;
        };
    }

    const fd = connectSocket(nspid) catch {
        std.debug.print("Could not connect to socket\n", .{});
        return 1;
    };
    defer _ = c.close(fd);

    if (print_output) {
        std.debug.print("Connected to remote JVM\n", .{});
    }

    writeCommand(fd, args) catch {
        std.debug.print("Error writing to socket\n", .{});
        return 1;
    };

    return readResponse(fd, args, print_output);
}

test "checkSocket returns false for non-existent" {
    try std.testing.expect(!checkSocket(999999));
}
