//! OpenJ9 JVM Dynamic Attach implementation
//!
//! Copyright The jattach authors
//! SPDX-License-Identifier: Apache-2.0

const std = @import("std");
const builtin = @import("builtin");
const main = @import("main.zig");
const psutil = @import("psutil.zig");

const c = @cImport({
    @cInclude("unistd.h");
    @cInclude("sys/socket.h");
    @cInclude("sys/stat.h");
    @cInclude("sys/file.h");
    @cInclude("sys/ipc.h");
    @cInclude("sys/sem.h");
    @cInclude("netinet/in.h");
    @cInclude("dirent.h");
    @cInclude("fcntl.h");
    @cInclude("time.h");
    @cInclude("string.h");
    @cInclude("errno.h");
    @cInclude("stdio.h");
    @cInclude("stdlib.h");
});

const MAX_PATH = main.MAX_PATH;
const MAX_NOTIF_FILES = 256;

/// Notification file locks
var notif_lock: [MAX_NOTIF_FILES]c_int = [_]c_int{-1} ** MAX_NOTIF_FILES;

/// Translate HotSpot command to OpenJ9 equivalent
fn translateCommand(buf: []u8, args: []const []const u8) []const u8 {
    if (args.len == 0) {
        return "";
    }

    const cmd = args[0];

    if (std.mem.eql(u8, cmd, "load") and args.len >= 2) {
        if (args.len > 2 and std.mem.eql(u8, args[2], "true")) {
            const options = if (args.len > 3) args[3] else "";
            const result = std.fmt.bufPrint(buf, "ATTACH_LOADAGENTPATH({s},{s})", .{ args[1], options }) catch return "";
            return result;
        } else {
            const options = if (args.len > 3) args[3] else "";
            const result = std.fmt.bufPrint(buf, "ATTACH_LOADAGENT({s},{s})", .{ args[1], options }) catch return "";
            return result;
        }
    } else if (std.mem.eql(u8, cmd, "jcmd")) {
        var pos: usize = 0;
        const prefix = "ATTACH_DIAGNOSTICS:";
        @memcpy(buf[pos .. pos + prefix.len], prefix);
        pos += prefix.len;

        const subcmd = if (args.len > 1) args[1] else "help";
        @memcpy(buf[pos .. pos + subcmd.len], subcmd);
        pos += subcmd.len;

        var i: usize = 2;
        while (i < args.len and pos < buf.len - 1) : (i += 1) {
            buf[pos] = ',';
            pos += 1;
            const arg = args[i];
            const copy_len = @min(arg.len, buf.len - pos);
            @memcpy(buf[pos .. pos + copy_len], arg[0..copy_len]);
            pos += copy_len;
        }
        return buf[0..pos];
    } else if (std.mem.eql(u8, cmd, "threaddump")) {
        const arg = if (args.len > 1) args[1] else "";
        const result = std.fmt.bufPrint(buf, "ATTACH_DIAGNOSTICS:Thread.print,{s}", .{arg}) catch return "";
        return result;
    } else if (std.mem.eql(u8, cmd, "dumpheap")) {
        const arg = if (args.len > 1) args[1] else "";
        const result = std.fmt.bufPrint(buf, "ATTACH_DIAGNOSTICS:Dump.heap,{s}", .{arg}) catch return "";
        return result;
    } else if (std.mem.eql(u8, cmd, "inspectheap")) {
        const arg = if (args.len > 1) args[1] else "";
        const result = std.fmt.bufPrint(buf, "ATTACH_DIAGNOSTICS:GC.class_histogram,{s}", .{arg}) catch return "";
        return result;
    } else if (std.mem.eql(u8, cmd, "datadump")) {
        const arg = if (args.len > 1) args[1] else "";
        const result = std.fmt.bufPrint(buf, "ATTACH_DIAGNOSTICS:Dump.java,{s}", .{arg}) catch return "";
        return result;
    } else if (std.mem.eql(u8, cmd, "properties")) {
        const str = "ATTACH_GETSYSTEMPROPERTIES";
        @memcpy(buf[0..str.len], str);
        return buf[0..str.len];
    } else if (std.mem.eql(u8, cmd, "agentProperties")) {
        const str = "ATTACH_GETAGENTPROPERTIES";
        @memcpy(buf[0..str.len], str);
        return buf[0..str.len];
    } else {
        @memcpy(buf[0..cmd.len], cmd);
        return buf[0..cmd.len];
    }
}

/// Unescape a string and print it on stdout
fn printUnescaped(str: []const u8) void {
    var i: usize = 0;

    // Find newline and truncate
    var end = str.len;
    for (str, 0..) |ch, idx| {
        if (ch == '\n') {
            end = idx;
            break;
        }
    }

    const data = str[0..end];

    while (i < data.len) {
        if (data[i] == '\\' and i + 1 < data.len) {
            const ch: u8 = switch (data[i + 1]) {
                'f' => 0x0c,
                'n' => '\n',
                'r' => '\r',
                't' => '\t',
                else => data[i + 1],
            };
            std.debug.print("{c}", .{ch});
            i += 2;
        } else {
            std.debug.print("{c}", .{data[i]});
            i += 1;
        }
    }
    std.debug.print("\n", .{});
}

/// Write command to socket
fn writeCommandOpenJ9(fd: c_int, cmd: []const u8) !void {
    var off: usize = 0;
    const len = cmd.len + 1; // Include null terminator

    while (off < len) {
        if (off < cmd.len) {
            const n = c.write(fd, &cmd[off], cmd.len - off);
            if (n <= 0) return error.WriteFailed;
            off += @intCast(n);
        } else {
            // Write null terminator
            const null_byte = [_]u8{0};
            const n = c.write(fd, &null_byte, 1);
            if (n <= 0) return error.WriteFailed;
            off += 1;
        }
    }
}

/// Read response from OpenJ9 JVM
fn readResponseOpenJ9(fd: c_int, cmd: []const u8, print_output: bool) u8 {
    var size: usize = 8192;
    var buf = std.heap.page_allocator.alloc(u8, size) catch return 1;
    defer std.heap.page_allocator.free(buf);

    var off: usize = 0;
    while (true) {
        const bytes_signed = c.read(fd, &buf[off], size - off);
        if (bytes_signed <= 0) {
            if (bytes_signed == 0) {
                std.debug.print("Unexpected EOF reading response\n", .{});
            } else {
                std.debug.print("Error reading response\n", .{});
            }
            return 1;
        }

        const bytes: usize = @intCast(bytes_signed);
        off += bytes;
        if (buf[off - 1] == 0) {
            break;
        }

        if (off >= size) {
            // Reallocate
            const new_size = size * 2;
            const new_buf = std.heap.page_allocator.alloc(u8, new_size) catch {
                std.debug.print("Failed to allocate memory for response\n", .{});
                return 1;
            };
            @memcpy(new_buf[0..off], buf[0..off]);
            std.heap.page_allocator.free(buf);
            buf = new_buf;
            size = new_size;
        }
    }

    var result: u8 = 0;

    if (std.mem.startsWith(u8, cmd, "ATTACH_LOADAGENT")) {
        if (!std.mem.startsWith(u8, buf[0..off], "ATTACH_ACK")) {
            // AgentOnLoad error code comes right after AgentInitializationException
            if (std.mem.startsWith(u8, buf[0..off], "ATTACH_ERR AgentInitializationException")) {
                var end: usize = 39;
                while (end < off and buf[end] >= '0' and buf[end] <= '9') : (end += 1) {}
                result = std.fmt.parseInt(u8, buf[39..end], 10) catch 255;
            } else {
                result = 255;
            }
        }
    } else if (std.mem.startsWith(u8, cmd, "ATTACH_DIAGNOSTICS:") and print_output) {
        // Look for diagnostic result
        const marker = "openj9_diagnostics.string_result=";
        if (std.mem.indexOf(u8, buf[0..off], marker)) |pos| {
            printUnescaped(buf[pos + marker.len .. off]);
            return result;
        }
    }

    if (print_output) {
        buf[off - 1] = '\n';
        std.debug.print("{s}", .{buf[0..off]});
    }

    return result;
}

/// Send detach command
fn detach(fd: c_int) void {
    writeCommandOpenJ9(fd, "ATTACH_DETACHED") catch return;

    var buf: [256]u8 = undefined;
    while (true) {
        const bytes = c.read(fd, &buf, buf.len);
        if (bytes <= 0 or buf[@as(usize, @intCast(bytes)) - 1] == 0) break;
    }
}

/// Acquire a file lock
fn acquireLock(subdir: []const u8, filename: []const u8) c_int {
    var path_buf: [MAX_PATH]u8 = undefined;
    const tmp_path = psutil.getTmpPathSlice();
    const path = std.fmt.bufPrint(&path_buf, "{s}/.com_ibm_tools_attach/{s}/{s}", .{ tmp_path, subdir, filename }) catch return -1;

    var path_z: [MAX_PATH]u8 = undefined;
    @memcpy(path_z[0..path.len], path);
    path_z[path.len] = 0;

    const lock_fd = c.open(&path_z, c.O_WRONLY | c.O_CREAT, @as(c.mode_t, 0o666));
    if (lock_fd < 0) {
        return -1;
    }

    if (c.flock(lock_fd, c.LOCK_EX) < 0) {
        _ = c.close(lock_fd);
        return -1;
    }

    return lock_fd;
}

/// Release a file lock
fn releaseLock(lock_fd: c_int) void {
    if (lock_fd < 0) return;

    _ = c.flock(lock_fd, c.LOCK_UN);
    _ = c.close(lock_fd);
}

/// Create attach socket (IPv6 or IPv4)
fn createAttachSocket() !struct { fd: c_int, port: u16 } {
    // Try IPv6 first
    var fd = c.socket(c.AF_INET6, c.SOCK_STREAM, 0);
    if (fd != -1) {
        var addr: c.sockaddr_in6 = std.mem.zeroes(c.sockaddr_in6);
        addr.sin6_family = c.AF_INET6;

        if (c.bind(fd, @ptrCast(&addr), @sizeOf(c.sockaddr_in6)) == 0) {
            if (c.listen(fd, 0) == 0) {
                var bound_addr: c.sockaddr_in6 = undefined;
                var addrlen: c.socklen_t = @sizeOf(c.sockaddr_in6);
                if (c.getsockname(fd, @ptrCast(&bound_addr), &addrlen) == 0) {
                    return .{ .fd = fd, .port = std.mem.bigToNative(u16, bound_addr.sin6_port) };
                }
            }
        }
        _ = c.close(fd);
    }

    // Fall back to IPv4
    fd = c.socket(c.AF_INET, c.SOCK_STREAM, 0);
    if (fd == -1) {
        return error.SocketFailed;
    }

    var addr: c.sockaddr_in = std.mem.zeroes(c.sockaddr_in);
    addr.sin_family = c.AF_INET;

    if (c.bind(fd, @ptrCast(&addr), @sizeOf(c.sockaddr_in)) != 0) {
        _ = c.close(fd);
        return error.BindFailed;
    }

    if (c.listen(fd, 0) != 0) {
        _ = c.close(fd);
        return error.ListenFailed;
    }

    var bound_addr: c.sockaddr_in = undefined;
    var addrlen: c.socklen_t = @sizeOf(c.sockaddr_in);
    if (c.getsockname(fd, @ptrCast(&bound_addr), &addrlen) != 0) {
        _ = c.close(fd);
        return error.GetSockNameFailed;
    }

    return .{ .fd = fd, .port = std.mem.bigToNative(u16, bound_addr.sin_port) };
}

/// Close attach socket and cleanup
fn closeAttachSocket(fd: c_int, pid: i32) void {
    var path_buf: [MAX_PATH]u8 = undefined;
    const tmp_path = psutil.getTmpPathSlice();
    const path = std.fmt.bufPrint(&path_buf, "{s}/.com_ibm_tools_attach/{d}/replyInfo", .{ tmp_path, pid }) catch {
        _ = c.close(fd);
        return;
    };

    var path_z: [MAX_PATH]u8 = undefined;
    @memcpy(path_z[0..path.len], path);
    path_z[path.len] = 0;

    _ = c.unlink(&path_z);
    _ = c.close(fd);
}

/// Generate a random key
fn randomKey() u64 {
    var key: u64 = @as(u64, @bitCast(c.time(null))) *% 0xc6a4a7935bd1e995;

    const fd = c.open("/dev/urandom", c.O_RDONLY);
    if (fd >= 0) {
        defer _ = c.close(fd);
        var key_bytes: [@sizeOf(u64)]u8 = undefined;
        _ = c.read(fd, &key_bytes, @sizeOf(u64));
        key = std.mem.readInt(u64, &key_bytes, .little);
    }

    return key;
}

/// Write reply info file
fn writeReplyInfo(pid: i32, port: u16, key: u64) !void {
    var path_buf: [MAX_PATH]u8 = undefined;
    const tmp_path = psutil.getTmpPathSlice();
    const path = std.fmt.bufPrint(&path_buf, "{s}/.com_ibm_tools_attach/{d}/replyInfo", .{ tmp_path, pid }) catch return error.PathTooLong;

    var path_z: [MAX_PATH]u8 = undefined;
    @memcpy(path_z[0..path.len], path);
    path_z[path.len] = 0;

    const fd = c.open(&path_z, c.O_WRONLY | c.O_CREAT | c.O_TRUNC, @as(c.mode_t, 0o600));
    if (fd < 0) {
        return error.OpenFailed;
    }
    defer _ = c.close(fd);

    var content_buf: [64]u8 = undefined;
    const content = std.fmt.bufPrint(&content_buf, "{x:0>16}\n{d}\n", .{ key, port }) catch return error.FormatError;
    _ = c.write(fd, content.ptr, content.len);
}

/// Notify semaphore
fn notifySemaphore(value: c_short, notif_count: usize) !void {
    var path_buf: [MAX_PATH]u8 = undefined;
    const tmp_path = psutil.getTmpPathSlice();
    const path = std.fmt.bufPrint(&path_buf, "{s}/.com_ibm_tools_attach/_notifier", .{tmp_path}) catch return error.PathTooLong;

    // Create null-terminated path
    var path_z: [MAX_PATH]u8 = undefined;
    @memcpy(path_z[0..path.len], path);
    path_z[path.len] = 0;

    const sem_key = c.ftok(&path_z, 0xa1);
    const sem = c.semget(sem_key, 1, c.IPC_CREAT | 0o666);
    if (sem < 0) {
        return error.SemaphoreError;
    }

    var op = c.sembuf{
        .sem_num = 0,
        .sem_op = value,
        .sem_flg = if (value < 0) c.IPC_NOWAIT else 0,
    };

    var count = notif_count;
    while (count > 0) : (count -= 1) {
        _ = c.semop(sem, &op, 1);
    }
}

/// Accept client connection
fn acceptClient(server_fd: c_int, key: u64) !c_int {
    // Set receive timeout to 5 seconds
    var tv = c.timeval{ .tv_sec = 5, .tv_usec = 0 };
    _ = c.setsockopt(server_fd, c.SOL_SOCKET, c.SO_RCVTIMEO, &tv, @sizeOf(@TypeOf(tv)));

    const client = c.accept(server_fd, null, null);
    if (client < 0) {
        std.debug.print("JVM did not respond\n", .{});
        return error.AcceptFailed;
    }
    errdefer _ = c.close(client);

    var buf: [35]u8 = undefined;
    var off: usize = 0;

    while (off < buf.len) {
        const bytes = c.recv(client, &buf[off], buf.len - off, 0);
        if (bytes <= 0) {
            std.debug.print("The JVM connection was prematurely closed\n", .{});
            _ = c.close(client);
            return error.ConnectionClosed;
        }
        off += @intCast(bytes);
    }

    var expected: [35]u8 = undefined;
    _ = std.fmt.bufPrint(&expected, "ATTACH_CONNECTED {x:0>16} ", .{key}) catch return error.FormatError;

    if (!std.mem.eql(u8, buf[0..34], expected[0..34])) {
        std.debug.print("Unexpected JVM response\n", .{});
        _ = c.close(client);
        return error.UnexpectedResponse;
    }

    // Reset the timeout
    tv.tv_sec = 0;
    _ = c.setsockopt(client, c.SOL_SOCKET, c.SO_RCVTIMEO, &tv, @sizeOf(@TypeOf(tv)));

    return client;
}

/// Lock notification files
fn lockNotificationFiles() usize {
    var count: usize = 0;

    var path_buf: [MAX_PATH]u8 = undefined;
    const tmp_path = psutil.getTmpPathSlice();
    const path = std.fmt.bufPrint(&path_buf, "{s}/.com_ibm_tools_attach", .{tmp_path}) catch return 0;

    var path_z: [MAX_PATH]u8 = undefined;
    @memcpy(path_z[0..path.len], path);
    path_z[path.len] = 0;

    const dir = c.opendir(&path_z);
    if (dir == null) return 0;
    defer _ = c.closedir(dir);

    while (c.readdir(dir)) |entry| {
        if (count >= MAX_NOTIF_FILES) break;

        const name = std.mem.sliceTo(&entry.*.d_name, 0);
        if (name.len > 0 and name[0] >= '1' and name[0] <= '9') {
            if (entry.*.d_type == c.DT_DIR or entry.*.d_type == c.DT_UNKNOWN) {
                notif_lock[count] = acquireLock(name, "attachNotificationSync");
                count += 1;
            }
        }
    }

    return count;
}

/// Unlock notification files
fn unlockNotificationFiles(count: usize) void {
    var i: usize = 0;
    while (i < count) : (i += 1) {
        if (notif_lock[i] >= 0) {
            releaseLock(notif_lock[i]);
            notif_lock[i] = -1;
        }
    }
}

/// Check if process is OpenJ9
pub fn isOpenJ9Process(pid: i32) bool {
    var path_buf: [MAX_PATH]u8 = undefined;
    const tmp_path = psutil.getTmpPathSlice();
    const path = std.fmt.bufPrint(&path_buf, "{s}/.com_ibm_tools_attach/{d}/attachInfo", .{ tmp_path, pid }) catch return false;

    var path_z: [MAX_PATH]u8 = undefined;
    @memcpy(path_z[0..path.len], path);
    path_z[path.len] = 0;

    var stats: c.struct_stat = undefined;
    return c.stat(&path_z, &stats) == 0;
}

/// Main OpenJ9 attach function
pub fn jattachOpenJ9(pid: i32, nspid: i32, args: []const []const u8, print_output: bool) u8 {
    _ = pid; // Host PID - used for process signaling on Linux

    const attach_lock = acquireLock("", "_attachlock");
    if (attach_lock < 0) {
        std.debug.print("Could not acquire attach lock\n", .{});
        return 1;
    }

    var notif_count: usize = 0;
    var server_socket: c_int = -1;
    var port: u16 = 0;

    // Create attach socket
    const socket_result = createAttachSocket() catch {
        std.debug.print("Failed to listen to attach socket\n", .{});
        releaseLock(attach_lock);
        return 1;
    };
    server_socket = socket_result.fd;
    port = socket_result.port;

    // Generate random key and write reply info
    const key = randomKey();
    writeReplyInfo(nspid, port, key) catch {
        std.debug.print("Could not write replyInfo\n", .{});
        closeAttachSocket(server_socket, nspid);
        releaseLock(attach_lock);
        return 1;
    };

    // Lock notification files and notify semaphore
    notif_count = lockNotificationFiles();
    notifySemaphore(1, notif_count) catch {
        std.debug.print("Could not notify semaphore\n", .{});
        closeAttachSocket(server_socket, nspid);
        unlockNotificationFiles(notif_count);
        releaseLock(attach_lock);
        return 1;
    };

    // Accept client connection
    const fd = acceptClient(server_socket, key) catch {
        closeAttachSocket(server_socket, nspid);
        unlockNotificationFiles(notif_count);
        notifySemaphore(-1, notif_count) catch {};
        releaseLock(attach_lock);
        return 1;
    };

    // Cleanup
    closeAttachSocket(server_socket, nspid);
    unlockNotificationFiles(notif_count);
    notifySemaphore(-1, notif_count) catch {};
    releaseLock(attach_lock);

    if (print_output) {
        std.debug.print("Connected to remote JVM\n", .{});
    }

    // Translate and send command
    var cmd_buf: [8192]u8 = undefined;
    const cmd = translateCommand(&cmd_buf, args);

    writeCommandOpenJ9(fd, cmd) catch {
        std.debug.print("Error writing to socket\n", .{});
        _ = c.close(fd);
        return 1;
    };

    const result = readResponseOpenJ9(fd, cmd, print_output);
    if (result != 1) {
        detach(fd);
    }
    _ = c.close(fd);

    return result;
}

test "translateCommand basic" {
    var buf: [1024]u8 = undefined;

    const result1 = translateCommand(&buf, &[_][]const u8{"properties"});
    try std.testing.expectEqualStrings("ATTACH_GETSYSTEMPROPERTIES", result1);

    const result2 = translateCommand(&buf, &[_][]const u8{"agentProperties"});
    try std.testing.expectEqualStrings("ATTACH_GETAGENTPROPERTIES", result2);
}
