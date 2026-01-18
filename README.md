# jattach - Zig Implementation

This is a Zig port of the jattach utility, a JVM Dynamic Attach tool.

## Overview

jattach is a utility to send commands to a JVM process via the Dynamic Attach mechanism.
It provides all-in-one **jmap + jstack + jcmd + jinfo** functionality in a single tiny program.

This Zig implementation is a port of the original C implementation, providing:
- Cross-platform support (Linux, macOS, FreeBSD)
- No external dependencies beyond libc
- Single binary deployment
- Memory safety through Zig's compile-time checks

## Building

### Prerequisites

- Zig 0.15.0 or later (uses new I/O API from Writergate)
- A C compiler (for linking libc)

### Build Commands

```bash
# Build the executable
zig build

# Build with optimizations
zig build -Doptimize=ReleaseFast

# Build the shared library
zig build lib

# Run tests
zig build test

# Run jattach directly
zig build run -- <pid> <cmd> [args...]
```

The built binary will be located at `zig-out/bin/jattach`.

## Usage

```bash
jattach <pid> <cmd> [args ...]
```

### Supported Commands

| Command | Description |
|---------|-------------|
| `load` | Load agent library |
| `properties` | Print system properties |
| `agentProperties` | Print agent properties |
| `datadump` | Show heap and thread summary |
| `threaddump` | Dump all stack traces (like jstack) |
| `dumpheap` | Dump heap (like jmap) |
| `inspectheap` | Heap histogram (like jmap -histo) |
| `setflag` | Modify manageable VM flag |
| `printflag` | Print VM flag |
| `jcmd` | Execute jcmd command |

### Examples

#### Load native agent
```bash
jattach <pid> load /path/to/agent.so true "options"
```

#### Load Java agent
```bash
jattach <pid> load instrument false "javaagent.jar=arguments"
```

#### Get thread dump
```bash
jattach <pid> threaddump
```

#### List available jcmd commands
```bash
jattach <pid> jcmd help -all
```

#### Get system properties
```bash
jattach <pid> properties
```

## Environment Variables

- `JATTACH_PATH`: Override the default temporary directory path used for JVM communication

## Platform Support

| Platform | HotSpot | OpenJ9 | Notes |
|----------|---------|--------|-------|
| Linux | ✅ | ✅ | Full container/namespace support |
| macOS | ✅ | ✅ | Tested on arm64 and x86_64 |
| FreeBSD | ✅ | ✅ | |
| Windows | ⚠️ Stub | ❌ | Use original C implementation |

Note: The Windows implementation is a stub. The full Windows implementation requires
complex shellcode injection which is not yet ported to Zig.
For Windows usage, please use the original C implementation.

## Container Support

On Linux, jattach supports attaching to JVM processes running inside containers.
It automatically handles namespace switching for:
- Network namespace (net)
- IPC namespace (ipc)
- Mount namespace (mnt)

## Library Usage

The Zig implementation can also be used as a library. The main function is:

```zig
pub fn jattach(pid: i32, args: []const []const u8, print_output: bool) u8
```

A C-compatible export is also provided:

```c
int jattach_lib(int pid, int argc, char** argv, int print_output);
```

## Project Structure

```
zig-src/
├── build.zig              # Zig build configuration
├── main.zig               # Main entry point and jattach function
├── psutil.zig             # Process utilities (get process info, namespace handling)
├── jattach_hotspot.zig    # HotSpot JVM attach implementation
├── jattach_openj9.zig     # OpenJ9 JVM attach implementation
├── jattach_windows.zig    # Windows-specific implementation
└── README.md              # This file
```

## Differences from C Implementation

1. **Memory Safety**: Zig's compile-time safety checks prevent common memory errors
2. **Error Handling**: Uses Zig's error union types instead of return codes
3. **No Preprocessor**: Platform-specific code uses `comptime` and `builtin.os.tag`
4. **Cleaner Build**: Single `build.zig` instead of Makefile with multiple targets
5. **C Interop**: Uses `@cImport` to interface with POSIX APIs directly

## Zig 0.15 Compatibility

This implementation is designed for Zig 0.15+ which includes breaking changes:
- Uses `b.createModule()` for build configuration
- Uses `@cImport` for C library access instead of `std.posix`
- Compatible with the new I/O API ("Writergate")
- Uses `std.debug.print` for output instead of `std.io.getStdOut()`

## License

Apache-2.0 (same as the original jattach)

## Credits

Original jattach: https://github.com/jattach/jattach