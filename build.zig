const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const version = "2.2";

    // Main executable
    const exe = b.addExecutable(.{
        .name = "jattach",
        .root_module = b.createModule(.{
            .root_source_file = b.path("main.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });

    const options = b.addOptions();
    options.addOption([]const u8, "version", version);
    exe.root_module.addOptions("config", options);

    // Platform-specific settings
    if (target.result.os.tag == .windows) {
        exe.root_module.linkSystemLibrary("advapi32", .{});
    }

    b.installArtifact(exe);

    // Run command
    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run jattach");
    run_step.dependOn(&run_cmd.step);

    // Tests
    const unit_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("main.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });

    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);

    // Library target (shared library)
    const lib = b.addLibrary(.{
        .name = "jattach",
        .linkage = .dynamic,
        .root_module = b.createModule(.{
            .root_source_file = b.path("main.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });
    lib.root_module.addOptions("config", options);

    if (target.result.os.tag == .windows) {
        lib.root_module.linkSystemLibrary("advapi32", .{});
    }

    const install_lib = b.addInstallArtifact(lib, .{});
    const lib_step = b.step("lib", "Build shared library");
    lib_step.dependOn(&install_lib.step);
}
