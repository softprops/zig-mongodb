const std = @import("std");

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});

    const optimize = b.standardOptimizeOption(.{});

    const bson = b.dependency("bson", .{
        .target = target,
        .optimize = optimize,
    }).module("bson");
    const mongodb = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .imports = &.{
            .{ .name = "bson", .module = bson },
        },
    });

    try b.modules.put(b.dupe("mongodb"), mongodb);

    // unit tests
    const unit_tests = b.addTest(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        // todo: how to parameterize this?
        .filters = &.{"hello"},
    });
    unit_tests.root_module.addImport("bson", bson);
    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);

    // const benchmark_tests = b.addTest(.{
    //     .root_source_file = b.path("src/bench.zig"),
    //     .target = target,
    //     .optimize = optimize,
    //     .filters = &.{"bench"},
    // });

    // const run_benchmark_tests = b.addRunArtifact(benchmark_tests);

    // const benchmark_step = b.step("bench", "Run benchmark tests");
    // benchmark_step.dependOn(&run_benchmark_tests.step);

    inline for ([_]struct {
        name: []const u8,
        src: []const u8,
    }{
        .{ .name = "demo", .src = "examples/demo/main.zig" },
    }) |example| {
        const example_step = b.step(try std.fmt.allocPrint(
            b.allocator,
            "{s}-example",
            .{example.name},
        ), try std.fmt.allocPrint(
            b.allocator,
            "build the {s} example",
            .{example.name},
        ));

        const example_run_step = b.step(try std.fmt.allocPrint(
            b.allocator,
            "run-{s}-example",
            .{example.name},
        ), try std.fmt.allocPrint(
            b.allocator,
            "run the {s} example",
            .{example.name},
        ));

        var exe = b.addExecutable(.{
            .name = example.name,
            .root_source_file = b.path(example.src),
            .target = target,
            .optimize = optimize,
        });
        exe.root_module.addImport("mongodb", mongodb);

        // run the artifact - depending on the example exe
        const example_run = b.addRunArtifact(exe);
        example_run_step.dependOn(&example_run.step);

        // install the artifact - depending on the example exe
        const example_build_step = b.addInstallArtifact(exe, .{});
        example_step.dependOn(&example_build_step.step);
    }
}
