// a work in progress
/// MONGO_CONNECTION=mongodb://user:pass@localhost:27017/test zig build run-demo-example
const std = @import("std");
const mongodb = @import("mongodb");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    if (std.posix.getenv("MONGO_CONNECTION")) |mc| {
        var client = mongodb.Client.init(
            allocator,
            try mongodb.ClientOptions.fromConnectionString(allocator, mc),
        );
        defer client.deinit();
        try client.hello();
    } else {
        std.log.err("missing MONGO_CONNECTION env var", .{});
    }
}
