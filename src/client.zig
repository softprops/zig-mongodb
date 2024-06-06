const std = @import("std");
const ClientOptions = @import("option.zig").ClientOptions;
const protocol = @import("protocol.zig");
const bson = @import("bson");
const RawBson = bson.types.RawBson;

const OS_TYPE = RawBson.string(switch (@import("builtin").os.tag) {
    .macos => "Darwin",
    .windows => "Windows",
    .linux => "Linux",
    .freebsd => "BSD",
    else => "Unix",
});

pub const Client = struct {
    allocator: std.mem.Allocator,
    options: ClientOptions,

    pub fn init(allocator: std.mem.Allocator, options: ClientOptions) @This() {
        return .{ .allocator = allocator, .options = options };
    }

    pub fn deinit(self: *@This()) void {
        self.options.deinit();
    }

    // caller owns calling stream.deinit()
    fn connection(self: *@This()) !std.net.Stream {
        // todo: impl connection pool
        return try std.net.tcpConnectToAddress(self.options.addresses[0]);
    }

    /// https://www.mongodb.com/docs/manual/reference/command/hello
    /// handshake https://github.com/mongodb/specifications/blob/master/source/auth/auth.md#authentication
    fn hello(self: *@This()) !void {
        if (self.options.database == null) {
            return error.DatabaseNotSelected;
        }
        const stream = try self.connection();
        defer stream.close();

        // write request
        var bsonBuf = std.ArrayList(u8).init(self.allocator);
        defer bsonBuf.deinit();
        var bsonWriter = bson.writer(self.allocator, bsonBuf.writer());
        defer bsonWriter.deinit();
        // hello command
        try bsonWriter.write(
            RawBson.document(&.{
                .{ "hello", RawBson.int32(1) },
                .{ "$db", RawBson.string(self.options.database.?) },
                .{
                    "client", RawBson.document(&.{
                        .{
                            "driver",
                            RawBson.document(
                                &.{
                                    .{ "name", RawBson.string("zig-bson") },
                                    .{ "version", RawBson.string("0.1.0") },
                                },
                            ),
                        },
                        .{
                            "os",
                            RawBson.document(&.{
                                // https://github.com/mongodb/specifications/blob/master/source/mongodb-handshake/handshake.rst#clientostype
                                .{
                                    "type", OS_TYPE,
                                },
                            }),
                        },
                    }),
                },
            }),
        );
        const bsonBytes = try bsonBuf.toOwnedSlice();
        defer self.allocator.free(bsonBytes);
        const requestBytes = try protocol.request(
            self.allocator,
            .{
                .request_id = 1,
                .response_to = 0,
                .op_code = .msg,
            },
            0,
            &.{
                .{
                    .kind = .body,
                    .payload = bsonBytes,
                },
            },
        );

        defer self.allocator.free(requestBytes);
        // msg len (including len bytes)
        try stream.writer().writeInt(i32, @intCast(requestBytes.len + 4), .little);
        try stream.writer().writeAll(requestBytes);

        // todo optional CRC-32C checksum

        // read response

        const msgLen = try stream.reader().readInt(i32, .little);
        const responseBuf = try self.allocator.alloc(u8, @intCast(msgLen - 4));
        defer self.allocator.free(responseBuf);
        _ = try stream.reader().readAll(responseBuf);
        var fbs = std.io.fixedBufferStream(responseBuf);
        var responseReader = std.io.countingReader(fbs.reader());
        // header
        std.debug.print("request id {d}\n", .{try responseReader.reader().readInt(i32, .little)});
        std.debug.print("response to {d}\n", .{try responseReader.reader().readInt(i32, .little)});
        // op code
        switch (protocol.OpCode.fromInt(try responseReader.reader().readInt(i32, .little))) {
            .reply => {
                std.debug.print("response flags  {d}\n", .{try responseReader.reader().readInt(i32, .little)});
                std.debug.print("cursor id {d}\n", .{try responseReader.reader().readInt(i64, .little)});
                std.debug.print("starting from {d}\n", .{try responseReader.reader().readInt(i32, .little)});
                std.debug.print("number returned {d}\n", .{try responseReader.reader().readInt(i32, .little)});
                var bsonReader = bson.reader(self.allocator, responseReader.reader());
                defer bsonReader.deinit();
                const docs = try bsonReader.read();
                //std.debug.print("documents {any}\n", .{docs});
                // https://www.mongodb.com/docs/manual/reference/method/db.runCommand/#response
                switch (docs) {
                    .document => |v| {
                        for (v.elements) |elem| {
                            std.debug.print("document {s}", .{elem.@"0"});
                            switch (elem.@"1") {
                                .string => |s| std.debug.print(" {s}\n", .{s}),
                                else => |otherwise| std.debug.print("{any}\n", .{otherwise}),
                            }
                        }
                    },
                    else => unreachable,
                }
            },
            .msg => {
                std.debug.print("response flags  {d}\n", .{try responseReader.reader().readInt(u32, .little)});
                // read sections until there's nothing left to read
                while (responseReader.bytes_read < responseBuf.len) {
                    switch (protocol.SectionKind.fromInt(try responseReader.reader().readInt(u8, .little))) {
                        .body => {
                            var bsonReader = bson.reader(self.allocator, responseReader.reader());
                            defer bsonReader.deinit();
                            const doc = try bsonReader.read();
                            //std.debug.print("documents {any}\n", .{docs});
                            // https://www.mongodb.com/docs/manual/reference/method/db.runCommand/#response
                            switch (doc) {
                                .document => |v| {
                                    for (v.elements) |elem| {
                                        std.debug.print("\ndocument {s}", .{elem.@"0"});
                                        switch (elem.@"1") {
                                            .string => |s| std.debug.print(" {s}", .{s}),
                                            else => |otherwise| std.debug.print(" {any}", .{otherwise}),
                                        }
                                    }
                                },
                                else => unreachable,
                            }
                        },
                        else => |otherwise| std.debug.print("section {s} not yet supported", .{otherwise}),
                    }
                }
            },
            else => |v| std.debug.print("op code {s} not yet supported", .{v}),
        }
    }
};

// https://www.mongodb.com/docs/manual/reference/command/hello/#syntax
test "hello" {
    var client = Client.init(
        std.testing.allocator,
        .{ .database = "test" },
    );
    try client.hello();
}
