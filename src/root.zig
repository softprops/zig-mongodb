// todo: https://github.com/mongodb/specifications/tree/master/source
// todo: https://www.mongodb.com/docs/manual/reference/mongodb-wire-protocol/
const std = @import("std");
const bson = @import("bson");
const RawBson = @import("bson").types.RawBson;

pub const SectionKind = enum(u8) {
    body = 0,
    doc_sequence = 1,
    internal = 2,

    fn toInt(self: @This()) u8 {
        return @intFromEnum(self);
    }

    fn fromInt(i: u8) @This() {
        return @enumFromInt(i);
    }

    pub fn format(
        self: @This(),
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        try writer.print("{s}", .{@tagName(self)});
    }
};

// https://www.mongodb.com/docs/manual/reference/mongodb-wire-protocol/#opcodes
pub const OpCode = enum(i32) {
    /// Wraps other opcodes using compression
    compressed = 2012,
    /// Send a message using the standard format. Used for both client requests and database replies.
    msg = 2013,
    /// Reply to a client request. responseTo is set. Deprecated in MongoDB 5.0. Removed in MongoDB 5.1.
    reply = 1,
    /// Update document. Deprecated in MongoDB 5.0. Removed in MongoDB 5.1.
    update = 2001,
    /// Insert document. Deprecated in MongoDB 5.0. Removed in MongoDB 5.1.
    insert = 2002,
    /// Formerly used for OP_GET_BY_OID.
    reserved = 2003,
    /// Query a collection. . Deprecated in MongoDB 5.0. Removed in MongoDB 5.1.
    query = 2004,
    /// Get more data from a query. See Cursors..  Deprecated in MongoDB 5.0. Removed in MongoDB 5.1.
    get_more = 2005,
    /// Delete document. Deprecated in MongoDB 5.0. Removed in MongoDB 5.1.
    delete = 2006,
    /// Notify database that the client has finished with the cursor.  Deprecated in MongoDB 5.0. Removed in MongoDB 5.1.
    kill_cursors = 2007,

    fn toInt(self: @This()) i32 {
        return @intFromEnum(self);
    }

    fn fromInt(i: i32) @This() {
        return @enumFromInt(i);
    }

    pub fn format(
        self: @This(),
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        try writer.print("{s}", .{@tagName(self)});
    }
};

// https://www.mongodb.com/docs/manual/reference/mongodb-wire-protocol/#standard-message-header
pub const Header = struct {
    /// The total size of the message in bytes. This total includes the 4 bytes that holds the message length.
    message_len: i32,
    /// A client or database-generated identifier that uniquely identifies the message
    request_id: i32,
    /// The requestID taken from the messages from the client.
    response_to: i32,
    /// Type of message. See Opcodes for details.
    op_code: OpCode,
};

///  https://www.mongodb.com/docs/manual/legacy-opcodes/#op_query
pub const OpQuery = struct {
    header: Header,
    flags: i32 = 0,
    // null terminated
    full_collection_name: []const u8,
    number_to_skip: i32,
    number_to_return: i32,
    query: bson.types.Document,
    return_fields_selector: ?bson.types.Document = null,
};

/// https://www.mongodb.com/docs/manual/legacy-opcodes/#op_reply
pub const OpReply = struct {
    header: Header,
    response_flags: i32,
    cursor_id: i64,
    starting_from: i32,
    number_returned: i32,
    documents: []const bson.types.Document,
};

pub const ClientOptions = struct {
    address: std.net.Address = .{
        .in = std.net.Ip4Address.init(
            .{ 127, 0, 0, 1 },
            27017,
        ),
    },
};

pub const Client = struct {
    allocator: std.mem.Allocator,
    options: ClientOptions,

    pub fn init(allocator: std.mem.Allocator, options: ClientOptions) @This() {
        return .{ .allocator = allocator, .options = options };
    }

    /// https://www.mongodb.com/docs/manual/reference/command/hello
    /// handshake https://github.com/mongodb/specifications/blob/master/source/auth/auth.md#authentication
    fn hello(self: *@This()) !void {
        // will expand to connection pool later
        const stream = try std.net.tcpConnectToAddress(self.options.address);
        defer stream.close();

        // write request

        var buf = std.ArrayList(u8).init(self.allocator);
        defer buf.deinit();

        var payload = buf.writer();
        // msg header
        try payload.writeInt(i32, 1, .little); // request id
        try payload.writeInt(i32, 0, .little); // response to
        try payload.writeInt(i32, OpCode.msg.toInt(), .little); // op code

        // op msg
        try payload.writeInt(u32, 0, .little); // flags
        try payload.writeInt(u8, SectionKind.body.toInt(), .little);
        var bsonBuf = std.ArrayList(u8).init(self.allocator);
        defer bsonBuf.deinit();
        var bsonWriter = bson.writer(self.allocator, bsonBuf.writer());
        defer bsonWriter.deinit();
        // hello command
        try bsonWriter.write(RawBson.document(&.{
            .{ "hello", RawBson.int32(1) },
            .{ "$db", RawBson.string("test") },
        }));
        const bsonBytes = try bsonBuf.toOwnedSlice();
        defer self.allocator.free(bsonBytes);
        try payload.writeAll(bsonBytes);

        const requestBytes = try buf.toOwnedSlice();
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
        //std.debug.print(".msg len {d}\n", .{msgLen});
        //std.debug.print("response bytes {any}\n", .{responseBuf});
        var fbs = std.io.fixedBufferStream(responseBuf);
        var responseReader = std.io.countingReader(fbs.reader());
        // header
        std.debug.print("request id {d}\n", .{try responseReader.reader().readInt(i32, .little)});
        std.debug.print("response to {d}\n", .{try responseReader.reader().readInt(i32, .little)});
        // op code
        switch (OpCode.fromInt(try responseReader.reader().readInt(i32, .little))) {
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
                    switch (SectionKind.fromInt(try responseReader.reader().readInt(u8, .little))) {
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
test "hello world" {
    var client = Client.init(std.testing.allocator, .{});
    try client.hello();
}
