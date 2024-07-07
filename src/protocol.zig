const std = @import("std");
const Document = @import("bson").types.Document;
const bson = @import("bson");
const RawBson = @import("bson").types.RawBson;

pub const SectionKind = enum(u8) {
    body = 0,
    doc_sequence = 1,
    internal = 2,

    pub fn toInt(self: @This()) u8 {
        return @intFromEnum(self);
    }

    pub fn fromInt(i: u8) @This() {
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

    pub fn toInt(self: @This()) i32 {
        return @intFromEnum(self);
    }

    pub fn fromInt(i: i32) @This() {
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
    //message_len: i32,
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
    query: Document,
    return_fields_selector: ?Document = null,
};

/// https://www.mongodb.com/docs/manual/legacy-opcodes/#op_reply
pub const OpReply = struct {
    header: Header,
    response_flags: i32,
    cursor_id: i64,
    starting_from: i32,
    number_returned: i32,
    documents: []const Document,
};

pub const Section = struct {
    kind: SectionKind,
    payload: []const u8,
};

pub fn write(allocator: std.mem.Allocator, stream: std.net.Stream, command: RawBson) !void {
    std.debug.print("\n -> writing command {any}\n\n", .{command});
    // assume op_msg for now
    var bsonBuf = std.ArrayList(u8).init(allocator);
    defer bsonBuf.deinit();
    var bsonWriter = bson.writer(allocator, bsonBuf.writer());
    defer bsonWriter.deinit();
    try bsonWriter.write(command);
    const bsonBytes = try bsonBuf.toOwnedSlice();
    defer allocator.free(bsonBytes);

    const requestBytes = try request(
        allocator,
        .{ .request_id = 1, .response_to = 0, .op_code = .msg },
        0,
        &.{
            .{ .kind = .body, .payload = bsonBytes },
        },
    );
    defer allocator.free(requestBytes);

    // checksum

    try stream.writer().writeInt(i32, @intCast(requestBytes.len + @sizeOf(i32)), .little);
    try stream.writer().writeAll(requestBytes);
}

/// caller owns freeing returned bytes
pub fn request(allocator: std.mem.Allocator, header: Header, flags: u32, sections: []const Section) ![]u8 {
    var buf = std.ArrayList(u8).init(allocator);
    defer buf.deinit();

    var payload = buf.writer();
    // msg header
    try payload.writeInt(i32, header.request_id, .little); // request id
    try payload.writeInt(i32, header.response_to, .little); // response to
    try payload.writeInt(i32, header.op_code.toInt(), .little); // op code
    try payload.writeInt(u32, flags, .little); // flags
    for (sections) |section| {
        try payload.writeInt(u8, section.kind.toInt(), .little);
        try payload.writeAll(section.payload);
    }
    return try buf.toOwnedSlice();
}

// compare with https://github.com/mongodb/mongo-rust-driver/blob/b781af26dfb17fe62823a866a025de9fb102e0b3/src/cmap/conn/wire/message.rs#L182
pub fn read(allocator: std.mem.Allocator, stream: std.net.Stream) !bson.Owned(RawBson) {
    // read std header
    // https://www.mongodb.com/docs/manual/reference/mongodb-wire-protocol/#standard-message-header
    const msgLen = try stream.reader().readInt(i32, .little);
    const responseBuf = try allocator.alloc(u8, @intCast(msgLen - @sizeOf(i32)));
    //errdefer allocator.free(responseBuf);
    defer allocator.free(responseBuf);
    _ = try stream.reader().readAll(responseBuf);
    var fbs = std.io.fixedBufferStream(responseBuf);
    var responseReader = std.io.countingReader(fbs.reader());
    _ = try responseReader.reader().readInt(i32, .little); // request id
    _ = try responseReader.reader().readInt(i32, .little); // response to
    const opCode = OpCode.fromInt(try responseReader.reader().readInt(i32, .little));

    // opCode dependant payload
    const OwnedBson = bson.Owned(RawBson);

    var body: ?OwnedBson = null;
    switch (opCode) {
        // assume msg for now, handle others in the future
        .msg => {
            // https://www.mongodb.com/docs/manual/reference/mongodb-wire-protocol/#std-label-wire-op-msg
            const flags = try responseReader.reader().readInt(u32, .little);
            _ = flags; // autofix
            //std.debug.print("response flags  {d}\n", .{flags});
            // read sections until we hit a known limit
            const msgLenPlusChecksum = @sizeOf(i32) * 2;
            while (responseBuf.len - responseReader.bytes_read > msgLenPlusChecksum) {
                switch (SectionKind.fromInt(try responseReader.reader().readInt(u8, .little))) {
                    .body => {
                        var bsonReader = bson.reader(allocator, responseReader.reader());
                        body = try bsonReader.read();
                    },
                    // todo: support sequence
                    else => |otherwise| std.debug.print("section {s} not yet supported", .{otherwise}),
                }
            }
            // todo: read checksum if flags contains "checksum present"
        },
        else => |v| std.debug.print("op code {s} not yet supported", .{v}),
    }
    return if (body) |b| b else error.NoBody;
}
