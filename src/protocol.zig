const std = @import("std");
const Document = @import("bson").types.Document;

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
