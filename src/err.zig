const std = @import("std");
const bson = @import("bson");

pub const Error = struct {
    pub const Code = enum(i32) {
        internal_error = 1,
        bad_value = 2,
        // todo: many, many, many more
        client_marked_killed = 46841,
    };
    errmsg: []const u8,
    /// todo: enumify
    /// https://www.mongodb.com/docs/manual/reference/error-codes/
    code: i32,
    codeName: []const u8,

    fn code(self: @This()) Code {
        return @enumFromInt(self.code);
    }
};

pub fn extractErr(allocator: std.mem.Allocator, doc: bson.types.RawBson) !bson.Owned(Error) {
    return doc.into(allocator, Error);
}

pub fn isErr(raw: bson.types.RawBson) bool {
    return switch (raw) {
        .document => |doc| if (doc.get("ok")) |ok| switch (ok) {
            .double => |doub| doub.value == 0.0,
            else => false,
        } else false,
        else => false,
    };
}
