const std = @import("std");
const bson = @import("bson");

pub const Error = struct {
    errmsg: []const u8,
    /// https://www.mongodb.com/docs/manual/reference/error-codes/
    code: i32,
    codeName: []const u8,
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
