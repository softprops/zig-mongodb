// todo: https://github.com/mongodb/specifications/tree/master/source
// todo: https://www.mongodb.com/docs/manual/reference/mongodb-wire-protocol/
const std = @import("std");
const mem = std.mem;

// re-export
pub const bson = @import("bson");
const RawBson = @import("bson").types.RawBson;
const protocol = @import("protocol.zig");
pub const ClientOptions = @import("option.zig").ClientOptions;
pub const Credentials = @import("option.zig").ClientOptions;
pub const Client = @import("client.zig").Client;

test {
    std.testing.refAllDecls(@This());
}
