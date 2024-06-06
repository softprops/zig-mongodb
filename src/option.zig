const std = @import("std");
const mem = std.mem;

const Credentials = struct {
    user: []const u8,
    pass: []const u8,
    source: ?[]const u8 = null,
    mechansim: ?[]const u8 = null,
    mechanism_properties: ?std.StringHashMap([]const u8) = null,
};

// https://www.mongodb.com/docs/drivers/rust/current/fundamentals/connections/connection-guide/
pub const ClientOptions = struct {
    database: ?[]const u8 = null,
    addresses: []const std.net.Address = &.{
        .{
            .in = std.net.Ip4Address.init(
                .{ 127, 0, 0, 1 },
                27017,
            ),
        },
    },
    credentials: ?Credentials = null,
    allocator: ?mem.Allocator = null,

    fn deinit(self: *@This()) void {
        if (self.allocator) |alloc| {
            alloc.free(self.addresses);
        }
    }

    // https://www.mongodb.com/docs/manual/reference/connection-string/#std-label-connections-standard-connection-string-format
    // https://github.com/mongodb/specifications/blob/master/source/connection-string/connection-string-spec.md#general-syntax
    fn fromConnectionString(allocator: mem.Allocator, url: []const u8) !ClientOptions {
        // todo: move to separate connection.zig file
        var options = ClientOptions{ .allocator = allocator };
        var remaining = url;
        if (mem.startsWith(u8, url, "mongodb://")) {
            remaining = remaining["mongodb://".len..];
            if (mem.indexOf(u8, remaining, "@")) |i| {
                // todo: percent decode - $ : / ? # [ ] @
                const credentials = remaining[0..i];
                const splitIndex = mem.indexOf(u8, credentials, ":").?;
                options.credentials = .{
                    .user = credentials[0..splitIndex],
                    .pass = credentials[splitIndex + 1 ..],
                };
                remaining = remaining[i + 1 ..];
            }
            if (mem.indexOf(u8, remaining, "?")) |i| {
                // todo: parse optional options
                _ = remaining[i..];
                remaining = remaining[0..i];
            }
            if (mem.indexOf(u8, remaining, "/")) |i| {
                options.database = remaining[i + 1 ..];
                remaining = remaining[i..];
            }
            const hostCount = std.mem.count(u8, remaining, ",");
            var addrBuf = try std.ArrayList(std.net.Address).initCapacity(allocator, hostCount + 1);
            defer addrBuf.deinit();
            var hosts = std.mem.split(u8, remaining, ",");
            while (hosts.next()) |host| {
                const hostPortIndex = mem.indexOf(u8, host, ":").?;
                var addrs = try std.net.getAddressList(
                    allocator,
                    host[0..hostPortIndex],
                    try std.fmt.parseInt(
                        u16,
                        host[hostPortIndex + 1 ..],
                        10,
                    ),
                );
                defer addrs.deinit();
                addrBuf.appendAssumeCapacity(addrs.addrs[1]);
            }
            options.addresses = try addrBuf.toOwnedSlice();

            return options;
        }
        return error.InvalidConnectionString;
    }
};

test "ClientOptions.fromConnectionString" {
    var options = try ClientOptions.fromConnectionString(
        std.testing.allocator,
        "mongodb://user:pass@localhost:27017",
    );
    defer options.deinit();

    try std.testing.expectEqualDeep(
        Credentials{ .user = "user", .pass = "pass" },
        options.credentials.?,
    );
}
