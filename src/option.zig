const std = @import("std");
const mem = std.mem;
const Credentials = @import("auth.zig").Credentials;

const DEFAULT_PORT: u16 = 27017;

// https://www.mongodb.com/docs/drivers/rust/current/fundamentals/connections/connection-guide/
pub const ClientOptions = struct {
    database: ?[]const u8 = null,
    addresses: []const std.net.Address = &.{
        .{
            .in = std.net.Ip4Address.init(
                .{ 127, 0, 0, 1 },
                DEFAULT_PORT,
            ),
        },
    },
    credentials: ?Credentials = null,
    options: ?std.StringHashMap([]const u8) = null,
    arena: ?std.heap.ArenaAllocator = null,

    pub fn deinit(self: *@This()) void {
        if (self.arena) |ar| ar.deinit();
    }

    fn decode(val: []u8) []u8 {
        return std.Uri.percentDecodeInPlace(val);
    }

    // https://www.mongodb.com/docs/manual/reference/connection-string/#std-label-connections-standard-connection-string-format
    // https://github.com/mongodb/specifications/blob/master/source/connection-string/connection-string-spec.md#general-syntax
    pub fn fromConnectionString(allocator: mem.Allocator, url: []const u8) !ClientOptions {
        var options = ClientOptions{ .arena = std.heap.ArenaAllocator.init(allocator) };
        var remaining = url;
        if (mem.startsWith(u8, url, "mongodb+srv://")) {
            // requires a dns query which requires udp and likely a separate library, deferring for now
            std.log.err("srv connection strings not yet supported", .{});
            return error.SrvNotSupported;
        }
        if (mem.startsWith(u8, url, "mongodb://")) {
            remaining = remaining["mongodb://".len..];
            if (mem.indexOf(u8, remaining, "@")) |i| {
                const credentials = remaining[0..i];
                const splitIndex = mem.indexOf(u8, credentials, ":").?;
                const user = try options.arena.?.allocator().dupe(u8, credentials[0..splitIndex]);
                const pass = try options.arena.?.allocator().dupe(u8, credentials[splitIndex + 1 ..]);
                options.credentials = .{
                    .user = decode(user),
                    .pass = decode(pass),
                };
                remaining = remaining[i + 1 ..];
            }
            if (mem.indexOf(u8, remaining, "?")) |i| {
                // todo: parse optional options
                // https://github.com/mongodb/specifications/blob/master/source/connection-string/connection-string-spec.md#keys
                var opts = std.mem.split(u8, remaining[i + 1 ..], "&");
                options.options = std.StringHashMap([]const u8).init(options.arena.?.allocator());
                while (opts.next()) |opt| {
                    var components = std.mem.split(u8, opt, "=");
                    const key = components.next().?;
                    const val = try options.arena.?.allocator().dupe(u8, components.next().?);
                    try options.options.?.put(key, decode(val));
                }

                remaining = remaining[0..i];
            }
            if (mem.indexOf(u8, remaining, "/")) |i| {
                const db = try options.arena.?.allocator().dupe(u8, remaining[i + 1 ..]);
                options.database = decode(db);
                remaining = remaining[0..i];
            }
            const hostCount = std.mem.count(u8, remaining, ",");
            var addrBuf = try std.ArrayList(std.net.Address).initCapacity(
                options.arena.?.allocator(),
                hostCount + 1,
            );
            defer addrBuf.deinit();
            var hosts = std.mem.split(u8, remaining, ",");
            while (hosts.next()) |hostStr| {
                // It can identify either a hostname, IP address, IP Literal, or UNIX domain socket
                // currently assuming hostname + port
                // https://github.com/mongodb/specifications/blob/master/source/connection-string/connection-string-spec.md#host
                var components = mem.split(u8, hostStr, ":");
                const host = components.next().?;
                const port = if (components.next()) |p| try std.fmt.parseInt(u16, p, 10) else DEFAULT_PORT;
                const addr = std.net.Address.resolveIp(host, port) catch blk: {
                    var addrs = try std.net.getAddressList(
                        options.arena.?.allocator(),
                        host,
                        port,
                    );
                    defer addrs.deinit();
                    break :blk addrs.addrs[1];
                };

                addrBuf.appendAssumeCapacity(addr);
            }
            options.addresses = try addrBuf.toOwnedSlice();

            return options;
        }
        return error.InvalidConnectionString;
    }
};

// see also https://github.com/mongodb/specifications/blob/master/source/connection-string/tests/README.md
test "ClientOptions.fromConnectionString" {
    var options = try ClientOptions.fromConnectionString(
        std.testing.allocator,
        "mongodb://user:pass@127.0.0.1/database?foo=bar",
    );
    defer options.deinit();

    try std.testing.expectEqualStrings("bar", options.options.?.get("foo").?);

    try std.testing.expectEqualDeep(
        (try std.net.Address.parseIp("127.0.0.1", 27017)).in,
        options.addresses[0].in,
    );

    try std.testing.expectEqualDeep(
        Credentials{ .user = "user", .pass = "pass" },
        options.credentials.?,
    );
}
