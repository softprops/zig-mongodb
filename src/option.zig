const std = @import("std");
const mem = std.mem;

const DEFAULT_PORT: u16 = 27017;

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
                DEFAULT_PORT,
            ),
        },
    },
    credentials: ?Credentials = null,
    options: ?std.StringHashMap([]const u8) = null,
    allocator: ?mem.Allocator = null,

    pub fn deinit(self: *@This()) void {
        if (self.allocator) |alloc| {
            alloc.free(self.addresses);
        }
        if (self.options) |o| {
            var oo = o;
            oo.deinit();
        }
    }

    fn decode(val: []const u8) []u8 {
        return std.Uri.percentDecodeInPlace(@constCast(val));
    }

    // https://www.mongodb.com/docs/manual/reference/connection-string/#std-label-connections-standard-connection-string-format
    // https://github.com/mongodb/specifications/blob/master/source/connection-string/connection-string-spec.md#general-syntax
    pub fn fromConnectionString(allocator: mem.Allocator, url: []const u8) !ClientOptions {
        var options = ClientOptions{ .allocator = allocator };
        var remaining = url;
        if (mem.startsWith(u8, url, "mongodb+srv://")) {
            // requires a dns query which requires udp and likely a separate library, deferring for now
            std.log.err("srv connection strings not yet supported", .{});
            return error.SrvNotSupported;
        }
        if (mem.startsWith(u8, url, "mongodb://")) {
            remaining = remaining["mongodb://".len..];
            if (mem.indexOf(u8, remaining, "@")) |i| {
                // todo: percent decode - $ : / ? # [ ] @

                const credentials = remaining[0..i];
                const splitIndex = mem.indexOf(u8, credentials, ":").?;
                options.credentials = .{
                    .user = decode(credentials[0..splitIndex]),
                    .pass = decode(credentials[splitIndex + 1 ..]),
                };
                remaining = remaining[i + 1 ..];
            }
            if (mem.indexOf(u8, remaining, "?")) |i| {
                // todo: parse optional options
                // https://github.com/mongodb/specifications/blob/master/source/connection-string/connection-string-spec.md#keys
                var opts = std.mem.split(u8, remaining[i + 1 ..], "&");
                options.options = std.StringHashMap([]const u8).init(allocator);
                while (opts.next()) |opt| {
                    var components = std.mem.split(u8, opt, "=");
                    try options.options.?.put(components.next().?, decode(components.next().?));
                }

                remaining = remaining[0..i];
            }
            if (mem.indexOf(u8, remaining, "/")) |i| {
                options.database = decode(remaining[i + 1 ..]);
                remaining = remaining[0..i];
            }
            const hostCount = std.mem.count(u8, remaining, ",");
            var addrBuf = try std.ArrayList(std.net.Address).initCapacity(allocator, hostCount + 1);
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
                    var addrs = try std.net.getAddressList(allocator, host, port);
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
