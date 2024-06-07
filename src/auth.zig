const std = @import("std");

pub const Credentials = struct {
    user: []const u8,
    pass: []const u8,
    source: ?[]const u8 = null,
    mechansim: ?Mechansim = null,
    mechanism_properties: ?std.StringHashMap([]const u8) = null,
};

pub const Mechansim = enum {
    @"MONGODB-CR",
    /// https://www.mongodb.com/docs/manual/core/security-scram/
    /// https://github.com/mongodb/specifications/blob/master/source/auth/auth.md#scram-sha-1
    @"SCRAM-SHA-1",
    /// https://www.mongodb.com/docs/manual/core/security-scram/
    /// https://github.com/mongodb/specifications/blob/master/source/auth/auth.md#scram-sha-256
    @"SCRAM-SHA-256",
    /// https://www.mongodb.com/docs/manual/core/security-x.509/
    /// https://www.mongodb.com/docs/manual/core/security-x.509/
    @"MONGODB-X509",
    /// https://www.mongodb.com/docs/manual/core/kerberos/
    GSSAPI,
    /// https://www.mongodb.com/docs/manual/core/security-ldap/#ldap-proxy-authentication
    PLAIN,
    @"MONGODB-AWS",
    @"MONGODB-OIDC",
};

/// caller owns freeing returned bytes
pub fn generateNonce(allocator: std.mem.Allocator) ![]u8 {
    const bytes: [32]u8 = undefined;
    std.crypto.random.bytes(bytes);
    const dest = try allocator.alloc(u8, std.base64.standard.Encoder.calcSize(bytes));
    return std.base64.standard.Encoder.encode(dest, bytes);
}

pub const Scram = enum {
    Sha1,
    Sha256,

    pub fn saltedPassword(self: @This(), allocator: std.mem.Allocator, user: []const u8, pass: []const u8, i: u32, salt: []const u8) ![]u8 {
        const normalized = switch (self) {
            .Sha1 => blk: {
                const md5 = std.crypto.hash.Md5.init(.{});
                const bytes: [md5.digest_length]u8 = undefined;
                const toHash = try std.fmt.allocPrint(allocator, "{s}:mongodb:{s}", .{ user, pass });
                defer allocator.free(toHash);
                md5.update(toHash);
                md5.final(bytes);
                const hex = std.fmt.allocPrint(allocator, "{s}", .{std.fmt.fmtSliceHexLower(bytes)});
                break :blk hex;
            },
            .Sha256 => unreachable,
        };
        return hi(normalized, salt, i);
    }

    fn hi(self: @This(), password: []const u8, salt: []const u8, rounds: u32) []u8 {
        return switch (self) {
            .Sha1 => blk: {
                const out: [256 / 8]u8 = undefined;
                try std.crypto.pwhash.pbkdf2(out, password, salt, rounds, std.crypto.auth.hmac.HmacSha1);
                break :blk out;
            },
            .Sha256 => blk: {
                const out: [160 / 8]u8 = undefined;
                try std.crypto.pwhash.pbkdf2(out, password, salt, rounds, std.crypto.auth.hmac.sha2.HmacSha256);
                break :blk out;
            },
        };
    }
};
