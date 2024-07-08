const std = @import("std");
const RawBson = @import("bson").types.RawBson;
const bson = @import("bson");
const protocol = @import("protocol.zig");
const err = @import("err.zig");
const Stream = @import("client.zig").Stream;

/// captures the first round of saml auth either initiated proactively as part of a connection
/// handshake or a request to authenticate via auth mechansim
pub const FirstRound = struct {
    request: Scram.ClientFirst,
    response: bson.Owned(RawBson),

    fn init(request: Scram.ClientFirst, response: bson.Owned(RawBson)) @This() {
        return .{ .request = request, .response = response };
    }

    fn deinit(self: *@This()) void {
        self.request.deinit();
        self.response.deinit();
    }
};

pub const Credentials = struct {
    username: []const u8,
    password: []const u8,
    source: ?[]const u8 = null,
    mechansim: ?Mechansim = .@"SCRAM-SHA-256",
    mechanism_properties: ?std.StringHashMap([]const u8) = null,

    pub fn authenticate(self: @This(), allocator: std.mem.Allocator, stream: Stream, speculativeAuth: ?FirstRound) !void {
        try (self.mechansim orelse Mechansim.@"SCRAM-SHA-256").authenticate(allocator, self, stream, speculativeAuth);
    }
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

    pub fn format(
        self: @This(),
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        try writer.print("{s}", .{@tagName(self)});
    }

    pub fn defaultSource(self: @This(), db: ?[]const u8) []const u8 {
        return switch (self) {
            .@"MONGODB-CR",
            .@"SCRAM-SHA-1",
            .@"SCRAM-SHA-256",
            => db orelse "admin",
            .@"MONGODB-X509", .@"MONGODB-OIDC", .@"MONGODB-AWS" => "$external",
            .PLAIN => db orelse "$external",
            .GSSAPI => "",
        };
    }

    pub fn speculativeAuthenticate(self: @This(), allocator: std.mem.Allocator, credentials: Credentials, db: []const u8) !Scram.ClientFirst {
        return try Scram.ClientFirst.init(allocator, try Scram.generateNonce(allocator), credentials.username, self, db);
    }

    // authenticates a tcp connection to a mongodb server
    fn authenticate(self: @This(), allocator: std.mem.Allocator, credentials: Credentials, stream: Stream, speculativeAuth: ?FirstRound) !void {
        const db = "admin";
        switch (self) {
            // https://en.wikipedia.org/wiki/Salted_Challenge_Response_Authentication_Mechanism
            .@"SCRAM-SHA-1", .@"SCRAM-SHA-256" => {
                const scram: Scram = if (self == .@"SCRAM-SHA-1") .sha1 else .sha256;
                var clientFirst = speculativeAuth orelse blk: {
                    var cf = try Scram.ClientFirst.init(allocator, try Scram.generateNonce(allocator), credentials.username, self, db);
                    try protocol.write(allocator, stream, cf.sasl());
                    break :blk FirstRound.init(cf, try protocol.read(allocator, stream));
                };
                defer clientFirst.deinit();

                var serverFirst = try Scram.ServerFirst.from(allocator, clientFirst.response.value);
                defer serverFirst.deinit();
                try serverFirst.validate(clientFirst.request.nonce);

                const saltedPassword = try scram.saltedPassword(allocator, credentials.username, credentials.password, serverFirst.i, serverFirst.salt);
                defer allocator.free(saltedPassword);
                var clientFinal = switch (scram) {
                    .sha1 => try Scram.ClientFinal.init(allocator, std.crypto.hash.Sha1, saltedPassword, clientFirst.request, serverFirst, db),
                    .sha256 => try Scram.ClientFinal.init(allocator, std.crypto.hash.sha2.Sha256, saltedPassword, clientFirst.request, serverFirst, db),
                };
                defer clientFinal.deinit();
                try protocol.write(allocator, stream, clientFinal.sasl());

                var clientFinalResp = try protocol.read(allocator, stream);
                defer clientFinalResp.deinit();

                if (err.isErr(clientFinalResp.value)) {
                    var reqErr = try err.extractErr(allocator, clientFinalResp.value);
                    defer reqErr.deinit();
                    std.debug.print("err {s}: {s}\n", .{ reqErr.value.codeName, reqErr.value.errmsg });
                    return;
                }

                var serverFinal = try Scram.ServerFinal.from(allocator, clientFinalResp.value);
                switch (scram) {
                    .sha1 => try serverFinal.validate(std.crypto.hash.Sha1, saltedPassword, clientFinal),
                    .sha256 => try serverFinal.validate(std.crypto.hash.sha2.Sha256, saltedPassword, clientFinal),
                }
                std.debug.print("validated auth\n", .{});
            },
            else => |v| std.debug.print("auth not yet implemented for {any} mechansim", .{v}),
        }
    }
};

test "Mechansim.tagName" {
    try std.testing.expectEqualStrings("SCRAM-SHA-1", @tagName(Mechansim.@"SCRAM-SHA-1"));
}

/// a SASL-based authentication handshake flow
/// The client sends a saslStart message and recieves a SASL response, after which the
/// client sends one more saslContinue to respond to a challenge
pub const Scram = enum {
    sha1,
    sha256,

    pub const ClientFirst = struct {
        mechanism: Mechansim,
        message: []const u8,
        nonce: []const u8,
        allocator: std.mem.Allocator,
        db: []const u8,

        fn init(
            allocator: std.mem.Allocator,
            nonce: []const u8,
            username: []const u8,
            mechanism: Mechansim,
            db: []const u8,
        ) !@This() {
            return .{
                .allocator = allocator,
                .mechanism = mechanism,
                .nonce = nonce,
                .message = try std.fmt.allocPrint(
                    allocator,
                    "n,,n={s},r={s}",
                    .{ username, nonce },
                ),
                .db = db,
            };
        }

        fn header(self: @This()) []const u8 {
            return self.message[0..3];
        }

        fn bare(self: @This()) []const u8 {
            return self.message[3..];
        }

        pub fn deinit(self: *@This()) void {
            self.allocator.free(self.nonce);
            self.allocator.free(self.message);
        }

        pub fn sasl(self: @This()) RawBson {
            return Sasl.start(self.mechanism, self.message, self.db);
        }
    };

    const ServerFirst = struct {
        allocator: std.mem.Allocator,
        saslResp: Sasl.Response,
        nonce: []const u8,
        salt: []const u8,
        i: u32,

        fn from(allocator: std.mem.Allocator, resp: RawBson) !@This() {
            const saslResp = try Sasl.parseResponse(resp);
            // assume string of the form "r={nonce},s={salt},i={i}"
            var parts = std.mem.split(u8, saslResp.payload, ",");
            const nonce = value(parts.next().?);
            const saltBytes = value(parts.next().?);
            const salt = try base64Decode(allocator, saltBytes);
            const i = try std.fmt.parseInt(u32, value(parts.next().?), 10);
            return .{ .allocator = allocator, .saslResp = saslResp, .nonce = nonce, .i = i, .salt = salt };
        }

        // for a give 'k=value' string, return value
        fn value(kv: []const u8) []const u8 {
            return kv[2..];
        }

        fn deinit(self: *@This()) void {
            self.allocator.free(self.salt);
        }

        /// validate the response
        fn validate(self: *@This(), nonce: []const u8) !void {
            if (self.saslResp.done) {
                return error.EarlyTermination;
            }
            if (!std.mem.eql(u8, nonce, self.nonce[0..nonce.len])) {
                return error.MismatchedNonce;
            }
            if (self.i < 4096) {
                return error.IterationCountLow;
            }
        }
    };

    const ClientFinal = struct {
        allocator: std.mem.Allocator,
        conversation_id: RawBson,
        message: []const u8,
        auth_message: []const u8,
        db: []const u8,

        fn init(allocator: std.mem.Allocator, comptime Hash: type, saltedPass: []const u8, clientFirst: ClientFirst, serverFirst: ServerFirst, db: []const u8) !@This() {
            var client_key = mac(Hash, "Client Key", saltedPass);
            var stored_key = hash(Hash, &client_key);

            const header = try base64Encode(allocator, clientFirst.header());
            defer allocator.free(header);

            // https://en.wikipedia.org/wiki/Salted_Challenge_Response_Authentication_Mechanism#Proofs
            const without_proof = try std.fmt.allocPrint(allocator, "c={s},r={s}", .{ header, serverFirst.nonce });
            defer allocator.free(without_proof);

            const auth_msg = try std.fmt.allocPrint(allocator, "{s},{s},{s}", .{ clientFirst.bare(), serverFirst.saslResp.payload, without_proof });

            var client_sig = mac(Hash, auth_msg, &stored_key);

            const xorBytes = try xor(allocator, &client_key, &client_sig);
            defer allocator.free(xorBytes);

            const client_proof = try base64Encode(allocator, xorBytes);
            defer allocator.free(client_proof);

            const msg = try std.fmt.allocPrint(allocator, "{s},p={s}", .{ without_proof, client_proof });

            return .{
                .allocator = allocator,
                .message = msg,
                .auth_message = auth_msg,
                .conversation_id = serverFirst.saslResp.conversation_id,
                .db = db,
            };
        }

        fn deinit(self: *@This()) void {
            self.allocator.free(self.message);
            self.allocator.free(self.auth_message);
        }

        fn sasl(self: @This()) RawBson {
            return Sasl.cont(self.conversation_id, self.message, self.db);
        }
    };

    const ServerFinal = struct {
        allocator: std.mem.Allocator,
        saslResp: Sasl.Response,
        body: Body,

        const Body = union(enum) { err: []const u8, verifier: []const u8 };

        fn from(allocator: std.mem.Allocator, resp: RawBson) !@This() {
            const saslResp = try Sasl.parseResponse(resp);
            return .{
                .allocator = allocator,
                .saslResp = saslResp,
                .body = switch (saslResp.payload[0]) {
                    'e' => .{ .err = saslResp.payload[2..] },
                    'v' => .{ .verifier = saslResp.payload[2..] },
                    else => return error.InvalidScramResponse,
                },
            };
        }

        fn validate(self: *@This(), comptime Hash: type, saltedPass: []const u8, clientFinal: ClientFinal) !void {
            if (!std.meta.eql(self.saslResp.conversation_id, clientFinal.conversation_id)) {
                return error.WrongConversation;
            }
            return switch (self.body) {
                .verifier => |ver| {
                    var server_key = mac(Hash, "Server Key", saltedPass);

                    const expected_bytes = mac(Hash, clientFinal.auth_message, &server_key);

                    const decodedVerifier = try base64Decode(self.allocator, ver);
                    defer self.allocator.free(decodedVerifier);

                    if (!std.crypto.utils.timingSafeEql([expected_bytes.len]u8, expected_bytes, decodedVerifier[0..expected_bytes.len].*)) {
                        return error.InvalidVerifier;
                    }
                },
                .err => return error.InvalidAuth,
            };
        }
    };

    // caller owns freeing memory
    fn saltedPassword(
        self: @This(),
        allocator: std.mem.Allocator,
        username: []const u8,
        password: []const u8,
        i: u32,
        salt: []const u8,
    ) ![]u8 {
        const normalized = switch (self) {
            .sha1 => blk: {
                const Hash = std.crypto.hash.Md5;
                var dest: [Hash.digest_length]u8 = undefined;
                var inst = Hash.init(.{});
                inst.update(username);
                inst.update(":mongo:");
                inst.update(password);
                inst.final(&dest);
                break :blk try std.fmt.allocPrint(allocator, "{s}", .{std.fmt.fmtSliceHexLower(&dest)});
            },
            // todo stringprep::saslprep(password) to normalize chars
            .sha256 => try allocator.dupe(u8, password),
        };

        defer allocator.free(normalized);
        return try self.hi(allocator, normalized, salt, i);
    }

    fn mac(comptime Hash: type, data: []const u8, key: []const u8) [std.crypto.auth.hmac.Hmac(Hash).mac_length]u8 {
        const hmac = std.crypto.auth.hmac.Hmac(Hash);
        var dest: [hmac.mac_length]u8 = undefined;
        hmac.create(&dest, data, key);
        return dest;
    }

    fn hash(comptime Hash: type, data: []const u8) [Hash.digest_length]u8 {
        var dest: [Hash.digest_length]u8 = undefined;
        Hash.hash(data, &dest, .{});
        return dest;
    }

    fn hi(self: @This(), allocator: std.mem.Allocator, password: []const u8, salt: []const u8, rounds: u32) ![]u8 {
        return switch (self) {
            .sha1 => blk: {
                const dest = try allocator.alloc(u8, 160 / 8);
                try std.crypto.pwhash.pbkdf2(dest, password, salt, rounds, std.crypto.auth.hmac.HmacSha1);
                break :blk dest;
            },
            .sha256 => blk: {
                const dest = try allocator.alloc(u8, 256 / 8);
                try std.crypto.pwhash.pbkdf2(dest, password, salt, rounds, std.crypto.auth.hmac.sha2.HmacSha256);
                break :blk dest;
            },
        };
    }

    // caller owns freeing returned bytes, we assume that l and r have the same len
    fn xor(allocator: std.mem.Allocator, l: []const u8, r: []const u8) ![]u8 {
        const dest = try allocator.alloc(u8, l.len);
        for (dest, 0..) |_, i| {
            dest[i] = l[i] ^ r[i];
        }
        return dest;
    }

    // caller owns freeing memory
    fn base64Encode(allocator: std.mem.Allocator, data: []const u8) ![]const u8 {
        const dest = try allocator.alloc(u8, std.base64.standard.Encoder.calcSize(data.len));
        _ = std.base64.standard.Encoder.encode(dest, data);
        return dest;
    }

    // caller owns freeing memory
    fn base64Decode(allocator: std.mem.Allocator, encoded: []const u8) ![]u8 {
        const dest = try allocator.alloc(u8, try std.base64.standard.Decoder.calcSizeForSlice(encoded));
        _ = try std.base64.standard.Decoder.decode(dest, encoded);
        return dest;
    }

    /// generates random 32 bytes, base64-encoded. caller owns freeing returned bytes
    fn generateNonce(allocator: std.mem.Allocator) ![]const u8 {
        var bytes: [32]u8 = undefined;
        std.crypto.random.bytes(&bytes);
        return try base64Encode(allocator, &bytes);
    }
};

/// https://github.com/mongodb/specifications/blob/master/source/auth/auth.md#sasl-mechanisms
const Sasl = struct {
    const Response = struct {
        conversation_id: RawBson,
        done: bool,
        payload: []const u8,
    };

    fn start(mechanism: Mechansim, payload: []const u8, db: []const u8) RawBson {
        return RawBson.document(
            &.{
                .{ "saslStart", RawBson.int32(1) },
                .{ "$db", RawBson.string(db) },
                .{ "mechanism", RawBson.string(@tagName(mechanism)) },
                .{ "payload", RawBson.binary(payload, .binary) },
                .{
                    "options", RawBson.document(
                        &.{
                            .{ "skipEmptyExchange", RawBson.boolean(true) },
                        },
                    ),
                },
            },
        );
    }

    fn cont(conversation_id: RawBson, payload: []const u8, db: []const u8) RawBson {
        return RawBson.document(
            &.{
                .{ "saslContinue", RawBson.int32(1) },
                .{ "$db", RawBson.string(db) },
                .{ "conversationId", conversation_id },
                .{ "payload", RawBson.binary(payload, .binary) },
            },
        );
    }

    fn parseResponse(resp: RawBson) !Response {
        switch (resp) {
            .document => |doc| {
                return .{
                    .conversation_id = doc.get("conversationId") orelse {
                        return error.ConversationIdMissing;
                    },
                    .done = if (doc.get("done")) |v| blk: {
                        switch (v) {
                            .boolean => |b| break :blk b,
                            else => return error.InvalidDone,
                        }
                    } else {
                        return error.DoneMissing;
                    },
                    .payload = if (doc.get("payload")) |v| blk: {
                        switch (v) {
                            .binary => |b| break :blk b.value,
                            else => return error.InvalidPayload,
                        }
                    } else {
                        return error.PayloadMissing;
                    },
                };
            },
            else => {
                return error.InvalidBson;
            },
        }
    }
};
