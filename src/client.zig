const std = @import("std");
const ClientOptions = @import("option.zig").ClientOptions;
const protocol = @import("protocol.zig");
const bson = @import("bson");
const RawBson = bson.types.RawBson;
const auth = @import("auth.zig");
const err = @import("err.zig");

const OS_TYPE = RawBson.string(switch (@import("builtin").os.tag) {
    .macos => "Darwin",
    .windows => "Windows",
    .linux => "Linux",
    .freebsd => "BSD",
    else => "Unix",
});

pub const Client = struct {
    allocator: std.mem.Allocator,
    options: ClientOptions,

    pub fn init(allocator: std.mem.Allocator, options: ClientOptions) @This() {
        return .{ .allocator = allocator, .options = options };
    }

    pub fn deinit(self: *@This()) void {
        self.options.deinit();
    }

    // caller owns calling stream.deinit()
    fn connection(self: *@This()) !std.net.Stream {
        // todo: impl connection pool
        return try std.net.tcpConnectToAddress(self.options.addresses[0]);
    }

    pub fn authenticate(self: *@This()) !void {
        const stream = try self.connection();
        defer stream.close();

        if (self.options.credentials) |creds| {
            try creds.authenticate(self.allocator, stream, null);
        }
    }

    fn find(self: *@This()) !void {
        const stream = try self.connection();
        defer stream.close();
        if (self.options.credentials) |creds| {
            try creds.authenticate(self.allocator, stream, null);
        }
        try protocol.write(self.allocator, stream, bson.types.RawBson.document(
            &.{
                .{ "find", bson.types.RawBson.string("system.users") },
                .{ "$db", bson.types.RawBson.string("admin") },
            },
        ));
        var doc = try protocol.read(self.allocator, stream);
        defer doc.deinit();

        if (err.isErr(doc.value)) {
            var reqErr = try err.extractErr(self.allocator, doc.value);
            defer reqErr.deinit();
            std.debug.print("error {s}", .{reqErr.value.errmsg});
            return;
        }

        std.debug.print("find resp {any}", .{doc.value});
    }

    /// todo move to its own module
    /// https://www.mongodb.com/docs/manual/reference/command/hello/#output
    const HelloResponse = struct {
        const TopologyVersion = struct {
            processId: bson.types.ObjectId,
            counter: i64,
        };
        /// A boolean value that reports when this node is writable. If true, then this instance is a primary in a replica set, or a mongos instance, or a standalone mongod.
        ///
        /// This field will be false if the instance is a secondary member of a replica set or if the member is an arbiter of a replica set.
        isWritablePrimary: bool,
        topologyVersion: TopologyVersion,
        /// The maximum permitted size of a BSON object in bytes for this mongod process.
        maxBsonObjectSize: i32 = 16 * 1024 * 1024,
        /// The maximum permitted size of a BSON wire protocol message. The default value is 48000000 bytes.
        maxMessageSizeBytes: i32,
        /// The maximum number of write operations permitted in a write batch. If a batch exceeds this limit, the client driver divides the batch into smaller groups each with counts less than or equal to the value of this field.
        maxWriteBatchSize: i32,
        /// Returns the local server time in UTC. This value is an ISO date.
        localTime: bson.types.Datetime,
        /// The time in minutes that a session remains active after its most recent use. Sessions that have not received a new read/write operation from the client or been refreshed with refreshSessions within this threshold are cleared from the cache. State associated with an expired session may be cleaned up by the server at any time.
        ///
        /// Only available when featureCompatibilityVersion is "3.6" or greater.
        logicalSessionTimeoutMinutes: i32,
        /// An identifier for the mongod / mongos instance's outgoing connection to the client.
        connectionId: i32,
        /// The earliest version of the wire protocol that this mongod or mongos instance is capable of using to communicate with clients.
        ///
        /// Clients may use minWireVersion to help negotiate compatibility with MongoDB.
        minWireVersion: i32,
        /// The latest version of the wire protocol that this mongod or mongos instance is capable of using to communicate with clients.
        ///
        /// Clients may use maxWireVersion to help negotiate compatibility with MongoDB.
        maxWireVersion: i32,
        /// A boolean value that, when true, indicates that the mongod or mongos is running in read-only mode.
        readOnly: bool,
        /// An array of SASL mechanisms used to create the user's credential or credentials, only present if client requests them
        saslSupportedMechs: ?[]const auth.Mechansim = null,
        ok: f64,
        /// returned from sharded instances
        msg: ?[]const u8 = null,
        hosts: ?[][]const u8 = null,
        /// returned from replica sets
        setName: ?[]const u8 = null,
        setVersion: ?[]const u8 = null,
        secondary: ?bool = null,
        passives: ?[][]const u8 = null,
        arbiters: ?[][]const u8 = null,
        primary: ?[]const u8 = null,
        arbiterOnly: ?bool = null,
        passive: ?bool = null,
        hidden: ?bool = null,
        tags: ?bson.types.Document = null,
        me: ?[]const u8 = null,
        // electionId

        // lastWrite

        speculativeAuthenticate: ?bson.types.Document = null,
    };

    // handshake?
    /// https://www.mongodb.com/docs/manual/reference/command/hello
    /// handshake https://github.com/mongodb/specifications/blob/master/source/auth/auth.md#authentication
    /// speculative auth https://github.com/mongodb/mongo/blob/master/src/mongo/db/auth/README.md#speculative-authentication
    pub fn hello(self: *@This()) !void {
        if (self.options.database == null) {
            return error.DatabaseNotSelected;
        }

        const stream = try self.connection();
        defer stream.close();

        const clientFirst: ?auth.Scram.ClientFirst = if (self.options.credentials) |creds| try creds.mechansim.?.speculativeAuthenticate(self.allocator, creds, "admin") else null;

        // write request
        try protocol.write(
            self.allocator,
            stream,
            RawBson.document(&.{
                .{ "hello", RawBson.int32(1) },
                .{ "$db", RawBson.string("admin") },
                .{ "saslSupportedMechs", RawBson.string("admin.demo") }, // todo: derive this, db.username
                .{
                    "client", RawBson.document(&.{
                        .{
                            "driver",
                            RawBson.document(
                                &.{
                                    .{ "name", RawBson.string("zig-bson") },
                                    .{ "version", RawBson.string("0.1.0") },
                                },
                            ),
                        },
                        .{
                            "os",
                            RawBson.document(&.{
                                // https://github.com/mongodb/specifications/blob/master/source/mongodb-handshake/handshake.rst#clientostype
                                .{
                                    "type", OS_TYPE,
                                },
                            }),
                        },
                    }),
                },
                .{
                    "speculativeAuthenticate", if (clientFirst) |cf| blk: {
                        var vcf = cf;
                        break :blk vcf.sasl();
                    } else RawBson.null(),
                },
            }),
        );

        if (clientFirst) |cf| {
            var vcf = cf;
            vcf.deinit();
        }

        // todo optional CRC-32C checksum

        var doc = try protocol.read(self.allocator, stream);
        defer doc.deinit();

        std.debug.print("\nhello resp raw {any}\n\n", .{doc.value});

        var helloResp = try doc.value.into(self.allocator, HelloResponse);
        defer helloResp.deinit();
        std.debug.print("hello resp {any}\n", .{helloResp.value});

        if (self.options.credentials) |creds| {
            try creds.authenticate(self.allocator, stream, null);
        }
    }
};

test "authenticate" {
    var client = Client.init(
        std.testing.allocator,
        .{
            .credentials = .{
                .username = "demo",
                .password = "omed",
                .mechansim = .@"SCRAM-SHA-256", // default?
            },
        },
    );
    defer client.deinit();
    client.authenticate() catch |e| {
        switch (e) {
            error.ConnectionRefused => {
                std.debug.print("mongodb not running {any}\n", .{e});
            },
            else => return e,
        }
        // catch errors until we set up a proper integration testing bootstrap on host
    };
}

test "find" {
    var client = Client.init(
        std.testing.allocator,
        .{
            .credentials = .{
                .username = "demo",
                .password = "omed",
                .mechansim = .@"SCRAM-SHA-256", // default?
            },
        },
    );
    defer client.deinit();
    client.find() catch |e| {
        switch (e) {
            error.ConnectionRefused => {
                std.debug.print("mongodb not running {any}\n", .{e});
            },
            else => return e,
        }
        // catch errors until we set up a proper integration testing bootstrap on host
    };
}

// https://www.mongodb.com/docs/manual/reference/command/hello/#syntax
test "hello" {
    var client = Client.init(
        std.testing.allocator,
        .{
            .database = "test",
            .credentials = .{
                .username = "demo",
                .password = "omed",
                .mechansim = .@"SCRAM-SHA-256", // default?
            },
        },
    );
    client.hello() catch |e| {
        switch (e) {
            error.ConnectionRefused => {
                std.debug.print("mongodb not running {any}\n", .{e});
            },
            else => return e,
        }
        // catch errors until we set up a proper integration testing bootstrap on host
    };
}
