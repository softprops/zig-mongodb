const std = @import("std");
const ClientOptions = @import("option.zig").ClientOptions;
const protocol = @import("protocol.zig");
const bson = @import("bson");
const RawBson = bson.types.RawBson;
const auth = @import("auth.zig");
const err = @import("err.zig");
const Owned = @import("root.zig").Owned;

// https://github.com/mongodb/specifications/blob/master/source/mongodb-handshake/handshake.rst#client-os-type
const OS_TYPE = RawBson.string(switch (@import("builtin").os.tag) {
    .macos => "Darwin",
    .windows => "Windows",
    .linux => "Linux",
    .freebsd => "BSD",
    else => "Unix",
});

// https://github.com/mongodb/specifications/blob/master/source/mongodb-handshake/handshake.rst#client-driver-name
const DRIVER = RawBson.document(
    &.{
        .{ "name", RawBson.string("zig-mongodb") },
        .{ "version", RawBson.string("0.1.0") },
    },
);

// provides reader/writer impl over both plain and tls streams
pub const Stream = union(enum) {
    const Tls = struct {
        plain: std.net.Stream,
        tls: std.crypto.tls.Client,
    };
    plain: std.net.Stream,
    tls: Tls,

    pub const ReadError = anyerror; // std.posix.ReadError;
    pub const WriteError = anyerror; //std.posix.WriteError;

    pub const Reader = std.io.Reader(Stream, ReadError, read);
    pub const Writer = std.io.Writer(Stream, WriteError, write);

    fn tls(stream: std.net.Stream, c: std.crypto.tls.Client) @This() {
        return .{ .tls = .{ .plain = stream, .tls = c } };
    }

    fn plain(stream: std.net.Stream) @This() {
        return .{ .plain = stream };
    }

    pub fn reader(self: @This()) Reader {
        return .{ .context = self };
    }

    pub fn writer(self: @This()) Writer {
        return .{ .context = self };
    }

    fn close(self: @This()) void {
        switch (self) {
            .plain => |s| s.close(),
            .tls => |s| s.plain.close(),
        }
    }

    pub fn read(self: Stream, buffer: []u8) ReadError!usize {
        return switch (self) {
            .plain => |s| s.read(buffer),
            .tls => |s| blk: {
                var vs = s;
                break :blk vs.tls.read(s.plain, buffer);
            },
        };
    }

    pub fn write(self: Stream, buffer: []const u8) WriteError!usize {
        return switch (self) {
            .plain => |s| s.write(buffer),
            .tls => |s| blk: {
                var vs = s;
                break :blk vs.tls.write(s.plain, buffer);
            },
        };
    }
};

pub const Connection = struct {
    stream: Stream,
    // does nothing now but will be release to a pool later
    fn release(_: @This()) void {}
};

pub const Client = struct {
    allocator: std.mem.Allocator,
    options: ClientOptions,
    conn: ?Connection = null,

    pub fn init(allocator: std.mem.Allocator, options: ClientOptions) @This() {
        return .{ .allocator = allocator, .options = options };
    }

    pub fn deinit(self: *@This()) void {
        self.options.deinit();
        if (self.conn) |c| c.stream.close();
    }

    fn connection(self: *@This()) !Connection {
        return self.conn orelse blk: {
            // todo: impl connection pool
            const addr = self.options.addresses[0];
            std.debug.print("connecting to {s}\n", .{addr.hostname});
            const underlying = try std.net.tcpConnectToAddress(addr.ipaddr);

            // todo: set client timeouts, i.e. xxxTimeoutMS, with something like the following
            const timeout = std.posix.timeval{
                .tv_sec = @as(i32, 1),
                .tv_usec = @as(i32, 0),
            };

            std.posix.setsockopt(underlying.handle, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&timeout)) catch {};
            const conn = Connection{ .stream = if (self.options.tls) Stream.tls(underlying, try std.crypto.tls.Client.init(underlying, .{}, addr.hostname)) else Stream.plain(underlying) };
            self.conn = conn;
            break :blk conn;
        };
    }

    pub fn authenticate(self: *@This()) !void {
        const conn = try self.connection();
        defer conn.release();

        if (self.options.credentials) |creds| {
            try creds.authenticate(self.allocator, conn.stream, null);
        }
    }

    pub const PingResponse = struct {
        ok: f64,
        fn isErr(self: @This()) bool {
            return self.ok != 0.0;
        }
    };

    fn ping(self: *@This()) !Owned(PingResponse) {
        const conn = try self.connection();
        defer conn.release();

        try protocol.write(self.allocator, conn.stream, bson.types.RawBson.document(
            &.{
                .{ "ping", bson.types.RawBson.int32(1) },
                .{ "$db", bson.types.RawBson.string("admin") },
            },
        ));

        var doc = try protocol.read(self.allocator, conn.stream);
        defer doc.deinit();

        if (err.isErr(doc.value)) {
            var reqErr = try err.extractErr(self.allocator, doc.value);
            defer reqErr.deinit();
            std.debug.print("error: {s}\n", .{reqErr.value.errmsg});
            return error.InvalidRequest;
        }

        return try doc.value.into(self.allocator, PingResponse);
    }

    // https://www.mongodb.com/docs/manual/reference/command/find/#mongodb-dbcommand-dbcmd.find
    // todo: return a Cursor type with a `.next()`-based iterator
    // see also https://www.mongodb.com/docs/manual/reference/command/getMore/#mongodb-dbcommand-dbcmd.getMore
    fn find(self: *@This()) !Owned(RawBson) {
        const conn = try self.connection();
        defer conn.release();
        if (self.options.credentials) |creds| {
            try creds.authenticate(self.allocator, conn.stream, null);
        }
        try protocol.write(self.allocator, conn.stream, bson.types.RawBson.document(
            &.{
                .{ "find", bson.types.RawBson.string("system.users") },
                .{ "$db", bson.types.RawBson.string("admin") },
            },
        ));

        var doc = try protocol.read(self.allocator, conn.stream);
        errdefer doc.deinit();

        if (err.isErr(doc.value)) {
            var reqErr = try err.extractErr(self.allocator, doc.value);
            defer reqErr.deinit();
            std.debug.print("error {s}", .{reqErr.value.errmsg});
            return error.InvalidRequest;
        }

        return doc;
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

    /// https://www.mongodb.com/docs/manual/reference/command/hello
    /// handshake https://github.com/mongodb/specifications/blob/master/source/auth/auth.md#authentication
    /// speculative auth https://github.com/mongodb/mongo/blob/master/src/mongo/db/auth/README.md#speculative-authentication
    pub fn hello(self: *@This()) !Owned(HelloResponse) {

        // compare with
        // java impl - https://github.com/mongodb/mongo-java-driver/blob/d8503c31a29b446ba21dfa2ded8cd38f298e3165/driver-core/src/main/com/mongodb/internal/connection/InternalStreamConnectionInitializer.java#L92
        // rust impl - https://github.com/mongodb/mongo-rust-driver/blob/b781af26dfb17fe62823a866a025de9fb102e0b3/src/cmap/establish/handshake.rs#L435

        if (self.options.database == null) {
            return error.DatabaseNotSelected;
        }

        const conn = try self.connection();
        defer conn.release();

        const clientFirst = if (self.options.credentials) |creds| try (creds.mechansim orelse auth.Mechansim.@"SCRAM-SHA-256").speculativeAuthenticate(self.allocator, creds, "admin") else null;

        const saslSupportedMechs = if (self.options.credentials) |creds| try std.fmt.allocPrint(self.allocator, "{s}.{s}", .{ if (creds.mechansim) |m| m.defaultSource(null) else "admin", creds.username }) else null;

        // write request
        try protocol.write(
            self.allocator,
            conn.stream,
            RawBson.document(&.{
                .{ "hello", RawBson.int32(1) },
                .{ "$db", RawBson.string("admin") },
                // .{ "loadBalanced", RawBson.boolean(true) }, // todo: set to true if connectionMode is loadBalanced
                // .{ "compression", RawBson.array(...) }, // todo: set if compressors is configured
                // only include if username is present but mechansim is not
                .{ "saslSupportedMechs", if (saslSupportedMechs) |sm| RawBson.string(sm) else RawBson.null() },
                .{
                    "client", RawBson.document(&.{
                        .{
                            "driver", DRIVER,
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
                // if we have credentials on file, save an extra server round trip by including client first
                // auth request with hello command. we then expect the server to response its response
                // embedded within hello's response
                // https://github.com/mongodb/specifications/blob/91de38e3ddfee11ae51d3a062535b877e0051527/source/mongodb-handshake/handshake.rst#speculative-authentication
                .{
                    "speculativeAuthenticate", if (clientFirst) |cf| cf.sasl() else RawBson.null(),
                },
            }),
        );

        if (clientFirst) |cf| {
            var vcf = cf;
            vcf.deinit();
        }

        if (saslSupportedMechs) |sm| self.allocator.free(sm);

        var doc = try protocol.read(self.allocator, conn.stream);
        defer doc.deinit();

        if (err.isErr(doc.value)) {
            var reqErr = try err.extractErr(self.allocator, doc.value);
            defer reqErr.deinit();
            std.debug.print("error: {s}\n", .{reqErr.value.errmsg});
            return error.InvalidRequest;
        }

        var resp = try doc.value.into(self.allocator, HelloResponse);
        errdefer resp.deinit();

        if (self.options.credentials) |creds| {
            std.debug.print("\nspeculativeAuthenticate response {?any}\n", .{resp.value.speculativeAuthenticate});
            // todo: include hello responses' speculative auth here to continue/complete auth conversation
            try creds.authenticate(self.allocator, conn.stream, null);
        }

        return resp;
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

test "ping" {
    const connectionStr = "mongodb://demo:omed@localhost/test";
    var client = Client.init(
        std.testing.allocator,
        try ClientOptions.fromConnectionString(std.testing.allocator, connectionStr),
    );
    defer client.deinit();
    if (client.ping()) |resp| {
        var vresp = resp;
        vresp.deinit();
    } else |e| {
        switch (e) {
            error.ConnectionRefused => {
                std.debug.print("mongodb not running {any}\n", .{e});
            },
            else => return e,
        }
        // catch errors until we set up a proper integration testing bootstrap on host
    }
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
    if (client.find()) |doc| {
        var vdoc = doc;
        vdoc.deinit();
    } else |e| {
        switch (e) {
            error.ConnectionRefused => {
                std.debug.print("mongodb not running {any}\n", .{e});
            },
            else => return e,
        }
        // catch errors until we set up a proper integration testing bootstrap on host
    }
}

// https://www.mongodb.com/docs/manual/reference/command/hello/#syntax
test "hello" {
    const connectionStr = "mongodb://demo:omed@localhost/test";
    var client = Client.init(
        std.testing.allocator,
        try ClientOptions.fromConnectionString(std.testing.allocator, connectionStr),
    );
    defer client.deinit();
    if (client.hello()) |resp| {
        var vresp = resp;
        vresp.deinit();
    } else |e| {
        std.debug.print("error? {any}\n", .{e});
        switch (e) {
            error.ConnectionRefused => {
                std.debug.print("mongodb not running {any}\n", .{e});
            },
            else => return e,
        }
        // catch errors until we set up a proper integration testing bootstrap on host
    }
}
