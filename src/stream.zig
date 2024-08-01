const std = @import("std");

/// provides reader/writer impl over both plain and tls streams
///
/// callers should call `close()` to release underlying resources
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

    /// create a new tls encrypted network stream
    pub fn tls(stream: std.net.Stream, c: std.crypto.tls.Client) @This() {
        return .{ .tls = .{ .plain = stream, .tls = c } };
    }

    /// create a new plain text network stream
    pub fn plain(stream: std.net.Stream) @This() {
        return .{ .plain = stream };
    }

    pub fn reader(self: @This()) Reader {
        return .{ .context = self };
    }

    pub fn writer(self: @This()) Writer {
        return .{ .context = self };
    }

    pub fn close(self: @This()) void {
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
