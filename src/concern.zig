const std = @import("std");

// https://github.com/mongodb/specifications/tree/91de38e3ddfee11ae51d3a062535b877e0051527/source/read-write-concern

/// The read concern option is available for the following operations:
///
/// * aggregate command
/// * count command
/// * distinct command
/// * find command
/// * mapReduce command where the out option is { inline: 1 }
/// * parallelCollectionScan command
/// * geoNear command
/// * geoSearch command
pub const ReadConcern = struct {
    pub const Level = enum {
        local,
        majority,
        linearizable,
        available,
        snapshot,
    };
    /// The level of the read concern.
    level: ?Level,
};

pub const WriteConcern = struct {
    pub const Acknowledgement = union(enum) {
        number: i32,
        majority: void,

        fn majority() @This() {
            return .{ .majority = {} };
        }

        fn number(n: i32) @This() {
            return .{ .number = n };
        }
    };
    /// If true, wait for the the write operation to get committed to the
    // journal
    journal: ?bool,
    ///  When an integer, specifies the number of nodes that should acknowledge
    //  the write and MUST be greater than or equal to 0.
    //  When a string, indicates tags. "majority" is defined, but users
    //  could specify other custom error modes.
    w: ?Acknowledgement,
    /// If provided, and the write concern is not satisfied within the
    /// specified timeout (in milliseconds), the server will return an error
    /// for the operation. When unspecified, a driver SHOULD NOT send "wtimeout".
    ///
    /// The value, if provided, MUST be greater than or equal to 0.
    wtimeoutMS: ?i64,
};
