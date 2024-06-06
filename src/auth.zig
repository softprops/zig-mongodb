const std = @import("std");

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
