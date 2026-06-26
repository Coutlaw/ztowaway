const std = @import("std");
const Io = std.Io;

const ztowaway = @import("ztowaway");
const network = @import("network.zig");
const log_level: std.log.default_level = .debug;
const log = std.log.scoped(.main);

pub fn main() !void {
    const interface_name = "wlan0";

    var main_allocator = std.heap.DebugAllocator(.{}){};
    defer _ = main_allocator.deinit();
    const allocator = main_allocator.allocator();

    const responded_hosts = try network.LocalNetworkArpScan(interface_name, allocator);
    defer allocator.free(responded_hosts);
    for (responded_hosts) |host| {
        log.info("Host Responded: {}", .{host});
    }
}
