const std = @import("std");
const Io = std.Io;

const ztowaway = @import("ztowaway");
const network = @import("network.zig");
const log_level: std.log.default_level = .debug;

pub fn main() !void {
    const host_info = try network.GetHostInterfaceInfo("wlan0");
    std.debug.print("MAC: {X:0>2}:{X:0>2}:{X:0>2}:{X:0>2}:{X:0>2}:{X:0>2}\n", .{
        host_info.macaddr[0], host_info.macaddr[1], host_info.macaddr[2], host_info.macaddr[3], host_info.macaddr[4], host_info.macaddr[5],
    });

    var main_allocator = std.heap.DebugAllocator(.{}){};
    defer _ = main_allocator.deinit();
    const allocator = main_allocator.allocator();

    const usable_hosts = try network.GetSubnetHosts(allocator, host_info.ipaddr, host_info.netmask);
    defer allocator.free(usable_hosts);

    std.debug.print("Local Network IPs:\n", .{});
    for (usable_hosts) |host| {
        std.debug.print("{}.{}.{}.{}\n", .{ host[0], host[1], host[2], host[3] });
    }
}
