const std = @import("std");
const Io = std.Io;

const ztowaway = @import("ztowaway");
const network = @import("network.zig");
const log_level: std.log.default_level = .debug;

pub fn main() !void {
    const interface_name = "wlan0";

    var main_allocator = std.heap.DebugAllocator(.{}){};
    defer _ = main_allocator.deinit();
    const allocator = main_allocator.allocator();

    _ = try network.LocalNetworkArpScan(interface_name, allocator);
}
