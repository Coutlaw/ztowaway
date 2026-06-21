const std = @import("std");
const Io = std.Io;

const ztowaway = @import("ztowaway");
const network = @import("network.zig");
const log_level: std.log.default_level = .debug;

pub fn main() !void {
    const hostInfo = try network.GetHostInterfaceInfo("wlan0");
    std.debug.print("MAC: {X:0>2}:{X:0>2}:{X:0>2}:{X:0>2}:{X:0>2}:{X:0>2}\n", .{
        hostInfo.macaddr[0], hostInfo.macaddr[1], hostInfo.macaddr[2], hostInfo.macaddr[3], hostInfo.macaddr[4], hostInfo.macaddr[5],
    });
}
