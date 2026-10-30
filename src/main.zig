const std = @import("std");
const io = std.Io;

const ztowaway = @import("ztowaway");
const discovery = @import("discovery.zig");
const log_level: std.log.default_level = .debug;
const log = std.log.scoped(.main);

fn shutdownSignals() std.os.linux.sigset_t {
    var mask = std.posix.sigemptyset();
    std.posix.sigaddset(&mask, .TERM); // systmctl stop
    std.pos
}

// Dummy logic until I wire up bootstrapping
fn onDiscovery(peer: discovery.Peer) void {
    log.info("peer up: {any}", .{peer.ipaddr});
}

pub fn main() !void {
    // TODO: Make this configurable based on host, or determine at runtime
    const interface_name = "wlan0";

    var main_allocator = std.heap.DebugAllocator(.{}){};
    defer _ = main_allocator.deinit();
    const allocator = main_allocator.allocator();

    const host_network_interface = try discovery.GetHostInterfaceInfo(interface_name);
    const responded_hosts = try discovery.LocalNetworkArpScan(allocator, host_network_interface);

    // TODO: make this not a defer and clean up after I am done with responded_hosts
    defer allocator.free(responded_hosts);
    for (responded_hosts) |host| {
        log.info("Host Responded: {}", .{host});
    }

    // Begin concurrent UDP searches for ztoaway agents
    var registry = discovery.Registry.init(allocator, io);
    defer registry.peers.deinit();

    var stop = std.atomic.Value(bool).init(false);

    var discovery_task = try io.concurrent(
        discovery.discoveryLoop,
        .{ responded_hosts, onDiscovery, &stop },
    );

    defer {
        stop.store(true, .release);
        discovery_task.await(io) catch |err| log.err("discovery failed:{}", .{err});
    }
}
