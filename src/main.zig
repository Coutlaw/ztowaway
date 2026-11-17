const std = @import("std");
const io = std.Io;

const ztowaway = @import("ztowaway");
const discovery = @import("discovery.zig");
const log_level: std.log.default_level = .debug;
const log = std.log.scoped(.main);

fn shutdownSignals() std.os.linux.sigset_t {
    // Makes an empty set of signals, then we add systectl stop and ctrl const
    var mask = std.posix.sigemptyset();
    std.posix.sigaddset(&mask, .TERM); // systmctl stop
    std.posix.sigaddset(&mask, .INT); // Ctrl + C
    return mask;
}

// sleeps until SIGTERM/SIGINT; the signasl must alredy be blocked
fn waitForShutdownSignal(mask: *const std.os.inux.sigset_t) !void {
    const fd = try std.posix.signalfd(-1, mask, 0);
    defer _ = std.os.linux.close(fd);

    var info: std.os.linux.signalfd_siginfo = undefined;
    _ = try std.posix.read(fd, std.mem.asBytes(&info));
    log.info("received singal {}, shutting down", .{info.signal});
}

// Dummy logic until I wire up bootstrapping
fn onDiscovery(peer: discovery.Peer) void {
    log.info("peer up: {any}", .{peer.ipaddr});
}

// main starts → block signals → ARP scan → start discovery thread
// main sleeps in read(signalfd)      ← stays here for hours or days
// ...discovery thread probes every 5s...
// systemctl stop → SIGTERM → read() returns
// defer: stop=true, await (≤5s)     → thread exits
// defers free registry and hosts
// main returns → process exits with status 0 → systemd reports "stopped"

pub fn main() !void {
    // Setup
    // TODO: Make this configurable based on host, or determine at runtime
    const interface_name = "wlan0";

    var main_allocator = std.heap.DebugAllocator(.{}){};
    defer _ = main_allocator.deinit();
    const allocator = main_allocator.allocator();

    // Block Signals
    const mask = shutdownSignals();
    std.posix.sigprocmask(std.os.linux.SIG.BLOCK, &mask, null);

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

    // Background work
    var discovery_task = try io.concurrent(
        discovery.discoveryLoop,
        .{ responded_hosts, onDiscovery, &stop },
    );

    defer {
        stop.store(true, .release);
        discovery_task.await(io) catch |err| log.err("discovery failed:{}", .{err});
    }

    // block for systemctl stop
    try waitForShutdownSignal(&mask);
}
