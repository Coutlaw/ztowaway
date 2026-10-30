const std = @import("std");

const log = std.log.scoped(.network);

// Ethernet Constants
const ETH_P_ARP = 0x0806;
const ARP_P_TYPE = 0x0800;
const ARPOP_REQUEST = 1;
const ARPHRD_ETHER = 1;
const ARPOP_REPLY = 2;

// Layer 2 broadcast MAC
pub const MACBroadcastAddr: [6]u8 = "FF:FF:FF:FF:FF:FF";
pub const MACBroadcastEthStruct = .{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

// Time Constants
const SEND_DELAY_NS = 500_000;
const WAIT_AFTER_LAST_SENT_MS = 5000;

// Linux Const
const MISSING_SOCKET_PERMS_ERROR_CODE = 18446744073709551615;

// Discovery Constants
const PROBE_INTERVAL_SECONDS = 5;
const DISCOVERY_PORT: u16 = 9999;
const PROBE_MAGIC: u36 = 0x42069; // later I will convert this to a secret

// Host
pub const HostInterface = struct {
    macaddr: [6]u8,
    ipaddr: [4]u8,
    netmask: [4]u8,
    ifindex: i32,
};

// Discovery
pub const MsgKind = enum(u8) { probe = 0, reply = 1 };

pub const DiscoveryMessage = extern struct {
    magic: u36,
    version: u8,
    kind: u8,
    _pad: u16 = 0,
    instance_id: u64,
};

// Discovered Host: A host that responds to an ARP frame
pub const KnownHost = struct {
    macaddr: [6]u8,
    ipaddr: [4]u8,
};

// verified peers
pub const PeerStatus = enum { known, up, down };
pub const Peer = struct {
    ipaddr: [4]u8,
    macaddr: [4]u8,
    last_seen_ms: i64,
    missed_hb: u8,
    status: PeerStatus,
};

// Registry used to track up/down instances of ztowaway agents
pub const Registry = struct {
    mutext: std.Io.Mutex = .{},
    peers: std.AutoHashMap([4]u8, Peer), // Zig supports structural hashing, pretty cool
    // Need this for 0.16 mutex usage
    io: std.Io,

    pub fn init(allocator: std.mem.Allocator, io: std.Io) Registry {
        return .{ .peers = std.AutoHashMap([4]u8, Peer).init(allocator), .io = io };
    }

    pub fn markUp(self: *Registry, ip: [4]u8, mac: [6]u8) !bool {
        // for now, not using cancellable locks so no need to try/catch
        self.mutext.lock(self.io);
        defer self.mutext.unlock(self.io);

        const now: i64 = std.Io.Clock.real.now(self.io).toMilliseconds();

        // inform if this was a down instance transfering to up
        const is_new_peer = if (self.peers.getPtr(ip)) |p| p.status == .up else false;

        try self.peers.put(ip, .{
            .ip = ip,
            .mac = mac,
            .last_seen_ms = now,
            .missed = 0,
            .status = .up,
        });

        return !is_new_peer;
    }

    // The idea here is that we will check 3 times for a missed heartbeat
    // after that we mark it down, since its UDP we may drop some packets
    pub fn markMissed(self: *Registry, ip: [4]u8) void {
        self.mutext.lock(self.io);
        defer self.mutext.unlock(self.io);
        if (self.peers.getPtr(ip)) |p| {
            p.missed_hb += 1;
            if (p.missed_hb >= 3) p.status = .down;
        }
    }

    pub fn snapshotUp(self: *Registry, allocator: std.mem.Allocator) ![]Peer {
        self.mutext.lock(self.io);
        defer self.mutex.unlock(self.io);

        var up_list = std.ArrayList(Peer).empty;
        defer up_list.deinit(allocator);

        // ensures if my type changes this code should survive
        var itterator = self.peers.valueIterator();
        while (itterator.next()) |p| {
            if (p.status == .up) try up_list.append(allocator, p.*);
        }

        return up_list.toOwnedSlice(allocator);
    }
};

// Helper Functions for probe message
fn sockaddrFromIp(ip: [4]u8, port: u16) std.os.linux.sockaddr.in {
    var addr = std.mem.zeroes(std.os.linux.sockaddr.in);
    addr.family = std.os.linux.AF.INET;
    addr.port = std.mem.nativeToBig(u16, port);
    addr.addr = @bitCast(ip);
    return addr;
}

pub fn handleReply(socket: std.os.linux.socket_t, registry: *Registry, known_hosts: []const KnownHost) !?Peer {
    var buf: [@sizeOf(DiscoveryMessage)]u8 = undefined;
    var src_addr: std.os.linux.sockaddr.in = undefined;
    var addr_len: u32 = @sizeOf(std.os.linux.sockaddr.in);

    const rc = std.os.linux.recvfrom(socket, &buf, buf.len, 0, @ptrCast(&src_addr), &addr_len);

    switch (std.os.linux.errno(rc)) {
        .SUCCESS => {},
        .AGAIN => return null,
        else => |err| {
            std.log.warn("recvfrom failed: {}", .{err});
            return null;
        },
    }

    if (rc != @sizeOf(DiscoveryMessage)) return null;

    var msg: DiscoveryMessage = @bitCast(buf);
    msg.magic = std.mem.bigToNative(u32, msg.magic);
    msg.instance_id = std.mem.bigToNative(u64, msg.instance_id);

    if (msg.magic != PROBE_MAGIC) return null;
    if (msg.kind != @intFromEnum(MsgKind.reply)) return null; // Something we don't expect to reply

    const ip: [4]u8 = @bitCast(src_addr.addr);

    const mac = for (known_hosts) |host| {
        if (std.mem.eql(u8, &host.ip, &ip)) break host.mac;
    } else {
        std.log.warn("reply from unregocnized host {any}, ignoring", .{ip});
        return null;
    };

    const is_new = registry.markUp(ip, mac);
    if (!is_new) return null;

    return Peer{
        .ip = ip,
        .mac = mac,
        .last_seen_ms = std.Io.Clock.real.now(std.io).toMilliseconds(),
        .missed = 0,
        .status = .up,
    };
}

pub fn sendProbes(socket: std.os.linux.socket_t, hosts: []KnownHost, our_instance_id: u64) !void {
    var wire = DiscoveryMessage{
        .magic = std.mem.nativeToBig(u32, PROBE_MAGIC),
        .version = 1,
        .kind = @intFromEnum(MsgKind.probe),
        .instance_id = std.mem.nativeToBig(u64, our_instance_id),
    };
    const bytes = std.mem.asBytes(&wire);

    for (hosts) |host| {
        const addr = sockaddrFromIp(host.ipaddr, DISCOVERY_PORT);
        const rc = std.os.linux.sendto(
            socket,
            bytes.ptr,
            bytes.len,
            0,
            @ptrCast(&addr),
            @sizeOf(std.os.linux.sockaddr.in),
        );
        switch (std.os.linux.errno(rc)) {
            .SUCCESS => {},
            else => |err| std.log.warn("sendto failed for {any}: {}", .{ host.ipaddr, err }),
        }
    }
}

pub fn respondToProbes(sock: std.os.linux.socket_t, my_instance_id: 64) !void {
    var buf: [@sizeOf(DiscoveryMessage)]u8 = undefined;
    var src_addr: std.os.linux.sockaddr.in = undefined;
    var addr_len: u32 = @sizeOf(std.os.linux.sockaddr.in);

    while (true) {
        const rc = std.os.linux.recvfrom(sock, &buf, buf.len, 0, @ptrCast(src_addr), &addr_len);
        if (std.os.linux.errno(rc) != .SUCCESS) continue; // suboptimal here,
        if (rc != @sizeOf(DiscoveryMessage)) continue;

        var msg: DiscoveryMessage = @bitCast(buf);
        msg.magic = std.mem.bigToNative(u32, msg.magic);
        if (msg.magic != PROBE_MAGIC or msg.kind != @intFromEnum(MsgKind)) continue;

        var wire = DiscoveryMessage{
            .magic = std.mem.nativeToBig(u32, PROBE_MAGIC),
            .version = 1,
            .kind = @intFromEnum(MsgKind.reply),
            .instance_id = std.mem.nativeToBig(u64, my_instance_id),
        };
        const reply_bytes = std.mem.asBytes(&wire);
        _ = std.os.linux.sendto(sock, reply_bytes.ptr, reply_bytes.len, 0, @ptrCast(&src_addr), addr_len);
    }
}

pub fn discoveryLoop(registry: *Registry, known_hosts: []KnownHost, on_discovery: *const fn (Peer) void, stop: *std.atomic.Value(bool)) !void {
    const probe_interval_ns: i128 = PROBE_INTERVAL_SECONDS * std.time.ms_per_s;
    var last_probe_time: i128 = 0;

    const udp_socket_rc = std.os.linux.socket(std.os.linux.AF.INET, std.posix.SOCK.DGRAM, std.posix.IPPROTO.UDP);
    if (std.os.linux.errno(udp_socket_rc) != .SUCCESS) {
        log.debug("Error Number: {}", .{std.os.linux.errno(udp_socket_rc)});
        return error.SocketFailed;
    }

    const udp_socket: i32 = @intCast(udp_socket_rc);
    defer _ = std.os.linux.close(udp_socket);

    var fds = [_]std.os.linux.pollfd{.{
        .fd = udp_socket,
        .events = std.os.linux.POLL.IN,
        .revents = 0,
    }};

    while (!stop.load(.acquire)) {
        const now: i64 = std.Io.Clock.real.now(registry.io).toMilliseconds();

        if (now - last_probe_time >= probe_interval_ns) {
            try sendProbes(udp_socket, known_hosts);
            last_probe_time = now;
        }

        const elapsed = now - last_probe_time;
        const remaining = probe_interval_ns - elapsed;
        const timeout_ms: i32 = if (remaining > 0) @intCast(@divTrunc(remaining, std.time.ms_per_s)) else 0;

        const n = try std.os.linux.poll(&fds, 1, timeout_ms);

        if (n > 0 and (fds[0].revents & std.os.linux.POLL.IN) != 0) {
            if (try handleReply(udp_socket, registry)) |peer| {
                registry.markUp(peer.ip, peer.mac);
                on_discovery(peer);
            }
        }
    }
}

// Constants for ARP frame
// TODO: use these once I figure out endiness for the encoded frame
pub const HardwareType = enum(u16) {
    ethernet = 1,
    _,
};

pub const ProtocolType = enum(u16) {
    ipv4 = 0x0800,
    _,
};

pub const Operation = enum(u16) {
    request = 1,
    reply = 2,
    _,
};

// RFC 826 compliant ARP payload
// note: I can do extern here and not packed because
// all fields are natrually aligned to ABI
// note 2: I'm using arrays here to stepside endiness problems
// with raw bytes over a socket
pub const ArpPacket = extern struct {
    htype: u16,
    ptype: u16,
    hlen: u8, // Hardware address len, always 6 for Eth
    plen: u8,
    oper: u16,
    sha: [6]u8, // sender hardware address
    spa: [4]u8, // sender ip
    tha: [6]u8, // target hardware address
    tpa: [4]u8, // target ip
};

// Layer II Ethernet Header
pub const EthHeader = extern struct {
    dst_mac: [6]u8,
    src_mac: [6]u8,
    eth_type: u16,
};

pub const ArpFrame = extern struct {
    eth: EthHeader,
    arp: ArpPacket,
};

pub fn GetHostInterfaceInfo(iface: []const u8) !HostInterface {
    const ioctl_socket: i32 = @intCast(std.os.linux.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, 0));

    // Set up the ifr (inerface request) struct with the interface name (e.g. "eth0", "enp3s0")
    var ifr = std.mem.zeroes(std.posix.ifreq); // ifreq == linux here
    if (iface.len > std.posix.IFNAMESIZE - 1) return error.InterfaceNameTooLong;
    @memcpy(ifr.ifrn.name[0..iface.len], iface);
    ifr.ifrn.name[iface.len] = 0;

    var info: HostInterface = undefined;

    // SIOCGIFHWADDR (network interface address aka MAC)
    const rc = std.os.linux.ioctl(ioctl_socket, std.os.linux.SIOCGIFHWADDR, @intFromPtr(&ifr));
    if (rc != 0) return error.IoctlFailed; // better error handling one day.
    @memcpy(&info.macaddr, ifr.ifru.hwaddr.data[0..6]);
    log.debug("MAC: {x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}", .{
        info.macaddr[0], info.macaddr[1], info.macaddr[2],
        info.macaddr[3], info.macaddr[4], info.macaddr[5],
    });

    // SIOCGIFINDEX (Interface Index)
    @memcpy(ifr.ifrn.name[0..iface.len], iface); // reset incase it was overwritten
    const iirq = std.os.linux.ioctl(ioctl_socket, std.os.linux.SIOCGIFINDEX, @intFromPtr(&ifr));
    if (iirq != 0) return error.IoctlFailed;
    info.ifindex = ifr.ifru.ivalue;
    log.debug("ifindex: {d}", .{info.ifindex});

    // SIOCGIFADDR (IP Addr)
    @memcpy(ifr.ifrn.name[0..iface.len], iface); // reset incase it was overwritten
    const iprq = std.os.linux.ioctl(ioctl_socket, std.os.linux.SIOCGIFADDR, @intFromPtr(&ifr));
    if (iprq != 0) return error.IoctlFailed;
    // casting the pointer to a sockaddr.in will prevent a AF_NET byte index  on sockaddr.data[2..6]
    const sin_addr: *const std.posix.sockaddr.in = @ptrCast(&ifr.ifru.addr);
    @memcpy(&info.ipaddr, std.mem.asBytes(&sin_addr.addr));
    log.debug("IP: {}.{}.{}.{}", .{
        info.ipaddr[0], info.ipaddr[1], info.ipaddr[2], info.ipaddr[3],
    });

    // SIOCGIFNETMASK (netmask)
    @memcpy(ifr.ifrn.name[0..iface.len], iface);
    const nmrq = std.os.linux.ioctl(ioctl_socket, std.os.linux.SIOCGIFNETMASK, @intFromPtr(&ifr));
    if (nmrq != 0) return error.IoctlFailed;
    const nm_sin: *const std.posix.sockaddr.in = @ptrCast(&ifr.ifru.addr);
    @memcpy(&info.netmask, std.mem.asBytes(&nm_sin.addr));
    log.debug("netmask: {}.{}.{}.{}", .{
        info.netmask[0], info.netmask[1],
        info.netmask[2], info.netmask[3],
    });

    _ = std.os.linux.close(ioctl_socket);

    return info;
}

// Given an ip and a mask, find all the usable ips in a given subnet
pub fn GetSubnetHosts(allocator: std.mem.Allocator, ip: [4]u8, mask: [4]u8) ![][4]u8 {
    const ip_u32 = std.mem.readInt(u32, &ip, .big);
    const mask_u32 = std.mem.readInt(u32, &mask, .big);

    const network = ip_u32 & mask_u32; // bitwise and, gives us the bit values we care about
    const broadcast = network | ~mask_u32;
    const host_count = broadcast - network -| 1; // subtract network from boradcast, drop the network addrs
    log.debug("network: {}, Broadcast: {}, Host Count: {}", .{ network, broadcast, host_count });

    var hosts = try allocator.alloc([4]u8, host_count);
    var addr = network + 1;

    for (0..host_count) |i_usize| {
        const i: u32 = @intCast(i_usize);
        std.mem.writeInt(u32, &hosts[i], addr, .big);
        addr += 1; // next address to try
    }

    return hosts;
}

test "subnet hosts happy path" {
    var debug_allocator = std.heap.DebugAllocator(.{}){};
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();

    const mask: [4]u8 = [4]u8{ 255, 255, 255, 248 };
    const host_ip: [4]u8 = [4]u8{ 192, 168, 1, 1 };

    const hosts = try GetSubnetHosts(allocator, host_ip, mask);
    defer allocator.free(hosts);

    const expectedHosts: [6][4]u8 = [6][4]u8{
        [4]u8{ 192, 168, 1, 1 },
        [4]u8{ 192, 168, 1, 2 },
        [4]u8{ 192, 168, 1, 3 },
        [4]u8{ 192, 168, 1, 4 },
        [4]u8{ 192, 168, 1, 5 },
        [4]u8{ 192, 168, 1, 6 },
    };

    try std.testing.expectEqual(hosts.len, expectedHosts.len);

    for (0..hosts.len) |i| {
        for (0..4) |j| {
            try std.testing.expectEqual(hosts[i][j], expectedHosts[i][j]);
        }
    }
}

pub fn FormatArpRequest(iface: HostInterface, target_ip: [4]u8) ArpFrame {
    return .{ .eth = .{
        .dst_mac = MACBroadcastEthStruct,
        .src_mac = iface.macaddr,
        .eth_type = std.mem.nativeToBig(u16, ETH_P_ARP),
    }, .arp = .{
        .htype = std.mem.nativeToBig(u16, ARPHRD_ETHER),
        .ptype = std.mem.nativeToBig(u16, ARP_P_TYPE),
        .hlen = 6,
        .plen = 4,
        .oper = std.mem.nativeToBig(u16, ARPOP_REQUEST),
        .sha = iface.macaddr,
        .spa = iface.ipaddr,
        .tha = std.mem.zeroes([6]u8),
        .tpa = target_ip,
    } };
}

pub fn FormatDestSockAddr(iface: HostInterface) std.os.linux.sockaddr.ll {
    return .{
        .family = std.os.linux.AF.PACKET,
        .protocol = std.mem.nativeToBig(u16, ETH_P_ARP),
        .ifindex = iface.ifindex,
        .hatype = ARPHRD_ETHER,
        .pkttype = 0,
        .halen = 6,
        .addr = .{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0 },
    };
}

pub fn LocalNetworkArpScan(allocator: std.mem.Allocator, hostiface: HostInterface) ![]KnownHost {
    const usable_ips = try GetSubnetHosts(allocator, hostiface.ipaddr, hostiface.netmask);
    defer allocator.free(usable_ips);

    // AF_PACKET and ETH_P_ARP will allow ARP resonses to sit in this sockets recieve buffer
    const raw_socket_rc = std.os.linux.socket(std.os.linux.AF.PACKET, std.posix.SOCK.RAW, std.mem.nativeToBig(u16, ETH_P_ARP));
    if (std.os.linux.errno(raw_socket_rc) != .SUCCESS) {
        log.debug("Error Number: {}", .{raw_socket_rc});
        if (raw_socket_rc == MISSING_SOCKET_PERMS_ERROR_CODE) {
            log.err("Missing the Capability to use raw socket hosts, run zig build setcap to rebuild binary", .{});
            return error.RawSocketCapabilityMissing;
        }

        return error.SocketFailed;
    }

    const raw_socket: i32 = @intCast(raw_socket_rc);
    defer _ = std.os.linux.close(raw_socket);

    const dest_sock_addr = FormatDestSockAddr(hostiface);

    // Ignore the target ip, it's just to get a non zero value
    var arpRequest = FormatArpRequest(hostiface, hostiface.ipaddr);

    // Track last sent packet
    var threaded_io = std.Io.Threaded.init_single_threaded;
    const io = threaded_io.io();
    var last_sent_time: i64 = std.Io.Clock.real.now(io).toMilliseconds();

    // Boardcast ARP to every known IP
    for (usable_ips, 0..) |target_ip, index| {
        arpRequest.arp.tpa = target_ip;
        const raw_msg = std.mem.asBytes(&arpRequest);

        const resp = std.os.linux.sendto(raw_socket, raw_msg, raw_msg.len, 0, @ptrCast(&dest_sock_addr), @sizeOf(std.os.linux.sockaddr.ll));
        if (std.os.linux.errno(resp) != std.os.linux.E.SUCCESS) {
            log.warn("sendto failed for {}.{}.{}.{}: errno {}", .{
                target_ip[0],             target_ip[1], target_ip[2], target_ip[3],
                std.os.linux.errno(resp),
            });
        }

        // Pace sends by pauing briefly between each send and not overwhelming the TX buffer
        // TODO: Could make this cooler by tracking TX buffer state and pacing dynamically
        try std.Io.sleep(io, .fromNanoseconds(SEND_DELAY_NS), .awake);

        if (index == usable_ips.len - 1) {
            last_sent_time = std.Io.Clock.real.now(io).toMicroseconds();
        }
    }

    // Unmanaged array list just creates explicit allocator handling and smaller struct
    var known_hosts = std.ArrayListUnmanaged(KnownHost).empty;
    defer known_hosts.deinit(allocator);

    var fds = [1]std.os.linux.pollfd{.{
        .fd = raw_socket,
        .events = std.os.linux.POLL.IN,
        .revents = 0,
    }};

    // Align here is just to help coerce the raw byte string into this structure without copying data
    var frame_buff: [@sizeOf(ArpFrame)]u8 align(@alignOf(ArpFrame)) = undefined;

    // Find responses in the recv buffer, break 5s after last tx from above
    while (true) {
        // Delay for after last sent message
        const now_ms = std.Io.Clock.real.now(io).toMilliseconds();
        const remaining_ms = (last_sent_time + WAIT_AFTER_LAST_SENT_MS) - now_ms;
        if (remaining_ms <= 0) break;

        const ready = std.os.linux.poll(&fds, 1, 5000); // 5s
        if (ready == 0) break;
        if (std.os.linux.errno(ready) != .SUCCESS) break;

        const n = std.os.linux.recvfrom(raw_socket, &frame_buff, frame_buff.len, 0, null, null);
        if (std.os.linux.errno(n) != .SUCCESS) continue;
        if (n < @sizeOf(ArpFrame)) continue;

        const frame: *const ArpFrame = @ptrCast(&frame_buff);
        if (frame.arp.oper != std.mem.nativeToBig(u16, ARPOP_REPLY)) continue;

        try known_hosts.append(allocator, .{
            .macaddr = frame.arp.sha,
            .ipaddr = frame.arp.spa,
        });
    }

    return try known_hosts.toOwnedSlice(allocator);
}

pub const Leader = struct {
    host: KnownHost,
    isMe: bool,
};

// World's simplest leader election, smallest IP among active hosts is elected leader
pub fn ElectLeader(hostiface: HostInterface, known_hosts: []const KnownHost) Leader {
    // Current leader is just ourself temporarily
    var current_leader = Leader{
        .host = .{ .ipaddr = hostiface.ipaddr, .macaddr = hostiface.macaddr },
        .isMe = true,
    };
    var current_ip_leader: u32 = 0;
    var next_ip_score: u32 = 0;

    for (current_leader.host.ipaddr) |v| {
        current_ip_leader += @intCast(v);
    }

    for (known_hosts) |host| {
        for (host.ipaddr) |v| {
            next_ip_score += @intCast(v);
        }

        if (next_ip_score < current_ip_leader) {
            current_leader.host.ipaddr = host.ipaddr;
            current_leader.host.macaddr = host.macaddr;
            current_leader.isMe = false;
            current_ip_leader = next_ip_score; //pass by value obvs
        }
    }

    return current_leader;
}

test "leader election test, not me" {
    const know_hosts = [4]KnownHost{
        KnownHost{ .ipaddr = [4]u8{ 192, 168, 1, 1 }, .macaddr = [6]u8{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xF2 } },
        KnownHost{ .ipaddr = [4]u8{ 192, 168, 1, 2 }, .macaddr = [6]u8{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xF3 } },
        KnownHost{ .ipaddr = [4]u8{ 192, 168, 1, 3 }, .macaddr = [6]u8{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xF4 } },
        KnownHost{ .ipaddr = [4]u8{ 192, 168, 1, 4 }, .macaddr = [6]u8{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xF5 } },
    };

    const hostiface = HostInterface{ .ipaddr = [4]u8{ 192, 168, 1, 10 }, .macaddr = [6]u8{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xF2 }, .ifindex = 0, .netmask = [4]u8{ 255, 255, 255, 254 } };

    const leader_result = ElectLeader(hostiface, &know_hosts);

    try std.testing.expectEqual(false, leader_result.isMe);
    try std.testing.expectEqual([4]u8{ 192, 168, 1, 1 }, leader_result.host.ipaddr);
    try std.testing.expectEqual([6]u8{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xF2 }, leader_result.host.macaddr);
}

test "leader election test, is me" {
    const know_hosts = [4]KnownHost{
        KnownHost{ .ipaddr = [4]u8{ 192, 168, 1, 1 }, .macaddr = [6]u8{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xF2 } },
        KnownHost{ .ipaddr = [4]u8{ 192, 168, 1, 2 }, .macaddr = [6]u8{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xF3 } },
        KnownHost{ .ipaddr = [4]u8{ 192, 168, 1, 3 }, .macaddr = [6]u8{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xF4 } },
        KnownHost{ .ipaddr = [4]u8{ 192, 168, 1, 4 }, .macaddr = [6]u8{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xF5 } },
    };

    const hostiface = HostInterface{ .ipaddr = [4]u8{ 192, 168, 0, 10 }, .macaddr = [6]u8{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xF2 }, .ifindex = 0, .netmask = [4]u8{ 255, 255, 255, 254 } };

    const leader_result = ElectLeader(hostiface, &know_hosts);

    try std.testing.expectEqual(false, leader_result.isMe);
    try std.testing.expectEqual([4]u8{ 192, 168, 1, 1 }, leader_result.host.ipaddr);
    try std.testing.expectEqual([6]u8{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xF2 }, leader_result.host.macaddr);
}
