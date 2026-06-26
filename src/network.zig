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

// Host
pub const HostInterface = struct {
    macaddr: [6]u8,
    ipaddr: [4]u8,
    netmask: [4]u8,
    ifindex: i32,
};

// Discovered Host: A host that responds to an ARP frame
pub const KnownHost = struct {
    macaddr: [6]u8,
    ipaddr: [4]u8,
};

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

pub fn GetHostInterfaceInfo(iface: []const u8, socket: i32) !HostInterface {
    // Set up the ifr (inerface request) struct with the interface name (e.g. "eth0", "enp3s0")
    var ifr = std.mem.zeroes(std.posix.ifreq); // ifreq == linux here
    if (iface.len > std.posix.IFNAMESIZE - 1) return error.InterfaceNameTooLong;
    @memcpy(ifr.ifrn.name[0..iface.len], iface);
    ifr.ifrn.name[iface.len] = 0;

    var info: HostInterface = undefined;

    // SIOCGIFHWADDR (network interface address aka MAC)
    const rc = std.os.linux.ioctl(socket, std.os.linux.SIOCGIFHWADDR, @intFromPtr(&ifr));
    if (rc != 0) return error.IoctlFailed; // better error handling one day.
    @memcpy(&info.macaddr, ifr.ifru.hwaddr.data[0..6]);
    log.debug("MAC: {x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}", .{
        info.macaddr[0], info.macaddr[1], info.macaddr[2],
        info.macaddr[3], info.macaddr[4], info.macaddr[5],
    });

    // SIOCGIFINDEX (Interface Index)
    @memcpy(ifr.ifrn.name[0..iface.len], iface); // reset incase it was overwritten
    const iirq = std.os.linux.ioctl(socket, std.os.linux.SIOCGIFINDEX, @intFromPtr(&ifr));
    if (iirq != 0) return error.IoctlFailed;
    info.ifindex = ifr.ifru.ivalue;
    log.debug("ifindex: {d}", .{info.ifindex});

    // SIOCGIFADDR (IP Addr)
    @memcpy(ifr.ifrn.name[0..iface.len], iface); // reset incase it was overwritten
    const iprq = std.os.linux.ioctl(socket, std.os.linux.SIOCGIFADDR, @intFromPtr(&ifr));
    if (iprq != 0) return error.IoctlFailed;
    // casting the pointer to a sockaddr.in will prevent a AF_NET byte index  on sockaddr.data[2..6]
    const sin_addr: *const std.posix.sockaddr.in = @ptrCast(&ifr.ifru.addr);
    @memcpy(&info.ipaddr, std.mem.asBytes(&sin_addr.addr));
    log.debug("IP: {}.{}.{}.{}", .{
        info.ipaddr[0], info.ipaddr[1], info.ipaddr[2], info.ipaddr[3],
    });

    // SIOCGIFNETMASK (netmask)
    @memcpy(ifr.ifrn.name[0..iface.len], iface);
    const nmrq = std.os.linux.ioctl(socket, std.os.linux.SIOCGIFNETMASK, @intFromPtr(&ifr));
    if (nmrq != 0) return error.IoctlFailed;
    const nm_sin: *const std.posix.sockaddr.in = @ptrCast(&ifr.ifru.addr);
    @memcpy(&info.netmask, std.mem.asBytes(&nm_sin.addr));
    log.debug("netmask: {}.{}.{}.{}", .{
        info.netmask[0], info.netmask[1],
        info.netmask[2], info.netmask[3],
    });

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
        .protocol = ETH_P_ARP,
        .ifindex = iface.ifindex,
        .hatype = ARPHRD_ETHER,
        .pkttype = 0,
        .halen = 6,
        .addr = .{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0 },
    };
}

//Eventually needs to return ![]KnownHost
pub fn LocalNetworkArpScan(hostiface: []const u8, allocator: std.mem.Allocator) ![]KnownHost {
    const ioctl_socket: i32 = @intCast(std.os.linux.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, 0));

    const host_network_interface = try GetHostInterfaceInfo(hostiface, ioctl_socket);
    const usable_ips = try GetSubnetHosts(allocator, host_network_interface.ipaddr, host_network_interface.netmask);
    defer allocator.free(usable_ips);
    _ = std.os.linux.close(ioctl_socket);

    // AF_PACKET and ETH_P_ARP will allow ARP resonses to sit in this sockets recieve buffer
    const raw_socket_rc = std.os.linux.socket(std.os.linux.AF.PACKET, std.posix.SOCK.RAW, std.mem.nativeToBig(u16, ETH_P_ARP));
    if (std.os.linux.errno(raw_socket_rc) != .SUCCESS) {
        log.debug("Error Number: {}", .{raw_socket_rc});
        if (raw_socket_rc == 18446744073709551615) {
            log.err("Missing the Capability to use raw socket hosts, run zig build setcap to rebuild binary", .{});
            return error.RawSocketCapabilityMissing;
        }

        return error.SocketFailed;
    }

    const raw_socket: i32 = @intCast(raw_socket_rc);
    defer _ = std.os.linux.close(raw_socket);

    const dest_sock_addr = FormatDestSockAddr(host_network_interface);

    // Ignore the target ip, it's just to get a non zero value
    var arpRequest = FormatArpRequest(host_network_interface, host_network_interface.ipaddr);

    // Boardcast ARP to every known IP
    for (usable_ips) |target_ip| {
        arpRequest.arp.tpa = target_ip;
        const raw_msg = std.mem.asBytes(&arpRequest);

        const resp = std.os.linux.sendto(raw_socket, raw_msg, raw_msg.len, 0, @ptrCast(&dest_sock_addr), @sizeOf(std.os.linux.sockaddr.ll));
        if (std.os.linux.errno(resp) != std.os.linux.E.SUCCESS) {
            log.warn("sendto failed for {}.{}.{}.{}: errno {}", .{
                target_ip[0],             target_ip[1], target_ip[2], target_ip[3],
                std.os.linux.errno(resp),
            });
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

    while (true) {
        const ready = std.os.linux.poll(&fds, 1, 1000); // 1ms
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
