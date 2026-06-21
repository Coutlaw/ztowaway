const std = @import("std");

const log = std.log.scoped(.network);

// Ethernet Constants
const ETH_P_ARP = 0x0806;
const ARPOP_REQUEST = 1;
const ARPHRD_ETHER = 1;

// Layer 2 broadcast MAC
pub const MACBroadcastAddr: [6]u8 = "FF:FF:FF:FF:FF:FF";

// Host
pub const HostInterface = struct {
    macaddr: [6]u8,
    ipaddr: [4]u8,
    netmask: [4]u8,
    ifindex: i32,
};

// Constants for ARP frame
pub const HardwareType = enum(16) {
    ethernet = 1,
    _,
};

pub const ProtocolType = enum(16) {
    ipv4 = 0x0800,
    _,
};

pub const Operation = enum(16) {
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
    htype: HardwareType,
    ptype: ProtocolType,
    hlen: u8, // Hardware address len, always 6 for Eth
    plen: u8,
    oper: Operation,
    senderHaddr: [6]u8,
    senderPaddr: [4]u8,
    targetHaddr: [6]u8,
    targetPaddr: [4]u8,
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
    // Dummy socket, needed for ioctl to find host MAC
    const dummySocket: i32 = @intCast(std.os.linux.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, 0));
    defer _ = std.os.linux.close(dummySocket);

    // Set up the ifr (inerface request) struct with the interface name (e.g. "eth0", "enp3s0")
    var ifr = std.mem.zeroes(std.posix.ifreq); // ifreq == linux here
    if (iface.len > std.posix.IFNAMESIZE - 1) return error.InterfaceNameTooLong;
    @memcpy(ifr.ifrn.name[0..iface.len], iface);
    ifr.ifrn.name[iface.len] = 0;

    var info: HostInterface = undefined;

    // SIOCGIFHWADDR (network interface address aka MAC)
    const rc = std.os.linux.ioctl(dummySocket, std.os.linux.SIOCGIFHWADDR, @intFromPtr(&ifr));
    if (rc != 0) return error.IoctlFailed; // better error handling one day.SIOCGIFHWADDR
    @memcpy(&info.macaddr, ifr.ifru.hwaddr.data[0..6]);
    log.debug("MAC: {x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}", .{
        info.macaddr[0], info.macaddr[1], info.macaddr[2],
        info.macaddr[3], info.macaddr[4], info.macaddr[5],
    });

    // SIOCGIFINDEX (Interface Index)
    @memcpy(ifr.ifrn.name[0..iface.len], iface); // reset incase it was overwritten
    const iirq = std.os.linux.ioctl(dummySocket, std.os.linux.SIOCGIFINDEX, @intFromPtr(&ifr));
    if (iirq != 0) return error.IoctlFailed;
    info.ifindex = ifr.ifru.ivalue;
    log.debug("ifindex: {d}", .{info.ifindex});

    // SIOCGIFADDR (IP Addr)
    @memcpy(ifr.ifrn.name[0..iface.len], iface); // reset incase it was overwritten
    const iprq = std.os.linux.ioctl(dummySocket, std.os.linux.SIOCGIFADDR, @intFromPtr(&ifr));
    if (iprq != 0) return error.IoctlFailed;
    // casting the pointer to a sockaddr.in will prevent a AF_NET byte index  on sockaddr.data[2..6]
    const sin_addr: *const std.posix.sockaddr.in = @ptrCast(&ifr.ifru.addr);
    @memcpy(&info.ipaddr, std.mem.asBytes(&sin_addr.addr));
    log.debug("IP: {}.{}.{}.{}", .{
        info.ipaddr[0], info.ipaddr[1], info.ipaddr[2], info.ipaddr[3],
    });

    // SIOCGIFNETMASK (netmask)
    @memcpy(ifr.ifrn.name[0..iface.len], iface);
    const nmrq = std.os.linux.ioctl(dummySocket, std.os.linux.SIOCGIFNETMASK, @intFromPtr(&ifr));
    if (nmrq != 0) return error.IoctlFailed;
    const nm_sin: *const std.posix.sockaddr.in = @ptrCast(&ifr.ifru.addr);
    @memcpy(&info.netmask, std.mem.asBytes(&nm_sin.addr));
    log.debug("netmask: {}.{}.{}.{}", .{
        info.netmask[0], info.netmask[1],
        info.netmask[2], info.netmask[3],
    });

    return info;
}
