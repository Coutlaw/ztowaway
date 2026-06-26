# ztowaway

A host process to automatically discover hosts on the same network running the same process, then bootstraps a k8s cluster automatically.

## Building

Sending raw ARP packets requires the `cap_net_raw` capability. Run `zig build setcap` after building to grant it, which avoids needing to run the program as root.
