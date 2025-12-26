Custom container runtime written in Go.

Features:
- No dependencies-ish
- Custom OCI image extractor
- Linux namespace isolation
- Custom Networking (veth pairs, NAT, Port forwarding)
- Ip allocation via stateful IPAM daemon
- Options for networking and port forwarding
- Go userspace controller
- State tracking


What it does NOT have:
- Support for several tar header types(xattrs, fifos, sparse, etc.)
- Cgroup resource limits
- Overlayfs
- Exec
- Security profiles

Requirements:
- Iptables
- Sudo
- Docker(just for pulls & saves)

To use just build it, also run with sudo if you're actually going to run it.
If it errors with no container veth then run it again(should be fixed but possible)
