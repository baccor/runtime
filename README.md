Custom container runtime written in Go.

Features:
- No dependencies-ish
- Custom OCI image extractor
- Linux namespace isolation
- Custom Networking (veth pairs, NAT, Port forwarding)
- Ip allocation via stateful IPAM daemon
- Options for networking and port forwarding
- Go userspace controller


What it does NOT have:
- Support for several tar header types(xattrs, fifos, sparse, etc.)
- Cgroup resource limits
- Overlayfs
- Container state tracking
- Exec(depends on state tracking)
- Security profiles
- port forward depends on net

To use just build it, also run with sudo if you're actually going to run it.
If it errors with no container veth then run it again(should be fixed but possible)
