Custom container runtime written in Go.

Features:
- No dependencies-ish
- Custom OCI(whiteouts/layers) image extractor
- Linux namespace isolation
- Custom Networking (veth pairs, NAT, Port forwarding)
- Network management via stateful IPAM daemon
- Options for networking, port forwarding, custom envs
- Go userspace controller
- State tracking
- Cgroups


What it does NOT have:
- Support for several tar header types(xattrs, fifos, sparse, etc.)
- Overlayfs
- Exec
- Security profiles

Requirements:
- Iptables
- Sudo
- Docker(just for pulls & saves, not a hard requirement)
- Systemd

To use just build it, also run with sudo if you're actually going to run it.

Usage: sudo ./dckr(assuming you build it like such) pullexp|run|pullnrun|lim

pullexp <image tag> (the tag has to match the manifest reference)

pullnrun <image tag> {net} {host:port} {ENV=VAL,ENV=VAL...}

run <image tag || rootfs path(extracted using pullexp)> {net} {host:port} {ENV=VAL,ENV=VAL...}

lim <PID> [cpu||mem||pid] <value>    
