package rnet

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/vishvananda/netlink"

	"math/rand"
)

func NetH(isnet bool) error {

	exs := false

	if _, err := netlink.LinkByName("brdg"); err == nil {
		exs = true
	} else if _, ok := err.(netlink.LinkNotFoundError); !ok {
		return fmt.Errorf("error checking for bridge: %v", err)
	}

	if exs == false {
		br := &netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Name: "brdg"}}

		if err := netlink.LinkAdd(br); err != nil {
			return fmt.Errorf("error creating bridge: %v", err)
		}

		addr := &netlink.Addr{IPNet: &net.IPNet{IP: net.IPv4(10, 0, 0, 1), Mask: net.CIDRMask(24, 32)}}

		if err := netlink.AddrAdd(br, addr); err != nil {
			return fmt.Errorf("error assigning address to bridge: %v", err)
		}

		if err := netlink.LinkSetUp(br); err != nil {
			return fmt.Errorf("error setting up bridge: %v", err)
		}

		ipf := "/proc/sys/net/ipv4/ip_forward"
		if err := os.WriteFile(ipf, []byte("1"), 0644); err != nil {
			return fmt.Errorf("error enabling IP forwarding: %v", err)
		}
	}

	return nil
}

func NetC(pid int) error {

	br, err := netlink.LinkByName("brdg")

	if err != nil {
		if _, ok := err.(netlink.LinkNotFoundError); ok {
			return fmt.Errorf("bridge not found")
		}
		return fmt.Errorf("error retrieving bridge: %v", err)
	}

	vthh := "vethz" + fmt.Sprint(rand.Intn(10000))
	vthc := "con-veth" + fmt.Sprint(rand.Intn(10000))

	if err := netlink.LinkAdd(&netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: vthh, MasterIndex: br.Attrs().Index},
		PeerName:  vthc,
	}); err != nil {
		return fmt.Errorf("error creating veth pair: %v", err)
	}

	veth, err := netlink.LinkByName(vthc)
	if err != nil {
		return fmt.Errorf("error retrieving container veth: %v", err)
	}

	hveth, err := netlink.LinkByName(vthh)
	if err != nil {
		return fmt.Errorf("error retrieving host veth: %v", err)
	}
	if err := netlink.LinkSetUp(hveth); err != nil {
		return fmt.Errorf("error setting host veth up: %v", err)
	}

	if err := netlink.LinkSetNsPid(veth, pid); err != nil {
		return fmt.Errorf("error setting container veth to ns: %v", err)
	}

	return nil
}

func Chnet() error {

	time.Sleep(250 * time.Millisecond)

	links, err := netlink.LinkList()
	if err != nil {
		return fmt.Errorf("error listing network interfaces: %v", err)
	}

	var cvth netlink.Link
	for _, link := range links {
		if strings.HasPrefix(link.Attrs().Name, "con-veth") {
			cvth = link
			break
		}
	}

	if cvth == nil {
		return fmt.Errorf("container veth interface not found")
	}

	veth := cvth

	netlink.LinkSetName(veth, "eth0")

	ipstr := os.Getenv("MINIDKR_IP")
	ip := net.ParseIP(ipstr)
	if ip == nil {
		return fmt.Errorf("invalid IP address: %s", ipstr)
	}

	addr := &netlink.Addr{IPNet: &net.IPNet{IP: ip, Mask: net.CIDRMask(24, 32)}}

	if err := netlink.AddrAdd(veth, addr); err != nil {
		return fmt.Errorf("error assigning address to veth: %v", err)
	}

	lo, err := netlink.LinkByName("lo")
	if err != nil {
		return fmt.Errorf("error retrieving loopback interface: %v", err)
	}

	if err := netlink.LinkSetUp(lo); err != nil {
		return fmt.Errorf("error setting loopback up: %v", err)
	}

	if err := netlink.LinkSetUp(veth); err != nil {
		return fmt.Errorf("error setting veth up: %v", err)
	}

	route := &netlink.Route{
		Dst:       nil,
		LinkIndex: veth.Attrs().Index,
		Gw:        net.IPv4(10, 0, 0, 1)}

	if err := netlink.RouteAdd(route); err != nil {
		return fmt.Errorf("error adding route: %v", err)
	}

	return nil
}

func Dif() (string, error) {

	rts, err := netlink.RouteGet(net.IPv4(8, 8, 8, 8))

	if err != nil {
		return "", fmt.Errorf("RouteGet failed: %v", err)
	}

	if len(rts) == 0 {
		return "", fmt.Errorf("no route to 8.8.8.8")
	}

	link, err := netlink.LinkByIndex(rts[0].LinkIndex)
	if err != nil {
		return "", fmt.Errorf("error retrieving link: %v", err)
	}

	attrs := link.Attrs()
	if attrs == nil {
		return "", fmt.Errorf("no attrs on link")
	}
	if attrs.Flags&net.FlagLoopback != 0 {
		return "", fmt.Errorf("resolved default intreface to lo")
	}
	return attrs.Name, nil

}

func Prtf(ip net.IP, port string) error {

	rlnet := "/proc/sys/net/ipv4/conf/all/route_localnet"
	if err := os.WriteFile(rlnet, []byte("1"), 0o644); err != nil {
		return fmt.Errorf("error enabling route_localnet: %v", err)
	}

	ips := ip.String()

	prts := strings.Split(port, ":")
	if len(prts) != 2 {
		return fmt.Errorf("invalid port format: %s", port)
	}

	hport, err := strconv.Atoi(prts[0])
	if err != nil {
		return fmt.Errorf("invalid host port: %v", err)
	}

	cport, err := strconv.Atoi(prts[1])
	if err != nil {
		return fmt.Errorf("invalid container port: %v", err)
	}

	houtfrwd := exec.Command(
		"iptables", "-t", "nat", "-A", "OUTPUT", "-d", "127.0.0.1/32",
		"-p", "tcp", "--dport", strconv.Itoa(hport),
		"-j", "DNAT", "--to-destination", fmt.Sprintf("%s:%d", ips, cport),
	)

	if out, err := houtfrwd.CombinedOutput(); err != nil {
		return fmt.Errorf("error setting up output port forwarding: %v, output: %s", err, string(out))
	}

	cportfrwd := exec.Command(
		"iptables", "-A", "FORWARD", "-p", "tcp",
		"-d", ips, "--dport", strconv.Itoa(cport),
		"-j", "ACCEPT",
	)

	if out, err := cportfrwd.CombinedOutput(); err != nil {
		return fmt.Errorf("error setting up port forwarding: %v, output: %s", err, string(out))
	}

	snat := exec.Command(
		"iptables", "-t", "nat", "-A", "POSTROUTING",
		"-s", "127.0.0.1/32",
		"-d", ips,
		"-p", "tcp",
		"--dport", strconv.Itoa(cport),
		"-j", "SNAT", "--to-source", "10.0.0.1",
	)
	if out, err := snat.CombinedOutput(); err != nil {
		return fmt.Errorf("error setting up SNAT: %v, output: %s", err, string(out))
	}

	return nil

}

func Masq(intf, ip string) error {
	iptbls := exec.Command("iptables", "-t", "nat", "-C", "POSTROUTING", "-s", ip, "-o", intf, "-j", "MASQUERADE")
	if err := iptbls.Run(); err == nil {
		return nil
	}

	iptblsr := exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING", "-s", ip, "-o", intf, "-j", "MASQUERADE")
	if err := iptblsr.Run(); err != nil {
		return fmt.Errorf("error setting up masquerading: %v", err)
	}

	nat := exec.Command("iptables", "-A", "FORWARD",
		"-s", ip, "-o", intf, "-j", "ACCEPT")
	if err := nat.Run(); err != nil {
		return fmt.Errorf("error setting up NAT: %v", err)
	}

	natn := exec.Command("iptables", "-A", "FORWARD",
		"-d", ip,
		"-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED",
		"-j", "ACCEPT")
	if err := natn.Run(); err != nil {
		return fmt.Errorf("error setting up NAT: %v", err)
	}

	return nil
}

func Clnup() error {

	intf, err := Dif()
	if err == nil {
		_ = exec.Command("iptables", "-t", "nat", "-D", "POSTROUTING", "-s",
			"10.0.0.0/24", "-o", intf, "-j", "MASQUERADE").Run()

		_ = exec.Command("iptables", "-D", "FORWARD",
			"-s", "10.0.0.0/24", "-o", intf, "-j", "ACCEPT").Run()

		_ = exec.Command("iptables", "-D", "FORWARD",
			"-d", "10.0.0.0/24",
			"-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED",
			"-j", "ACCEPT").Run()
	}

	br, err := netlink.LinkByName("brdg")
	if err == nil {
		lnks, err := netlink.LinkList()
		if err == nil {

			for _, lnk := range lnks {
				if !strings.HasPrefix(lnk.Attrs().Name, "vethz") {
					continue
				}

				if lnk.Attrs().MasterIndex == br.Attrs().Index {
					_ = netlink.LinkDel(lnk)
				}
			}
		}

		if br != nil && err == nil {
			_ = netlink.LinkSetDown(br)
			_ = netlink.LinkDel(br)
		}
	}

	ipf := "/proc/sys/net/ipv4/ip_forward"
	if err := os.WriteFile(ipf, []byte("0"), 0644); err != nil {
		return fmt.Errorf("error disabling IP forwarding: %v", err)
	}

	_ = os.WriteFile("/proc/sys/net/ipv4/conf/all/route_localnet", []byte("0"), 0o644)

	return nil

}

func PrtfD(ip, port string) error {

	prts := strings.Split(port, ":")
	if len(prts) != 2 {
		return fmt.Errorf("invalid port format: %s", port)
	}

	hport, err := strconv.Atoi(prts[0])
	if err != nil {
		return fmt.Errorf("invalid host port: %v", err)
	}

	cport, err := strconv.Atoi(prts[1])
	if err != nil {
		return fmt.Errorf("invalid container port: %v", err)
	}

	houtfrwd := exec.Command(
		"iptables", "-t", "nat", "-D", "OUTPUT",
		"-p", "tcp", "--dport", strconv.Itoa(hport),
		"-j", "DNAT", "--to-destination", fmt.Sprintf("%s:%d", ip, cport),
	)

	if out, err := houtfrwd.CombinedOutput(); err != nil {
		return fmt.Errorf("error cleaning up output port forwarding: %v, output: %s", err, string(out))
	}

	cportfrwd := exec.Command(
		"iptables", "-D", "FORWARD", "-p", "tcp",
		"-d", ip, "--dport", strconv.Itoa(cport),
		"-j", "ACCEPT",
	)

	if out, err := cportfrwd.CombinedOutput(); err != nil {
		return fmt.Errorf("error cleaning up port forwarding: %v, output: %s", err, string(out))
	}

	snat := exec.Command(
		"iptables", "-t", "nat", "-D", "POSTROUTING",
		"-s", "127.0.0.1/32",
		"-d", ip,
		"-p", "tcp",
		"--dport", strconv.Itoa(cport),
		"-j", "SNAT", "--to-source", "10.0.0.1",
	)
	if out, err := snat.CombinedOutput(); err != nil {
		return fmt.Errorf("error cleaning up SNAT: %v, output: %s", err, string(out))
	}

	return nil

}
