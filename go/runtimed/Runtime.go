package runtimed

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"mdkr/initz"
	"mdkr/manifest"
	"mdkr/rnet"
	"mdkr/state"
	"mdkr/structs"
	"mdkr/whiteouts"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
)

func Pullexp(img string) (tmppth string, imgstr *structs.Img, err error) {

	var imgstruct structs.Img

	if err := exec.Command("docker", "pull", img).Run(); err != nil {
		fmt.Printf("error pulling docker image: %v", err)
		return "", nil, err
	}

	val := strings.ReplaceAll(img, "/", "_")

	if err := exec.Command("docker", "save", "-o", val+".tar", img).Run(); err != nil {
		fmt.Printf("error saving docker image: %v", err)
		return "", nil, err
	}

	wd, err := os.Getwd()
	if err != nil {
		fmt.Printf("Error getting current directory: %v\n", err)
		return "", nil, err
	}
	imgpath := filepath.Join(wd, val+".tar")
	if err := manifest.FManifest(imgpath, img, &imgstruct); err != nil {
		fmt.Printf("Error processing image manifest: %v\n", err)
		return "", nil, err
	}

	defer os.Remove(imgpath)

	basepth := "/var/tmp/minidkr/" + val + "-" + fmt.Sprintf("%d", rand.Intn(10000))
	if err := os.MkdirAll(basepth, 0755); err != nil {
		fmt.Printf("error preparing rootfs path: %v", err)
		return "", nil, err
	}

	if err := makec(&imgstruct, basepth); err != nil {
		_ = os.RemoveAll(basepth)
		fmt.Fprintf(os.Stderr, "makec error: %v\n", err)
		return "", nil, err

	}

	return basepth, &imgstruct, nil
}

func gz(r io.Reader) (io.Reader, io.Closer, error) {
	br := bufio.NewReader(r)

	hdr, err := br.Peek(2)
	if err == nil && len(hdr) == 2 && hdr[0] == 0x1f && hdr[1] == 0x8b {
		gr, err := gzip.NewReader(br)
		if err != nil {
			return nil, nil, err
		}
		return gr, gr, nil
	}

	return br, io.NopCloser(nil), nil
}

func makec(imgstruct *structs.Img, basepth string) error {
	meta := make(map[string]structs.Metadata)

	defer Rm()

	for _, layer := range imgstruct.Layerpth {
		f, err := os.Open(layer)
		if err != nil {
			return fmt.Errorf("error opening layer %s: %w", layer, err)
		}

		g, gc, err := gz(f)
		if err != nil {
			f.Close()
			return fmt.Errorf("gzip wrap failed for %s: %w", layer, err)
		}

		tr := tar.NewReader(g)
		if err := whiteouts.Whiteouts(tr, meta, basepth); err != nil {
			gc.Close()
			f.Close()
			return fmt.Errorf("error processing layer %s: %w", layer, err)
		}
		gc.Close()
		f.Close()

	}

	for pth, md := range meta {
		if err := os.Chmod(pth, md.Mode.Perm()); err != nil {
			fmt.Printf("error setting permissions on %s", pth)
		}
		if err := os.Chown(pth, md.Uid, md.Gid); err != nil {
			fmt.Printf("error setting ownership on %s\n", pth)
		}
		if err := os.Chtimes(pth, md.Mtime, md.Mtime); err != nil {
			fmt.Printf("error setting times on %s", pth)
		}
	}

	fmt.Printf("Container filesystem created at %s\n", basepth)
	return nil

}

func Rm() error {
	fls, err := filepath.Glob("/tmp/imglayer_*")

	if err != nil {
		return err
	}

	for _, fl := range fls {
		if err := os.RemoveAll(fl); err != nil {
			fmt.Printf("error removing temp file %s: %v\n", fl, err)
		}
	}

	return nil
}

func Runet(img, port string, isnet bool, conf structs.Confjs, cenv string) error {

	if err := Rundae(); err != nil {
		return fmt.Errorf("error initalizing daemon: %v", err)
	}

	if isnet || port != "" {

		if err := Prenet(isnet); err != nil {
			return fmt.Errorf("error setting up host network: %v", err)
		}

	}

	exe, err := os.Executable()
	if err != nil {
		return err
	}

	str, err := Cmnd(conf)
	if err != nil {
		return fmt.Errorf("error preparing entrypoint: %v", err)
	}
	strjs, err := json.Marshal(str)
	if err != nil {
		return fmt.Errorf("error marshaling argv: %v", err)
	}
	env := []string{
		"MINIDKR_STR=" + string(strjs),
	}
	if len(conf.Config.Env) > 0 {
		env = append(env, conf.Config.Env...)
	}
	if cenv != "" {
		prts := strings.Split(cenv, ",")
		env = append(env, prts...)
	}
	hasPath := false
	for _, e := range env {
		if strings.HasPrefix(e, "PATH=") {
			hasPath = true
			break
		}
	}
	if !hasPath {
		env = append(env, "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/bin")
	}

	ipa := ""
	pidfr := ""
	if isnet || port != "" {
		ip, err := IPalloc(isnet, port)
		if err != nil {
			return fmt.Errorf("error allocating ip: %v", err)
		}
		defer func() {
			_ = IPfree(pidfr, ipa)
		}()

		ipa = ip
	}
	if port != "" {
		defer rnet.PrtfD(ipa, port)
	}

	cmd := exec.Command(exe, "frk", img, port)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUTS | syscall.CLONE_NEWPID | syscall.CLONE_NEWNS |
			syscall.CLONE_NEWIPC | syscall.CLONE_NEWNET, Pdeathsig: syscall.SIGKILL}

	cmd.Env = env
	if isnet || port != "" {
		cmd.Env = append(cmd.Env, "MINIDKR_IP="+ipa)
	}
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Start()
	if err != nil {
		return err
	}

	pid := cmd.Process.Pid
	fmt.Printf("Started process with PID %d\n", pid)
	pidfr = strconv.Itoa(pid)
	err = pidreg(pidfr, ipa)
	if err != nil {
		return err
	}
	if ipa == "" {
		defer IPfree(pidfr, "")
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGINT)

	done := make(chan struct{})

	go func() {
		select {
		case <-sigs:
			if cmd.Process != nil {
				_ = cmd.Process.Kill()
			}
		case <-done:
			return
		}
	}()

	err = cmd.Wait()
	close(done)

	return nil
}

func Frk(rootfs string) error {

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if err := syscall.Mount("", "/", "", syscall.MS_REC|syscall.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("error making mounts private: %v", err)
	}

	if err := rootpv(rootfs); err != nil {
		return err
	}

	if err := os.MkdirAll("/proc", 0555); err != nil {
		return fmt.Errorf("error creating /proc: %v", err)
	}

	flgs := uintptr(syscall.MS_NODEV | syscall.MS_NOSUID | syscall.MS_NOEXEC)
	if err := syscall.Mount("proc", "/proc", "proc", flgs, ""); err != nil {
		return fmt.Errorf("error mounting /proc: %v", err)
	}

	if err := os.MkdirAll("/dev", 0755); err != nil {
		return fmt.Errorf("error creating /dev: %v", err)
	}

	fl := uintptr(syscall.MS_NOSUID | syscall.MS_STRICTATIME)
	if err := syscall.Mount("devtmpfs", "/dev", "devtmpfs", fl, ""); err != nil {
		return fmt.Errorf("error mounting devtmpfs on /dev: %v", err)
	}

	_ = os.Remove("/dev/fd")
	_ = os.Remove("/dev/stdin")
	_ = os.Remove("/dev/stdout")
	_ = os.Remove("/dev/stderr")

	if err := os.Symlink("/proc/self/fd", "/dev/fd"); err != nil && !os.IsExist(err) {
		return fmt.Errorf("error creating /dev/fd: %v", err)
	}
	if err := os.Symlink("/proc/self/fd/0", "/dev/stdin"); err != nil && !os.IsExist(err) {
		return fmt.Errorf("error creating /dev/stdin: %v", err)
	}
	if err := os.Symlink("/proc/self/fd/1", "/dev/stdout"); err != nil && !os.IsExist(err) {
		return fmt.Errorf("error creating /dev/stdout: %v", err)
	}
	if err := os.Symlink("/proc/self/fd/2", "/dev/stderr"); err != nil && !os.IsExist(err) {
		return fmt.Errorf("error creating /dev/stderr: %v", err)
	}

	if err := os.MkdirAll("/sys", 0555); err != nil {
		return fmt.Errorf("error creating /sys: %v", err)
	}

	if err := syscall.Mount("sysfs", "/sys", "sysfs", 0, ""); err != nil {
		return fmt.Errorf("error mounting /sys: %v", err)
	}

	if err := syscall.Sethostname([]byte("minidkr-" + fmt.Sprintf("%d", rand.Intn(10000)))); err != nil {
		return fmt.Errorf("error setting hostname: %v", err)
	}

	dns := "nameserver 1.1.1.1\nnameserver 8.8.8.8"
	lh := "127.0.0.1 localhost\n::1 ip6-localhost ip6-loopback"

	ipstr := os.Getenv("MINIDKR_IP")
	if ipstr != "" {
		if err := rnet.Chnet(); err != nil {
			return fmt.Errorf("error configuring network: %v", err)
		}
		if err := os.MkdirAll("/etc", 0755); err != nil {
			return fmt.Errorf("error creating /etc for dns: %v", err)
		}
		if err := os.WriteFile("/etc/resolv.conf", []byte(dns), 0644); err != nil {
			return fmt.Errorf("error setting dns: %v", err)
		}
		if err := os.WriteFile("/etc/hosts", []byte(lh), 0644); err != nil {
			return fmt.Errorf("error setting /etc/hosts: %v", err)
		}

	}

	lo, err := netlink.LinkByName("lo")
	netlink.LinkSetUp(lo)
	if err != nil {
		fmt.Printf("can't set up lo link: %v", err)
	}

	strjs := os.Getenv("MINIDKR_STR")
	var str []string

	if strjs != "" {
		if err := json.Unmarshal([]byte(strjs), &str); err != nil {
			return fmt.Errorf("invalid MINIDKR_STR: %v", err)
		}
	}

	if len(str) == 0 {
		str = []string{"/bin/sh"}
	}
	env := os.Environ()

	path, err := exec.LookPath(str[0])
	if err != nil {
		return fmt.Errorf("lookpath failed for %q: %v", str[0], err)
	}

	if err := syscall.Exec(path, str, env); err != nil {
		return fmt.Errorf("error executing container process: %v", err)
	}

	return nil
}

func rootpv(rootfs string) error {
	if err := syscall.Mount(rootfs, rootfs, "", syscall.MS_BIND|syscall.MS_REC, ""); err != nil {
		return fmt.Errorf("error bind mounting rootfs: %v", err)
	}

	old := filepath.Join(rootfs, "oldroot")
	if err := os.MkdirAll(old, 0700); err != nil {
		return fmt.Errorf("error creating oldroot dir: %v", err)
	}

	if err := syscall.PivotRoot(rootfs, old); err != nil {
		return fmt.Errorf("error performing pivot_root: %v", err)
	}

	if err := os.Chdir("/"); err != nil {
		return fmt.Errorf("error changing directory to new root: %v", err)
	}

	if err := syscall.Unmount("/oldroot", syscall.MNT_DETACH); err != nil {
		return fmt.Errorf("error unmounting old root: %v", err)
	}

	if err := os.RemoveAll("/oldroot"); err != nil {
		return fmt.Errorf("error removing old root dir: %v", err)
	}

	return nil
}

func Pullnrun(imgpth string, isnet bool, port, cenv string) error {

	tmppth, imgstruct, err := Pullexp(imgpth)
	if err != nil {
		return fmt.Errorf("error pulling and exporting image: %v", err)
	}
	defer os.RemoveAll(tmppth)
	confstr, err := Confp(imgstruct)
	if err != nil {
		return fmt.Errorf("error parsing config: %v", err)
	}

	if isnet {
		if err := Runet(tmppth, port, true, confstr, cenv); err != nil {
			return fmt.Errorf("error running container with network: %v", err)
		}
	} else if !isnet {
		if err := Runet(tmppth, port, false, confstr, cenv); err != nil {
			return fmt.Errorf("error running container: %v", err)
		}
	}

	return nil

}

func Confp(imgstruct *structs.Img) (structs.Confjs, error) {
	var confjs structs.Confjs
	if err := json.Unmarshal(imgstruct.Confjs, &confjs); err != nil {
		return structs.Confjs{}, fmt.Errorf("error unmarshalling image config: %v", err)
	}

	return confjs, nil

}

func Cmnd(confjs structs.Confjs) ([]string, error) {
	entp := confjs.Config.Entrypoint
	cmd := confjs.Config.Cmd
	if len(entp) == 0 && len(cmd) == 0 {
		return []string{"/bin/sh"}, nil
	}
	if len(entp) == 0 {
		return cmd, nil
	}
	if len(cmd) == 0 {
		return entp, nil
	}
	encmd := make([]string, 0, len(entp)+len(cmd))
	encmd = append(encmd, entp...)
	encmd = append(encmd, cmd...)
	return encmd, nil
}

func Iftar(img string) (imgpth string, confstr structs.Confjs, err error, isdir bool) {
	var imgstr structs.Img
	finf, err := os.Stat(img)
	if err != nil {
		if os.IsNotExist(err) {
			return "", structs.Confjs{}, fmt.Errorf("error: file/path doesn't exist"), false
		}
	}

	switch {

	case finf.Mode().IsDir():

		return img, structs.Confjs{}, nil, true

	case finf.Mode().IsRegular():
		if !finf.Mode().IsRegular() {
			return "", structs.Confjs{}, fmt.Errorf("error: not a regular file or directory"), false
		}

		if err := manifest.FManifest(img, "", &imgstr); err != nil {
			return "", structs.Confjs{}, fmt.Errorf("error extracting rootfs from image: %w", err), false
		}
		basepth := "/var/tmp/minidkr/" + "temp" + "-" + fmt.Sprintf("%d", rand.Intn(10000))
		if err := os.MkdirAll(basepth, 0755); err != nil {
			fmt.Printf("error preparing rootfs path: %v", err)
			return "", structs.Confjs{}, err, false
		}
		if err := makec(&imgstr, basepth); err != nil {
			return "", structs.Confjs{}, fmt.Errorf("error processing image: %w", err), false
		}
		confjs, err := Confp(&imgstr)
		if err != nil {
			return "", structs.Confjs{}, fmt.Errorf("error processing config: %w", err), false
		}
		return basepth, confjs, nil, false

	default:
		return "", structs.Confjs{}, fmt.Errorf("%q is not a valid file/directory", img), false
	}

}

func Delbase(basepth string) error {
	if strings.HasPrefix(basepth, "/var/tmp/minidkr/temp-") {
		if err := os.RemoveAll(basepth); err != nil {
			return fmt.Errorf("error removing tmp path: %v", err)
		}
	}
	return nil

}

const skt = "/run/minidkr.sock"

func Daeinit() error {

	if err := initz.Init(); err != nil {
		return fmt.Errorf("error initializing state: %v", err)
	}

	ln, err := net.Listen("unix", skt)
	if err != nil {
		return fmt.Errorf("listen on %s: %v", skt, err)
	}
	defer ln.Close()

	if err := os.Chmod(skt, 0660); err != nil {
		log.Printf("chmod socket: %v", err)
	}

	log.Printf("daemon listening on %s", skt)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			continue
		}
		go state.HCon(conn)
	}
}

func IPalloc(isnet bool, port string) (string, error) {
	conn, err := net.Dial("unix", skt)
	if err != nil {
		return "", fmt.Errorf("dial daemon: %w", err)
	}
	defer conn.Close()

	net := 0
	if isnet {
		net = 1
	}

	if _, err := fmt.Fprintln(conn, "alloc", strconv.Itoa(net), port); err != nil {
		return "", fmt.Errorf("error allocating ip: %w", err)
	}

	r := bufio.NewReader(conn)
	line, err := r.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("error reading response: %w", err)
	}

	line = strings.TrimSpace(line)
	parts := strings.SplitN(line, " ", 2)

	if len(parts) == 0 {
		return "", fmt.Errorf("error: no response from daemon")
	}

	switch parts[0] {
	case "allocated":
		if len(parts) != 2 || parts[1] == "" {
			return "", fmt.Errorf("daemon OK without ip")
		}
		return parts[1], nil
	case "error":
		if len(parts) == 2 {
			return "", fmt.Errorf("daemon error: %s", parts[1])
		}
		return "", fmt.Errorf("daemon error")
	default:
		return "", fmt.Errorf("error, unexpected response: %q", line)
	}
}

func Prenet(isnet bool) error {

	conn, err := net.Dial("unix", skt)
	if err != nil {
		return fmt.Errorf("dial daemon: %w", err)
	}
	defer conn.Close()

	if isnet {
		if _, err := fmt.Fprintln(conn, "prenet", "net"); err != nil {
			return fmt.Errorf("error preparing net: %w", err)
		}
	} else {
		if _, err := fmt.Fprintln(conn, "prenet"); err != nil {
			return fmt.Errorf("error preparing net: %w", err)
		}
	}

	r := bufio.NewReader(conn)
	line, err := r.ReadString('\n')
	if err != nil {
		return fmt.Errorf("error reading response: %w", err)
	}

	line = strings.TrimSpace(line)
	parts := strings.SplitN(line, " ", 2)

	if len(parts) == 0 {
		return fmt.Errorf("error: no response from daemon")
	}

	switch parts[0] {
	case "done":
		return nil
	case "error":
		if len(parts) == 2 {
			return fmt.Errorf("daemon error: %s", parts[1])
		}
		return fmt.Errorf("daemon error")
	default:
		return fmt.Errorf("error, unexpected response: %q", line)
	}
}

func pidreg(pid, ipa string) error {

	conn, err := net.Dial("unix", skt)
	if err != nil {
		return fmt.Errorf("dial daemon: %w", err)
	}
	defer conn.Close()

	if ipa != "" {
		prts := strings.Split(ipa, ".")
		ipa = prts[len(prts)-1]
	}

	if _, err := fmt.Fprintln(conn, "pidreg", pid, ipa); err != nil {
		return fmt.Errorf("error registering ip: %w", err)
	}

	r := bufio.NewReader(conn)
	line, err := r.ReadString('\n')
	if err != nil {
		return fmt.Errorf("error reading response: %w", err)
	}

	line = strings.TrimSpace(line)
	parts := strings.SplitN(line, " ", 2)

	if len(parts) == 0 {
		return fmt.Errorf("error: no response from daemon")
	}

	switch parts[0] {
	case "done":
		return nil
	case "error":
		if len(parts) == 2 {
			return fmt.Errorf("daemon error: %s", parts[1])
		}
		return fmt.Errorf("daemon error")
	default:
		return fmt.Errorf("error, unexpected response: %q", line)
	}

}

func IPfree(pid, ip string) error {
	conn, err := net.Dial("unix", skt)
	if err != nil {
		return fmt.Errorf("dial daemon: %w", err)
	}
	defer conn.Close()

	if _, err := fmt.Fprintln(conn, "free", pid, ip); err != nil {
		return fmt.Errorf("error freeing ip: %w", err)
	}

	r := bufio.NewReader(conn)
	line, err := r.ReadString('\n')
	if err != nil {
		return fmt.Errorf("error reading response: %w", err)
	}

	line = strings.TrimSpace(line)
	parts := strings.SplitN(line, " ", 2)

	if len(parts) == 0 {
		return fmt.Errorf("error: no response from daemon")
	}

	switch parts[0] {
	case "freed":
		return nil
	case "error":
		if len(parts) == 2 {
			return fmt.Errorf("daemon error: %s", parts[1])
		}
		return fmt.Errorf("daemon error")
	default:
		return fmt.Errorf("error, unexpected response: %q", line)
	}
}

func Pidc(pid string) error {
	conn, err := net.Dial("unix", skt)
	if err != nil {
		return fmt.Errorf("dial daemon: %w", err)
	}
	defer conn.Close()

	if _, err := fmt.Fprintln(conn, "pidchk", pid); err != nil {
		return fmt.Errorf("error checking pid: %w", err)
	}

	r := bufio.NewReader(conn)
	line, err := r.ReadString('\n')
	if err != nil {
		return fmt.Errorf("error reading response: %w", err)
	}

	line = strings.TrimSpace(line)
	parts := strings.SplitN(line, " ", 2)

	if len(parts) == 0 {
		return fmt.Errorf("error: no response from daemon")
	}

	switch parts[0] {
	case "done":
		return nil
	case "error":
		if len(parts) == 2 {
			return fmt.Errorf("daemon error: %s", parts[1])
		}
		return fmt.Errorf("daemon error")
	default:
		return fmt.Errorf("error, unexpected response: %q", line)
	}
}

func Rundae() error {

	conn, err := net.Dial("unix", skt)
	if err == nil {
		conn.Close()
		return nil
	}

	_ = os.Remove(skt)

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("error executing daemon: %v", err)
	}

	cmd := exec.Command(exe, "init")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("error starting daemon: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	return nil
}

func Run(args []string) int {
	if len(os.Args) > 5 && os.Args[1] == "run" || len(os.Args) < 3 && os.Args[1] == "run" {
		fmt.Println("Usage: dckr run <Img/rootfs destination> {net} {host:port} {ENV=VAL,ENV=VAL...}")
		return 1
	}

	switch len(os.Args) {

	case 3:

		path, confjs, err, isdir := Iftar(os.Args[2])
		if err != nil {
			fmt.Fprintf(os.Stderr, "error preparing image: %v", err)
			return 1
		}
		if !isdir {
			defer Delbase(path)
		}
		if err := Runet(path, "", false, confjs, ""); err != nil {
			fmt.Fprintf(os.Stderr, "error running image: %v\n", err)
			return 1
		}
		return 0

	case 4:
		if os.Args[3] == "net" {

			path, confjs, err, isdir := Iftar(os.Args[2])
			if err != nil {
				fmt.Fprintf(os.Stderr, "error preparing image: %v", err)
				return 1
			}
			if !isdir {
				defer Delbase(path)
			}
			if err := Runet(path, "", true, confjs, ""); err != nil {
				fmt.Fprintf(os.Stderr, "error running image: %v\n", err)
				return 1
			}

			return 0

		} else if strings.Contains(os.Args[3], "=") {
			path, confjs, err, isdir := Iftar(os.Args[2])
			if err != nil {
				fmt.Fprintf(os.Stderr, "error preparing image: %v", err)
				return 1
			}
			if !isdir {
				defer Delbase(path)
			}
			if err := Runet(path, "", false, confjs, os.Args[3]); err != nil {
				fmt.Fprintf(os.Stderr, "error running image: %v\n", err)
				return 1
			}

			return 0

		} else if strings.Contains(os.Args[3], ":") {
			path, confjs, err, isdir := Iftar(os.Args[2])
			if err != nil {
				fmt.Fprintf(os.Stderr, "error preparing image: %v", err)
				return 1
			}
			if !isdir {
				defer Delbase(path)
			}
			if err := Runet(path, os.Args[3], false, confjs, ""); err != nil {
				fmt.Fprintf(os.Stderr, "error running image: %v\n", err)
				return 1
			}

			return 0

		} else {
			fmt.Println("Usage: dckr run <Img/rootfs destination> {net} {host:port} {ENV=VAL,ENV=VAL...}")
			return 1
		}

	case 5:

		if os.Args[3] == "net" && strings.Contains(os.Args[4], "=") {

			path, confjs, err, isdir := Iftar(os.Args[2])
			if err != nil {
				fmt.Fprintf(os.Stderr, "error preparing image: %v", err)
				return 1
			}
			if !isdir {
				defer Delbase(path)
			}
			if err := Runet(path, "", true, confjs, os.Args[4]); err != nil {
				fmt.Fprintf(os.Stderr, "error running image: %v\n", err)
				return 1
			}

			return 0

		} else if os.Args[3] == "net" && strings.Contains(os.Args[4], ":") {
			path, confjs, err, isdir := Iftar(os.Args[2])
			if err != nil {
				fmt.Fprintf(os.Stderr, "error preparing image: %v", err)
				return 1
			}
			if !isdir {
				defer Delbase(path)
			}
			if err := Runet(path, os.Args[4], true, confjs, ""); err != nil {
				fmt.Fprintf(os.Stderr, "error running image: %v\n", err)
				return 1
			}

			return 0

		} else if strings.Contains(os.Args[3], ":") && strings.Contains(os.Args[4], "=") {
			path, confjs, err, isdir := Iftar(os.Args[2])
			if err != nil {
				fmt.Fprintf(os.Stderr, "error preparing image: %v", err)
				return 1
			}
			if !isdir {
				defer Delbase(path)
			}
			if err := Runet(path, os.Args[3], true, confjs, os.Args[4]); err != nil {
				fmt.Fprintf(os.Stderr, "error running image: %v\n", err)
				return 1
			}

			return 0

		} else {
			fmt.Println("Usage: dckr run <Img/rootfs destination> {net} {host:port} {ENV=VAL,ENV=VAL...}")
			return 1
		}

	case 6:

		if strings.Contains(os.Args[4], ":") && strings.Contains(os.Args[5], "=") {
			path, confjs, err, isdir := Iftar(os.Args[2])
			if err != nil {
				fmt.Fprintf(os.Stderr, "error preparing image: %v", err)
				return 1
			}
			if !isdir {
				defer Delbase(path)
			}
			if err := Runet(path, os.Args[4], true, confjs, os.Args[5]); err != nil {
				fmt.Fprintf(os.Stderr, "error running image: %v\n", err)
				return 1
			}

			return 0

		} else {
			fmt.Println("Usage: dckr run <Img/rootfs destination> {net} {host:port} {ENV=VAL,ENV=VAL...}")
			return 1
		}

	default:

		fmt.Println("Usage: dckr run <Img/rootfs destination> {net} {host:port} {ENV=VAL,ENV=VAL...}")
		return 1

	}

}

func Pnr(args []string) int {
	if len(os.Args) < 3 || len(os.Args) > 6 {
		fmt.Println("Usage: dckr pullnrun <image> {net} {host:port} {ENV=VAL,ENV=VAL...}")
		return 1
	}

	switch len(os.Args) {

	case 3:

		if err := Pullnrun(os.Args[2], false, "", ""); err != nil {
			fmt.Fprintf(os.Stderr, "pullnrun error: %v\n", err)
			return 1
		}
		return 0

	case 4:

		if os.Args[3] == "net" {

			if err := Pullnrun(os.Args[2], true, "", ""); err != nil {
				fmt.Fprintf(os.Stderr, "pullnrun error: %v\n", err)
				return 1
			}
		} else if strings.Contains(os.Args[3], "=") {
			if err := Pullnrun(os.Args[2], false, "", os.Args[3]); err != nil {
				fmt.Fprintf(os.Stderr, "pullnrun error: %v\n", err)
				return 1
			}
		} else {
			if err := Pullnrun(os.Args[2], false, os.Args[3], ""); err != nil {
				fmt.Fprintf(os.Stderr, "pullnrun error: %v\n", err)
				return 1
			}

		}
		return 0

	case 5:

		if os.Args[3] == "net" && strings.Contains(os.Args[4], "=") {
			if err := Pullnrun(os.Args[2], true, "", os.Args[4]); err != nil {
				fmt.Fprintf(os.Stderr, "pullnrun error: %v\n", err)
				return 1
			}
		} else if os.Args[3] == "net" {
			if err := Pullnrun(os.Args[2], true, os.Args[4], ""); err != nil {
				fmt.Fprintf(os.Stderr, "pullnrun error: %v\n", err)
				return 1
			}
		} else {
			if err := Pullnrun(os.Args[2], false, os.Args[3], os.Args[4]); err != nil {
				fmt.Fprintf(os.Stderr, "pullnrun error: %v\n", err)
				return 1
			}
		}

		return 0

	case 6:
		if err := Pullnrun(os.Args[2], true, os.Args[4], os.Args[5]); err != nil {
			fmt.Fprintf(os.Stderr, "pullnrun error: %v\n", err)
			return 1
		}
		return 0

	default:

		fmt.Println("Usage: dckr pullnrun <image> {net} {host:port} {ENV=VAL,ENV=VAL...}")
		return 1
	}
}

func Exp(args []string) int {
	if len(os.Args) != 3 {
		fmt.Println("Usage: dckr pullexp <image>")
		return 1
	}
	if _, _, err := Pullexp(os.Args[2]); err != nil {
		fmt.Fprintf(os.Stderr, "pullexp error: %v\n", err)
		er := Rm()
		if er != nil {
			fmt.Fprintf(os.Stderr, "error during cleanup: %v\n", er)
			return 1
		}
		return 1
	}
	return 0
}

func Pre(args []string) error {
	if len(os.Args) == 2 && os.Args[1] == "init" {
		signal.Ignore(syscall.SIGHUP, syscall.SIGINT)
		if err := Daeinit(); err != nil {
			return err
		}
		return nil
	}

	if len(os.Args) >= 3 && os.Args[1] == "frk" {
		if err := Frk(os.Args[2]); err != nil {
			fmt.Fprintf(os.Stderr, "fork error: %v\n", err)
			return err
		}
		return nil
	}
	return nil

}
