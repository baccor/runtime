package state

import (
	"bufio"
	"fmt"
	"mdkr/initz"
	"mdkr/structs"
	"net"
	"strings"
	"sync"
)

type Snc struct {
	mu    sync.Mutex
	State structs.State
}

func AllocIp(s *Snc) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return initz.Alloc(&s.State)
}

func FrIp(ip string, s *Snc) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return initz.Fr(ip, &s.State)
}

func HCon(conn net.Conn, s *Snc) {
	defer conn.Close()

	r := bufio.NewReader(conn)
	l, err := r.ReadString('\n')
	if err != nil {
		return
	}

	l = strings.TrimSpace(l)
	parts := strings.Split(l, " ")

	switch parts[0] {
	case "alloc":
		ip, err := AllocIp(s)
		if err != nil {
			fmt.Fprintf(conn, "error %v\n", err)
			return
		}
		fmt.Fprintf(conn, "allocated %s\n", ip)

	case "free":
		if len(parts) != 2 {
			fmt.Fprintln(conn, "error bad syntax")
			return
		}
		if err := FrIp(parts[1], s); err != nil {
			fmt.Fprintf(conn, "error %v\n", err)
			return
		}
		fmt.Fprintln(conn, "freed")

	default:
		fmt.Fprintln(conn, "error unknown command")
	}
}
