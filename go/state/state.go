package state

import (
	"bufio"
	"fmt"
	"mdkr/initz"
	"mdkr/rnet"
	"net"
	"strings"
)

func HCon(conn net.Conn) {
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
		if len(parts) == 3 {

			ip, err := initz.Alloc(parts[1], parts[2])
			if err != nil {
				fmt.Fprintf(conn, "error %v\n", err)
				return
			}
			fmt.Fprintf(conn, "allocated %s\n", ip)
		} else if len(parts) == 2 {
			ip, err := initz.Alloc(parts[1], "")
			if err != nil {
				fmt.Fprintf(conn, "error %v\n", err)
				return
			}
			fmt.Fprintf(conn, "allocated %s\n", ip)
			return
		} else {
			fmt.Fprintln(conn, "error unknown command")
			return
		}

	case "free":
		if len(parts) == 3 {

			if err := initz.Cln(parts[1], parts[2]); err != nil {
				fmt.Fprintf(conn, "error %v\n", err)
				return
			}
			fmt.Fprintln(conn, "freed")
			return
		} else if len(parts) == 2 {
			if err := initz.Cln(parts[1], ""); err != nil {
				fmt.Fprintf(conn, "error %v\n", err)
				return
			}
			fmt.Fprintln(conn, "freed")
			return
		} else {
			fmt.Fprintln(conn, "error unknown command")
			return
		}

	case "prenet":
		if len(parts) == 2 && parts[1] == "net" {
			if err := rnet.NetH(true); err != nil {
				fmt.Fprintf(conn, "error %v\n", err)
				return
			}
			fmt.Fprintln(conn, "done")
		} else if len(parts) == 1 {
			if err := rnet.NetH(false); err != nil {
				fmt.Fprintf(conn, "error %v\n", err)
				return
			}
			fmt.Fprintln(conn, "done")
		} else {
			fmt.Fprintln(conn, "error unknown prenet command")
			return
		}

	case "pidreg":
		if len(parts) != 2 && len(parts) != 3 {
			fmt.Fprintf(conn, "error %v\n", err)
			return
		}
		if len(parts) == 2 {
			if err := initz.Pidregd(parts[1], ""); err != nil {
				fmt.Fprintf(conn, "error %v\n", err)
				return
			}
			fmt.Fprintln(conn, "done")
			return
		}
		if len(parts) == 3 {
			if err := initz.Pidregd(parts[1], parts[2]); err != nil {
				fmt.Fprintf(conn, "error %v\n", err)
				return
			}
			fmt.Fprintln(conn, "done")
			return
		} else {
			fmt.Fprintln(conn, "error unknown command")
			return
		}

	case "pidchk":

		if len(parts) != 2 {
			fmt.Fprintf(conn, "error %v\n", err)
			return
		}
		if len(parts) == 2 {
			if err := initz.Pidchk(parts[1]); err != nil {
				fmt.Fprintf(conn, "error %v\n", err)
				return
			}
			fmt.Fprintln(conn, "done")
			return
		} else {
			fmt.Fprintln(conn, "error unknown command")
			return
		}

	default:
		fmt.Fprintln(conn, "error unknown command")
		return
	}
}
