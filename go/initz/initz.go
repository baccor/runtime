package initz

import (
	"database/sql"
	"errors"
	"fmt"
	"mdkr/rnet"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"

	_ "modernc.org/sqlite"
)

const pth = "/var/tmp/minidkr/"
const statesql = "file:///var/tmp/minidkr/state.sqlite?_pragma=foreign_keys(1)"
const dbpth = "/var/tmp/minidkr/state.sqlite"

func Init() error {
	if _, err := os.Stat(dbpth); os.IsNotExist(err) {

		if err := os.MkdirAll(pth, 0755); err != nil {
			return fmt.Errorf("error creating state dir: %w", err)
		}
		crt, err := os.Create(dbpth)
		if err != nil {
			return fmt.Errorf("error creating state: %w", err)
		}
		defer crt.Close()
		db, err := sql.Open("sqlite", statesql)
		if err != nil {
			return fmt.Errorf("error opening state: %w", err)
		}
		defer db.Close()
		if err := ss(db); err != nil {
			return fmt.Errorf("error preparing state: %w", err)
		}
		return nil
	}

	return nil
}

func ss(db *sql.DB) error {
	sqlp := []string{

		`CREATE TABLE IF NOT EXISTS podnet (
		id INTEGER PRIMARY KEY,
		ip INTEGER UNIQUE,
		isnet INTEGER NOT NULL DEFAULT 0,
		port TEXT ,
		CHECK (isnet IN (0, 1)),
		CHECK (ip BETWEEN 2 AND 254)
		);`,

		`CREATE TABLE IF NOT EXISTS pods (
		id INTEGER PRIMARY KEY,
		pid INTEGER NOT NULL DEFAULT 0,
		podnetid INTEGER UNIQUE,
		FOREIGN KEY (podnetid) REFERENCES podnet(id)
		ON UPDATE CASCADE
		ON DELETE RESTRICT	
		
		);`,
	}

	tr, err := db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tr.Rollback() }()

	for _, c := range sqlp {
		if _, err := tr.Exec(c); err != nil {
			return fmt.Errorf("database exec failed: %w", err)
		}
	}

	return tr.Commit()

}

func Alloc(isnet, port string) (string, error) {

	db, err := sql.Open("sqlite", statesql)
	if err != nil {
		return "", fmt.Errorf("error opening state: %w", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	sqlc, err := db.Begin()
	if err != nil {
		return "", err
	}
	defer func() { _ = sqlc.Rollback() }()

	var ipi int
	err = sqlc.QueryRow(`
		WITH RECURSIVE nums(n) AS (
        SELECT 2
        UNION ALL
        SELECT n + 1 FROM nums WHERE n < 254
        )
        SELECT n
        FROM nums
        WHERE NOT EXISTS (SELECT 1 FROM podnet WHERE ip = n)
        ORDER BY n
        LIMIT 1;`).Scan(&ipi)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", fmt.Errorf("no free IPs available")
		}
		return "", err
	}

	netconv, err := strconv.Atoi(isnet)
	if err != nil {
		return "", fmt.Errorf("error converting isnet to int")
	}

	_, err = sqlc.Exec(`INSERT INTO podnet(ip, id, isnet, port) VALUES (?, ?, ?, ?)`, ipi, ipi, netconv, port)
	if err != nil {
		return "", err
	}

	if err := sqlc.Commit(); err != nil {
		return "", err
	}
	ip := "10.0.0." + strconv.Itoa(ipi)

	if isnet == "1" {
		if err := masq(ip); err != nil {
			return "", fmt.Errorf("error setting up masq")
		}
	}

	if port != "" {
		nip := net.ParseIP(ip)
		if err := rnet.Prtf(nip, port); err != nil {
			return "", fmt.Errorf("error processing forwarded port: %v", err)
		}
	}

	return ip, nil
}

func masq(ip string) error {

	intf, err := rnet.Dif()
	if err != nil {
		return fmt.Errorf("error determining default interface: %v", err)
	}
	if err := rnet.Masq(intf, ip); err != nil {
		return fmt.Errorf("error setting up masquerading: %v", err)
	}

	return nil

}

func unmasq(ip string) error {

	intf, err := rnet.Dif()
	if err != nil {
		return fmt.Errorf("error determining default interface: %v", err)
	}

	iptblsr := exec.Command("iptables", "-t", "nat", "-D", "POSTROUTING", "-s", ip, "-o", intf, "-j", "MASQUERADE")
	_ = iptblsr.Run()

	nat := exec.Command("iptables", "-D", "FORWARD",
		"-s", ip, "-o", intf, "-j", "ACCEPT")
	_ = nat.Run()

	natn := exec.Command("iptables", "-D", "FORWARD",
		"-d", ip,
		"-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED",
		"-j", "ACCEPT")
	_ = natn.Run()

	return nil
}

func Pidregd(pid, ip string) error {

	pidi, err := strconv.Atoi(pid)
	if err != nil {
		return fmt.Errorf("error converting pid: %s", pid)
	}

	db, err := sql.Open("sqlite", statesql)
	if err != nil {
		return fmt.Errorf("error opening state: %w", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	sqlc, err := db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = sqlc.Rollback() }()

	if ip != "" {
		if err := rnet.NetC(pidi); err != nil {
			return fmt.Errorf("error setting up network: %v", err)
		}
	}

	if ip == "" {

		_, err := sqlc.Exec(`INSERT INTO pods (pid, podnetid) VALUES (?, NULL);`, pidi)
		if err != nil {
			return err
		}
		return sqlc.Commit()

	}

	parts := strings.Split(ip, ".")
	ipi, err := strconv.Atoi(parts[len(parts)-1])
	if err != nil {
		return fmt.Errorf("error converting ip: %s", ip)
	}

	res, err := sqlc.Exec(`INSERT INTO pods (pid, podnetid) VALUES (?, ?);`, pidi, ipi)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("pid %s was not allocated", ip)
	}
	return sqlc.Commit()
}

func Cln(pid, ip string) error {

	var isnet int
	var port sql.NullString
	prts := strings.Split(ip, ".")
	ipi := prts[len(prts)-1]
	pidi, err := strconv.Atoi(pid)
	if err != nil {
		return err
	}

	db, err := sql.Open("sqlite", statesql)
	if err != nil {
		return fmt.Errorf("error opening state: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	defer db.Close()

	sqlc, err := db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = sqlc.Rollback() }()

	if pid != "" && ip == "" {
		pidi, err := strconv.Atoi(pid)
		if err != nil {
			return fmt.Errorf("error converting pid: %s", pid)
		}

		_, err = sqlc.Exec(`DELETE FROM pods WHERE pid = ?`, pidi)
		if err != nil {
			return err
		}
		return sqlc.Commit()

	}

	err = sqlc.QueryRow(
		`SELECT isnet, port FROM podnet WHERE ip = ?`,
		ipi,
	).Scan(&isnet, &port)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("ip %s not found in podnet", ipi)
		}
		return err
	}

	prt := ""
	if port.Valid {
		prt = port.String
	}

	var cnt int
	if err := sqlc.QueryRow(`SELECT COUNT(*) FROM podnet`).Scan(&cnt); err != nil {
		return err
	}
	_, err = sqlc.Exec(`DELETE FROM pods WHERE pid = ?`, pidi)
	if err != nil {
		return err
	}

	_, err = sqlc.Exec(`DELETE FROM podnet WHERE id = ?`, ipi)
	if err != nil {
		return err
	}

	sqlc.Commit()

	if prt != "" {
		rnet.PrtfD(ip, prt)
	}

	if cnt == 1 {
		rnet.Clnup()
	}

	if err := unmasq(ip); err != nil {
		return fmt.Errorf("error cleaning up masq")
	}

	return nil
}

func Pidchk(pid string) error {

	if pid == "" {
		return fmt.Errorf("error checking for pid, empty")
	}

	pidi, err := strconv.Atoi(pid)

	if err != nil {
		return fmt.Errorf("error converting pid: %s", pid)
	}
	db, err := sql.Open("sqlite", statesql)
	if err != nil {
		return fmt.Errorf("error opening state: %w", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	sqlc, err := db.Begin()
	if err != nil {
		return err
	}

	var p int
	if err := sqlc.QueryRow(`SELECT 1 FROM pods WHERE pid = ?`, pidi).Scan(&p); err != nil {
		return err
	}

	if p == 1 {
		return nil
	}
	return fmt.Errorf("pid doesn't match or exists")

}
