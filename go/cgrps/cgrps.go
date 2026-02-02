package cgrps

import (
	"fmt"
	"mdkr/runtimed"
	"os"
	"strconv"

	"github.com/opencontainers/cgroups"
	"github.com/opencontainers/cgroups/manager"
)

func Lim(args []string) int {

	if len(os.Args) != 5 {
		fmt.Println("usage: dckr lim <PID> [cpu||mem||pid] <value>")
		return 1
	}

	pid, err := strconv.Atoi(os.Args[2])
	if err != nil {
		fmt.Println("error converting pid string to int")
		return 1
	}

	switch os.Args[3] {

	case "cpu":

		val, err := strconv.Atoi(os.Args[4])
		if err != nil {
			fmt.Printf("error converting value string to int")
			return 1
		}
		if err := cginit(pid, 0, int64(val), 0); err != nil {
			fmt.Printf("%v\n", err)
			return 1
		}
		return 0

	case "mem":

		val, err := strconv.Atoi(os.Args[4])
		if err != nil {
			fmt.Println("error converting value string to int")
			return 1
		}
		if err := cginit(pid, int64(val), 0, 0); err != nil {
			fmt.Printf("%v\n", err)
			return 1
		}
		return 0

	case "pid":

		val, err := strconv.Atoi(os.Args[4])
		if err != nil {
			fmt.Println("error converting value string to int")
			return 1
		}
		if err := cginit(pid, 0, 0, int64(val)); err != nil {
			fmt.Printf("%v\n", err)
			return 1
		}
		return 0

	default:
		fmt.Println("usage: dckr lim <PID> [cpu||mem||pid] <value>")
		return 1
	}

}

func cginit(pid int, mem, cpu, ps int64) error {

	pids := strconv.Itoa(pid)
	if err := runtimed.Pidc(pids); err != nil {
		return fmt.Errorf("error checking pid: %w", err)
	}

	cg := &cgroups.Cgroup{
		Parent:      "system.slice",
		ScopePrefix: "minidkr",
		Name:        pids,
		Resources:   &cgroups.Resources{},
		Systemd:     true,
	}

	if mem != 0 {
		cg.Resources.Memory = mem
	}

	if cpu != 0 {
		cg.Resources.CpuQuota = cpu
	}

	if ps != 0 {
		cg.Resources.PidsLimit = &ps
	}

	mngr, err := manager.New(cg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return err
	}

	exsts, err := iscgrp(pid)
	if err != nil {
		return err
	}

	if !exsts {
		if err := mngr.Apply(pid); err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			return err
		}
	}

	if err := mngr.Set(cg.Resources); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return err
	}

	return nil

}

func iscgrp(pid int) (exst bool, err error) {

	pth := fmt.Sprintf("/sys/fs/cgroup/system.slice/minidkr-%d.scope", pid)
	_, err = os.Lstat(pth)
	if err != nil && !os.IsExist(err) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	return true, nil

}
