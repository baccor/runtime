package main

import (
	"fmt"
	"mdkr/runtimed"
	"os"
)

func main() {

	if len(os.Args) < 2 {
		fmt.Println("Usage: dckr <pullexp/run/pullnrun> [args...]")
		os.Exit(1)
	}

	runtimed.Pre(os.Args)

	switch os.Args[1] {

	case "pullexp":
		runtimed.Exp(os.Args)

	case "run":
		runtimed.Run(os.Args)

	case "pullnrun":
		runtimed.Pnr(os.Args)

	default:
		fmt.Println("Usage: dckr <pullexp/run/pullnrun> [args...]")
		os.Exit(1)
	}

}
