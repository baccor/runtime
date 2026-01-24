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
		os.Exit(runtimed.Exp(os.Args))

	case "run":
		os.Exit(runtimed.Run(os.Args))

	case "pullnrun":
		os.Exit(runtimed.Pnr(os.Args))

	default:
		fmt.Println("Usage: dckr <pullexp/run/pullnrun> [args...]")
		os.Exit(1)
	}

}
