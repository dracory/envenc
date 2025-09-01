package main

import (
	"os"

	"github.com/dracory/envenc"
)

func main() {
	args := os.Args
	envenc.NewCli().Run(args[0:])
}
