package main

import (
	"fmt"
	"os"

	"github.com/pkg/profile"
)

func main() {

	defer profile.Start().Stop()

	for _, arg := range os.Args[1:] {

		fmt.Printf("Processing file %q ...\n", arg)
		//_ = parseBccAuditFile(arg)
		_ = processAuditFile(arg)

	}
	PrintStats()
}
