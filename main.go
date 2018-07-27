package main

import (
	"fmt"
	"os"

	"github.com/pkg/profile"
)

func main() {

	defer profile.Start().Stop()

	//initIPPoll()
	_ = ReadIPPool()

	for k, v := range ippool.M {
		fmt.Println(k, v.A[123].Name, v.A[123].Cnt)

	}
	for _, arg := range os.Args[1:] {

		fmt.Printf("Processing file %q ...\n", arg)
		//_ = parseBccAuditFile(arg)
		_ = processAuditFile(arg)

	}
	PrintStats()
	for k, v := range ippool.M {
		fmt.Println(k, v.A[123].Name, v.A[123].Cnt)

	}

	//SaveIPPool()
}
