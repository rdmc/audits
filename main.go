package main

import (
	"fmt"

	"github.com/pkg/profile"
)

func main() {

	defer profile.Start().Stop()

	//initIPPoll()
	_ = ReadIPPool()

	for k, v := range ippool.M {
		fmt.Println(k, v.A[0].Name)

	}
	/*

		for _, arg := range os.Args[1:] {

			fmt.Printf("Processing file %q ...\n", arg)
			//_ = parseBccAuditFile(arg)
			_ = processAuditFile(arg)

		}
		PrintStats()
	*/
}
