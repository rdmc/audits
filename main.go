package main

import (
	"fmt"
	"os"

	"github.com/pkg/profile"
)

//Global var stats, MUST reformat later
var stats struct {
	header       int
	action       map[AuditAction]int
	ipClassifier map[string]int
	errors       int
	cnt          int
	pubIP        int
	notPubIP     int
}

func init() {
	stats.action = make(map[AuditAction]int)
	stats.ipClassifier = make(map[string]int)
	stats.header = 0
	stats.errors = 0
	stats.cnt = 0
}

// PrintStats will print stats...
func PrintStats() {
	fmt.Println("conter: ", stats.cnt)
	fmt.Println("header: ", stats.header)
	fmt.Println("errors: ", stats.errors)
	//
	fmt.Println("pub ip: ", stats.pubIP)
	fmt.Println("private ip: ", stats.notPubIP)

	fmt.Println("action:", len(stats.action))
	for k, v := range stats.action {
		fmt.Printf("\t%d = %d\n", int(k), v)
	}
	fmt.Println("ip classifier:", len(stats.ipClassifier))
	for k, v := range stats.ipClassifier {
		fmt.Printf("\t%q = %d\n", k, v)
	}
}

func main() {

	defer profile.Start().Stop()
	/*
		f = FocaISPRec
		StartTime:	time.Now()
		Duration:	time.Duration(301)
		IPAddress	net.IP()
		MACAddress	mac}
	*/
	initIPPoll()
	//_ = ReadIPPool()

	/*
		for k, v := range ippool.M {
			fmt.Println(k, v.A[123].Name, v.A[123].Cnt)

		}
	*/
	for _, arg := range os.Args[1:] {

		fmt.Printf("Processing file %q ...\n", arg)
		//_ = parseBccAuditFile(arg)
		_ = processAuditFile(arg)

	}
	PrintStats()
	/*
		for k, v := range ippool.M {
			fmt.Println(k, v.A[123].Name, v.A[123].Cnt)

		}
	*/
	//SaveIPPool()
}
