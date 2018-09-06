package main

import (
	"fmt"
	"log"
	"os"
	"time"

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

//var fw FocaFileWriter

func main() {
	var err error
	wc := time.Now()
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

	fw, err = newFocaISPFile("out.txt")
	if err != nil {
		log.Fatal("Error creating file:", err)
	}

	for _, arg := range os.Args[1:] {

		fmt.Printf("Processing file %q ...\n", arg)
		//_ = parseBccAuditFile(arg)
		_ = processAuditFile(arg)

	}

	ippool.WalkAll(func(node *IPNode) {
		var foca FocaISPRec
		//fmt.Println("walk ", node.Name)
		if node.Status == 1 {
			foca = FocaISPRec{IPAddress: node.FIR.IPAddress, MACAddress: node.FIR.MACAddress,
				StartTime: node.FIR.StartTime, Duration: uint32(node.LastStartTime.Sub(node.FIR.StartTime).Seconds())}
			emitFocaISP(&foca)
			//node.FIR.IPAddress = ar.IPAddress
			//node.FIR.MACAddress = ar.HWAddress
			node.FIR.StartTime = node.LastStartTime
			node.FIR.Duration = 0
			node.Status = 1
			node.Cnt = 1
			node.Cnt++

		}
	})

	fmt.Println("Duration:", time.Now().Sub(wc))

	PrintStats()
	/*
		for k, v := range ippool.M {
			fmt.Println(k, v.A[123].Name, v.A[123].Cnt)

		}
	*/
	//SaveIPPool()
}
