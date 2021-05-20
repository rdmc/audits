package main

import (
	"flag"
	"fmt"
	"log"
	"path/filepath"
	"time"
	//"github.com/pkg/profile"
)

const (
	//timeformat2 = "20060102150405"
	dateFormat       = "20060102"
	auditFileFormat  = "ipaudits_%4d.%02d.%02d_*"
	searchFileFormat = "search_isp_001_%4d%02d%02d23590.gz" // day + 1??? 23:59 ??
	auditDir         = "/usr/local/lib/ipcmdr/data/archive"
	//auditDir = "../archive"
	outputDir = "/home/search_isp/data"
	//outputDir = "../data"

	version = "FOCA 4.1, IPv4 only"
)

var (
	//default "load IP Pool "from audit_ippool_(day -1).gob" ....
	zeroOpt = flag.Bool("z", false, "Initialize IP Pool to all zeros, otherwise o read from saved.gob file.")
	//lastOpt  = flag.Bool("l", false, "Load IP Pool from audit_last.gob")
	closeOpt = flag.Bool("c", false, "Try to close  all cumulative opened records")
	//note l,z,g are mutualy excluxive
	searchFile = "search_isp_001_2018061902360.gz"

	logFile = filepath.Join("./", "audit.log")
	//
	info *log.Logger
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
	//wc := time.Now()
	//defer profile.Start().Stop()
	/*
		f = FocaISPRec
		StartTime:	time.Now()
		Duration:	time.Duration(301)
		IPAddress	net.IP()
		MACAddress	mac}
	*/
	flag.Parse()

	if flag.NArg() != 1 {
		fmt.Println("usage of audit:\naudit [-z] [-c] <YYYMMDDD>")
		flag.PrintDefaults()
		log.Fatal("Bye, bye.")
		// PROGRAM TERMINATE
	}

	day, err := time.Parse(dateFormat, flag.Arg(0))
	if err != nil {
		log.Fatalf("error parsing date, %s.", err)
	}

	y, m, d := day.Date()

	//if *zeroOpt && *lastOpt {
	//	log.Fatalf("Incompatible flags set, -z and -l")
	//}

	log.Printf("autits for day %s\t, started...\n", day.Format(dateFormat))

	auditPatern := fmt.Sprintf(auditFileFormat, y, m, d)
	//fmt.Printf("files: %s\n", auditPatern)
	matchFiles, err := filepath.Glob(filepath.Join(auditDir, auditPatern))
	if err != nil || len(matchFiles) == 0 {
		log.Fatal("No audit files found or match error, in base=%s, match=%s.\n", auditDir, auditPatern)
	}

	if *zeroOpt {
		initIPPoll()
	} else { // for now assuma flag -l is set...
		_ = ReadIPPool()
	}

	searchFile = fmt.Sprintf(searchFileFormat, y, m, d)
	searchFile = filepath.Join(outputDir, searchFile)
	fw, err = newFocaISPFile(searchFile)
	if err != nil {
		log.Fatal("Error creating file:", err)
	}

	for _, arg := range matchFiles {

		fmt.Printf("Processing file %q ...", filepath.Base(arg))
		//_ = parseBccAuditFile(arg)
		_ = processAuditFile(arg)

	}

	if *closeOpt {
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
	}
	//fmt.Println("Duration:", time.Now().Sub(wc))

	//PrintStats()
	SaveIPPool()
	fw.w.Close()
	fw.file.Close()
}
