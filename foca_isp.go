package main

import (
	"compress/gzip"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/rdmc/mac"
	//"github.com/rdmc/mac"
)

// FOCA_ISP_LINE:
// "7,20180630110500,,,,,,2043,1,,,,,ISP,,100081169222,00:05:ca:69:db:34,"
// #18 coma delimitated fields
//01- 	7		- EventType - FIXED: "7"
//02- 	20180630110500	- StartTimeKey - AAAAMMDDHHMMSS
//03-07	IGNORE
//08-	2043		- Duration - int in seconds
//09-	1		 - CallType - FIXED: "1"
//10-13	IGNORE
//14-	ISP		- NetworkElement - FIXED: "ISP"
//15	IGNORE
//16-	100081169222	- IPAddress - AAABBBCCCDDD
//17	00:05:ca:69:db:34 - MACAddress
//18	IGNORE

const MAXRENEW = 20*time.Hour - 10*time.Minute //

type FocaISPRec struct {
	StartTime  time.Time
	Duration   uint32
	IPAddress  net.IP
	MACAddress mac.MAC
}

func (f *FocaISPRec) String() string {

	const FocaISPLineFmt = "7,%s,,,,,,%d,1,,,,,ISP,,%03d%03d%03d%03d,%s,"

	t := f.IPAddress.To4() // ensure IP is a 4 byte array

	return fmt.Sprintf(FocaISPLineFmt, f.StartTime.Format("20060102150405"), f.Duration,
		t[0], t[1], t[2], t[3], f.MACAddress)
}

func writeFocaISP(f *FocaISPRec) {
}

// TODO:
// FOCA !!!!!!
type FocaFileWriter struct {
	filename string
	file     *os.File
	w        *gzip.Writer
	// stats
	errors   int
	linesCnt int
}

var fw *FocaFileWriter

func newFocaISPFile(fname string) (*FocaFileWriter, error) {

	f, err := os.Create(fname)
	if err != nil {
		// flag error
		return nil, err
	}
	w := gzip.NewWriter(f)
	fiw := &FocaFileWriter{
		filename: fname,
		file:     f,
		w:        w,
	}

	return fiw, nil

}

/*
func newFocaISPFile(fname string) *FocaFileWriter {
	return &FocaFileWriter{
		//fname:        filename,
		w: w,
	}
}
*/

/*
 *  for emit a new focaIspRec, id day(ar.startdate) != day(saved startdate)
 *  if ar.starDate - saved.StartDate > max (12H, 24h ????)
 *  run walk ate the end of a cycle, and emti all open renews....
 *  more testing
 */

func WorkFunc(ar *AuditRecord) error {

	var foca FocaISPRec

	ip := ip2int(ar.IPAddress)
	node, ok := ippool.getIPNode(ip)
	if !ok {
		stats.notPubIP++
		return fmt.Errorf("IP address %d is not in ower pool", ip)
	}

	stats.pubIP++
	node.Cnt++

	switch ar.Action {
	case AA_IGNORE:
		//fmt.Println("IGNORE, action=", ar.Action)
		if node.Status == 0 {
			// do nothing
		} else {
			// do nothing
		}
		// increment countetrs
	case AA_BIND:
		//fmt.Println("BIND")
		if node.Status == 0 {
			node.FIR.IPAddress = ar.IPAddress
			node.FIR.MACAddress = ar.HWAddress
			node.FIR.StartTime = ar.StartTime
			node.FIR.Duration = 0
			node.Status = 1
			node.Cnt = 1
		} else { // node already with information
			foca = FocaISPRec{IPAddress: ar.IPAddress, MACAddress: ar.HWAddress,
				StartTime: node.FIR.StartTime, Duration: uint32(ar.StartTime.Sub(node.FIR.StartTime).Seconds())}
			emitFocaISP(&foca)
			node.FIR.IPAddress = ar.IPAddress
			node.FIR.MACAddress = ar.HWAddress
			node.FIR.StartTime = ar.StartTime
			node.FIR.Duration = 0
			node.Status = 1
			node.Cnt = 1
			node.Cnt++
		}
	case AA_RENEW:
		//fmt.Println("RENEW")
		if node.Status == 0 {
			//fmt.Println("WARNING: Renew on a empty ipnode...")
			node.FIR.IPAddress = ar.IPAddress
			node.FIR.MACAddress = ar.HWAddress
			node.FIR.StartTime = ar.StartTime
			node.FIR.Duration = 0
			node.Status = 1
			node.Cnt = 1
		} else {
			if ar.HWAddress.String() != node.FIR.MACAddress.String() {
				fmt.Println("ERROR: diferente MAC Addrsses  for a renew operation....")
				fmt.Print("\tIP ar=", ar.IPAddress, ", node=", node.FIR.IPAddress, "ar.action=", ar.Action)
				fmt.Println(", MAC ar=", ar.HWAddress.String(), ", node=", node.FIR.MACAddress.String())
				return fmt.Errorf("diferent MAC Addresss dor same ip")
			}
			if ar.StartTime.Sub(node.FIR.StartTime) > MAXRENEW { //
				foca = FocaISPRec{IPAddress: ar.IPAddress, MACAddress: ar.HWAddress,
					StartTime: node.FIR.StartTime, Duration: uint32(ar.StartTime.Sub(node.FIR.StartTime).Seconds())}
				emitFocaISP(&foca)
				node.FIR.StartTime = ar.StartTime
				node.Status = 1
			}
			node.Cnt++
		}
		node.LastStartTime = ar.StartTime
	case AA_NAK, AA_DELETE:
		//fmt.Println("NACK/DELETE")
		if node.Status == 0 {
			// do nothing
		} else {
			foca = FocaISPRec{IPAddress: ar.IPAddress, MACAddress: ar.HWAddress,
				StartTime: node.FIR.StartTime, Duration: uint32(ar.StartTime.Sub(node.FIR.StartTime).Seconds())}
			emitFocaISP(&foca)
			node.FIR.StartTime = ar.StartTime // deeria ser zero!!!
			node.Status = 0
		}
	default:
		//fmt.Println("DEFAULT, action=", ar.Action)

	}

	return nil
}

func emitFocaISP(f *FocaISPRec) {
	//fmt.Println("FOCA:\t", f.String())
	fmt.Fprintln(fw.w, f.String())
}
