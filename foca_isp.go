package main

import (
	"bufio"
	"fmt"
	"net"
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

type FocaISPRec struct {
	StartTime  time.Time
	Duration   uint32
	IPAddress  net.IP
	MACAddress mac.MAC
}

func (f *FocaISPRec) String() string {
	const FocaISOLineFmt = "7,%s,,,,,,%d,1,,,,,ISP,,%03d%03d%03d%03d,%s,"
	t := f.IPAddress.To4() // ensure IP is a 4 byte array
	return fmt.Sprintf(FocaISOLineFmt, f.StartTime.Format("20060102150405"), f.Duration,
		t[0], t[1], t[2], t[3], f.MACAddress)
}

// TODO:
// FOCA !!!!!!
type FocaFileWriter struct {
	fname string
	w     *bufio.Writer
	buf   []byte

	// stats
	errors   int
	headers  int
	linesCnt int
}

func newFocaISPFileWriter(scanner *bufio.Scanner) *AuditFileReader {
	return &AuditFileReader{
		//fname:        filename,
		s:            scanner,
		buf:          make([]byte, 1024),
		fieldIndexes: make([]int, FieldsPerRecord, FieldsPerRecord),
		fields:       make([]string, FieldsPerRecord, FieldsPerRecord),
	}
}

/*
func FocaISPWriterCh(filename string, in chan FocaISPRec) error {
	//of, err := os.Create(filename)	// TODO: open with append
	of, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0755)
	if err != nil {
		return err
	}
	go func() {

	}()

	go func() {
		// flush
		// close

	}()
}
*/
