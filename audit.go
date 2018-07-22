package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/rdmc/mac"
)

// "Start Time","End Time","IP Address","Gateway","HW Address","Client ID","Acti                                                                                 on",
// "Host Sent","Host Received","A DNS Update","Protocol","Circuit ID","Remote ID                                                                                 ",
// "Vendor Class ID","DOCSIS DeviceClass","Vendor-Specific Data","Interface ID"

// header "Start Time" .....

/*
action
protocol
remoteID
vendorClassID
interfaceID
*/

// Audit represents a logged dhcp operation.
// from Incognito BCC 6.x
type Audit struct {
	StartTime time.Time
	EndTime   time.Time
	DeltaTime time.Duration
	IPAddress net.IP
	Gateway   net.IP
	//HWAddress          string
	HWAddress          mac.MAC
	ClientID           string
	Action             string // uint8
	HostSent           string
	HostReceived       string
	ADNSUpdate         string // uint8 or bool
	Protocol           string // uint8
	CircuitID          string
	RemoteID           mac.MAC
	VendorClassID      string // uint8
	DOCSISDeviceClass  string
	VendorSpecificData string
	InterfaceID        string
}

//Global var stats, MUST reformat later
var stats struct {
	header        int
	action        map[string]int
	aDNSUpdate    map[string]int
	protocol      map[string]int
	vendorClassID map[string]int
	interfaceID   map[string]int
	ipClassifier  map[string]int
	errors        int
	cnt           int
}

type state int

const (
	fieldStart state = iota
	fieldCore
	fieldEnd
)

const (
	quote         = '"'
	comma         = ','
	fieldsPerLine = 17 // BCC Audit file have 17 fields in each line
	LF            = '\n'
	CR            = '\r'

	timeFormat = "Mon Jan 2 15:04:05 2006"
	headerMark = "Start Time" // if first field is "Start Time", the line is the header of the file
)

func init() {
	stats.action = make(map[string]int)
	stats.aDNSUpdate = make(map[string]int)
	stats.protocol = make(map[string]int)
	stats.vendorClassID = make(map[string]int)
	stats.interfaceID = make(map[string]int)
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

	fmt.Println("action:", len(stats.action))
	for k, v := range stats.action {
		fmt.Printf("\t%q = %d\n", k, v)
	}

	fmt.Println("aDNSUpdate:", len(stats.aDNSUpdate))
	for k, v := range stats.aDNSUpdate {
		fmt.Printf("\t%q = %d\n", k, v)
	}

	fmt.Println("protocol:", len(stats.protocol))
	for k, v := range stats.protocol {
		fmt.Printf("\t%q = %d\n", k, v)
	}

	fmt.Println("vendorClassId:", len(stats.vendorClassID))
	for k, v := range stats.vendorClassID {
		fmt.Printf("\t%q = %d\n", k, v)
	}

	fmt.Println("InterfaceID:", len(stats.interfaceID))
	for k, v := range stats.interfaceID {
		fmt.Printf("\t%q = %d\n", k, v)
	}

	fmt.Println("ip classifier:", len(stats.ipClassifier))
	for k, v := range stats.ipClassifier {
		fmt.Printf("\t%q = %d\n", k, v)
	}
}

func (a *Audit) String() string {
	s := " StartTime: " + a.StartTime.String()
	s += ", EndTime: " + a.EndTime.String()
	s += ", DeltaTime: " + a.DeltaTime.String()
	s += ", IPAddress: " + a.IPAddress.String()
	s += ", Gateway: " + a.Gateway.String()
	s += ", HWAddress: " + a.HWAddress.CiscoString()
	s += ", ClientID: " + a.ClientID
	s += ", Action: " + a.Action
	s += ", HostSent: " + a.HostSent
	s += ", HostReceived: " + a.HostReceived
	s += ", ADNSUpdate: " + a.ADNSUpdate
	s += ", Protocol: " + a.Protocol
	s += ", CircuitID: " + a.CircuitID
	s += ", RemoteID: " + a.RemoteID.CiscoString()
	s += ", VendorClassID: " + a.VendorClassID
	s += ", DOCSISDeviceClass: " + a.DOCSISDeviceClass
	s += ", VendorSpecificData: " + a.VendorSpecificData
	s += ", InterfaceID: " + a.InterfaceID

	return strings.Replace(s, ",", "\n", -1)
}

// ParseAuditRecord make a Audit struct from an alices of strings
func ParseAuditRecord(r []string) (*Audit, error) {
	const timeFormat = "Mon Jan 2 15:04:05 2006"
	var err error
	if len(r) != 17 {
		stats.errors++
		return nil, fmt.Errorf("Invalid number of fields")
	}

	a := &Audit{}

	if r[0] == "Start Time" {
		stats.header++
		return a, nil // CHANGE-ME
	}

	a.StartTime, err = time.Parse(timeFormat, r[0])
	if err != nil {
		log.Println("[StartTime]error", err)
		stats.errors++
	}

	a.EndTime, err = time.Parse(timeFormat, r[1])
	if err != nil {
		log.Println("[EndTime] error", err)
		stats.errors++
	}

	a.DeltaTime = a.EndTime.Sub(a.StartTime)

	a.IPAddress = net.ParseIP(r[2])
	if a.IPAddress == nil {
		log.Println("[IPAddress] error parsing ip: ", r[2])
		stats.errors++
	}

	stats.ipClassifier[strings.Join(strings.Split(a.IPAddress.String(), ".")[:2], ".")]++

	a.Gateway = net.ParseIP(r[3])
	if a.Gateway == nil {
		log.Println("[Gateway] error parsing ip: ", r[3])
		stats.errors++
	}

	//a.HWAddress, err = mac.ParseMAC(r[4])
	if err != nil {
		log.Println("[HWAddress] error", err)
		stats.errors++
	}

	a.ClientID = r[5]
	a.Action = r[6]
	stats.action[a.Action]++
	a.HostSent = r[7]
	a.HostReceived = r[8]
	a.ADNSUpdate = r[9]
	stats.action[a.ADNSUpdate]++
	a.Protocol = r[10]
	stats.protocol[a.Protocol]++
	a.CircuitID = r[11]

	rid := r[12] //RemoteID

	if len(rid) == 6 {
		// some CM encode RemoteID as a 6 bytes string...
		// "4z`***" [34:7a:2c:*], "pv0***" [70:76:30:*],  "|&4***" [7c:26:34:*]

		rid = fmt.Sprintf("%x", rid)
	}

	if len(rid) == 10 && rid[0] == 'A' {
		// in FTTH,  Remote ID = ONT circuit (acount ID), prefixed with "AA":
		// 	   e.g. "A000123456" becames "AA:A0:00:12:34:56"
		rid = "AA" + rid
	}

	// HFC =>, Remote ID = CM mac addr
	a.RemoteID, err = mac.ParseMAC(rid)
	if err != nil {
		log.Println("[RemoteID]error", err)
		stats.errors++
	}

	if i := strings.Index(r[13], ":"); i > 0 {
		a.VendorClassID = r[13][:i]
		stats.vendorClassID[a.VendorClassID]++
	}

	a.DOCSISDeviceClass = fmt.Sprintf("%0.32s", r[14])
	a.VendorSpecificData = fmt.Sprintf("%0.32s", r[15])
	a.InterfaceID = r[16]
	stats.vendorClassID[a.InterfaceID]++
	/*
		if len(r[12]) == 6 {
			fmt.Println("RemoteID=", r[12])
			fmt.Printf("Record: %v\n", r)
			fmt.Println("LINE:", a.String())

		}
	*/
	return a, nil
}

/*
func parseBCCAuditRecord(s bufio.Scanner) {
	return scanner.Err()
}
*/
func parseBccAuditFile(fname string) (err error) {

	var buf []byte
	var sbuf string
	var fieldCnt int
	var record []byte
	lin := 0
	record = make([]byte, fieldsPerLine)
	_ = record

	fieldIndexes := make([]int, fieldsPerLine, fieldsPerLine)

	file, err := os.Open(fname)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

scanner_looop:
	for scanner.Scan() {

		buf = scanner.Bytes()
		sbuf = string(buf)

		if len(buf) != len(sbuf) {
			fmt.Println("len []bytes != len string.", len(buf), len(sbuf))
		}

		if len(buf) != utf8.RuneCountInString(sbuf) {
			fmt.Println("len []bytes != len string.", len(buf), utf8.RuneCountInString(sbuf))
		}

		// ===========================================================================
		lin++
		state := fieldStart
		fieldCnt = 0

		//line_loop:
		for i, c := range buf {

			if state == fieldStart {
				if c == quote {
					state = fieldCore
					continue
				} else {
					fmt.Printf("Error at line %d, col %d:  expected %q, got %q\n.", lin, i, quote, c)
					// increment error starts ....
					continue scanner_looop
				}
			}
			if state == fieldEnd {
				if c == comma {
					state = fieldStart
				} else {
					// backtrack, to handle a '"' at the midle of a field
					state = fieldCore
					fieldCnt--
				}
			}
			if state == fieldCore {
				if c == quote {
					state = fieldEnd
					fieldIndexes[fieldCnt] = i
					fieldCnt++
					if fieldCnt > fieldsPerLine {
						fmt.Printf("Error at line %d, col %d: to many fields in this line.\n", lin, i)
						// incremnet error starts ....
						continue scanner_looop
					}

				}
			}

		}

		/*
		*
		 */

		if fieldCnt != fieldsPerLine {
			stats.errors++
			fmt.Printf("Error line %d, have %d fields, lines must have exacly %d\n.", lin, fieldCnt, fieldsPerLine)
			return fmt.Errorf("line must have exactly 17 itens")
		}

		a := &Audit{}

		//fmt.Println(string(buf[1:fieldIndexes[0]]))

		if string(buf[1:fieldIndexes[0]]) == headerMark { // "Start Time"
			stats.header++
			continue scanner_looop
		}

		a.StartTime, err = time.Parse(timeFormat, string(buf[1:fieldIndexes[0]]))
		if err != nil {
			log.Println("[StartTime]error", err)
			stats.errors++
		}

		_ = a

		//fmt.Println(audit.String())
		//fmt.Println("======================================================================================")

		// ==============================================================================================
		/*
				fmt.Printf("line=%v\n", string(buf))
				fmt.Printf("Linecnt=%d, fieldCnt=%d, indexes=%v\n", lin, fieldCnt, fieldIndexes)

				li := 1
				for i, v := range fieldIndexes {
					fmt.Printf("field: %2d: %q\n", i, string(buf[li:v]))
					li = v + 3
				}
			*
				/*
					if lin > 6 {
						break scanner_looop
					}
		*/
	}
	fmt.Println("total lines:", lin)
	return scanner.Err()

}

/*
func parseBCCAuditRecord(s bufio.Scanner) {
	return scanner.Err()
}
*/
func parseBccAuditFile2(fname string) (err error) {

	var buf []byte
	var sbuf string
	var fieldCnt int
	var record []byte
	lin := 0
	record = make([]byte, fieldsPerLine)
	_ = record

	fieldIndexes := make([]int, fieldsPerLine, fieldsPerLine)

	file, err := os.Open(fname)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

scanner_looop:
	for scanner.Scan() {

		buf = scanner.Bytes()
		sbuf = string(buf)

		if len(buf) != len(sbuf) {
			fmt.Println("len []bytes != len string.", len(buf), len(sbuf))
		}

		if len(buf) != utf8.RuneCountInString(sbuf) {
			fmt.Println("len []bytes != len string.", len(buf), utf8.RuneCountInString(sbuf))
		}

		// ===========================================================================
		lin++
		state := fieldStart
		fieldCnt = 0

		//line_loop:
		for i, c := range buf {

			if state == fieldStart {
				if c == quote {
					state = fieldCore
					continue
				} else {
					fmt.Printf("Error at line %d, col %d:  expected %q, got %q\n.", lin, i, quote, c)
					// increment error starts ....
					continue scanner_looop
				}
			}
			if state == fieldEnd {
				if c == comma {
					state = fieldStart
				} else {
					// backtrack, to handle a '"' at the midle of a field
					state = fieldCore
					fieldCnt--
				}
			}
			if state == fieldCore {
				if c == quote {
					state = fieldEnd
					fieldIndexes[fieldCnt] = i
					fieldCnt++
					if fieldCnt > fieldsPerLine {
						fmt.Printf("Error at line %d, col %d: to many fields in this line.\n", lin, i)
						// incremnet error starts ....
						continue scanner_looop
					}

				}
			}

		}

		/*
		*
		 */

		if fieldCnt != fieldsPerLine {
			stats.errors++
			fmt.Printf("Error line %d, have %d fields, lines must have exacly %d\n.", lin, fieldCnt, fieldsPerLine)
			return fmt.Errorf("line must have exactly 17 itens")
		}
		/*
			a := &Audit{}

			//fmt.Println(string(buf[1:fieldIndexes[0]]))

			if string(buf[1:fieldIndexes[0]]) == headerMark { // "Start Time"
				stats.header++
				continue scanner_looop
			}

			a.StartTime, err = time.Parse(timeFormat, string(buf[1:fieldIndexes[0]]))
			if err != nil {
				log.Println("[StartTime]error", err)
				stats.errors++
			}

			_ = a
		*/
		// r = record []string
		var r []string
		li := 1
		for _, v := range fieldIndexes {
			f := string(buf[li:v])
			li = v + 3
			r = append(r, f)
		}

		audit, _ := ParseAuditRecord(r)
		_ = audit

		//fmt.Println(audit.String())
		//fmt.Println("======================================================================================")

		// ==============================================================================================
		/*
				fmt.Printf("line=%v\n", string(buf))
				fmt.Printf("Linecnt=%d, fieldCnt=%d, indexes=%v\n", lin, fieldCnt, fieldIndexes)

				li := 1
				for i, v := range fieldIndexes {
					fmt.Printf("field: %2d: %q\n", i, string(buf[li:v]))
					li = v + 3
				}
			*
				/*
					if lin > 6 {
						break scanner_looop
					}
		*/
	}
	fmt.Println("total lines:", lin)
	return scanner.Err()

}
