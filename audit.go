package main

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

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

// AuditRecord represents a logged dhcp operation.
// from Incognito BCC 6.x
type AuditRecord struct {
	StartTime    time.Time
	EndTime      time.Time
	DeltaTime    time.Duration
	IPAddress    net.IP
	Gateway      net.IP
	HWAddress    mac.MAC
	ClientID     string
	Action       string // uint8	// TDO: Create a map[string]int (unit8)
	HostSent     string
	HostReceived string
	//	ADNSUpdate         string // uint8 or bool	// NC
	//	Protocol           string // uint8		// NC allways "DHCPV4"
	CircuitID     string
	RemoteID      mac.MAC
	VendorClassID string // uint8		// NC
	//	DOCSISDeviceClass  string // NC
	//	VendorSpecificData string // NC
	//	InterfaceID        string // NC
}

//Global var stats, MUST reformat later
var stats struct {
	header int
	action map[string]int
	//	aDNSUpdate    map[string]int
	//	protocol      map[string]int
	//	vendorClassID map[string]int
	//	interfaceID   map[string]int
	ipClassifier map[string]int
	errors       int
	cnt          int
	pubIP        int
	notPubIP     int
}

type state int

const (
	fieldStart state = iota
	fieldCore
	fieldEnd
)

// Some "usefull" constants to stop warnings....
const (
	quote           = '"'
	comma           = ','
	FieldsPerRecord = 17 // BCC Audit file have 17 fields in each line
	LF              = '\n'
	CR              = '\r'

	timeFormat = "Mon Jan 2 15:04:05 2006"
	headerMark = "Start Time" // if first field is "Start Time", the line is the header of the file
)

func init() {
	stats.action = make(map[string]int)
	//	stats.aDNSUpdate = make(map[string]int)
	//	stats.protocol = make(map[string]int)
	//	stats.vendorClassID = make(map[string]int)
	//	stats.interfaceID = make(map[string]int)
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
		fmt.Printf("\t%q = %d\n", k, v)
	}
	/*
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
	*/
	fmt.Println("ip classifier:", len(stats.ipClassifier))
	for k, v := range stats.ipClassifier {
		fmt.Printf("\t%q = %d\n", k, v)
	}
}

func (a *AuditRecord) String() string {
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
	//s += ", ADNSUpdate: " + a.ADNSUpdate
	//s += ", Protocol: " + a.Protocol
	s += ", CircuitID: " + a.CircuitID
	s += ", RemoteID: " + a.RemoteID.CiscoString()
	s += ", VendorClassID: " + a.VendorClassID
	//s += ", DOCSISDeviceClass: " + a.DOCSISDeviceClass
	//s += ", VendorSpecificData: " + a.VendorSpecificData
	//s += ", InterfaceID: " + a.InterfaceID

	return strings.Replace(s, ",", "\n", -1)
}

// ParseAuditRecord make a Audit struct from an a slice of strings
func ParseAuditRecord(r []string) (*AuditRecord, error) {
	const timeFormat = "Mon Jan 2 15:04:05 2006"
	var err error

	a := &AuditRecord{}

	if len(r) != 17 {
		stats.errors++
		return nil, fmt.Errorf("Invalid number of fields")
	}

	if r[0] == "Start Time" {
		stats.header++
		return nil, fmt.Errorf("Header record") // CHANGE-ME
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
	//a.ADNSUpdate = r[9]
	//stats.action[a.ADNSUpdate]++
	//a.Protocol = r[10]
	//stats.protocol[a.Protocol]++
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
	/*
		if i := strings.Index(r[13], ":"); i > 0 {
			a.VendorClassID = r[13][:i]
			stats.vendorClassID[a.VendorClassID]++
		}

		a.DOCSISDeviceClass = fmt.Sprintf("%0.32s", r[14])
		a.VendorSpecificData = fmt.Sprintf("%0.32s", r[15])
		a.InterfaceID = r[16]
		stats.vendorClassID[a.InterfaceID]++
	*/
	return a, nil
}

// A ParseError is returnned for parsing errors
type ParseError struct {
	Line   int // Line where error occurred, 1-indexed
	Column int // Colum (bytew index) where the error occurred, 0-indexed
	//Char	rune    // Character where the error occurred.
	Err error // The actual Error.
}

func (e *ParseError) Error() string {
	if e.Err == ErrFieldCount {
		return fmt.Sprintf("record on line %d: %v", e.Line, e.Err)
	}
	return fmt.Sprintf("parse error on line %d, column %d: %v", e.Line, e.Column, e.Err)
}

// These are the error that can be returned im ParseError.Err.
var (
	ErrQuote      = errors.New("expected a \"")
	ErrFieldCount = errors.New("wrong number of fields")
	//ErrFieldCount = errors.New("wrong number of fields")
)

// AuditFileReader holds information needed for parsing audit records in the audit file.
type AuditFileReader struct {
	//fname string
	s            *bufio.Scanner
	buf          []byte
	fieldIndexes []int
	numLine      int
	fields       []string
	// stats
	errors   int
	headers  int
	linesCnt int
}

func newAuditFileReader(scanner *bufio.Scanner) *AuditFileReader {
	return &AuditFileReader{
		//fname:        filename,
		s:            scanner,
		buf:          make([]byte, 1024),
		fieldIndexes: make([]int, FieldsPerRecord, FieldsPerRecord),
		fields:       make([]string, FieldsPerRecord, FieldsPerRecord),
	}
}

//iterate all lines on audit file
func processAuditFile(filename string) (err error) {

	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	r := newAuditFileReader(scanner)

	for r.s.Scan() {
		rec, err := r.splitAuditRecordFields()
		if err != nil {
			log.Println("ERROR:", err)
			continue
		}
		ar, err := ParseAuditRecord(rec)
		if err != nil {
			log.Println("ERROR:", err)
			continue
		}

		ip := ip2int(ar.IPAddress)
		node, ok := ippool.getIPNode(ip)
		if !ok {
			stats.notPubIP++
		} else {
			stats.pubIP++
			node.cnt++
		}

	}
	node, ok := ippool.getIPNode(ip2int(net.IPv4(81, 20, 244, 123)))
	if ok {
		fmt.Println("FOUND, name:", node.Name, ", addr:", node.addr, ", counter:", node.cnt)
	} else {
		fmt.Println("NOT, FOUND")
	}
	fmt.Println("==================")
	fmt.Println("lin: ", r.linesCnt, ", err:", r.errors)

	return r.s.Err() // Scanner.err()
}

func (r *AuditFileReader) splitAuditRecordFields() (rec []string, err error) {

	// Read line
	r.buf = r.s.Bytes()
	r.linesCnt++
	state := fieldStart
	fieldCnt := 0

	// a very simple finit state machine, split the fields od  a audit record
	// all fields are inside double quotes, separated by a comma, with no whitespaces,
	// like: "field1","fielde2",...,"field17"
	for i, c := range r.buf {
		switch state {
		case fieldStart:
			if c == quote {
				state = fieldCore
				continue
			} else {
				r.errors++
				err = &ParseError{Line: r.linesCnt, Column: i, Err: ErrQuote}
				return nil, err
			}
		case fieldEnd:
			if c == comma {
				state = fieldStart
			} else {
				// backtrack, to handle a '"' in the midle of a field.
				state = fieldCore
				fieldCnt--
			}
			fallthrough
		case fieldCore:
			if c == quote {
				state = fieldEnd
				r.fieldIndexes[fieldCnt] = i
				fieldCnt++
				if fieldCnt > FieldsPerRecord {
					r.errors++
					err = &ParseError{Line: r.linesCnt, Column: i, Err: ErrFieldCount}
					return nil, err
				}
				//case default:
				//  never reached
			}
		}

	}
	if fieldCnt != FieldsPerRecord {
		r.errors++
		err = &ParseError{Line: r.linesCnt, Column: 0, Err: ErrFieldCount}
		return nil, err
	}

	//var rec []string
	/*	li := 1
		for _, v := range r.fieldIndexes {
			field := string(r.buf[li:v])
			li = v + 3
			rec = append(rec, field)
		}
	*/
	//var rec []string
	li := 1
	for i, v := range r.fieldIndexes {
		r.fields[i] = string(r.buf[li:v])
		li = v + 3
		//rec = append(rec, fields)
	}

	//err = r.s.Err() // Scanner.Err()
	return r.fields, nil
}
