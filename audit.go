package main

import (
	"bufio"
	"compress/gzip"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/rdmc/mac"
)

// "Start Time","End Time","IP Address","Gateway","HW Address","Client ID","Acti                                                                                 on",
// "Host Sent","Host Received","A DNS Update","Protocol","Circuit ID","Remote ID                                                                                 ",
// "Vendor Class ID","DOCSIS DeviceClass","Vendor-Specific Data","Interface ID"

// header "Start Time" .....

// AuditRecord represents a logged dhcp operation.
// from Incognito BCC 6.x
type AuditRecord struct {
	StartTime time.Time
	//	EndTime   time.Time
	//	DeltaTime uint //time.Duration
	IPAddress net.IP
	Gateway   net.IP
	HWAddress mac.MAC
	Action    AuditAction // 	int or uint8, uint32? what is more eficient?
	CircuitID string      // can be usefull in FTTH
	RemoteID  mac.MAC     // CM MAC in HFC, Acouint ID in FTTH
}

// Some "usefull" constants ....
const (
	quote           = '"'
	comma           = ','
	FieldsPerRecord = 17 // BCC Audit file have 17 fields in each line
	LF              = '\n'
	CR              = '\r'

	timeFormat = "Mon Jan 2 15:04:05 2006"
	headerMark = "Start Time" // if first field is "Start Time", the line is the header of the file
)

type AuditAction int

const (
	AA_NULL AuditAction = iota
	AA_RENEW
	AA_DELETE
	AA_NAK
	//AA_TIMEOUT
	//AA_TEMP
	AA_BIND
	AA_IGNORE
)

// dhcpAction, dhcp messages and states
var dhcpActionMap = map[string]AuditAction{
	"Renewal":                    AA_RENEW,
	"Released":                   AA_DELETE,
	"Denied: No Match":           AA_NAK,
	"Lease Expired":              AA_IGNORE,
	"NAK:Not Renewable":          AA_NAK,
	"NAK:No Record of the lease": AA_NAK,
	"Offered":                    AA_IGNORE,
	"Active":                     AA_BIND,
	"Forced":                     AA_BIND,
	"Offer expired":              AA_IGNORE,
	"Denied: No Addresses":       AA_IGNORE,
	"Declined":                   AA_NAK,
}

func (a *AuditRecord) String() string {
	// TODO: use strings.Builder:
	// 	var b strings.Builder
	//      b.WriteString(" StartTime: " + a.StartTime.String())
	//      .....
	s := " StartTime: " + a.StartTime.String()
	//	s += ", EndTime: " + a.EndTime.String()
	//	s += ", DeltaTime: " + strconv.Itoa(int(a.DeltaTime))
	s += ", IPAddress: " + a.IPAddress.String()
	s += ", Gateway: " + a.Gateway.String()
	s += ", HWAddress: " + a.HWAddress.CiscoString()
	s += ", Action: " + strconv.Itoa(int(a.Action))
	s += ", CircuitID: " + a.CircuitID
	s += ", RemoteID: " + a.RemoteID.CiscoString()

	//return strings.Replace(s, ",", "\n", -1)
	return s
}

// ParseAuditRecord make a Audit struct from an a slice of strings
func ParseAuditRecord(r []string) (*AuditRecord, error) {
	const timeFormat = "Mon Jan 2 15:04:05 2006"
	var (
		err error
		ok  bool
	)

	a := &AuditRecord{}

	if len(r) != 17 {
		stats.errors++
		return nil, fmt.Errorf("Invalid number of fields")
	}

	if r[0] == "Start Time" {
		stats.header++
		return nil, ErrSkip
	}

	a.StartTime, err = time.Parse(timeFormat, r[0])
	if err != nil {
		log.Println("[StartTime]error", err)
		stats.errors++
	}
	/*
		a.EndTime, err = time.Parse(timeFormat, r[1])
		if err != nil {
			log.Println("[EndTime] error", err)
			stats.errors++
		}

		a.DeltaTime = uint(a.EndTime.Sub(a.StartTime).Seconds())
	*/
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

	a.HWAddress, err = mac.ParseMAC(r[4])
	if err != nil {
		log.Println("[HWAddress] error", err)
		stats.errors++
	}

	a.Action, ok = dhcpActionMap[r[6]]
	if !ok {
		log.Println("Unknow Action:", r[6])
	}
	stats.action[a.Action]++

	a.CircuitID = r[11]

	rid := r[12] //RemoteID

	if len(rid) == 6 {
		// some CMs encodes RemoteID as a 6 bytes string...
		// "4z`***" [34:7a:2c:*], "pv0***" [70:76:30:*],  "|&4***" [7c:26:34:*]

		rid = fmt.Sprintf("%x", rid)
	}

	// handle ftth account ids
	if len(rid) == 10 && rid[0] == 'A' {
		// in FTTH,  Remote ID = ONT circuit (acount ID), prefixed with "AA":
		// 	   e.g. "A000123456" becames "AA:A0:00:12:34:56"
		rid = "AA" + rid
	}

	// HFC =>, Remote ID = CM mac addr
	a.RemoteID, err = mac.ParseMAC(rid)
	if err != nil {
		//log.Println("[RemoteID]error", err)
		stats.errors++
	}
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
	ErrSkip       = errors.New("skip to next record") // not an error
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

	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	f, err := gzip.NewReader(file)
	if err != nil {
		log.Fatal(err)
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
			if err.Error() == ErrSkip.Error() {
				// not an error
				continue
			}
			log.Println("ERROR:", err)
			continue
		}

		WorkFunc(ar)
	}

	//fmt.Println("==================")
	fmt.Println("lin: ", r.linesCnt, ", err:", r.errors)

	return r.s.Err() // Scanner.err()
}

func (r *AuditFileReader) splitAuditRecordFields() (rec []string, err error) {

	type faState int //finit automaton states
	const (
		fieldStart faState = iota
		fieldCore
		fieldEnd
	)

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
				// backtrack, to handle a '"' at midle of a field.
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

	// Build a []string record
	li := 1
	for i, v := range r.fieldIndexes {
		r.fields[i] = string(r.buf[li:v])
		li = v + 3
		//rec = append(rec, fields)
	}

	//err = r.s.Err() // Scanner.Err()
	return r.fields, nil
}
