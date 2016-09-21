package main

import (
	"encoding/csv"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"./mac"
)

// "Start Time","End Time","IP Address","Gateway","HW Address","Client ID","Acti                                                                                 on",
// "Host Sent","Host Received","A DNS Update","Protocol","Circuit ID","Remote ID                                                                                 ",
// "Vendor Class ID","DOCSIS DeviceClass","Vendor-Specific Data","Interface ID"

// header "Start Time" .....

/*
action: 10
	"Offered" = 575734
	"Released" = 13793
	"Active" = 49625
	"Lease Expired" = 47181
	"NAK:No Record of the lease" = 99
	"Forced" = 4357
	"Renewal" = 295084
	"Offer expired" = 4760
	"NAK:Not Renewable" = 23146
	"Failover conflict" = 852
aDNSUpdate: 1
	"Successful" = 1014631
protocol: 2
	"DHCPV4" = 1013268
	"BOOTP" = 1363
vendorClassId: 37
	"docsis3.0" = 29302
	"dhcpcd-5.2.10" = 2
	"docsis2.0" = 97423
	"'nosstb'" = 485
	"nosstb" = 18
	"udhcp 1.12.1" = 12
	"Vigor2820 series" = 3
	"MSFT 98" = 8
	"50" = 39
	"RV082" = 6
	"huawei AR1220" = 21
	"OpenTV" = 9891
	"MSFT 5.0" = 1314
	"dslforum.org" = 38
	"Vigor2925" = 10
	"nds" = 44227
	"" = 1129922
	"udhcp 0.9.8" = 107
	"dhcpcd-5.5.6" = 100
	"fon_test" = 104193
	"BR32L" = 22
	"pktc1.5" = 611676
	"Vigor2820" = 5
	"udhcp 1.20.2" = 4
	"dhcpcd-6.10.0" = 3
	"udhcp 1.24.2" = 2
	"udhcp 0.9.9-pre" = 283
	"udhcp 1.11.2" = 8
	"udhcp 1.11.1" = 5
	"ciscopnp" = 3
	"4d" = 41
	"udhcp 0.9.7" = 5
	"AirStation Series BUFFALO INC." = 8
	"Vigor2110n" = 6
	"udhcp 1.15.2" = 2
	"Vigor2820n" = 3
	"udhcp 1.17.4" = 65
InterfaceID: 0
ip classifier: 11
	"10.213" = 39558
	"10.98" = 601000
	"128.65" = 30028
	"10.156" = 52
	"172.16" = 54308
	"100.82" = 28550
	"78.29" = 78110
	"81.20" = 14843
	"0.0" = 23245
	"192.168" = 57822
	"10.212" = 87115

*/

type AuditString struct {
	StartTime          string
	EndTime            string
	IPAddress          string
	Gateway            string
	HWAddress          string
	ClientID           string
	Action             string
	HostSent           string
	HostReceived       string
	ADNSUpdate         string
	Protocol           string
	CircuitID          string
	RemoteID           string
	VendorClassID      string
	DOCSISDeviceClass  string
	VendorSpecificData string
	InterfaceID        string
}

var stats struct {
	header         int
	action         map[string]int
	aDNSUpdate     map[string]int
	protocol       map[string]int
	vendorClassID  map[string]int
	interfaceID    map[string]int
	ipClassifier   map[string]int
	docsisDevClass map[string]int
	errors         int
	cnt            int
}

func init() {
	stats.action = make(map[string]int)
	stats.aDNSUpdate = make(map[string]int)
	stats.protocol = make(map[string]int)
	stats.vendorClassID = make(map[string]int)
	stats.interfaceID = make(map[string]int)
	stats.ipClassifier = make(map[string]int)
	stats.docsisDevClass = make(map[string]int)
	stats.header = 0
	stats.errors = 0
	stats.cnt = 0
}

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

	fmt.Println("docsis device class:", len(stats.docsisDevClass))
	for k, v := range stats.docsisDevClass {
		fmt.Printf("\t%q = %d\n", k, v)
	}

}

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
	StartTime          time.Time
	EndTime            time.Time
	DeltaTime          time.Duration
	IPAddress          net.IP
	Gateway            net.IP
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
		log.Println("error", err)
		stats.errors++
	}

	a.EndTime, err = time.Parse(timeFormat, r[1])
	if err != nil {
		log.Println("error", err)
		stats.errors++
	}

	a.DeltaTime = a.EndTime.Sub(a.StartTime)

	a.IPAddress = net.ParseIP(r[2])
	if a.IPAddress == nil {
		log.Println("error parsing ip: ", r[2])
		stats.errors++
	}

	stats.ipClassifier[strings.Join(strings.Split(a.IPAddress.String(), ".")[:2], ".")]++

	a.Gateway = net.ParseIP(r[3])
	if a.Gateway == nil {
		log.Println("error parsing ip: ", r[3])
		stats.errors++
	}

	a.HWAddress, err = mac.ParseMAC(r[4])
	if err != nil {
		log.Println("error HWAddr", err)
		stats.errors++
	}

	a.ClientID = r[5]
	a.Action = r[6]
	stats.action[a.Action]++

	a.HostSent = r[7]
	a.HostReceived = r[8]
	a.ADNSUpdate = r[9]
	stats.aDNSUpdate[a.ADNSUpdate]++

	a.Protocol = r[10]
	stats.protocol[a.Protocol]++
	a.CircuitID = r[11]

	a.RemoteID, err = mac.ParseMAC(r[12])
	if err != nil {
		log.Println("error RemoteID", err)
		stats.errors++
	}

	i := strings.Index(r[13], ":")
	if i < 0 {
		i = len(r[13])
		if i > 32 {
			i = 32
		}
	}
	a.VendorClassID = r[13][:i]
	stats.vendorClassID[a.VendorClassID]++

	a.DOCSISDeviceClass = fmt.Sprintf("%0.8s", r[14])
	stats.vendorClassID[a.DOCSISDeviceClass]++
	a.VendorSpecificData = fmt.Sprintf("%0.32s", r[15])
	a.InterfaceID = r[16]
	stats.vendorClassID[a.InterfaceID]++

	stats.cnt++

	return a, nil
}

func (a *AuditString) String2() string {
	s := " StartTime: " + a.StartTime
	s += ", EndTime: " + a.EndTime
	s += ", IPAddress: " + a.IPAddress
	s += ", Gateway: " + a.Gateway
	s += ", HWAddress: " + a.HWAddress
	s += ", ClientID: " + a.ClientID
	s += ", Action: " + a.Action
	s += ", HostSent: " + a.HostSent
	s += ", HostReceived: " + a.HostReceived
	s += ", ADNSUpdate: " + a.ADNSUpdate
	s += ", Protocol: " + a.Protocol
	s += ", CircuitID: " + a.CircuitID
	s += ", RemoteID: " + a.RemoteID
	s += ", VendorClassID: " + fmt.Sprintf("%0.32s", a.VendorClassID)
	s += ", DOCSISDeviceClass: " + fmt.Sprintf("%0.32s", a.DOCSISDeviceClass)
	s += ", VendorSpecificData: " + fmt.Sprintf("%0.32s", a.VendorSpecificData)
	s += ", InterfaceID: " + a.InterfaceID

	return strings.Replace(s, ",", "\n", -1)
}

func main() {

	for i, arg := range os.Args {
		if i == 0 {
			continue
		}
		// print index and value
		//fmt.Println("item", i, "is", arg)
		_ = arg

		file, err := os.Open(arg)
		if err != nil {
			log.Fatal(err)
		}
		defer file.Close()

		reader := csv.NewReader(file)
		//reader.FieldsPerRecord = 17
		lin := 0

		for {
			record, err := reader.Read()
			if err == io.EOF {
				break
			}
			lin++

			if err != nil {
				log.Println("#Error:", err)
				continue

			}

			audit, _ := ParseAuditRecord(record)
			_ = audit
			//fmt.Println(len(record), ":", lin, record)
			//fmt.Println(audit.String())
			//fmt.Println("================================================================================")
		}

	}

	PrintStats()

}
