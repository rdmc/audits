package main

import (
	"encoding/binary"
	"encoding/gob"
	"fmt"
	"log"
	"net"
	"os"
)

const filename = "save.gob"

type IP = uint32

//type IP uint32 // ipv4 as a 32bit unsigned int

type IPNode struct {
	name  string
	addr  net.IP
	cnt   int
	cargo [256]byte // lastro para teste
}

type Block1K struct {
	network IP
	a       [1024]IPNode
}

type IPPool struct {
	//m     map[net.IP]*Block1K // net.IP canot be a key in a map... use a string or a UINT
	m     map[IP]*Block1K
	cargo []byte
}

func NewBlock1K(net IP) *Block1K {
	b := &Block1K{network: net}
	for i := 0; i < 1024; i++ {
		b.a[i].addr = int2ip(uint32(net) + uint32(i))
		b.a[i].name = fmt.Sprintf("ip=%v, index=%d", int2ip(uint32(net)+uint32(i)), i)
	}
	return b
}

// main !!!
var ippool IPPool

func SaveIPPool() error {

	f, err := os.Create(filename)
	if err != nil {
		log.Fatal("Error opening file", err)
	}
	defer f.Close()

	enc := gob.NewEncoder(f)

	if err := enc.Encode(&ippool); err != nil {
		log.Fatal("Error encoding", err)
	}

	return nil
}

func ReadIPPool() error {

	f, err := os.Open(filename)
	if err != nil {
		log.Fatal("Error opening file", err)
	}
	defer f.Close()

	dec := gob.NewDecoder(f)

	if err := dec.Decode(&ippool); err != nil {
		log.Fatal("Error encoding", err)
	}

	return nil

	return nil
}

func (ipp *IPPool) getIPNode(ip IP) (*IPNode, bool) {
	base := ip & 0xfffffc00
	index := ip & 0x000003ff
	b1Kp, ok := ipp.m[base]
	if !ok {
		return nil, false
	}
	return &b1Kp.a[index], true
}

// helper functions
func ip2int(ip net.IP) uint32 {
	if len(ip) == 16 {
		return binary.BigEndian.Uint32(ip[12:16])
	}
	return binary.BigEndian.Uint32(ip)
}

func int2ip(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, nn)
	return ip
}

func generate1KNetworks(cidrNet string) {
	//_, ipv4Net, err := net.ParseCIDR("78.29.128.0/18")
	_, ipv4Net, err := net.ParseCIDR(cidrNet)
	if err != nil {
		log.Fatal(err)
	}
	ms, _ := ipv4Net.Mask.Size()
	ms = 22 - ms
	if ms < 0 || ms > 6 {
		log.Fatal("network must be a [/16  to /22]")
	}
	for i := 0; i < 1<<uint(ms); i++ {
		b := NewBlock1K(IP(ip2int(ipv4Net.IP)))
		ippoll.m[IP(ip2int(ipv4Net.IP))] = b
		fmt.Println("#", i, ", net:", ipv4Net.IP, "/22.")
		ipv4Net.IP[2] = ipv4Net.IP[2] + 4
	}
}

func init() {
	fmt.Println("Initializing IP Pool memory...")
	ippo0l.m = make(map[IP]*Block1K, 30)
	generate1KNetworks("81.20.240.0/20")
	generate1KNetworks("78.29.128.0/18")
	generate1KNetworks("128.65.224.0/19")
	generate1KNetworks("185.218.12.0/22")
	generate1KNetworks("185.224.164.0/22")

}
