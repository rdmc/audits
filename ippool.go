package main

import (
	"encoding/binary"
	"net"
)

/*
// exemplo de um tipo
// baseado em https://golang.org/pkg/container/list/


type YYY        // as a Node/Element
 func (y *YYY) Next() *YYY
 func (y *YYY) Prev() *YYY

type XXX        // as a List

//???? The Zere value of XXX is am emply XXX readdy to use ????
// define a reasonable Zero Value....

  func New() *XXX       // New returns an initialized XXX.

 func(x *XXX) Back() *YYY
 func(x *XXX) Front() *YYY

 func(x *XXX) Init() *XXX // Init initializes or clears XXX x.

 func(x *XXX) Len() Init


 func(x *XXX) Insert(y *YYY) *YYY
 func(x *XXX) Remove(y *YYY) *YYY


XXX_test.golang
ver https://golang.org/src/container/list/list_test.go

*/

type IP uint32 // ipv4 as a 32bit unsigned int

type IPNode struct {
	name  string
	addr  net.IP
	cargo [256]byte // lastro para teste
}

type Block1K struct {
	network IP
	a       [1024]IPNode
}

type IPPoll struct {
	//m     map[net.IP]*Block1K // net.IP canot be a key in a map... use a string or a UINT
	m     map[IP]*Block1K
	cargo []byte
}

func (ipp *IPPoll) getIPNode(ip IP) (*IPNode, bool) {
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
