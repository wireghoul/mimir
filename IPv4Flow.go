/*====================================================================
Copyright 2013 Southfork Security, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
====================================================================*/

package main

import (
	"errors"
	"fmt"
	"net"
	"time"
)

type IPPortPair struct {
	IP   net.IP
	Port uint16
}

//For proper flow accounting we won't create a new flow for each direction of the connection
//Always sort based on the the ip, then port with lowest going to A and highest going to B
//We will always assume the first packet we see dictates the "source"
type IPv4Flow struct {
	a, b             IPPortPair
	bytesAB, bytesBA uint64
	aIsSource        bool
	alias            string
	lastUpdate       time.Time
	startTime        time.Time
	traffic          uint64
	id               uint64
}

func (pp IPPortPair) String() string {
	return fmt.Sprintf("{\"ip\" : \"%v\", \"port\" : \"%d\"}", pp.IP, pp.Port)
}

func (f IPv4Flow) String() string {
	if f.aIsSource {
		return fmt.Sprintf("%v:%d [%d] -> %v:%d [%d]", f.a.IP, f.a.Port, f.bytesAB, f.b.IP, f.b.Port, f.bytesBA)
	}
	return fmt.Sprintf("%v:%d [%d] -> %v:%d [%d]", f.b.IP, f.b.Port, f.bytesBA, f.a.IP, f.a.Port, f.bytesAB)
}

func (f IPv4Flow) ID() uint64 {
	return f.id
}

func (f *IPv4Flow) SetID(ID uint64) {
	f.id = ID
}

func (pp IPPortPair) IPv4ToUint32() (uint32, error) {
	var r uint32 = 0
	var x uint32 = 0
	ipv4 := pp.IP.To4()
	if ipv4 == nil {
		return 0, errors.New("Not an IPv4 address")
	}
	for i := 0; i < 4; i++ {
		r |= (uint32(ipv4[i]) << x)
		x += 8
	}
	return r, nil
}

//return 0 on identical
//	< 0 on pp is less than other
//	> 0 on pp greater than other
//	and IPv6 address is always "larger" than an IPv4 address
func (pp IPPortPair) Compare(other IPPortPair) int8 {

	//check if they are disparit IP versions
	if len(pp.IP) > len(other.IP) {
		return 1
	} else if len(pp.IP) < len(other.IP) {
		return -1
	} else {
		for i := 0; i < len(pp.IP); i++ {
			if pp.IP[i] > other.IP[i] {
				return 1
			} else if pp.IP[i] < other.IP[i] {
				return -1
			}
		}
	}
	return 0
}

func (f *IPv4Flow) ImportPacket(pkt *Packet) error {
	var src, dst IPPortPair
	//ensure its an IPv4 packet
	if pkt.Type != IP4_TYPE {
		return errors.New("Invalid packet type")
	}
	src.IP = pkt.Header.SrcIP
	src.Port = pkt.Header.SrcPort
	dst.IP = pkt.Header.DstIP
	dst.Port = pkt.Header.DstPort

	//decide who is A vs B
	cmp := src.Compare(dst)
	if cmp == 0 {
		return errors.New("Identical src/dst ip port pair")
	} else if cmp > 0 {
		f.aIsSource = false
		f.b = src
		f.a = dst
		f.bytesBA = uint64(len(pkt.Data))
		f.bytesAB = 0
	} else if cmp < 0 {
		f.aIsSource = true
		f.a = src
		f.b = dst
		f.bytesAB = uint64(len(pkt.Data))
		f.bytesBA = 0
	}
	if *verbose {
		if f.aIsSource {
			fmt.Printf("%v [%d] -> %v {%x : %x}\n", f.a.String(), len(pkt.Data), f.b.String(), pkt.Type, pkt.Protocol)
		} else {
			fmt.Printf("%v <- %v [%d] {%x : %x}\n", f.a.String(), f.b.String(), len(pkt.Data), pkt.Type, pkt.Protocol)
		}
	}
	f.startTime = time.Now()
	f.lastUpdate = time.Now()
	return nil
}

func (f IPv4Flow) CreateIndex() (x FlowIndexType) {
	//populate ports
	x.Src[14] = byte(f.a.Port >> 8)
	x.Src[15] = byte(f.a.Port & 0xff)
	x.Dst[14] = byte(f.b.Port >> 8)
	x.Dst[15] = byte(f.b.Port & 0xff)

	//populate IPs, assuming we will never have a flow between different IP sizes
	for i := 0; i < len(f.a.IP) && i < 16; i++ {
		x.Src[i] = f.a.IP[i]
		x.Dst[i] = f.b.IP[i]
	}
	return x
}

func (f *IPv4Flow) Update(flow FlowItem) error {
	if flow.FlowType() != f.FlowType() {
		return errors.New("Mismatch flow type on Update")
	}

	f.lastUpdate = flow.StartTime()
	ABytes, BBytes := flow.ABBytes()

	f.bytesAB += ABytes
	f.bytesBA += BBytes

	return nil
}

func (f IPv4Flow) TrafficBytes() (uint64, uint64) {
	if f.aIsSource {
		return f.bytesAB, f.bytesBA
	}
	return f.bytesBA, f.bytesAB
}

func (f IPv4Flow) ABBytes() (uint64, uint64) {
	return f.bytesAB, f.bytesBA
}

func (f IPv4Flow) SourceBytes() uint64 {
	if f.aIsSource {
		return f.bytesAB
	}
	return f.bytesBA
}

func (f IPv4Flow) DestBytes() uint64 {
	if f.aIsSource {
		return f.bytesAB
	}
	return f.bytesBA
}

func (f IPv4Flow) SourceString() string {
	if f.aIsSource {
		return f.a.String()
	}
	return f.b.String()
}

func (f IPv4Flow) DestString() string {
	if f.aIsSource {
		return f.b.String()
	}
	return f.a.String()
}

func (f IPv4Flow) FlowType() uint16 {
	return IPV4FLOW
}

func (f IPv4Flow) Alias() string {
	return f.alias
}

func (f *IPv4Flow) SetAlias(x string) {
	f.alias = x
}

func (f IPv4Flow) LastUpdate() time.Time {
	return f.lastUpdate
}

func (f IPv4Flow) StartTime() time.Time {
	return f.startTime
}

func (f IPv4Flow) JSON() (r string) {
	var src, dst string
	var sb, rb uint64
	if f.aIsSource {
		src = f.a.String()
		sb = f.bytesAB
		dst = f.b.String()
		rb = f.bytesBA
	} else {
		dst = f.a.String()
		rb = f.bytesAB
		src = f.b.String()
		sb = f.bytesBA
	}

	return fmt.Sprintf("\"flowID\":\"%d\",\"info\":{ \"src\":%s,\"dst\":%s,\"sendbytes\":\"%d\",\"recvbytes\":\"%d\"}", f.ID(), src, dst, sb, rb)
}

func (f IPv4Flow) NewFlow() {
	ipA := f.a.String()
	ipB := f.b.String()
	reverseDNS.CacheIpName(ipA)
	reverseDNS.CacheIpName(ipB)
}
