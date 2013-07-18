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
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"
)

const (
	IP4_TYPE  = 0x0800
	ARP_TYPE  = 0x0806
	IP6_TYPE  = 0x86DD
	VLAN_TYPE = 0x8100

	IP_ICMP = 1
	IP_INIP = 4
	IP_TCP  = 6
	IP_UDP  = 17

	LINK_NULL = 0
	LINK_ETHERNET = 1
	LINKTYPE_LINUX_SLL = 113
)

type Packet struct {
	LinkLayer uint16
	Time      time.Time
	Caplen    uint32
	Len       uint32
	Type      uint16
	DstMAC    uint64
	SrcMAC    uint64
	Data      []byte
	Header    IPHeader
	HeaderLen uint8
	Length    uint16
	Protocol  byte
	Payload   []byte
}

type IPHeader struct {
	SrcIP, DstIP     net.IP
	SrcPort, DstPort uint16
}

func (p *Packet) Parse() (err error) {
	//FIXME - make this deal with non-ethernet packets
	switch p.LinkLayer {
	case LINK_ETHERNET:
		return p.parseEthernet()
	case LINKTYPE_LINUX_SLL:
		return p.parseLinuxSLL()
	default:
		fmt.Printf("Unknown link layer: %v\n", p.LinkLayer)
	}
	return errors.New("unknown link type")
}

func (p *Packet) parseLinuxSLL() (err error) {
	//move payload past ethernet header
	p.Payload = p.Data[16:]
	p.Type = uint16(binary.BigEndian.Uint16(p.Data[14:16]))
	p.SrcMAC = 0
	p.DstMAC = 0

	switch p.Type {
	case IP4_TYPE:
		err = p.parseIPv4()
	case ARP_TYPE:
		err = p.parseArp()
	default:
		return errors.New("Unknown Packet Type")
	}
	return err
}

func (p *Packet) parseEthernet() (err error) {
	//move payload past ethernet header
	p.Payload = p.Data[14:]
	p.Type = uint16(binary.BigEndian.Uint16(p.Data[12:14]))
	p.SrcMAC = 0
	p.DstMAC = 0
	dst := p.Data[0:6]
	src := p.Data[6:12]

	for i := uint(0); i < 6; i++ {
		p.SrcMAC = (p.SrcMAC << 8) + uint64(src[i])
		p.DstMAC = (p.DstMAC << 8) + uint64(dst[i])
	}

	switch p.Type {
	case IP4_TYPE:
		err = p.parseIPv4()
	case ARP_TYPE:
		err = p.parseArp()
	default:
		return errors.New("Unknown Packet Type")
	}
	return err
}

//FIXME - We should try to do SOMETHING with tracking ARP
func (p *Packet) parseArp() (err error) {
	return nil
}

func (p *Packet) parseIPv4() (err error) {
	p.Protocol = p.Payload[9]
	srcIP := p.Payload[12:16]
	dstIP := p.Payload[16:20]
	p.Header.SrcIP = net.IPv4(srcIP[0], srcIP[1], srcIP[2], srcIP[3])
	p.Header.DstIP = net.IPv4(dstIP[0], dstIP[1], dstIP[2], dstIP[3])
	p.HeaderLen = uint8(p.Payload[0]) & 0x0F
	p.Length = uint16(binary.BigEndian.Uint16(p.Data[2:4]))
	pEnd := int(p.Length)
	if pEnd > len(p.Payload) {
		pEnd = len(p.Payload)
	}
	if len(p.Payload) <= int(p.HeaderLen)*4  || int(p.HeaderLen)*4 > pEnd {
		return errors.New("Packet is smaller than header.")
	}

	p.Payload = p.Payload[p.HeaderLen*4 : pEnd]
	switch p.Protocol {
	case IP_TCP:
		err = p.parseTCP()
	case IP_UDP:
		err = p.parseUDP()
	case IP_ICMP:
		err = p.parseICMP()
	default:
		fmt.Printf("Unknown IP packet type of %v\n", p.Protocol)
		err = p.parseGeneric()
	}

	return err
}

func (p *Packet) parseTCP() (err error) {
	p.Header.SrcPort = binary.BigEndian.Uint16(p.Payload[0:2])
	p.Header.DstPort = binary.BigEndian.Uint16(p.Payload[2:4])
	dataOffset := (p.Payload[12] & 0xF0) >> 4
	if int(dataOffset*4) > len(p.Payload) {
		fmt.Printf("%d >= %d\n", int(dataOffset*4), len(p.Payload))
		return errors.New("Failed to parse TCP packet.  Possible fragmentation\n")
	}
	p.Payload = p.Payload[dataOffset*4:]
	return nil
}

func (p *Packet) parseUDP() (err error) {
	p.Header.SrcPort = binary.BigEndian.Uint16(p.Payload[0:2])
	p.Header.DstPort = binary.BigEndian.Uint16(p.Payload[2:4])
	if len(p.Payload) <= 8 {
		return errors.New("Failed to parse UDP packet.  Possible fragmentation\n")
	}
	p.Payload = p.Payload[8:]
	return nil
}

func (p *Packet) parseICMP() (err error) {
	p.Header.SrcPort = 0
	p.Header.DstPort = 0

	return nil
}

func (p *Packet) parseGeneric() (err error) {
	p.Header.SrcPort = 0
	p.Header.DstPort = 0

	return nil
}

func (p *Packet) Stats() string {
	return fmt.Sprintf("time %v:\t\tpktlen: %v\t\tcaplen: %v", p.Time, p.Len, p.Caplen)
}

func toUint32(data []byte, flip bool) uint32 {
	if flip {
		return binary.BigEndian.Uint32(data)
	}
	return binary.LittleEndian.Uint32(data)
}

func toUint16(data []byte, flip bool) uint16 {
	if flip {
		return binary.BigEndian.Uint16(data)
	}
	return binary.LittleEndian.Uint16(data)
}
