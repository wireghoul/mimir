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
	"io/ioutil"
	"time"
)

type IPPcapStream struct {
	pcapHandle *Pcap
	die        bool
	status     bool
	dieReason  error
	dumper     PcapFileWriter
}

func (ipcs *IPPcapStream) Init(device string, snaplen int, promisc bool, timeout uint32, filter string, dumpUnparsable bool) error {
	sniffDev, err := OpenActiveDevice(*dev, DEFAULT_SNAPLEN, true, 1000, filter)
	if err != nil {
		return errors.New(fmt.Sprintf("Failed to open active device: %v", err))
	}
	ipcs.pcapHandle = sniffDev
	if dumpUnparsable {
		fout, err := ioutil.TempFile("/tmp/", "IPPcapStreamDump")
		if err != nil {
			return err
		}
		ipcs.dumper.Init(fout, true)
	} else {
		ipcs.dumper.Init(nil, false)
	}
	return nil
}

func (ipcs *IPPcapStream) MainFeederLoop(flowManagerProducerChan chan FlowItem) {
	ipcs.die = false
	ipcs.status = true
	ipcs.dieReason = nil
	var pkt *Packet = nil
	var err error

	for pkt, err = ipcs.pcapHandle.Next(); err == nil && ipcs.die == false; pkt, err = ipcs.pcapHandle.Next() {
		if pkt == nil {
			continue
		}
		err := pkt.Parse()
		if err != nil {
			ipcs.dumper.WritePacket(pkt)
			continue
		}
		if pkt.Type == IP4_TYPE {
			var ipv4flow IPv4Flow
			ipv4flow.ImportPacket(pkt)
			var flowItem FlowItem = &ipv4flow
			flowManagerProducerChan <- flowItem
		} else if pkt.Type == IP6_TYPE {
			if *verbose {
				fmt.Printf("Got IPv6 packet, skipping\n")
			}
			continue
		} else {
			if *verbose {
				fmt.Printf("Got non IP packet of type 0x%04x, skipping\n", pkt.Type)
			}
			ipcs.dumper.WritePacket(pkt)
			continue
		}
	}
	if pkt == nil {
		ipcs.dieReason = errors.New(fmt.Sprintf("Got a nil packet, so probably lost handle on libpcap"))
	} else {
		ipcs.dieReason = nil
	}
	ipcs.status = false
	fmt.Println("Good bye")
}

func (ipcs *IPPcapStream) Status() (bool, error) {
	if ipcs.status {
		return true, nil
	}
	return false, ipcs.dieReason
}

func (ipcs *IPPcapStream) Stop() error {
	ipcs.die = true
	for ipcs.status == true {
		time.Sleep(10 * time.Millisecond)
	}
	ipcs.pcapHandle.Close()
	return ipcs.dieReason
}
