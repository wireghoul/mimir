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

/*
#cgo LDFLAGS: -lpcap
#include <stdlib.h>
#include <pcap.h>

int pcap_next_cruft(pcap_t *p, struct pcap_pkthdr **pkt_header, u_char **pkt_data) {
	return pcap_next_ex(p, pkt_header, (const u_char **)pkt_data);
}

int pcap_set_filter(pcap_t *p, char* device, char *filter, char* errbuff, int errbuff_size) {
	struct bpf_program fp;
	if (pcap_compile(p, &fp, filter, 0, 0) == -1) {
		snprintf(errbuff, errbuff_size, "Couldn't parse filter %s: %s\n", filter, pcap_geterr(p));
    		return -2;
	}
	if (pcap_setfilter(p, &fp) == -1) {
		snprintf(errbuff, errbuff_size, "Couldn't apply filter %s: %s\n", filter, pcap_geterr(p));
		return -1;
	}
	return 0;
}
*/
import "C"
import (
	"encoding/binary"
	"errors"
	"io"
	"io/ioutil"
	"os"
	"time"
	"unsafe"
)

type Pcap struct {
	cptr *C.pcap_t
	linkLayer	uint16
}

type PcapPacketHeader struct {
	Ts_sec, Ts_usec, Incl_len, Orig_len uint32
}

type PcapFileHeader struct {
	Magic                      uint32
	VersionMajor, VersionMinor uint16
	ThisZone                   int32
	SigFigs, SnapLen, Network  uint32
}

type PcapFileWriter struct {
	fout   io.Writer
	active bool
}

const (
	ERRBUF_SIZE = 256
)

func (p *Pcap) Next() (*Packet, error) {
	pkt, result := p.nextPacket()
	//actual error
	if result < 0 {
		return nil, errors.New("Failure on packet read")
	} else if result > 0 {
		return pkt, nil
	}
	return nil, nil
}

func (p *Pcap) nextPacket() (pkt *Packet, result int32) {
	var pkthdrPtr *C.struct_pcap_pkthdr
	var pkthdr C.struct_pcap_pkthdr
	var bufPtr *C.u_char
	var buf unsafe.Pointer

	result = int32(C.pcap_next_cruft(p.cptr, &pkthdrPtr, &bufPtr))

	buf = unsafe.Pointer(bufPtr)

	if buf == nil {
		return nil, result
	}

	//why are we copying the struct to another device? can't we just reference it? directly?
	pkthdr = *pkthdrPtr
	pkt = new(Packet)
	pkt.Time = time.Unix(int64(pkthdr.ts.tv_sec), int64(pkthdr.ts.tv_usec))
	pkt.Caplen = uint32(pkthdr.caplen)
	pkt.Len = uint32(pkthdr.len)
	pkt.Data = make([]byte, pkthdr.caplen)
	pkt.LinkLayer = p.linkLayer

	//copy the data into our go structure
	for i := uint32(0); i < pkt.Caplen; i++ {
		pkt.Data[i] = *(*byte)(unsafe.Pointer(uintptr(buf) + uintptr(i)))
	}

	return
}

//Opens a pcap handle
func OpenActiveDevice(dev string, snaplen uint32, promisc bool, timeout_ms uint32, filter string) (*Pcap, error) {
	var cbuf *C.char
	cbuf = (*C.char)(C.calloc(ERRBUF_SIZE, 1))
	handle := new(Pcap)
	var cpromisc int32 = 0
	if promisc {
		cpromisc = 1
	}

	cdev := C.CString(dev)
	defer C.free(unsafe.Pointer(cdev))
	handle.cptr = C.pcap_open_live(cdev, C.int(snaplen), C.int(cpromisc), C.int(timeout_ms), cbuf)
	if handle.cptr == nil {
		return nil, errors.New(C.GoString(cbuf))
	}
	x := C.pcap_datalink(handle.cptr)
	handle.linkLayer = uint16(x)

	C.free(unsafe.Pointer(cbuf))
	if filter != "" {
		ret := int32(C.pcap_set_filter(handle.cptr, cdev, C.CString(filter), cbuf, ERRBUF_SIZE-1))
		if ret != 0 {
			C.free(unsafe.Pointer(handle.cptr))
			return nil, errors.New(C.GoString(cbuf))
		}
	}
	return handle, nil
}

func GetDeviceList() ([]string, error) {
	var ifs []string
	var buf *C.char
	buf = (*C.char)(C.calloc(ERRBUF_SIZE, 1))
	defer C.free(unsafe.Pointer(buf))

	var devs *C.pcap_if_t
	if C.pcap_findalldevs((**C.pcap_if_t)(&devs), buf) == -1 {
		return nil, errors.New(C.GoString(buf))
	}
	defer C.pcap_freealldevs((*C.pcap_if_t)(devs))
	dev := devs
	var devcount uint32

	// figure out how many devices we have available
	for devcount = 0; dev != nil; dev = (*C.pcap_if_t)(dev.next) {
		devcount++
	}

	dev = devs
	for i := uint32(0); dev != nil; dev = (*C.pcap_if_t)(dev.next) {
		ifs = append(ifs, C.GoString(dev.name))
		i++
	}
	return ifs, nil
}

func DeviceAvailableForSniffing(dev string) (bool, error) {
	devs, err := GetDeviceList()
	if err != nil {
		return false, err
	}
	for i := range devs {
		if dev == devs[i] {
			return true, nil
		}
	}

	return false, nil
}

func (p *Pcap) Close() error {
	// is there a possible error condition here?
	C.pcap_close(p.cptr)
	return nil
}

func (w *PcapFileWriter) Init(fout *os.File, enable bool) error {
	if !enable {
		w.fout = ioutil.Discard
		w.active = false
		return nil
	}
	if fout == nil {
		return errors.New("Invalid file handle")
	}
	w.active = true
	w.fout = fout

	//generate header
	ETHERNET := uint32(1)
	hdr := PcapFileHeader{0xa1b2c3d4, 2, 4, -7, 0, DEFAULT_SNAPLEN, ETHERNET}
	return binary.Write(w.fout, binary.LittleEndian, hdr)
}

func (w *PcapFileWriter) WritePacket(pkt *Packet) error {
	if !w.active {
		return nil
	}
	if pkt.Data == nil {
		return nil
	}
	var hdr PcapPacketHeader
	hdr.Incl_len = uint32(len(pkt.Data))
	hdr.Orig_len = pkt.Len
	hdr.Ts_sec = uint32(time.Now().Unix())
	ns := time.Now().UnixNano() - (time.Now().Unix() * 1000000000)
	if ns < 0 {
		ns = 0
	}
	hdr.Ts_usec = uint32((ns / 1000))
	err := binary.Write(w.fout, binary.LittleEndian, hdr)
	if err != nil {
		return nil
	}
	return binary.Write(w.fout, binary.LittleEndian, pkt.Data)
}
