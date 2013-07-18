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
	"flag"
	"fmt"
	"os"
	"time"
)

var (
	dev           = flag.String("d", "eth0", "Device to get all up on, and sniff it")
	verbose       = flag.Bool("v", false, "Verbose logging")
	flowStats     = flag.Int("flow-stats", 0, "Interval to output flow stats.  0 disables.")
	flowDuration  = flag.Int("flow-duration", 300, "How much time to wait after we haven't seen a flow to expire it")
	webEnable     = flag.Bool("web-enable", false, "Enable webserver")
	webRoot       = flag.String("web-root", "/tmp/www", "Root directory for the webserver")
	webDebug      = flag.Bool("web-debug", false, "Enable webserver debugging, prints request URIs")
	webPort       = flag.Int("web-port", 80, "Port to listen on for the web server")
	webEnableAuth = flag.Bool("web-enable-auth", false, "Enable authentication")
	webEnableSSL = flag.Bool("web-enable-ssl", false, "Enable SSL")
    webSSLCertFile = flag.String("web-ssl-cert-file", "", "Certificate file for SSL")
    webSSLKeyFile = flag.String("web-ssl-key-file", "", "Private Key file for SSL")
	dumpUnusable  = flag.Bool("dump-unusable-packets", false, "Specify that streams should dump unparsable packets to a pcap file")
	enableReverseDNS  = flag.Bool("enable-reverse-dns", true, "Enable a thread to try and resolve DNS names for IPS")
	maxmindFile   = flag.String("maxmind-db", "", "MaxMind City database")
	flowExecutive FlowExecutive
	geoip *GeoIP
	reverseDNS 	ReverseDNSManager
)

const (
	DEFAULT_SNAPLEN = 0xffff
	KB              = 1024
	MB              = (1024 * 1024)
	GB              = (1024 * 1024 * 1024)
)

func init() {
	flag.Parse()
	avail, err := DeviceAvailableForSniffing(*dev)
	if err != nil {
		fmt.Printf("ERROR: %v\n", err)
		os.Exit(-1)
	}
	if !avail {
		fmt.Printf("ERROR: %s is not available for sniffing\n", *dev)
		os.Exit(-1)
	}
	if *flowDuration <= 0 || *flowDuration > 0xffff {
		fmt.Printf("ERROR: Invalid flow duration parameter of %d\n", *flowDuration)
		os.Exit(-1)
	}
	err = flowExecutive.Init()
	if err != nil {
		fmt.Printf("ERROR: Unable to init flowExecutive.  %v\n", err)
		os.Exit(-1)
	}

	if *maxmindFile != "" {
		geoip = BuildGeoIP(*maxmindFile, uint16(4096))
		if geoip == nil {
			fmt.Printf("ERROR: Failed to load GeoIP database\n")
			os.Exit(-1)
		}
	}
	if *enableReverseDNS {
		err := reverseDNS.Init(360) //expire DNS after 1 hour
		if err != nil {
			fmt.Printf("ERROR: Failed to initialized the reverse DNS\n")
			os.Exit(-1)
		}
	}
}

func main() {
	var ipPcapStream IPPcapStream
	var webPcapStream IPPcapStream
	reporterDieChan := make(chan bool)

	err := ipPcapStream.Init(*dev, DEFAULT_SNAPLEN, true, 1000, "ip", *dumpUnusable)
	if err != nil {
		fmt.Printf("ERROR on Init for PCAP stream.  %v\n", err)
		return
	}
	err = webPcapStream.Init(*dev, DEFAULT_SNAPLEN, true, 1000, "ip and port 80", *dumpUnusable)
	if err != nil {
		fmt.Printf("ERROR on Init for WEB PCAP stream.  %v\n", err)
		return
	}
	var ipfeeder FeederStream = &ipPcapStream
	var webfeeder FeederStream = &webPcapStream
	err = flowExecutive.CreateManagerFeederStream("IPPCAP", ipfeeder, uint16(*flowDuration))
	if err != nil {
		fmt.Printf("Failed to build Stream %v.  %v\n", "IPPCAP", err)
	}

	err = flowExecutive.CreateManagerFeederStream("WEBPCAP", webfeeder, uint16(*flowDuration))
	if err != nil {
		fmt.Printf("Failed to build Stream %v.  %v\n", "WEBPCAP", err)
	}

	if *flowStats > 0 {
		go flowStatReporter(uint16(*flowStats), reporterDieChan)
	}

	if *webEnable {
		mgr, err := flowExecutive.GetFlowManager("IPPCAP")
		if err != nil {
			fmt.Printf("Failed to start webserver.  %v\n", err)
			os.Exit(-1)
		}
        var wi WebserverInit
        wi.ListenOn = fmt.Sprintf(":%d", uint16(*webPort))
        wi.Root = *webRoot
        wi.UseAuth = *webEnableAuth
        wi.UseSSL = *webEnableSSL
        wi.CertFile = *webSSLCertFile
        wi.KeyFile = *webSSLKeyFile
		err = StartWebServer(wi, mgr)
		if err != nil {
			fmt.Printf("Failed to start webserver: %v\n", err)
			os.Exit(-1)
		}
	}

	var a bool
	fmt.Scan(&a)
	//kill the reporter loop
	reporterDieChan <- true
	flowExecutive.KillFeederManager("IPPCAP")
}

func flowStatReporter(updateInterval uint16, dieChan chan bool) {
	die := false
	go func() {
		<-dieChan
		die = true
	}()
	fmt.Printf("Starting Stat Reporter\n")

	for die == false {
		time.Sleep(time.Duration(updateInterval) * time.Second)
		keys := flowExecutive.GetManagerPairKeys()
		if len(keys) == 0 {
			continue
		}
		fmt.Printf("\nTracked Flows:\n")

		for x := range keys {
			mgr, err := flowExecutive.GetFlowManager(keys[x])
			if err != nil {
				fmt.Printf("Failed to get reference on %v\n", keys[x])
				continue
			}
			fmt.Printf("\t%s: %d\n", keys[x], mgr.Count())
		}
		fmt.Printf("\n")
	}
}
