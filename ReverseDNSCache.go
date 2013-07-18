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
	"time"
)

type dnsEntry struct {
	ip string
	hostname string
	lastUpdate time.Time
}
	

type ReverseDNSManager struct {
	dnsMap map[string]dnsEntry
	entryLifetime uint16
	die bool
	initialized bool
}

//just adds the IP to the list of things to query.
//this is an asynchronous call and returns immediately regardless
func (dns *ReverseDNSManager) CacheIpName(ip string) {
	if ! dns.initialized {
		return
	}
	return
}

func (dns *ReverseDNSManager) QueryIp(ip string) string {
	if ! dns.initialized {
		return ""
	}
	return "coreysucks.com"
}

//duration is how long a reverse DNS entry stays in the cache without being updated
func (dns *ReverseDNSManager) Init(entryDuration uint16) error {
	dns.die = false
	dns.entryLifetime = entryDuration
	go dns.expirationThread()
	dns.initialized = true
	return nil
}

func (dns *ReverseDNSManager) expirationThread() {
	for dns.die != true {
		time.Sleep(time.Duration(dns.entryLifetime) * time.Second)
	}
}

func (dns *ReverseDNSManager) Quit() {
	dns.die = true
}
