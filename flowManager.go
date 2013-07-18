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
	"os"
	"sync"
	"time"
)

const (
	_ = iota // skip 0
	IPV4FLOW
)

type FlowItem interface {
	CreateIndex() FlowIndexType
	TrafficBytes() (uint64, uint64)
	ABBytes() (uint64, uint64)
	SourceString() string
	DestString() string
	Alias() string
	String() string
	JSON() string
	SetAlias(string)
	FlowType() uint16
	Update(item FlowItem) error
	LastUpdate() time.Time
	StartTime() time.Time
	ID() uint64
	SetID(uint64)
	//whenever the flowManager determines this is a new flow this function is called
	//The NewFlow function is blocking and called by the flow manager.  So be quick!
	NewFlow()
}

type FlowIndexType struct {
	Src [18]byte
	Dst [18]byte
}

type FlowList struct {
	list           map[FlowIndexType]FlowItem
	indexer        map[uint64]FlowIndexType
	indexCounter   uint64
	Lock           sync.RWMutex
	init           bool
	expireDuration time.Duration
	die            bool
}

func (l *FlowList) InitFlowList(flowExpireDurationSeconds uint16) (err error) {
	if l.init {
		return errors.New("Tried to init an already initialized flowManager\n")
	}
	if l.list == nil {
		l.list = make(map[FlowIndexType]FlowItem, 1024)
	}
	if l.indexer == nil {
		l.indexer = make(map[uint64]FlowIndexType, 1024)
	}
	l.indexCounter = 0
	l.expireDuration = time.Duration(flowExpireDurationSeconds) * time.Second
	l.init = true
	l.die = false
	return nil
}

func (l *FlowList) Stop() error {
	if l.init == false {
		return errors.New("Attempted to stop a non-ready FlowManager")
	}
	l.die = true
	return nil
}

//main routine that spins and accepts flow records of the main producer channel
func (l *FlowList) FlowManagerMain(flowManagerConsumerChan chan FlowItem) {
	if !l.init {
		fmt.Printf("FlowManagerMain on unitialized flowManager\n")
		os.Exit(-1)
	}
	l.die = false
	//waiting for the death signal

	//pruning function
	go func(interval time.Duration) {
		for l.die == false {
			l.ExpireFlows()
			time.Sleep(interval)
		}
	}(10 * time.Second)

	for l.die == false {
		f := <-flowManagerConsumerChan
		l.AddFlow(f)
	}
}

//AddFlow is used for adding to a flow to the flow list
//it also updates an existing flow if it exists
func (l *FlowList) AddFlow(flow FlowItem) error {
	if !l.init {
		return errors.New("AddFlow against a non-initialized FlowManager")
	}
	idx := flow.CreateIndex()

	//check if a flow already exists and update it if it does
	//FIXME - optmize this to do fewer lookups
	l.Lock.Lock()
	x, ok := l.list[idx]
	if ok {
		x.Update(flow)
		l.list[idx] = x
	} else {
		l.indexCounter++
		flowID := l.indexCounter
		l.list[idx] = flow
		l.indexer[flowID] = idx
		flow.SetID(flowID)
		flow.NewFlow()
	}
	l.Lock.Unlock()
	return nil
}

func (l *FlowList) Count() int {
	return len(l.list)
}

func (l *FlowList) GetFlow(ID uint64) (r FlowItem, err error) {
	idx, ok := l.indexer[ID]
	if !ok {
		return nil, errors.New("Non-existent flow ID")
	}
	r, ok = l.list[idx]
	if !ok {
		//this is a strange state, nuke the flow index
		l.Lock.Lock()
		delete(l.indexer, ID)
		l.Lock.Unlock()
		return nil, errors.New("Non-existent flow")
	}
	err = nil
	return
}

func (l FlowList) ActiveFlowIDs() (r []uint64) {
	l.Lock.RLock()
	for id, _ := range l.indexer {
		r = append(r, id)
	}
	l.Lock.RUnlock()
	return r
}

//Basically Runs through the list of flows and "expires" any that have
//not been seen in a certain duration.
func (l *FlowList) ExpireFlows() error {
	//go ripping through the entire list looking for expirable items
	//Because writes lock the entire map, we don't want to lock the list for 
	//the whole scan, so we pull the flows that should be expired and throw them in a 
	//temporary list, then go through that last and lock/expire/unlock the list
	toExpireList := make([]FlowIndexType, 16)

	l.Lock.RLock()
	for key, value := range l.list {
		//throw the value into the toExpireList
		if time.Since(value.LastUpdate()) > l.expireDuration {
			if *verbose {
				fmt.Printf("going to kill flow (%f) : %s\n", time.Since(value.LastUpdate()).Seconds(), value.String())
			}
			toExpireList = append(toExpireList, key)
		}
	}
	l.Lock.RUnlock()

	//walk through the to expire list and try to destroy each flow
	for key := range toExpireList {
		//it is safe to delete from a map even if the key is missing
		l.Lock.Lock()
		x, ok := l.list[toExpireList[key]]
		if ok {
			delete(l.indexer, x.ID())
		}
		delete(l.list, toExpireList[key])
		l.Lock.Unlock()
	}
	return nil
}
