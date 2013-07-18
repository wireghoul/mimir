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
	"sync"
)

type FeederStream interface {
	MainFeederLoop(chan FlowItem)
	Stop() error
}

type managerItem struct {
	flowChan chan FlowItem
	manager  FlowList
	feeder   FeederStream
	name     string
}

type FlowExecutive struct {
	lock sync.Mutex
	list map[string]managerItem
}

func (f *FlowExecutive) Init() error {
	f.list = make(map[string]managerItem, 4)
	return nil
}

func (f *FlowExecutive) CreateManagerFeederStream(name string, feeder FeederStream, duration uint16) error {
	_, ok := f.list[name]
	if ok {
		return errors.New("Duplicate name on CreateManagerFeederStream")
	}

	var mgr managerItem
	mgr.flowChan = make(chan FlowItem, 128) //jack up the buffer a bit
	err := mgr.manager.InitFlowList(duration)
	if err != nil {
		return err
	}
	mgr.feeder = feeder
	f.list[name] = mgr
	go mgr.manager.FlowManagerMain(mgr.flowChan)
	go mgr.feeder.MainFeederLoop(mgr.flowChan)

	return nil
}

func (f *FlowExecutive) KillFeederManager(name string) error {
	//try to get the managerItem
	_, ok := f.list[name]
	if !ok {
		return errors.New("Invalid Pair name")
	}

	//shutdown the feeder and manager, then remove the pair from the map
	mgrI := f.list[name]
	err := mgrI.manager.Stop()
	if err != nil {
		return err
	}
	err = mgrI.feeder.Stop()
	if err != nil {
		return err
	}
	delete(f.list, name)
	return nil
}

func (f *FlowExecutive) GetFlowManager(name string) (*FlowList, error) {
	mgr, ok := f.list[name]
	if ok {
		return &(mgr.manager), nil
	}
	return nil, errors.New("Not Found")
}

//return a list of manager pairs that are active
func (f *FlowExecutive) GetManagerPairKeys() (x []string) {
	for key, _ := range f.list {
		x = append(x, key)
	}
	return x
}
