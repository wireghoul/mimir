// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"log"
	"time"
	"bufio"
	"io"
	"errors"
	"./websocket"
)

// This example demonstrates a trivial client.
func ExampleInteract() {
	origin := "http://localhost/"
	url := "ws://localhost:8080/socket"
	ws, err := websocket.Dial(url, "", origin)
	if err != nil {
		log.Fatal(err)
	}
	rdr := bufio.NewReader(ws)

	for i := 0; i < 5;  i++ {
		s, err := requestAllFlows(ws, rdr)
		if err != nil {
			fmt.Printf("ERROR: %v\n", err)
		} else {
			fmt.Printf("Received: %s\n", s)
		}
		time.Sleep(time.Second * 1)
	}
	s, err := requestSingleFlow(ws, rdr, 35)
	if err != nil {
		fmt.Printf("ERROR: %v\n", err)
	} else {
		fmt.Printf("Received: %s\n", s)
	}

}

func sendRequest(wtr io.Writer, rdr *bufio.Reader, req string) (string, error) {
	if _, err := wtr.Write([]byte(req)); err != nil {
		return "", errors.New("Write error")
	}
	s, err := rdr.ReadString('\n')
	if err != nil {
		return "", errors.New("recv error")
	}
	return s, nil
}

func requestAllFlows(wtr io.Writer, rdr *bufio.Reader) (string, error) {
	return sendRequest(wtr, rdr, "GET_ALL_FLOWS")
}

func requestSingleFlow(wtr io.Writer, rdr *bufio.Reader, flowID uint32) (string, error) {
	return sendRequest(wtr, rdr, fmt.Sprintf("GET_SINGLE_FLOW %d", flowID))
}

func main() {
	ExampleInteract()
}
