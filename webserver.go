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
	"net/http"
	"os"
	"strconv"
	"strings"
	"io"
	"time"
    "net"
	"./websocket"
)

type WebserverInit struct {
    ListenOn string
    Root string
    UseAuth bool
    UseSSL bool
    CertFile string
    KeyFile string
}

var (
	fileHandler http.Handler
	flowTracker *FlowList
    authCJ AuthCookieJar
    checkAuth bool
)

func (wi *WebserverInit) Verify() error {
    fi, err := os.Stat(wi.Root)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return errors.New(fmt.Sprintf("%s is not a directory\n", wi.Root))
	}

    if wi.UseAuth {
        //Verify that the root directory has a directory /login in it
        loginDir := fmt.Sprintf("%s/login/", wi.Root)
        fi, err := os.Stat(loginDir)
        if err != nil {
            return errors.New(fmt.Sprintf("The root HTTP directory %s does not have a \"login\" directory for authentication", wi.Root))
        }
        if !fi.IsDir() {
            return errors.New(fmt.Sprintf("The HTTP directory %s/login is not a directory", wi.Root))
        }

        //Verify that the *root*/login directory has login.html in it
        loginFile := fmt.Sprintf("%s/login/login.html", wi.Root)
        fi, err = os.Stat(loginFile)
        if err != nil {
            return errors.New(fmt.Sprintf("The login HTTP directory %s does not contain \"login.html\" directory for authentication", wi.Root))
        }
        if fi.IsDir() {
            return errors.New(fmt.Sprintf("The login HTTP file %s/login/login.html is not a file", wi.Root))
        }
        checkAuth = true
    }

    //FIXME - enfoce this
    //if wi.UseAuth == true && wi.UseSSL == false {
    //    return errors.New("Requested authentication without SSL.  I can not let you do that Dave.")
    //}
    if wi.UseSSL == true {
        if wi.CertFile == "" || wi.KeyFile == "" {
            return errors.New("Requested SSL but KeyFile and CertFile were not set")
        }
        err := verifyFile(wi.CertFile)
        if err != nil {
            return err
        }
        err = verifyFile(wi.KeyFile)
        if err != nil {
            return err
        }
    } else {
        if wi.CertFile != "" || wi.KeyFile != "" {
            return errors.New("KeyFile or CertFile specified but UseSSL was not enabled")
        }
    }
    return nil
}

func verifyFile(filepath string) error {
    fi, err := os.Stat(filepath)
    if err != nil {
        return errors.New(fmt.Sprintf("%s does not exist", filepath))
    }
    if fi.IsDir() {
        return errors.New(fmt.Sprintf("%s is not a file", filepath))
    }
    return nil
}

func StartWebServer(wi WebserverInit, fl *FlowList) error {
	err := wi.Verify()
	if err != nil {
		return err
	}
	flowTracker = fl
	http.HandleFunc("/api/", APIfunc)
	http.Handle("/socket", websocket.Handler(FlowWebSocket))
	fileHandler = http.FileServer(http.Dir(wi.Root))
	http.HandleFunc("/", Filefunc)
    if wi.UseAuth {
        authCJ.Init(time.Minute*30)
	    http.HandleFunc("/go_auth/", loginFunc)
    }
    if wi.UseSSL {
        go http.ListenAndServeTLS(wi.ListenOn, wi.CertFile, wi.KeyFile, nil)
    } else {
	    go http.ListenAndServe(wi.ListenOn, nil)
    }
	return nil
}

func loginFunc(w http.ResponseWriter, r *http.Request) {
    if r.Method != "POST" {
        http.Error(w, "Invalid login", http.StatusServiceUnavailable)
        return
    }
    user := r.FormValue("user")
    hash := r.FormValue("hash")
    addr, _, _ := net.SplitHostPort(r.RemoteAddr)

    fmt.Printf("Attempt to login with creds %s %s from %s\n", user, hash, addr)
    http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}

func Filefunc(w http.ResponseWriter, r *http.Request) {
    if checkAuth && !authCJ.Verify(r) {
        if r.RequestURI == "/" || r.RequestURI == "" || strings.HasSuffix("#", r.RequestURI) {
            http.Redirect(w, r, "/login/login.html", http.StatusTemporaryRedirect)
            return
        } else if !strings.HasPrefix(r.URL.Path, "/login/") {
            http.Error(w, "Access Denied", http.StatusUnauthorized)
            return
        }
    }

	if *verbose || *webDebug {
		fmt.Printf("URL REQUEST: %v\n", r.RequestURI)
	}
    if r.RequestURI == "/" || r.RequestURI == "" {
        http.Redirect(w, r, "/app/", http.StatusTemporaryRedirect)
    } else {
	    fileHandler.ServeHTTP(w, r)
    }
}

func APIfunc(w http.ResponseWriter, r *http.Request) {
    if checkAuth && !authCJ.Verify(r) {
        http.Error(w, "Access Denied", http.StatusUnauthorized)
        return
    }
	if *verbose || *webDebug {
		fmt.Printf("URL REQUEST: %v\n", r.RequestURI)
	}
	x := strings.Split(strings.TrimRight(r.RequestURI, "/"), "/")
	if len(x) != 3 {
		//throw an error, because fuck them
		http.NotFoundHandler().ServeHTTP(w, r)
		fmt.Printf("Len of args is %v\n", len(x))
		return
	}

	PerformAPIRequest(strings.Split(x[2], "?"), w, r)
}

func PerformAPIRequest(id []string, w http.ResponseWriter, r *http.Request) {
	if len(id) <= 0 {
		fmt.Fprintf(w, "You hit the API page, congrats.  But you need to speak up, and give me some GET parameters.\n")
		return
	}
	switch id[0] {
	case "stat":
		statAPIRequest(w, r)
	case "json":
		jsonflowsAPIRequest(w, r)
	default:
		fmt.Fprintf(w, "You hit the API page, congrats.  Unfortunately I don't know what the fuck you want\n")
	}
}

func statAPIRequest(w http.ResponseWriter, r *http.Request) {
	flowIDs := flowTracker.ActiveFlowIDs()
	fmt.Fprintf(w, "Currently tracking %d flows\n", len(flowIDs))
	for _, id := range flowIDs {
		fi, err := flowTracker.GetFlow(id)
		if err == nil {
			fmt.Fprintf(w, "%d: %s\n", id, fi.String())
		} else {
			fmt.Printf("Flow ID %d gave me a bad response\n", id)
		}
	}

}

func jsonflowsAPIRequest(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.NotFoundHandler().ServeHTTP(w, r)
	}
	flowIDStr := r.FormValue("flowID")
	if flowIDStr == "" {
		x := jsonflowsSendAll()
		fmt.Fprintf(w, "%s", x)
		return
	}

	flowID, err := strconv.ParseUint(flowIDStr, 10, 64)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "Invalid flowID")
		return
	}
	fi, err := flowTracker.GetFlow(flowID)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "Invalid flowID")
		return
	}
	fmt.Fprintf(w, "{%s}", fi.JSON())
}

func jsonflowsSendAll() string {
	flowIDs := flowTracker.ActiveFlowIDs()
	x := "[ "
	isFirst := true
	for _, id := range flowIDs {
		fi, err := flowTracker.GetFlow(id)
		if err == nil {
			if isFirst == true {
				x += fmt.Sprintf("{%s}", fi.JSON())
				isFirst = false
			} else {
				x += fmt.Sprintf(", {%s}", fi.JSON())
			}
		} else {
			fmt.Fprintf(os.Stderr, "Flow ID %d gave me a bad response\n", id)
		}
	}
	x+= fmt.Sprintf(" ]\n")
	return x
}

func webSocketSendError(ws io.Writer, reason, request string) {
	fmt.Fprintf(ws, "{ \"error\" : \"%s\", \"requested\" : \"%s\" }\n", reason, request)
}

func sendRegularFlows(ws *websocket.Conn, interval *uint32, die *bool) {
	for *die != true {
		time.Sleep(time.Duration(*interval) * time.Millisecond)
		x := jsonflowsSendAll()
		fmt.Fprintf(ws, "{ \"type\" : \"flowUpdate\",  \"data\": %s }", x)
	}
}

// Echo the data received on the WebSocket.
func FlowWebSocket(ws *websocket.Conn) {
    if checkAuth && !authCJ.Verify(ws.Request()) {
        ws.Close()
        return
    }
	die := false
	interval := uint32(500)
	startedRegularFlows := false

	cmd, err := getCommand(ws)
	for (cmd != "exit" && err == nil) {
		if cmd == "START_FLOW_UPDATE" {
			if !startedRegularFlows {
				go sendRegularFlows(ws, &interval, &die)
				startedRegularFlows = true
			}
		} else if strings.HasPrefix(cmd, "SET_UPDATE_INTERVAL ") {
			bits := strings.Split(cmd, " ")
			if len(bits) != 2 {
				webSocketSendError(ws, "Invalid UPDATE_INTERVAL", strings.Join(bits[1:], " "))
			} else {
				temp, err := strconv.ParseUint(bits[1], 10, 64)
				if err != nil {
				webSocketSendError(ws, "Invalid UPDATE_INTERVAL", strings.Join(bits[1:], " "))
				} else {
					interval = uint32(temp)
				}
			}
		} else if strings.HasPrefix(cmd, "GET_SINGLE_FLOW ") {
			bits := strings.Split(cmd, " ")
			if len(bits) != 2 {
				webSocketSendError(ws, "Invalid flowID", strings.Join(bits[1:], " "))
			} else {
				flowID, err := strconv.ParseUint(bits[1], 10, 64)
				if err != nil {
					webSocketSendError(ws, "Invalid flowID", bits[1])
				} else {
					fi, err := flowTracker.GetFlow(flowID)
					if err != nil {
						webSocketSendError(ws, "flowID unavailable", bits[1])
					} else {
						fmt.Fprintf(ws, "{%s}", fi.JSON())
					}
				}
			}
		} else if strings.HasPrefix(cmd, "GET_GEO_LOCATION ") {
			fmt.Printf("%s\n", cmd)
			bits := strings.Split(cmd, " ")
			if len(bits) < 3 {
				return
			}
			geoipID := bits[1]
			args := bits[2:]
			response := "[ "
			for i := range(args) {
				lat, long, err := geoip.GetLatLong(args[i])
				if err != nil {
					fmt.Printf("Failed to find %s\n", args[i])
					continue
				}
				if i > 0 {
					response += ", "
				}
				response += fmt.Sprintf("{ \"host\" : \"%s\", \"location\" : { \"lat\" : \"%f\", \"long\" : \"%f\" } }", args[i], lat, long)
			}
			response += " ]"
			fmt.Fprintf(ws, "{ \"type\" : \"geoipResponse\",  \"id\": \"%s\", \"data\": %s }", geoipID, response)
		} else {
			fmt.Fprintf(ws, "{ \"error\" : \"Invalid command\", \"sent\" : \"%s\" }", cmd)
		}
		cmd, err = getCommand(ws)
	}
	if err != nil && err.Error() != "EOF" {
		fmt.Printf("Got error: %v\n", err)
	}	
}

func getCommand(ws *websocket.Conn) (string, error) {
	var cmd []byte = make([]byte, 128)
        n, err := ws.Read(cmd)
	if err != nil {
		return "", err
	} else if n <= 0 {
		return "", errors.New("ErrFailRead")
	}

	return string(cmd[:n]), nil
}
