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
    "net"
    "time"
    "net/http"
)

var (
    
)

type AuthData struct {
    Username string
    Admin bool
    RemoteAddr net.IP
    Expires time.Time
}

type AuthCookieJar struct {
    auths map[string]AuthData
    timeout time.Duration
    expireCookieLoopRunning bool
    expireCookieLoopDie bool
}

func tester() {
    return
}

func (cj *AuthCookieJar) Init(timeout time.Duration) error {
    cj.timeout = timeout
    if cj.expireCookieLoopRunning == true {
        return nil
    }
    cj.expireCookieLoopDie = false
    go cj.expireCookieLoop()

    return nil
}

func (cj *AuthCookieJar) Close(timeout time.Duration) error {
    cj.expireCookieLoopDie = true
    return nil
}

func (cj *AuthCookieJar) AddNew(cookie string, auth AuthData) error {
    return nil
}

func (cj *AuthCookieJar) Verify(req *http.Request) bool {
    cookie, err := req.Cookie("mimir_auth")
    if err != nil {
        return false
    }
    ip, _, err := net.SplitHostPort(req.RemoteAddr)
    if err != nil {
        return false
    }
    a, ok := cj.auths[cookie.Value]
    if !ok {
        return false
    } else if a.RemoteAddr.String() != ip {
        return false
    } else if time.Now().After(a.Expires) {
        return false
    }
    a.Expires = time.Now().Add(cj.timeout)
    return true
}

func (cj *AuthCookieJar) expireCookies() {
    return
}

func (cj *AuthCookieJar) expireCookieLoop() {
    cj.expireCookieLoopRunning = true
    for cj.expireCookieLoopDie == false {
        time.Sleep(cj.timeout)
        cj.expireCookies()
    }
}
