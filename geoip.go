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

/* 
 * Original author: Stiletto <blasux@blasux.ru>
 *
 * This program is free software. It comes without any warranty, to
 * the extent permitted by applicable law. You can redistribute it
 * and/or modify it under the terms of the Do What The Fuck You Want
 * To Public License, Version 2, as published by Sam Hocevar. See
 * http://sam.zoy.org/wtfpl/COPYING for more details. */

package main

/*
#cgo LDFLAGS: -lGeoIP
#include <stdio.h>
#include <errno.h>
#include <GeoIP.h>
#include <GeoIPCity.h>

//typedef GeoIP* GeoIP_pnt
*/
import "C"
import (
	"errors"
	"unsafe"
)

type GeoIP struct {
	gi *C.GeoIP
}

func BuildGeoIP(base string, cacheSize uint16) *GeoIP {
	cbase := C.CString(base)
	gi := C.GeoIP_open(cbase, C.GEOIP_INDEX_CACHE|C.GEOIP_CHECK_CACHE)
	C.free(unsafe.Pointer(cbase))
	if gi == nil {
		return nil
	}
	return &GeoIP{gi}
}

func (gi *GeoIP) fullLookupGetLatLong(ip string) (float64, float64, error) {
	if gi == nil {
		return 0.0, 0.0, errors.New("GeoIP not initialized")
	}
	cip := C.CString(ip)
	record := C.GeoIP_record_by_name(gi.gi, cip)
	C.free(unsafe.Pointer(cip))

	if record != nil {
		var lat, long float64
		lat = float64(record.latitude)
		long = float64(record.longitude)
		C.free(unsafe.Pointer(record))
		return lat, long, nil
	}
	return 0.0, 0.0, errors.New("No Record")
}

// eventually we may want to build some sort of caching system
// so we aren't constantly hitting the full DB
func (gi *GeoIP) GetLatLong(ip string) (float64, float64, error) {
	return gi.fullLookupGetLatLong(ip)
}
