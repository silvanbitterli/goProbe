/////////////////////////////////////////////////////////////////////////////////
//
// keyval.go
//
// Flow map primitives and their utility functions
//
// Written by Lennart Elsen lel@open.ch
//
// Copyright (c) 2016 Open Systems AG, Switzerland
// All Rights Reserved.
//
/////////////////////////////////////////////////////////////////////////////////

package goDB

import (
	"bytes"
	"fmt"
	"sort"

	"github.com/els0r/goProbe/pkg/goDB/protocols"
	"github.com/els0r/goProbe/pkg/types"
	jsoniter "github.com/json-iterator/go"
)

// Key stores the 5-tuple which defines a goProbe flow
type Key struct {
	Sip      [types.IPWidth]byte
	Dip      [types.IPWidth]byte
	Dport    [types.PortWidth]byte
	Protocol byte
}

// ExtraKey is a Key with time and interface information
type ExtraKey struct {
	Time     int64
	Hostname string
	HostID   uint
	Iface    string
	Key
}

// Val stores the goProbe flow counters
type Val struct {
	NBytesRcvd uint64 `json:"bytes_rcvd"`
	NBytesSent uint64 `json:"bytes_sent"`
	NPktsRcvd  uint64 `json:"packets_rcvd"`
	NPktsSent  uint64 `json:"packets_sent"`
}

// AggFlowMap stores all flows where the source port from the FlowLog has been aggregated
type AggFlowMap map[Key]*Val

type ListItem struct {
	Key
	*Val
}
type AggFlowList []ListItem

// ATTENTION: apart from the obvious use case, the following methods are used to provide flow information
// via syslog, so don't unnecessarily change the order of the fields.

// String prints the key as a comma separated attribute list
func (k Key) String() string {
	return fmt.Sprintf("%s,%s,%d,%s",
		types.RawIPToString(k.Sip[:]),
		types.RawIPToString(k.Dip[:]),
		int(types.PortToUint16(k.Dport)),
		protocols.GetIPProto(int(k.Protocol)),
	)
}

// MarshalJSON implements the Marshaler interface
func (k Key) MarshalJSON() ([]byte, error) {
	return jsoniter.Marshal(
		struct {
			SIP   string `json:"sip"`
			DIP   string `json:"dip"`
			Dport uint16 `json:"dport"`
			Proto string `json:"ip_protocol"`
		}{
			types.RawIPToString(k.Sip[:]),
			types.RawIPToString(k.Dip[:]),
			types.PortToUint16(k.Dport),
			protocols.GetIPProto(int(k.Protocol)),
		},
	)
}

// String prints the comma-seperated flow counters
func (v *Val) String() string {
	return fmt.Sprintf("%d,%d,%d,%d",
		v.NPktsRcvd,
		v.NPktsSent,
		v.NBytesRcvd,
		v.NBytesSent,
	)
}

// MarshalJSON implements the Marshaler interface for the whole flow map
func (a AggFlowMap) MarshalJSON() ([]byte, error) {
	var toMarshal []interface{}

	for k, v := range a {
		toMarshal = append(toMarshal,
			struct {
				Attributes Key  `json:"attributes"`
				Counters   *Val `json:"counters"`
			}{k, v},
		)
	}
	return jsoniter.Marshal(toMarshal)
}

// Flatten converts a flow map to a flat table / list
func (a AggFlowMap) Flatten() (list AggFlowList) {
	list = make(AggFlowList, 0, len(a))
	for K, V := range a {
		list = append(list, ListItem{K, V})
	}

	return
}

// Sort orders relevant flow columns so that they become more compressible
func (l AggFlowList) Sort() AggFlowList {
	sort.Slice(l, func(i, j int) bool {

		iv, jv := l[i], l[j]

		if comp := bytes.Compare(iv.Sip[:], jv.Sip[:]); comp != 0 {
			return comp < 0
		}
		if comp := bytes.Compare(iv.Dip[:], jv.Dip[:]); comp != 0 {
			return comp < 0
		}
		if comp := bytes.Compare(iv.Dport[:], jv.Dport[:]); comp != 0 {
			return comp < 0
		}
		if iv.Protocol != jv.Protocol {
			return iv.Protocol < jv.Protocol
		}

		return false
	})

	return l
}
