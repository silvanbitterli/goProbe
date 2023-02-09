/////////////////////////////////////////////////////////////////////////////////
//
// db_writer.go
//
// Written by Lorenz Breidenbach lob@open.ch, January 2016
// Copyright (c) 2015 Open Systems AG, Switzerland
// All Rights Reserved.
//
/////////////////////////////////////////////////////////////////////////////////

package goDB

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/els0r/goProbe/pkg/goDB/encoder/bitpack"
	"github.com/els0r/goProbe/pkg/goDB/encoder/encoders"
	"github.com/els0r/goProbe/pkg/goDB/storage/gpfile"
	"github.com/els0r/goProbe/pkg/types/hashmap"
)

const (
	// QueryLogFile is the name of the query log written by the query package
	QueryLogFile = "query.log"
	// MetadataFileName specifies the location of the daily column metadata file
	MetadataFileName = "meta.json"
)

// DayTimestamp returns timestamp rounded down to the nearest day
func DayTimestamp(timestamp int64) int64 {
	return (timestamp / EpochDay) * EpochDay
}

// DBWriter writes goProbe flows to goDB database files
type DBWriter struct {
	dbpath string
	iface  string

	dayTimestamp int64
	encoderType  encoders.Type

	metadata *Metadata
}

// NewDBWriter initializes a new DBWriter
func NewDBWriter(dbpath string, iface string, encoderType encoders.Type) (w *DBWriter) {
	return &DBWriter{dbpath, iface, 0, encoderType, new(Metadata)}
}

func (w *DBWriter) dailyDir(timestamp int64) (path string) {
	dailyDir := strconv.FormatInt(DayTimestamp(timestamp), 10)
	path = filepath.Join(w.dbpath, w.iface, dailyDir)
	return
}

func (w *DBWriter) writeMetadata(timestamp int64, meta BlockMetadata) error {
	if w.dayTimestamp != DayTimestamp(timestamp) {
		w.metadata = nil
		w.dayTimestamp = DayTimestamp(timestamp)
	}

	path := filepath.Join(w.dailyDir(timestamp), MetadataFileName)

	if w.metadata == nil {
		w.metadata = TryReadMetadata(path)
	}

	w.metadata.Blocks = append(w.metadata.Blocks, meta)

	return WriteMetadata(path, w.metadata)
}

func (w *DBWriter) writeBlock(timestamp int64, column string, data []byte) error {
	path := filepath.Join(w.dailyDir(timestamp), column+".gpf")
	gpfile, err := gpfile.New(path, gpfile.ModeWrite, gpfile.WithEncoder(w.encoderType))
	if err != nil {
		return err
	}
	defer gpfile.Close()

	if err := gpfile.WriteBlock(timestamp, data); err != nil {
		return err
	}

	return nil
}

func (w *DBWriter) createQueryLog() error {
	var (
		err     error
		logfile *os.File
	)
	qlogPath := filepath.Join(w.dbpath, QueryLogFile)
	logfile, err = os.OpenFile(qlogPath, os.O_CREATE, 0666)
	if err != nil {
		err = fmt.Errorf("failed to create query log: %s", err)
		return err
	}
	logfile.Close()
	err = os.Chmod(qlogPath, 0666)
	if err != nil {
		err = fmt.Errorf("failed to set query log permissions: %s", err)
		return err
	}
	return nil
}

// Write takes an aggregated flow map and its metadata and writes it to disk for a given timestamp
func (w *DBWriter) Write(flowmap *hashmap.AggFlowMap, meta BlockMetadata, timestamp int64) (InterfaceSummaryUpdate, error) {
	var (
		dbdata [ColIdxCount][]byte
		update InterfaceSummaryUpdate
		err    error
	)

	err = os.MkdirAll(w.dailyDir(timestamp), 0755)
	if err != nil {
		err = fmt.Errorf("Could not create daily directory: %s", err.Error())
		return update, err
	}

	// check if the query log exists and create it if necessary
	err = w.createQueryLog()
	if err != nil {
		return update, err
	}

	dbdata, update = dbData(w.iface, timestamp, flowmap)

	for i := columnIndex(0); i < ColIdxCount; i++ {
		if err = w.writeBlock(timestamp, columnFileNames[i], dbdata[i]); err != nil {
			return update, err
		}
	}

	meta.FlowCount = update.FlowCount
	meta.Traffic = update.Traffic

	if err = w.writeMetadata(timestamp, meta); err != nil {
		return update, err
	}

	return update, err
}

func dbData(iface string, timestamp int64, aggFlowMap *hashmap.AggFlowMap) ([ColIdxCount][]byte, InterfaceSummaryUpdate) {
	var dbData [ColIdxCount][]byte
	summUpdate := new(InterfaceSummaryUpdate)

	v4List, v6List := aggFlowMap.Flatten()
	v4List = v4List.Sort()
	v6List = v6List.Sort()
	for i := columnIndex(0); i < ColIdxAttributeCount; i++ {
		columnSizeof := columnSizeofs[i]
		if columnSizeof == ipSizeOf {
			dbData[i] = make([]byte, 0, 4*len(v4List)+16*len(v6List))
		} else {
			dbData[i] = make([]byte, 0, columnSizeofs[i]*(len(v4List)+len(v6List)))
		}
	}

	summUpdate.Timestamp = time.Unix(timestamp, 0)
	summUpdate.Interface = iface

	// loop through the v4 & v6 flow maps to extract the relevant
	// values into database blocks.
	var bytesRcvd, bytesSent, pktsRcvd, pktsSent []uint64
	for _, flow := range v4List {

		summUpdate.FlowCount++
		summUpdate.Traffic += flow.NBytesRcvd
		summUpdate.Traffic += flow.NBytesSent

		// counters
		bytesRcvd = append(bytesRcvd, flow.NBytesRcvd)
		bytesSent = append(bytesSent, flow.NBytesSent)
		pktsRcvd = append(pktsRcvd, flow.NPktsRcvd)
		pktsSent = append(pktsSent, flow.NPktsSent)

		// attributes
		dbData[DportColIdx] = append(dbData[DportColIdx], flow.GetDport()...)
		dbData[ProtoColIdx] = append(dbData[ProtoColIdx], flow.GetProto())
		dbData[SipColIdx] = append(dbData[SipColIdx], flow.GetSip()...)
		dbData[DipColIdx] = append(dbData[DipColIdx], flow.GetDip()...)
	}
	for _, flow := range v6List {

		summUpdate.FlowCount++
		summUpdate.Traffic += flow.NBytesRcvd
		summUpdate.Traffic += flow.NBytesSent

		// counters
		bytesRcvd = append(bytesRcvd, flow.NBytesRcvd)
		bytesSent = append(bytesSent, flow.NBytesSent)
		pktsRcvd = append(pktsRcvd, flow.NPktsRcvd)
		pktsSent = append(pktsSent, flow.NPktsSent)

		// attributes
		dbData[DportColIdx] = append(dbData[DportColIdx], flow.GetDport()...)
		dbData[ProtoColIdx] = append(dbData[ProtoColIdx], flow.GetProto())
		dbData[SipColIdx] = append(dbData[SipColIdx], flow.GetSip()...)
		dbData[DipColIdx] = append(dbData[DipColIdx], flow.GetDip()...)
	}

	// Perform bit packing on the counter columns
	dbData[BytesRcvdColIdx] = bitpack.Pack(bytesRcvd)
	dbData[BytesSentColIdx] = bitpack.Pack(bytesSent)
	dbData[PacketsRcvdColIdx] = bitpack.Pack(pktsRcvd)
	dbData[PacketsSentColIdx] = bitpack.Pack(pktsSent)

	// TODO: Quick-shot, this information should be stored in the metadata for this directory instead !!!
	v4Len := make([]byte, 8)
	binary.BigEndian.PutUint64(v4Len, uint64(len(v4List)))
	dbData[BytesRcvdColIdx] = append(v4Len, dbData[BytesRcvdColIdx]...)

	return dbData, *summUpdate
}
