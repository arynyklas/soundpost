// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

// Package timezone loads only the explicitly pinned Go1.24.5 timezone dataset.
// It never consults environment variables, host files, time.Local or the network.
package timezone

import (
 "archive/zip"
 "crypto/sha256"
 "encoding/hex"
 "bytes"
 _ "embed"
 "errors"
 "io"
 "time"
)

const DatasetSHA256 = "58b3770b2c2216eaa856c18464dcac90bcb8547764e40ef660ef3b0f19cd43d0"
const maxZoneBytes = 64<<10

//go:embed zoneinfo.zip
var dataset []byte
var errDataset=errors.New("invalid pinned timezone dataset")
var datasetDigest=func()string{digest:=sha256.Sum256(dataset);return hex.EncodeToString(digest[:])}()
// DatasetDigest binds profile configuration to actual embedded bytes, not a
// declared identity constant or a possibly different external zone archive.
func DatasetDigest()string{return datasetDigest}
var ErrUnknown=errors.New("unknown pinned timezone")

type datasetIndex struct{files map[string]*zip.File;err error}
// This contains only immutable public distribution metadata, never query values
// or caller-selected locations. It is initialized once, not a tenant cache.
var index=func()datasetIndex{
 reader,e:=zip.NewReader(bytes.NewReader(dataset),int64(len(dataset)));if e!=nil{return datasetIndex{err:errDataset}}
 files:=make(map[string]*zip.File,len(reader.File))
 for _,file:=range reader.File{
  if file.UncompressedSize64>maxZoneBytes||len(file.Name)>256{return datasetIndex{err:errDataset}}
  if _,duplicate:=files[file.Name];duplicate{return datasetIndex{err:errDataset}};files[file.Name]=file
 }
 return datasetIndex{files:files}
}()

func LoadLocation(name string)(*time.Location,error){
 if name==""||name=="UTC"{return time.UTC,nil}
 // "Local" must be supplied by the caller's explicit trusted configuration;
 // silently resolving it through host time.Local would change profile identity.
 if name=="Local"{return nil,ErrUnknown}
 if index.err!=nil{return nil,index.err}
 file:=index.files[name];if file==nil{return nil,ErrUnknown}
 reader,e:=file.Open();if e!=nil{return nil,errDataset};defer reader.Close()
 data,e:=io.ReadAll(io.LimitReader(reader,maxZoneBytes+1));if e!=nil||len(data)>maxZoneBytes{return nil,errDataset}
 location,e:=time.LoadLocationFromTZData(name,data);if e!=nil{return nil,errDataset};return location,nil
}
