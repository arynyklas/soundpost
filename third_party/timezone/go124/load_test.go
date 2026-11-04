// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package timezone

import (
 "crypto/sha256"
 "encoding/hex"
 "errors"
 "testing"
 "time"
)

func TestPinnedDatasetIdentityAndLocation(t *testing.T){
 // Replacing the embedded dataset without updating the locked identity must fail.
 digest:=sha256.Sum256(dataset);if hex.EncodeToString(digest[:])!=DatasetSHA256{t.Fatal("timezone data differs from declared locked identity")}
 t.Setenv("ZONEINFO","unavailable-generic-zoneinfo-fixture.zip")
 location,e:=LoadLocation("America/New_York");if e!=nil{t.Fatal(e)}
 winter:=time.Date(2026,1,1,0,0,0,0,location);summer:=time.Date(2026,7,1,0,0,0,0,location)
 _,winterOffset:=winter.Zone();_,summerOffset:=summer.Zone()
 if winterOffset!=-18000||summerOffset!=-14400{t.Fatalf("wrong explicit dataset offsets %d/%d",winterOffset,summerOffset)}
 if winter.Unix()!=1767243600||summer.Unix()!=1782878400{t.Fatalf("wrong pinned epoch values %d/%d",winter.Unix(),summer.Unix())}
}
func TestPinnedLookupNeverFallsBackToHost(t *testing.T){
 for _,name:=range []string{"Local","../UTC","/etc/localtime","Not/A_Zone"}{if _,e:=LoadLocation(name);!errors.Is(e,ErrUnknown){t.Fatalf("host fallback or wrong unknown result for %q: %v",name,e)}}
 for _,name:=range []string{"","UTC"}{location,e:=LoadLocation(name);if e!=nil||location!=time.UTC{t.Fatalf("UTC %q: %v %v",name,location,e)}}
}
