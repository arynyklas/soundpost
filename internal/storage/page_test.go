// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"github.com/arynyklas/soundpost/internal/model"
	"reflect"
	"testing"
)

func TestTypedPageUsesPayloadArenaInsteadOfPerRowObjects(t *testing.T) {
	resource := model.Resource{Service: model.NewID(), Environment: model.NewID(), Build: model.NewID(), Instance: "test", Labels: model.Labels{}}
	rows := make([]model.Record, pageRows)
	for i := range rows {
		rows[i] = model.Record{ID: model.NewID(), Kind: model.Metric, ObservedAt: model.UnixNano(i), Resource: resource, Payload: model.Payload{Metric: &model.MetricPoint{Name: "requests", Labels: model.Labels{{Name: "zone", Value: "a"}}, SampleKind: "float", Value: ptrBits(0x8000000000000000), Unit: "1", Type: "gauge"}}}
	}
	page := recordsPage(rows, model.NewID(), model.NewID(), model.Cursor{Group: model.NewID(), Index: 1})
	data, err := encodePage(page)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodePage(data)
	if err != nil {
		t.Fatal(err)
	}
	base := reflect.ValueOf(decoded.Values[0].Metric).Pointer()
	size := reflect.TypeOf(model.MetricPoint{}).Size()
	for i := range decoded.Values {
		if reflect.ValueOf(decoded.Values[i].Metric).Pointer() != base+uintptr(i)*size {
			t.Fatal("metric allocated as an individual row object", i)
		}
		if uint64(*decoded.Values[i].Metric.Value) != 0x8000000000000000 {
			t.Fatal("signed zero lost")
		}
	}
	if !reflect.DeepEqual(decoded.Values, page.Values) {
		t.Fatal("arena changed native values")
	}
}
func TestPageChecksumAndUnknownColumnVersionReject(t *testing.T) {
	resource := model.Resource{Service: model.NewID(), Environment: model.NewID(), Build: model.NewID()}
	row := model.Record{ID: model.NewID(), Kind: model.Metric, ObservedAt: -1, Resource: resource, Payload: model.Payload{Metric: &model.MetricPoint{Name: "n", Value: ptrBits(0x7ff8000000000001)}}}
	page := recordsPage([]model.Record{row}, model.NewID(), model.NewID(), model.Cursor{Group: model.NewID(), Index: 1})
	data, err := encodePage(page)
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)-1] ^= 1
	if _, err = decodePage(data); err == nil {
		t.Fatal("corrupt checksum accepted")
	}
	data[len(data)-1] ^= 1
	data[5] = 2
	if _, err = decodePage(data); err == nil {
		t.Fatal("unknown page version accepted")
	}
}
