// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"soundpost/internal/model"
	"strconv"
)

func (c *smokeChild) ingestRaw(raw []byte, encoding, credential string) (int, []byte, error) {
	r, e := http.NewRequest("POST", c.address.URL+"/ingest/v1/batches", bytes.NewReader(raw))
	if e != nil {
		return 0, nil, e
	}
	r.Header.Set("Authorization", "Bearer "+credential)
	r.Header.Set("Content-Type", "application/json")
	if encoding != "" {
		r.Header.Set("Content-Encoding", encoding)
	}
	client := *c.client
	client.Jar = nil
	response, e := client.Do(r)
	if e != nil {
		return 0, nil, e
	}
	defer response.Body.Close()
	body, e := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	return response.StatusCode, body, e
}
func checkAtomicPrivacy(c *smokeChild, credential string, org model.ID, resource model.Resource, base model.Batch, canary string) error {
	reject := func(name string, raw []byte, encoding string, want int) error {
		status, body, e := c.ingestRaw(raw, encoding, credential)
		if e = requireSmokeResponse("privacy_"+name, status, want, body, e); e != nil {
			return e
		}
		if bytes.Contains(body, []byte(canary)) {
			return &smokeFailure{Stage: "privacy_" + name, Code: "content_leak"}
		}
		return nil
	}
	b := base
	b.ID = model.NewID()
	b.Producer = model.NewID()
	b.Records = []model.Record{{ID: model.NewID(), Kind: model.ErrorKind, ObservedAt: 1, Resource: resource, Payload: model.Payload{Error: &model.ErrorOccurrence{Occurrence: model.NewID(), Class: "TypeError", Mechanism: "manual", Build: resource.Build, Handled: true, Frames: []model.Frame{}}}}}
	b.RouteSlot, _ = model.OwnerSlot(org, b.Project, b.Source, b.Producer, b.Records[0])
	raw, _ := json.Marshal(b)
	var wire map[string]json.RawMessage
	json.Unmarshal(raw, &wire)
	var records []map[string]json.RawMessage
	json.Unmarshal(wire["records"], &records)
	var payload map[string]json.RawMessage
	json.Unmarshal(records[0]["payload"], &payload)
	value, _ := json.Marshal(canary)
	for _, field := range []string{"body", "headers", "cookies", "credentials", "prompt", "response", "sql", "locals", "heap", "objects", "message", "url"} {
		payload[field] = value
		records[0]["payload"], _ = json.Marshal(payload)
		wire["records"], _ = json.Marshal(records)
		bad, _ := json.Marshal(wire)
		if e := reject("forbidden_"+field, bad, "", 422); e != nil {
			return e
		}
		delete(payload, field)
	}
	if e := reject("duplicate_json", []byte(`{"version":1,"version":1}`), "", 422); e != nil {
		return e
	}
	if e := reject("invalid_utf8", []byte("{\"version\":1,\"extension\":\"\xff\"}"), "", 422); e != nil {
		return e
	}
	oversized := b
	oversized.ID = model.NewID()
	oversized.Records = make([]model.Record, 513)
	for i := range oversized.Records {
		oversized.Records[i] = b.Records[0]
		oversized.Records[i].ID = model.NewID()
	}
	raw, _ = json.Marshal(oversized)
	if e := reject("record_count", raw, "", 422); e != nil {
		return e
	}
	valueBits := model.FloatBits(0x3ff0000000000000)
	first := model.Record{ID: model.NewID(), Kind: model.Metric, ObservedAt: 1, Resource: resource, Payload: model.Payload{Metric: &model.MetricPoint{Name: "mixed_one", Labels: model.Labels{}, SampleKind: "float", Value: &valueBits, Type: "gauge", Unit: "1"}}}
	mixed := b
	mixed.ID = model.NewID()
	mixed.Records = []model.Record{first}
	mixed.RouteSlot, _ = model.OwnerSlot(org, b.Project, b.Source, b.Producer, first)
	found := false
	for i := range 128 {
		second := first
		second.ID = model.NewID()
		point := *first.Payload.Metric
		point.Name = "mixed_other_" + strconv.Itoa(i)
		second.Payload.Metric = &point
		slot, _ := model.OwnerSlot(org, b.Project, b.Source, b.Producer, second)
		if slot != mixed.RouteSlot {
			mixed.Records = append(mixed.Records, second)
			found = true
			break
		}
	}
	if !found {
		return errors.New("fixed slot owner routing failed")
	}
	raw, _ = json.Marshal(mixed)
	if e := reject("mixed_slot", raw, "", 422); e != nil {
		return e
	}
	foreign := b
	foreign.Project = model.NewID()
	raw, _ = json.Marshal(foreign)
	if e := reject("foreign_project", raw, "", 403); e != nil {
		return e
	}
	raw, _ = json.Marshal(b)
	raw = bytes.Replace(raw, []byte(`"observed_at_ns":"1"`), []byte(`"observed_at_ns":"9223372036854775808"`), 1)
	if e := reject("int64_overflow", raw, "", 422); e != nil {
		return e
	}
	var compressed bytes.Buffer
	z := gzip.NewWriter(&compressed)
	chunk := []byte(canary)
	for written := 0; written <= 4<<20; written += len(chunk) {
		if _, e := z.Write(chunk); e != nil {
			return e
		}
	}
	if e := z.Close(); e != nil {
		return e
	}
	return reject("gzip_expansion", compressed.Bytes(), "gzip", 413)
}
