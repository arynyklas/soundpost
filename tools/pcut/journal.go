// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

// entry is the payload of one journal line.
//
//	start   the generator began (info: producers, series, endpoints)
//	issue   a batch is about to be sent for the first time (written and fsynced BEFORE the first send)
//	ack     the cluster acknowledged the batch with a receipt (written and fsynced BEFORE the writer counts it or sends the next)
//	reject  the cluster answered with something that is not retryable
//	lost    the generator stopped before the batch was acknowledged (drain limit)
//	end     the generator finished; info carries its counters
type entry struct {
	Cnt      int             `json:"cnt,omitempty"` // records in the batch: sequence numbers n..n+cnt-1, observed 1 ms apart from ts
	T        string          `json:"t"`
	At       int64           `json:"at"`
	W        string          `json:"w,omitempty"`
	N        uint64          `json:"n,omitempty"`
	ID       string          `json:"id,omitempty"`
	Rec      string          `json:"rec,omitempty"`
	Ts       int64           `json:"ts,omitempty"`
	Member   string          `json:"member,omitempty"`
	Started  int64           `json:"started,omitempty"`
	Attempts int             `json:"attempts,omitempty"`
	Receipt  json.RawMessage `json:"receipt,omitempty"`
	Detail   string          `json:"detail,omitempty"`
	Info     json.RawMessage `json:"info,omitempty"`
}

// jline is one journal line: its number, the sum of the line before it and its own sum over both and the payload. A reader
// refuses a line that was cut short, changed, dropped or swapped.
type jline struct {
	Seq  int             `json:"seq"`
	Prev string          `json:"prev"`
	Sum  string          `json:"sum"`
	Body json.RawMessage `json:"body"`
}

func chain(prev string, seq int, body []byte) string {
	h := sha256.New()
	h.Write([]byte(prev))
	h.Write([]byte{0})
	fmt.Fprintf(h, "%d", seq)
	h.Write([]byte{0})
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil))
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

type pending struct {
	body []byte
	done chan error
}

// journal appends lines durably: Append returns only after the line is on the disk (fsync). Concurrent appends share one fsync.
type journal struct {
	f    *os.File
	q    chan *pending
	fin  chan struct{}
	mu   sync.Mutex
	dead error
	seq  int
	prev string
}

func createJournal(path string) (*journal, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	if err = syncDir(filepath.Dir(path)); err != nil {
		f.Close()
		return nil, err
	}
	j := &journal{f: f, q: make(chan *pending, 4096), fin: make(chan struct{})}
	go j.loop()
	return j, nil
}

func (j *journal) loop() {
	defer close(j.fin)
	for p := range j.q {
		batch := []*pending{p}
	drain:
		for len(batch) < 1024 {
			select {
			case more, ok := <-j.q:
				if !ok {
					break drain
				}
				batch = append(batch, more)
			default:
				break drain
			}
		}
		var buf bytes.Buffer
		for _, p := range batch {
			j.seq++
			sum := chain(j.prev, j.seq, p.body)
			line, _ := json.Marshal(jline{Seq: j.seq, Prev: j.prev, Sum: sum, Body: p.body})
			j.prev = sum
			buf.Write(line)
			buf.WriteByte('\n')
		}
		_, err := j.f.Write(buf.Bytes())
		if err == nil {
			err = j.f.Sync()
		}
		if err != nil {
			j.mu.Lock()
			j.dead = err
			j.mu.Unlock()
		}
		for _, p := range batch {
			p.done <- err
		}
	}
}

// Append writes one entry and returns when it is fsynced. After a failed write or sync the journal refuses everything.
func (j *journal) Append(e entry) error {
	j.mu.Lock()
	dead := j.dead
	j.mu.Unlock()
	if dead != nil {
		return dead
	}
	body, err := json.Marshal(e)
	if err != nil {
		return err
	}
	p := &pending{body: body, done: make(chan error, 1)}
	j.q <- p
	return <-p.done
}

func (j *journal) Close() error {
	close(j.q)
	<-j.fin
	return j.f.Close()
}

// journalRead is a journal read back and checked.
type journalRead struct {
	Entries  []entry
	TornTail bool // the file ends inside a line (the generator was killed mid-write): that line is ignored
	Head     string
}

func readJournal(path string) (*journalRead, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	rd := bufio.NewReaderSize(f, 1<<20)
	out := &journalRead{}
	prev := ""
	for n := 1; ; n++ {
		line, err := rd.ReadBytes('\n')
		if errors.Is(err, io.EOF) {
			if len(line) > 0 {
				out.TornTail = true
			}
			break
		}
		if err != nil {
			return nil, err
		}
		var jl jline
		if err = json.Unmarshal(line, &jl); err != nil {
			return nil, fmt.Errorf("journal line %d is not a journal line", n)
		}
		if jl.Seq != n || jl.Prev != prev || jl.Sum != chain(prev, n, jl.Body) {
			return nil, fmt.Errorf("journal line %d breaks the chain (cut, changed, dropped or swapped)", n)
		}
		var e entry
		if err = json.Unmarshal(jl.Body, &e); err != nil {
			return nil, fmt.Errorf("journal line %d has an undecodable entry", n)
		}
		out.Entries = append(out.Entries, e)
		prev = jl.Sum
	}
	out.Head = prev
	return out, nil
}
