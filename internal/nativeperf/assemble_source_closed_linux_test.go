//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"context"
	"errors"
	"testing"
	"time"
)

// What a closed ProfileSource serves, and whose context explains its end (l4w33 mutation battery A, second pass).

// A source that was closed serves nothing more: not an item the read before the close had already queued.
func TestProfileSourceClosedServesNothingMoreEvenWhatItHadQueued(t *testing.T) {
	s := &ProfileSource{source: plainSource{}, domain: ClockDomain{HostID: "host", BootID: "boot"}, pending: []AcquisitionItem{sidebandSample(10)}}
	if item, err := s.NextItem(context.Background()); err != nil || item.Event == nil {
		t.Fatalf("the queued item of a live source: %+v %v", item, err)
	}
	s = &ProfileSource{source: plainSource{}, domain: ClockDomain{HostID: "host", BootID: "boot"}, pending: []AcquisitionItem{sidebandSample(10)}, closed: true}
	if item, err := s.NextItem(context.Background()); !errors.Is(err, ErrAcquisitionClosed) || item.Event != nil {
		t.Fatalf("the queued item of a closed source: %+v %v, want ErrAcquisitionClosed", item, err)
	}
}

// closeDuringRead closes the ProfileSource that is reading from it, then hands over an item.
type closeDuringRead struct {
	s    *ProfileSource
	item AcquisitionItem
}

func (c *closeDuringRead) Next(context.Context) (SanitizedEvent, error) {
	return SanitizedEvent{}, ErrProgressRequired
}
func (c *closeDuringRead) Close() error { return nil }
func (c *closeDuringRead) NextItem(context.Context) (AcquisitionItem, error) {
	c.s.Close()
	return c.item, nil
}

// A source that is closed while it reads does not publish what it read: it reports that it was closed.
func TestProfileSourceClosedWhileItReadsPublishesNothing(t *testing.T) {
	s := &ProfileSource{domain: ClockDomain{HostID: "host", BootID: "boot"}}
	s.source = &closeDuringRead{s: s, item: sidebandSample(10)}
	if item, err := s.NextItem(context.Background()); !errors.Is(err, ErrAcquisitionClosed) || item.Event != nil {
		t.Fatalf("%+v %v, want ErrAcquisitionClosed and no item", item, err)
	}
}

// The end of a closed source is explained by the context of the caller who is asking when that one has ended, by the
// owner's when the owner has, and is the closed error otherwise.
func TestProfileSourceClosedReportsTheContextOfTheCallerFirstThenTheOwners(t *testing.T) {
	owner, ownerStops := context.WithCancel(context.Background())
	s := &ProfileSource{source: plainSource{}, closed: true, owner: owner}
	caller, callerStops := context.WithCancel(context.Background())
	if _, err := s.NextItem(caller); !errors.Is(err, ErrAcquisitionClosed) {
		t.Fatalf("both live: %v", err)
	}
	callerStops()
	if _, err := s.NextItem(caller); !errors.Is(err, context.Canceled) {
		t.Fatalf("the caller's context ended: %v, want context.Canceled", err)
	}
	ownerStops()
	if _, err := s.NextItem(context.Background()); !errors.Is(err, context.Canceled) {
		t.Fatalf("the owner's context ended: %v, want context.Canceled", err)
	}
	// a caller whose context ended with a deadline is told so, not told what the owner's ended with
	deadline, stop := context.WithDeadline(context.Background(), time.Now().Add(-time.Hour))
	defer stop()
	if _, err := s.NextItem(deadline); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("the caller's deadline: %v, want context.DeadlineExceeded", err)
	}
}
