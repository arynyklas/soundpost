// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"testing"
	"time"
)

// quickBalance makes the placement act within a test's patience; the proportions of the production values hold.
func quickBalance(t *testing.T) {
	t.Helper()
	previous := balance
	balance = balanceParams{every: 20 * time.Millisecond, settled: 300 * time.Millisecond, healthy: 200 * time.Millisecond, cooldown: 400 * time.Millisecond, maxCooldown: 3 * time.Second, lag: 64}
	t.Cleanup(func() { balance = previous })
}

func spreadConfig(_, group int, cfg *Config) {
	cfg.LeaderSpread, cfg.LeaderSeed = true, uint64(group)
}

func leaderCounts(c *asyncCluster, groups int) (counts [4]int, all bool) {
	all = true
	for i := range groups {
		l := c.leader(i)
		if l == 0 {
			all = false
			continue
		}
		counts[l]++
	}
	return counts, all
}

func termSum(c *asyncCluster, groups int) (sum uint64) {
	for i := range groups {
		for n := range 3 {
			if g := c.groups[n][i]; g != nil {
				sum += g.Status().Term
				break
			}
		}
	}
	return sum
}

// One member is up first and campaigns for every group, and a leader keeps its leadership for as long as it is healthy:
// that member led 63 of the 65 groups of the three-node installation and its card carried what the group
// appends were for two followers. With the placement every group ends up led by its preferred member (the seed
// modulo the voters: nine groups over three members is three each), by a handful of transfers and no more.
func TestLeadershipIsSharedOutEvenlyAndStaysPut(t *testing.T) {
	quickBalance(t)
	const groups = 9
	c := newAsyncCluster(t, groups, spreadConfig)
	for i := range groups {
		if err := c.groups[0][i].Campaign(); err != nil {
			t.Fatal(err)
		}
	}
	await(t, 10*time.Second, "every group led by member 1", func() bool {
		counts, all := leaderCounts(c, groups)
		return all && counts[1] == groups
	})
	before := termSum(c, groups)
	await(t, 30*time.Second, "three groups led by each member", func() bool {
		counts, all := leaderCounts(c, groups)
		return all && counts[1] == 3 && counts[2] == 3 && counts[3] == 3
	})
	for i := range groups {
		want := uint64(i%3 + 1)
		if got := c.leader(i); got != want {
			t.Fatalf("group %d is led by member %d, its preferred leader is %d", i, got, want)
		}
	}
	// Placed: nothing moves any more. A transfer that was repeated, or a leader that gave leadership to a member that
	// then gave it back, would show as a new term.
	terms := termSum(c, groups)
	time.Sleep(3 * time.Second)
	if now := termSum(c, groups); now != terms {
		t.Fatalf("leadership kept moving after it was placed: the terms of the groups grew by %d in 3 s", now-terms)
	}
	// Six of the nine groups moved, once each, and a move is one term: a placement that oscillates or retries shows here.
	if moved := terms - before; moved > 9 {
		t.Fatalf("the groups changed term %d times to move six of them once each", moved)
	}
}

// A member that is down is not given groups, whatever it prefers, and gets them when it is back and healthy.
func TestAGroupIsNotHandedToAMemberThatIsDown(t *testing.T) {
	quickBalance(t)
	const groups = 6
	c := newAsyncCluster(t, groups, spreadConfig)
	c.stop(2) // member 3 is down from the start
	for i := range groups {
		if err := c.groups[0][i].Campaign(); err != nil {
			t.Fatal(err)
		}
	}
	await(t, 30*time.Second, "groups of members 1 and 2 on their preferred leaders", func() bool {
		for i := range groups {
			want := uint64(i%3 + 1)
			if want == 3 {
				continue
			}
			if c.leader(i) != want {
				return false
			}
		}
		return true
	})
	// The groups member 3 prefers stay with a live member for as long as it is away.
	time.Sleep(2 * time.Second)
	for i := range groups {
		if i%3 == 2 {
			if l := c.leader(i); l == 0 || l == 3 {
				t.Fatalf("group %d (preferring member 3, which is down) is led by %d", i, l)
			}
		}
	}
	terms := termSum(c, groups)
	c.start(2)
	await(t, 30*time.Second, "member 3 leads its groups once it is back", func() bool {
		for i := range groups {
			if i%3 == 2 && c.leader(i) != 3 {
				return false
			}
		}
		return true
	})
	if moved := termSum(c, groups) - terms; moved > 4 {
		t.Fatalf("the groups changed term %d times to hand member 3 its two groups", moved)
	}
}
