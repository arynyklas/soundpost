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
	shareOut(t, 0, 0)
}

// The same on a machine that is busy: the campaigns take longer than balance.settled plus the stagger, so the first
// groups are being handed over, and the members that hear no leader of the last groups elect one themselves, while
// the campaigns are still going on. "Every group led by member 1 at one moment" is not a state this ever reaches, and
// the placement does not depend on where the groups started.
func TestLeadershipIsSharedOutEvenlyWhenTheCampaignsAreSlow(t *testing.T) {
	shareOut(t, 100*time.Millisecond, 0)
}

// The same when the machine stalls for a moment once the groups are led (member 1 cut off for longer than the longest
// election timeout, which is what a process that is not scheduled for that long looks like to the others): the others
// elect leaders of their own, and the groups that member 1 gets back to are led by whoever won. Each of those elections
// is a new term, nine of them before the first group is moved, and none of them is a move.
func TestLeadershipIsSharedOutEvenlyWhenTheFirstMemberIsCutOffForAWhile(t *testing.T) {
	shareOut(t, 0, 400*time.Millisecond)
}

// transfers is how many leadership transfers the placement of the nine groups has started, on any member.
func transfers(c *asyncCluster, groups int) (sum uint64) {
	for i := range groups {
		for n := range 3 {
			if g := c.groups[n][i]; g != nil {
				sum += g.LeaderTransfers()
			}
		}
	}
	return sum
}

// shareOut starts nine groups with member 1 campaigning for each, pause apart, cuts member 1 off for cutOff once every
// group is led, and holds the placement to the preferred members, exactly, and to the transfers it takes: a group is
// handed over at most once, whoever led it (its preferred member never gives it away), and a transfer that did not
// take is tried again a few times at most. What it does not count is elections: they change terms too, as many as a
// loaded machine makes, and none of them is a move.
func shareOut(t *testing.T, pause, cutOff time.Duration) {
	t.Helper()
	quickBalance(t)
	const groups = 9
	c := newAsyncCluster(t, groups, spreadConfig)
	for i := range groups {
		if err := c.groups[0][i].Campaign(); err != nil {
			t.Fatal(err)
		}
		time.Sleep(pause)
	}
	if cutOff > 0 {
		await(t, 10*time.Second, "every group has a leader", func() bool {
			for i := range groups {
				if c.leader(i) == 0 {
					return false
				}
			}
			return true
		})
		c.wire.mu.Lock()
		c.wire.down[1] = true
		c.wire.mu.Unlock()
		time.Sleep(cutOff)
		c.wire.mu.Lock()
		c.wire.down[1] = false
		c.wire.mu.Unlock()
	}
	// Every group led by its preferred member: nine groups over three members is three each. A count of three
	// per member is not enough, it is also reached on the way, with the wrong groups.
	await(t, 30*time.Second, "every group led by its preferred member", func() bool {
		for i := range groups {
			if c.leader(i) != uint64(i%3+1) {
				return false
			}
		}
		return true
	})
	// Placed: nothing moves any more. A transfer that was repeated, or a leader that gave leadership to a member that
	// then gave it back, would show as a new term.
	terms := termSum(c, groups)
	time.Sleep(3 * time.Second)
	if now := termSum(c, groups); now != terms {
		t.Fatalf("leadership kept moving after it was placed: the terms of the groups grew by %d in 3 s", now-terms)
	}
	moves := transfers(c, groups)
	t.Logf("%d transfers placed %d groups (terms now %d)", moves, groups, terms)
	if moves == 0 {
		t.Fatal("nine groups started by one member were placed without a single leadership transfer: the count is not counting")
	}
	if moves > groups+3 {
		t.Fatalf("%d leadership transfers to place %d groups, want at most one each and 3 that did not take", moves, groups)
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
