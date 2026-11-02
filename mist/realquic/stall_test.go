package realquic

import (
	"testing"
	"time"
)

// fakeClock is a manually advanced clock for detector tests.
type fakeClock struct {
	now time.Time
}

func (c *fakeClock) Now() time.Time { return c.now }

func (c *fakeClock) Advance(d time.Duration) { c.now = c.now.Add(d) }

func TestStallDetectorTripsAfterTimeout(t *testing.T) {
	clk := &fakeClock{now: time.Unix(1000, 0)}
	d := NewStallDetector(8*time.Second, clk.Now)
	d.Start()
	if d.Stalled() {
		t.Fatal("stalled immediately after Start")
	}
	clk.Advance(7*time.Second + 999*time.Millisecond)
	if d.Stalled() {
		t.Fatal("stalled before timeout")
	}
	clk.Advance(time.Millisecond)
	if !d.Stalled() {
		t.Fatal("not stalled at exactly timeout")
	}
}

func TestStallDetectorProgressResetsTimer(t *testing.T) {
	clk := &fakeClock{now: time.Unix(1000, 0)}
	d := NewStallDetector(5*time.Second, clk.Now)
	d.Start()
	clk.Advance(4 * time.Second)
	d.Report(1024)
	clk.Advance(4 * time.Second)
	if d.Stalled() {
		t.Fatal("progress at 4s should have reset the 5s window")
	}
	clk.Advance(time.Second)
	if !d.Stalled() {
		t.Fatal("no progress for 5s after last report should stall")
	}
	if got := d.Total(); got != 1024 {
		t.Fatalf("total=%d, want 1024", got)
	}
}

func TestStallDetectorZeroBytesDoNotReset(t *testing.T) {
	clk := &fakeClock{now: time.Unix(1000, 0)}
	d := NewStallDetector(5*time.Second, clk.Now)
	d.Start()
	clk.Advance(4 * time.Second)
	d.Report(0)
	d.Report(-7)
	clk.Advance(2 * time.Second)
	if !d.Stalled() {
		t.Fatal("zero/negative reports must not reset the stall timer")
	}
}

func TestStallDetectorUnstartedNeverStalls(t *testing.T) {
	clk := &fakeClock{now: time.Unix(1000, 0)}
	d := NewStallDetector(time.Second, clk.Now)
	clk.Advance(time.Hour)
	if d.Stalled() {
		t.Fatal("unstarted detector must never report stalled")
	}
	if got := d.Idle(); got != 0 {
		t.Fatalf("unstarted idle=%v, want 0", got)
	}
}

func TestStallDetectorNonPositiveTimeoutNeverStalls(t *testing.T) {
	clk := &fakeClock{now: time.Unix(1000, 0)}
	d := NewStallDetector(0, clk.Now)
	d.Start()
	clk.Advance(time.Hour)
	if d.Stalled() {
		t.Fatal("non-positive timeout must fail safe to never-stalled")
	}
}

func TestStallDetectorResetRearms(t *testing.T) {
	clk := &fakeClock{now: time.Unix(1000, 0)}
	d := NewStallDetector(5*time.Second, clk.Now)
	d.Start()
	d.Report(512)
	clk.Advance(10 * time.Second)
	if !d.Stalled() {
		t.Fatal("should stall before reset")
	}
	d.Reset()
	if d.Stalled() {
		t.Fatal("reset must clear the stall")
	}
	if got := d.Total(); got != 0 {
		t.Fatalf("reset total=%d, want 0", got)
	}
	clk.Advance(5 * time.Second)
	if !d.Stalled() {
		t.Fatal("should stall again one timeout after reset with no progress")
	}
}

func TestStallDetectorIdle(t *testing.T) {
	clk := &fakeClock{now: time.Unix(1000, 0)}
	d := NewStallDetector(time.Minute, clk.Now)
	d.Start()
	clk.Advance(3 * time.Second)
	if got := d.Idle(); got != 3*time.Second {
		t.Fatalf("idle=%v, want 3s", got)
	}
}

func TestReconnectPolicyDelayAndCap(t *testing.T) {
	p := ReconnectPolicy{}
	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 8 * time.Second}
	for i, w := range want {
		if got := p.Delay(i); got != w {
			t.Fatalf("delay(%d)=%v, want %v", i, got, w)
		}
	}
	if p.Delay(-1) != time.Second {
		t.Fatalf("negative attempt delay=%v, want 1s", p.Delay(-1))
	}
	for _, n := range []int{0, 1, 2} {
		if p.Exhausted(n) {
			t.Fatalf("exhausted(%d) with default cap 3", n)
		}
	}
	if !p.Exhausted(3) {
		t.Fatal("exhausted(3) with default cap 3")
	}
	custom := ReconnectPolicy{MaxReconnects: 1, BaseDelay: 500 * time.Millisecond, MaxDelay: time.Second}
	if got := custom.Delay(0); got != 500*time.Millisecond {
		t.Fatalf("custom delay(0)=%v", got)
	}
	if got := custom.Delay(5); got != time.Second {
		t.Fatalf("custom delay capped=%v, want 1s", got)
	}
	if !custom.Exhausted(1) {
		t.Fatal("custom cap 1 should exhaust at 1")
	}
}
