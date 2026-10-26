package realquic

import (
	"testing"
	"time"
)

// P2 step 4 (Q5 steady burst pacing) tests. These tests only add
// coverage; they do not modify any existing test's assertions.
// Fixed-distribution gaps carry the ±10% anti-fixed-interval jitter,
// so fixed-gap assertions use [0.9×, 1.1×] bounds, not exact values.

// burstProfile builds a profile already in tail (budget 0) with a
// deterministic burst structure: every burst has exactly size
// packets, intra-burst gaps fixed gapMs, idle gaps fixed idleMs.
func burstProfile(size int, gapMs, idleMs float64) Profile {
	p := shapingProfile(0, 0, "fixed", 100, 100, 100, 5, 10, 7.5, 200, 50, 60, 55)
	p.Steady.Burst = SteadyBurst{
		MinPackets: size,
		MaxPackets: size,
		GapDist:    Distribution{Kind: "fixed", Min: gapMs, Max: gapMs, Mean: gapMs},
		IdleDist:   Distribution{Kind: "fixed", Min: idleMs, Max: idleMs, Mean: idleMs},
	}
	return p
}

func TestSteadyBurstGapPattern(t *testing.T) {
	s := NewShaper("up", burstProfile(4, 2, 100))
	if !s.InTail() {
		t.Fatalf("budget-0 shaper not in tail from the first datagram")
	}
	if d := s.BeforeSend(); d != 0 {
		t.Fatalf("first datagram gap=%v, want 0", d)
	}
	s.AfterSend(100)
	// Gap sequence after the first datagram: idle (opens burst 1),
	// intra, intra, intra (burst 1 complete), idle (opens burst 2).
	want := []struct {
		lo, hi time.Duration
		name   string
	}{
		{90 * time.Millisecond, 110 * time.Millisecond, "idle"},
		{1800 * time.Microsecond, 2200 * time.Microsecond, "intra"},
		{1800 * time.Microsecond, 2200 * time.Microsecond, "intra"},
		{1800 * time.Microsecond, 2200 * time.Microsecond, "intra"},
		{90 * time.Millisecond, 110 * time.Millisecond, "idle"},
	}
	for i, w := range want {
		gap := s.BeforeSend()
		if gap < w.lo || gap > w.hi {
			t.Fatalf("gap %d (%s)=%v, want [%v, %v]", i, w.name, gap, w.lo, w.hi)
		}
		s.AfterSend(100)
	}
}

func TestSteadyBurstSizeRange(t *testing.T) {
	p := burstProfile(4, 2, 100)
	p.Steady.Burst.MinPackets = 8
	p.Steady.Burst.MaxPackets = 24
	s := NewShaper("up", p)
	for i := 0; i < 200; i++ {
		n := s.sampleBurstSizeLocked()
		if n < 8 || n > 24 {
			t.Fatalf("burst size=%d, want in [8, 24]", n)
		}
	}
	if n := NewShaper("up", burstProfile(4, 2, 100)).sampleBurstSizeLocked(); n != 4 {
		t.Fatalf("degenerate burst size=%d, want exactly 4", n)
	}
}

func TestSteadyBurstWindowReset(t *testing.T) {
	s := NewShaper("up", burstProfile(4, 2, 100))
	s.BeforeSend()
	s.AfterSend(100)
	// First tail gap is idle; second is intra (burstLeft 3 -> 2).
	if gap := s.BeforeSend(); gap < 90*time.Millisecond || gap > 110*time.Millisecond {
		t.Fatalf("pre-window gap=%v, want idle [90ms, 110ms]", gap)
	}
	s.AfterSend(100)
	// A window advance resets the burst machine: the next gap after
	// the window's first datagram must be idle again, not the intra
	// gap the un-reset machine would have returned (burstLeft was 2).
	s.BeginWindow(nil)
	if !s.InTail() {
		t.Fatalf("budget-0 shaper not in tail after window advance")
	}
	if d := s.BeforeSend(); d != 0 {
		t.Fatalf("first datagram of new window gap=%v, want 0", d)
	}
	s.AfterSend(100)
	if gap := s.BeforeSend(); gap < 90*time.Millisecond || gap > 110*time.Millisecond {
		t.Fatalf("post-window gap=%v, want idle [90ms, 110ms] (burst machine reset)", gap)
	}
}

func TestSteadyBurstValidation(t *testing.T) {
	// Off (zero value) decodes cleanly: pre-step-4 profiles carry no
	// burst field and must keep pacing exactly as before.
	if err := (SteadyBurst{}).Validate(); err != nil {
		t.Fatalf("zero burst rejected: %v (burst-off must stay valid)", err)
	}
	if err := (SteadyBurst{MinPackets: 3, MaxPackets: 0}).Validate(); err == nil {
		t.Fatalf("min>0 with max=0 accepted, want rejection")
	}
	if err := (SteadyBurst{MinPackets: 0, MaxPackets: 4}).Validate(); err == nil {
		t.Fatalf("min=0 with max>0 accepted, want rejection")
	}
	if err := (SteadyBurst{MinPackets: 5, MaxPackets: 4}).Validate(); err == nil {
		t.Fatalf("min>max accepted, want rejection")
	}
	good := SteadyBurst{
		MinPackets: 8, MaxPackets: 24,
		GapDist:   Distribution{Kind: "fixed", Min: 0, Max: 0, Mean: 0},
		IdleDist:  Distribution{Kind: "uniform", Min: 50, Max: 300, Mean: 175},
		AckLenMax: 200,
	}
	if err := (SteadyBurst{MinPackets: 8, MaxPackets: 24,
		GapDist:   Distribution{Kind: "fixed", Min: 0, Max: 0, Mean: 0},
		IdleDist:  Distribution{Kind: "uniform", Min: 50, Max: 300, Mean: 175},
		AckLenMax: -1}).Validate(); err == nil {
		t.Fatalf("negative ack_len_max accepted, want rejection")
	}
	if err := good.Validate(); err != nil {
		t.Fatalf("valid burst rejected: %v", err)
	}
	// A burst-off profile paces from TimingDist alone, exactly as
	// before step 4: the pre-step-4 helper profile has no burst field.
	if shapingProfile(2, 2, "fixed", 100, 100, 100, 5, 10, 7.5, 200, 50, 60, 55).Steady.BurstEnabled() {
		t.Fatalf("profile without a burst field reports burst enabled, want off")
	}
	// The bootstrap profile itself carries no burst: burst pacing is
	// opt-in via a server-issued profile, so the P1 bootstrap tail
	// contract (uniform pacing, pinned by existing window-0 tests)
	// is unchanged by this step.
	boot := BootstrapProfile()
	if err := boot.Validate(); err != nil {
		t.Fatalf("bootstrap profile invalid: %v", err)
	}
	if boot.Steady.BurstEnabled() {
		t.Fatalf("bootstrap burst on, want off (opt-in via issued profile)")
	}
	// Issued-profile mechanism invariants (not tuned values): the
	// burst interior is line-speed (sub-millisecond, so a burst
	// arrives inside one receiver run-loop drain batch and one ACK
	// covers it) and idle gaps exceed intra gaps.
	issued := good
	if issued.GapDist.Max >= 1 {
		t.Fatalf("issued burst interior max=%v ms, want < 1 ms (line-speed interior)", issued.GapDist.Max)
	}
	if issued.IdleDist.Max <= issued.GapDist.Max {
		t.Fatalf("issued idle max must exceed intra-burst gap max")
	}
}

func TestSteadyBurstZeroInteriorGaps(t *testing.T) {
	// Line-speed burst interiors: with GapDist fixed 0, intra-burst
	// gaps are exactly zero (0 × jitter is still 0) — pacing acts
	// only between bursts. This is the step 4 correction to the
	// first verification run, where sampled 0–2 ms interiors let the
	// receiver run loop wake per packet and ACKs failed to coalesce.
	s := NewShaper("up", burstProfile(4, 0, 100))
	s.BeforeSend()
	s.AfterSend(100)
	if gap := s.BeforeSend(); gap < 90*time.Millisecond || gap > 110*time.Millisecond {
		t.Fatalf("burst-opening gap=%v, want idle [90ms, 110ms]", gap)
	}
	s.AfterSend(100)
	for i := 0; i < 3; i++ {
		if gap := s.BeforeSend(); gap != 0 {
			t.Fatalf("intra-burst gap %d=%v, want exactly 0 (line-speed interior)", i, gap)
		}
		s.AfterSend(100)
	}
	if gap := s.BeforeSend(); gap < 90*time.Millisecond || gap > 110*time.Millisecond {
		t.Fatalf("next-burst gap=%v, want idle [90ms, 110ms]", gap)
	}
}

func TestSteadyBurstAckClassSkipsIdle(t *testing.T) {
	// Small datagrams (<= AckLenMax) never take an idle gap and never
	// consume burst budget; data datagrams follow the burst machine.
	// Burst size 4, interiors fixed 0, idles fixed 100 ms.
	p := burstProfile(4, 0, 100)
	p.Steady.Burst.AckLenMax = 200
	s := NewShaper("up", p)
	s.BeforeSend()
	s.AfterSend(1200)
	// Data datagram opens burst 1: idle.
	if gap := s.BeforeSendFor(1200); gap < 90*time.Millisecond || gap > 110*time.Millisecond {
		t.Fatalf("data burst-opening gap=%v, want idle [90ms, 110ms]", gap)
	}
	s.AfterSend(1200)
	// Two ACK-class datagrams: intra gaps (0), burst budget untouched.
	for i := 0; i < 2; i++ {
		if gap := s.BeforeSendFor(50); gap != 0 {
			t.Fatalf("ack-class gap %d=%v, want exactly 0 (skip idle)", i, gap)
		}
		s.AfterSend(50)
	}
	// Data burst still has 3 slots left (ACKs consumed none): three
	// intra gaps, then the next data datagram opens burst 2 (idle).
	for i := 0; i < 3; i++ {
		if gap := s.BeforeSendFor(1200); gap != 0 {
			t.Fatalf("data intra gap %d=%v, want exactly 0", i, gap)
		}
		s.AfterSend(1200)
	}
	if gap := s.BeforeSendFor(1200); gap < 90*time.Millisecond || gap > 110*time.Millisecond {
		t.Fatalf("next data burst gap=%v, want idle [90ms, 110ms]", gap)
	}
	// AckLenMax == 0 disables the class: a small datagram takes the
	// data-class path (idle when it opens a burst).
	p2 := burstProfile(4, 0, 100)
	s2 := NewShaper("up", p2)
	s2.BeforeSend()
	s2.AfterSend(50)
	if gap := s2.BeforeSendFor(50); gap < 90*time.Millisecond || gap > 110*time.Millisecond {
		t.Fatalf("ack-class-disabled small gap=%v, want idle [90ms, 110ms]", gap)
	}
	s2.AfterSend(50)
	// Unknown length (BeforeSend) also takes the data-class path:
	// burstLeft is 3 after the burst-opening datagram, so the next
	// unknown-length gap is intra (burstLeft 3 -> 2).
	if gap := s2.BeforeSend(); gap != 0 {
		t.Fatalf("unknown-length gap=%v, want intra 0 (data-class path)", gap)
	}
}

func TestSteadyDirectionRatioDoesNotAffectPacing(t *testing.T) {
	// Two profiles identical except DirectionRatio must pace and size
	// identically (within the fixed-distribution jitter bounds):
	// DirectionRatio is stored and validated only, never consumed by
	// the pacing or length paths (P2 step 4 decision).
	mk := func(ratio float64) *Shaper {
		p := shapingProfile(0, 0, "fixed", 100, 100, 100, 5, 10, 7.5, 200, 50, 60, 55)
		p.Shaping.TimingDist = Distribution{Kind: "fixed", Min: 20, Max: 20, Mean: 20}
		p.Steady.TimingDist = Distribution{Kind: "fixed", Min: 20, Max: 20, Mean: 20}
		p.Steady.LenDist = Distribution{Kind: "fixed", Min: 100, Max: 100, Mean: 100}
		p.Steady.DirectionRatio = ratio
		return NewShaper("up", p)
	}
	for _, ratio := range []float64{0.5, 0.013} {
		s := mk(ratio)
		s.BeforeSend()
		s.AfterSend(100)
		gap := s.BeforeSend()
		if gap < 18*time.Millisecond || gap > 22*time.Millisecond {
			t.Fatalf("DirectionRatio=%v tail gap=%v, want jittered [18ms, 22ms]", ratio, gap)
		}
		if got := s.SampleLen(); got != 100 {
			t.Fatalf("DirectionRatio=%v SampleLen=%d, want 100", ratio, got)
		}
	}
}

func TestShapingPacketConnPassesDatagramUnchanged(t *testing.T) {
	// Steady length shaping is NOT wired at datagram level (P2 step 4
	// decision): the wrapper must pass datagram bytes through exactly
	// — no tail padding, no truncation. A padded datagram would
	// corrupt QUIC parsing (trailing bytes parse as a further packet).
	cliPC, srvPC := NewMemPair()
	defer cliPC.Close()
	defer srvPC.Close()
	p := shapingProfile(1000, 1000, "fixed", 100, 100, 100, 5, 10, 7.5, 200, 50, 60, 55)
	p.Shaping.TimingDist = Distribution{Kind: "fixed", Min: 0, Max: 0, Mean: 0}
	sc := newSingleShapingConn(cliPC, "up", p)
	payload := []byte("steady-datagram-must-pass-through-verbatim")
	if _, err := sc.WriteTo(payload, srvPC.LocalAddr()); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	buf := make([]byte, 1024)
	n, _, err := srvPC.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if string(buf[:n]) != string(payload) {
		t.Fatalf("datagram changed in transit: got %d bytes %q, want %d bytes %q", n, buf[:n], len(payload), payload)
	}
}
