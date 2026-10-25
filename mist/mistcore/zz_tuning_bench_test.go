// Tuning benchmarks for the 2026-10-25 speed-tuning pass (baseline:
// Weave 1.0.40, Speedtest download 32.06 Mbps at 223ms RTT).
//
// These quantify each candidate bottleneck before any parameter is
// changed, so tuning decisions rest on numbers, not intuition:
//
//   - CheckRTO scan cost vs in-flight size (per-packet Tick calls
//     CheckRTO, so scan cost x packet rate = CPU burned on RTO scans).
//   - BBR ramp on a simulated link (time from initial window to 90%
//     of link rate; decides whether the initial window matters for
//     sustained throughput).
//   - Raw AEAD throughput (sanity: is crypto anywhere near binding?).
package mistcore

import (
	"fmt"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// BenchmarkCheckRTOInflight measures one CheckRTO call with N packets
// in flight (all freshly sent, none due, so the cost is the pure map
// scan). Production calls CheckRTO once per received packet via
// readPump's Tick, plus once per 10ms timer tick.
func BenchmarkCheckRTOInflight(b *testing.B) {
	for _, n := range []int{100, 700, 2200} {
		b.Run(fmt.Sprintf("n=%d", n), func(b *testing.B) {
			rel := NewUDPReliability(nil)
			frames := [][]byte{EncodeUDPFrame(UDPFramePing, 0, nil)}
			for i := 0; i < n; i++ {
				rel.PacketSent(uint32(i), frames, 1329)
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				rel.CheckRTO()
			}
		})
	}
}

// TestBBRRampSimulatedLink drives BBR over a simulated link (fixed
// bottleneck rate + RTT) and logs the ramp time to 90% of link rate
// and the steady-state pacing rate. It reuses the fakeClock pattern
// from TestBBRStartupExitSimulatedLink. The link serializes packets
// at the bottleneck rate; ACKs return one RTT after transmission.
func TestBBRRampSimulatedLink(t *testing.T) {
	const (
		pktSize    = 1350
		linkMbps   = 100
		rtt        = 223 * time.Millisecond
		simSeconds = 10
	)
	linkRate := float64(linkMbps) * 1e6 / 8 // bytes/sec

	clk := &fakeClock{now: time.Now()}
	ctl := NewBBRControllerWithClock(pktSize, clk)

	var pktNum uint32
	inflight := 0
	linkFree := clk.now // next time the link can finish a packet
	type pendingAck struct {
		at   time.Time
		pn   uint32
		size int
	}
	var acks []pendingAck

	rampAt := time.Duration(-1)
	var steadySum float64
	var steadyN int
	simStart := clk.now
	simEnd := simStart.Add(simSeconds * time.Second)

	// Event loop: send while cwnd allows, paced at PacingRate;
	// deliver ACKs whose time has come.
	nextSend := clk.now
	for clk.now.Before(simEnd) {
		// Deliver due ACKs first (advances BBR state).
		for len(acks) > 0 && !acks[0].at.After(clk.now) {
			a := acks[0]
			acks = acks[1:]
			inflight -= a.size
			ctl.OnPacketAcked(a.pn, a.size, inflight, rtt)
		}
		// Send one packet if cwnd + pacing allow.
		rate := ctl.PacingRate()
		if rate > 0 && inflight+pktSize <= ctl.CongestionWindow() && !clk.now.Before(nextSend) {
			// Link serialization: completion no earlier than linkFree.
			start := clk.now
			if linkFree.After(start) {
				start = linkFree
			}
			finish := start.Add(time.Duration(float64(pktSize) / linkRate * float64(time.Second)))
			linkFree = finish
			acks = append(acks, pendingAck{at: finish.Add(rtt), pn: pktNum, size: pktSize})
			ctl.OnPacketSent(pktNum, pktSize, inflight+pktSize)
			inflight += pktSize
			pktNum++
			nextSend = clk.now.Add(time.Duration(float64(pktSize) / rate * float64(time.Second)))
		}
		// Advance to the next interesting instant.
		next := nextSend
		if len(acks) > 0 && acks[0].at.Before(next) {
			next = acks[0].at
		}
		if next.After(clk.now) {
			clk.Advance(next.Sub(clk.now))
		} else {
			clk.Advance(time.Microsecond)
		}
		// Track ramp + steady state (last 5s of the simulation).
		if rampAt < 0 && rate >= 0.9*linkRate {
			rampAt = clk.now.Sub(simStart)
		}
		if clk.now.After(simEnd.Add(-5 * time.Second)) {
			steadySum += rate
			steadyN++
		}
	}
	steady := 0.0
	if steadyN > 0 {
		steady = steadySum / float64(steadyN)
	}
	t.Logf("BBR ramp: link=%.0f Mbps rtt=%v initialWindow=10pkts timeTo90%%=%v steadyPacing=%.2f Mbps (%.0f%% of link)",
		float64(linkMbps), rtt, rampAt, steady*8/1e6, steady/linkRate*100)
	if rampAt < 0 {
		t.Fatalf("BBR never reached 90%% of link rate in %ds", simSeconds)
	}
}

// BenchmarkAEADThroughput measures raw XChaCha20-Poly1305 seal/open
// rates at Mist packet size, to bound crypto's share of CPU at
// 32 Mbps and at higher rates.
func BenchmarkAEADThroughput(b *testing.B) {
	key := make([]byte, chacha20poly1305.KeySize)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		b.Fatal(err)
	}
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	plain := make([]byte, 1300)
	sealed := aead.Seal(nil, nonce, plain, nil)
	b.Run("seal", func(b *testing.B) {
		b.SetBytes(1300)
		for i := 0; i < b.N; i++ {
			_ = aead.Seal(nil, nonce, plain, nil)
		}
	})
	b.Run("open", func(b *testing.B) {
		b.SetBytes(1300)
		for i := 0; i < b.N; i++ {
			_, _ = aead.Open(nil, nonce, sealed, nil)
		}
	})
}
