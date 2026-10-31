// Stage B (B5, REALQUIC-DESIGN-v3 §3.4): burst packet counts must NOT
// be carried over automatically once datagram sizes grow.
//
// §3.4 states the fact these tests pin: "Burst 以包数定义：同包数突发
// 在包变大后承载更多字节、占用拥塞窗口更多。尺寸上线后，突发包数
// 参数必须重新验证（不是自动沿用）". The tests are designed to FAIL
// if anyone assumes byte occupancy is unchanged: every key assertion
// is an inequality or a fit-flip between the old size (1308B, the
// pre-Stage-B ceiling) and the new size (1452B, the quic-go stack
// limit in UDP payload bytes), never an equality that a
// size-blind model would also satisfy.
//
// What these tests deliberately do NOT do: they do not set new burst
// numbers. Burst numerics stay PROVISIONAL (D2 step 5); the tests
// prove the old numbers cannot be assumed valid and show HOW a
// corrected count is derived (floor of byte budget / packet size),
// but locking a corrected count needs a real-network byte budget
// that loopback cannot supply. See the B5 conclusion in the Stage B
// report.
package realquic

import (
	"testing"
	"time"
)

// driveBurst sends packets datagrams of length pktSize through a
// fresh fixed-8 burst shaper and returns the pacing gaps it took and
// the total bytes the shaper's own event log recorded for them.
func driveBurst(t *testing.T, packets, pktSize int) ([]time.Duration, int) {
	t.Helper()
	s := NewShaper("up", burstProfile(packets, 0, 100))
	var gaps []time.Duration
	for i := 0; i < packets; i++ {
		gaps = append(gaps, s.BeforeSendFor(pktSize))
		s.AfterSend(pktSize)
	}
	total := 0
	for _, ev := range s.Events() {
		total += ev.Len
	}
	if got := s.SentInWindow(); got != packets {
		t.Fatalf("burst of %d x %dB: shaper counted %d datagrams, want %d", packets, pktSize, got, packets)
	}
	return gaps, total
}

func TestBurstSamePacketCountCarriesMoreBytes(t *testing.T) {
	const oldSize = 1308 // pre-Stage-B ceiling, UDP payload bytes
	const newSize = 1452 // quic-go stack limit, UDP payload bytes
	const packets = 8    // issued burst minimum (PROVISIONAL number, used as the carried-over value under test)

	oldGaps, oldBytes := driveBurst(t, packets, oldSize)
	newGaps, newBytes := driveBurst(t, packets, newSize)

	// The packet machine is size-blind: both runs take the same gap
	// STRUCTURE (first datagram 0, exactly one idle gap opening the
	// burst, the rest line-speed intra gaps). The idle value itself
	// is CSPRNG-sampled from a fixed 100ms distribution (±10%
	// jitter), so the two runs' idle values legitimately differ and
	// are compared as a range, not for equality. A test that only
	// watched gap structure would conclude "nothing changed" —
	// which is exactly the wrong conclusion §3.4 warns against.
	for _, gaps := range [][]time.Duration{oldGaps, newGaps} {
		if len(gaps) != packets {
			t.Fatalf("gap count=%d, want %d", len(gaps), packets)
		}
		idle := 0
		for i, g := range gaps {
			if i == 0 {
				if g != 0 {
					t.Fatalf("first gap=%v, want 0", g)
				}
				continue
			}
			if g >= 90*time.Millisecond && g <= 110*time.Millisecond {
				idle++
			} else if g != 0 {
				t.Fatalf("gap %d=%v, want idle [90ms,110ms] or intra 0", i, g)
			}
		}
		if idle != 1 {
			t.Fatalf("idle gaps=%d, want exactly 1 per %d-packet burst", idle, packets)
		}
	}
	// ...but the bytes are not identical. This inequality is the
	// test's core: any model that assumes "same burst = same window
	// occupancy" fails here.
	if newBytes == oldBytes {
		t.Fatalf("burst bytes unchanged at %d, want growth with packet size (assumption under test)", oldBytes)
	}
	if want := packets * oldSize; oldBytes != want {
		t.Fatalf("old burst bytes=%d, want %d x %d = %d", oldBytes, packets, oldSize, want)
	}
	if want := packets * newSize; newBytes != want {
		t.Fatalf("new burst bytes=%d, want %d x %d = %d", newBytes, packets, newSize, want)
	}
	if diff := newBytes - oldBytes; diff != packets*(newSize-oldSize) {
		t.Fatalf("burst byte growth=%d, want %d x %d = %d", diff, packets, newSize-oldSize, packets*(newSize-oldSize))
	}
	// Window-fit flip: a byte budget that held the old burst no
	// longer holds the new one. 11000 sits strictly between the two
	// totals (10464 < 11000 < 11616), so the flip is not a rounding
	// artefact.
	const windowBytes = 11000
	if oldBytes > windowBytes {
		t.Fatalf("old burst %d exceeds window %d, want fit (test setup)", oldBytes, windowBytes)
	}
	if newBytes <= windowBytes {
		t.Fatalf("new burst %d still fits window %d, want overrun (old count not carriable)", newBytes, windowBytes)
	}
	// The corrected count for the same byte budget is strictly
	// smaller: floor(11000/1452) = 7, not the carried-over 8. This
	// is the derivation rule a re-validation must apply — it is
	// asserted as a rule, not as a new locked parameter.
	if corrected := windowBytes / newSize; corrected != 7 || corrected >= packets {
		t.Fatalf("re-derived burst count=%d, want 7 < carried-over %d", corrected, packets)
	}
}

func TestBurstMaxPacketCountOverrunsOldByteBudget(t *testing.T) {
	// The same flip at the issued burst maximum (24 packets,
	// PROVISIONAL): the old max burst (24 x 1308 = 31392B) fits a
	// 32000B budget, the new max burst (24 x 1452 = 34848B) does
	// not. Carrying the [8, 24] range over unchanged therefore
	// overruns any byte budget calibrated at the old size, at the
	// top of the range even when the bottom still fits.
	const oldSize, newSize, maxPackets = 1308, 1452, 24
	const windowBytes = 32000
	oldBytes, newBytes := maxPackets*oldSize, maxPackets*newSize
	if oldBytes != 31392 || newBytes != 34848 {
		t.Fatalf("max burst bytes old=%d new=%d, want 31392/34848", oldBytes, newBytes)
	}
	if oldBytes > windowBytes {
		t.Fatalf("old max burst %d exceeds window %d (test setup)", oldBytes, windowBytes)
	}
	if newBytes <= windowBytes {
		t.Fatalf("new max burst %d still fits window %d, want overrun", newBytes, windowBytes)
	}
	if corrected := windowBytes / newSize; corrected >= maxPackets {
		t.Fatalf("re-derived max count=%d, want < carried-over %d", corrected, maxPackets)
	}
}

func TestBurstPacketsPerMBDropWithSize(t *testing.T) {
	// The §3.4 packet-count view of the same fact: per megabyte, the
	// packet count drops about 10% when the payload grows from 1308
	// to 1452 (floor division, same 10^6-byte MB as the design note).
	oldPerMB := 1000000 / 1308
	newPerMB := 1000000 / 1452
	if oldPerMB != 764 || newPerMB != 688 {
		t.Fatalf("packets/MB old=%d new=%d, want 764/688", oldPerMB, newPerMB)
	}
	if newPerMB >= oldPerMB {
		t.Fatalf("packets/MB did not drop with larger packets: %d -> %d", oldPerMB, newPerMB)
	}
	// The drop must be material (~10%), not a rounding wobble: a
	// model that treats the packet rate as size-independent would
	// miss roughly a tenth of the per-MB packet (and ACK) load.
	if dropPct := float64(oldPerMB-newPerMB) / float64(oldPerMB) * 100; dropPct < 9 || dropPct > 11 {
		t.Fatalf("packets/MB drop=%.1f%%, want ~10%%", dropPct)
	}
}
