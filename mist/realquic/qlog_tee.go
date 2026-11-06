package realquic

import (
	"github.com/quic-go/quic-go/qlogwriter"
)

// Lab-only qlog tee trace (Stage C wiring, W-1).
//
// A lab harness often needs ONE connection's qlog events in two
// places at once: a JSON-SEQ file (the full client/server qlog) and
// a PMTU tracker (which consumes only recovery:mtu_updated and
// parameters_set and produces no JSON — see pmtu.go). quic-go's
// Config.Tracer hands a connection exactly one Trace, so the tee is
// that one Trace: every producer quic-go (or http3) asks for fans
// its events out to both sides.
//
// Lifecycle notes, learned from quic-go v0.64.1's FileSeq:
//
//   - A FileSeq only drains its event channel while its Run method
//     runs in a goroutine; the harness that creates the FileSeq must
//     start `go fileSeq.Run()` itself — the tee cannot do it, because
//     it only sees the Trace interface, not the FileSeq. Without Run,
//     RecordEvent blocks once the 50-event channel fills.
//   - Closing a tee recorder closes both sides' recorders. A
//     FileSeq closes its file only when its LAST producer closes;
//     http3's producers are not closed on connection teardown, so a
//     qlog file's content is complete (events are encoded eagerly)
//     even though the FileSeq itself may never formally close before
//     process exit. That is a quic-go lifecycle property, not a tee
//     bug: do not "fix" it by closing the file early.
//   - SupportsSchemas reports the file side's answer (falling back
//     to the PMTU side when there is no file): http3 gates its own
//     qlog on this, and the PMTU side's answer is always false
//     (it consumes events, it does not produce qlog JSON).
//
// This is a LAB instrument only. Production must not depend on
// parsing qlog for runtime decisions (see pmtu.go header), and the
// tee must never be wired into a production dial or listen path.

// NewTeeTrace returns a Trace fanning every recorded event out to
// both file and pmtu. Either side may be nil (single-side tee); both
// nil returns nil (no trace), so a harness can pass the result
// straight into a Tracer without a nil-trace special case. The
// returned Trace is safe for concurrent use by the stack's producers.
func NewTeeTrace(file, pmtu qlogwriter.Trace) qlogwriter.Trace {
	if file == nil && pmtu == nil {
		return nil
	}
	return &teeTrace{file: file, pmtu: pmtu}
}

type teeTrace struct {
	file qlogwriter.Trace
	pmtu qlogwriter.Trace
}

// AddProducer returns a Recorder writing every event to both sides'
// recorders (each side's AddProducer is called fresh per producer,
// so quic-go's per-component producer accounting stays correct on
// both sides).
func (t *teeTrace) AddProducer() qlogwriter.Recorder {
	var recs []qlogwriter.Recorder
	if t.file != nil {
		if r := t.file.AddProducer(); r != nil {
			recs = append(recs, r)
		}
	}
	if t.pmtu != nil {
		if r := t.pmtu.AddProducer(); r != nil {
			recs = append(recs, r)
		}
	}
	return &teeRecorder{recs: recs}
}

func (t *teeTrace) SupportsSchemas(schema string) bool {
	if t.file != nil && t.file.SupportsSchemas(schema) {
		return true
	}
	if t.pmtu != nil && t.pmtu.SupportsSchemas(schema) {
		return true
	}
	return false
}

type teeRecorder struct {
	recs []qlogwriter.Recorder
}

func (r *teeRecorder) RecordEvent(ev qlogwriter.Event) {
	for _, rec := range r.recs {
		rec.RecordEvent(ev)
	}
}

// Close closes both sides' recorders and reports the first error, if
// any. Closing is idempotent only as far as the sides allow: the
// stack calls each producer's Close exactly once, and the tee does
// not add its own bookkeeping on top.
func (r *teeRecorder) Close() error {
	var first error
	for _, rec := range r.recs {
		if err := rec.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}
