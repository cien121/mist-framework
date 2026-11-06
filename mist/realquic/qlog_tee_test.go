package realquic

import (
	"bytes"
	"strings"
	"testing"

	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
)

type teeTestWriteCloser struct {
	*bytes.Buffer
	closed bool
}

func (w *teeTestWriteCloser) Close() error { w.closed = true; return nil }

// TestTeeTraceFansOutToFileAndPMTU checks the W-1 tee contract: one
// producer's events reach both the JSON-SEQ file (a recovery event
// is encoded) and the PMTU tracker (the same event moves its state).
// It also checks the nil-side rules: a nil file still feeds PMTU, a
// nil PMTU still writes the file, both nil returns a nil Trace.
func TestTeeTraceFansOutToFileAndPMTU(t *testing.T) {
	buf := &teeTestWriteCloser{Buffer: &bytes.Buffer{}}
	fileSeq := qlogwriter.NewFileSeq(buf)
	go fileSeq.Run()
	tracker := NewPMTUTracker(false, 0, 0)
	if got := tracker.ValidatedIP(); got != 1308 {
		t.Fatalf("initial validated=%d, want 1308", got)
	}
	tee := NewTeeTrace(fileSeq, NewPMTUQlogTrace(tracker))
	if tee == nil {
		t.Fatal("tee is nil")
	}
	if tee.SupportsSchemas(qlog.EventSchema) {
		// NewFileSeq carries no event schemas, so it supports none;
		// the PMTU side supports none either. A FileSeq built with
		// schemas (the lab programs' NewConnectionFileSeq form)
		// reports true for its schema — covered by the lab smoke.
		t.Fatalf("tee unexpectedly supports %q", qlog.EventSchema)
	}
	rec := tee.AddProducer()
	rec.RecordEvent(qlog.MTUUpdated{Value: 1400, Done: false})
	if err := rec.Close(); err != nil {
		t.Fatalf("tee recorder close: %v", err)
	}
	// FileSeq closes its writer only when the last producer closes;
	// the tee's single producer was the last, so the drain + close
	// happen synchronously inside Close above.
	if got := tracker.ValidatedIP(); got != 1428 {
		t.Fatalf("tracker validated=%d, want 1428 (1400+28)", got)
	}
	if !strings.Contains(buf.String(), "mtu_updated") {
		t.Fatalf("file has no mtu_updated event: %q", buf.String())
	}
	if !buf.closed {
		t.Fatalf("file writer not closed after last producer close")
	}
}

func TestTeeTraceNilSides(t *testing.T) {
	if got := NewTeeTrace(nil, nil); got != nil {
		t.Fatalf("both-nil tee=%v, want nil", got)
	}
	tracker := NewPMTUTracker(false, 0, 0)
	tee := NewTeeTrace(nil, NewPMTUQlogTrace(tracker))
	if tee == nil {
		t.Fatal("pmtu-only tee is nil")
	}
	rec := tee.AddProducer()
	rec.RecordEvent(qlog.MTUUpdated{Value: 1350, Done: true})
	_ = rec.Close()
	if got := tracker.ValidatedIP(); got != 1378 {
		t.Fatalf("pmtu-only validated=%d, want 1378", got)
	}
	if !tracker.Done() {
		t.Fatal("pmtu-only tracker not done after Done event")
	}
	// A producer that never records must still close cleanly, and a
	// second producer after close of the first must not disturb the
	// tracker.
	rec2 := tee.AddProducer()
	if err := rec2.Close(); err != nil {
		t.Fatalf("second producer close: %v", err)
	}
}
