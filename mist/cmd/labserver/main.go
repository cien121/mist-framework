// Command labserver is the pilot-only real-QUIC lab server for Stage 3
// pilot Tier 1. It wraps mist/realquic.NewServer with rotation disabled
// (single cycle, PLAN D4) and serves one UDP PacketConn. The pilot key
// comes only from the MIST_KEY environment variable (hex of 32 bytes);
// it is never written to code, logs, reports, or the command line.
//
// Stage C wiring (W-1) observability, all lab-only and off by flag:
//
//	-qlog-dir: one qlog JSON-SEQ file per accepted connection, named
//	  <connID>_<sanitized-peer>.sqlog (connID is the QUIC Original
//	  Destination Connection ID quic-go passes to the trace factory;
//	  the peer address comes from the same factory via
//	  ServerConfig.TraceFactory, because quic-go's plain Tracer
//	  callback receives no peer address).
//	-events-out: at shutdown, Server.DownEventsByAddr as JSON (peer
//	  address string -> down-direction send events).
//	-pmtu-out: at shutdown, one PMTU report per peer address as JSON
//	  (target_ip, stack_enforced_target_ip, validated_ip,
//	  peer_cap_ip, peer_cap_known, pmtu_done, ceiling_ip).
//
// Every accepted connection gets its own PMTU tracker (family from
// the peer address) whether or not -qlog-dir is set, fed by the same
// tee trace that feeds the qlog file when one is requested. The
// tracker is observation only: it never influences handshake,
// routing, or shaping. No key material or profile parameter value is
// ever written to any of these files: PMTU integers are stack
// observations, event lengths are datagram sizes.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
	"mist/realquic"
)

// buildCommit is injected at build time with -ldflags -X main.buildCommit.
var buildCommit = "dev"

// decodeKey decodes the MIST_KEY environment value: 64 hex chars = 32 bytes.
func decodeKey(env string) ([]byte, error) {
	if env == "" {
		return nil, fmt.Errorf("MIST_KEY is not set")
	}
	key, err := hex.DecodeString(env)
	if err != nil {
		return nil, fmt.Errorf("MIST_KEY is not hex: %v", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("MIST_KEY decodes to %d bytes, want 32", len(key))
	}
	return key, nil
}

// profileHash12 returns the first 12 hex chars of the SHA-256 of the
// profile encoding. Profile parameter values are never logged.
func profileHash12(p realquic.Profile) string {
	enc, err := realquic.EncodeProfile(p)
	if err != nil {
		return "encode-error"
	}
	sum := sha256.Sum256(enc)
	return hex.EncodeToString(sum[:])[:12]
}

// isIPv6Addr reports whether addr's IP is IPv6 (an IPv4-mapped or
// unparsable address counts as IPv4, matching the tracker's family
// rule: only a genuine IPv6 peer gets the 48-byte header mapping).
func isIPv6Addr(addr net.Addr) bool {
	if addr == nil {
		return false
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		host = addr.String()
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil {
		return false
	}
	return ip.To4() == nil
}

// sanitizePeer renders a peer address string safe for a file name:
// colons (IPv6/port separators) and slashes become underscores,
// brackets are dropped. Dots and digits pass through unchanged, so
// 127.0.0.1:54321 stays human-readable.
func sanitizePeer(peer string) string {
	r := strings.NewReplacer(":", "_", "/", "_", "[", "", "]", "")
	return r.Replace(peer)
}

// connObs is one accepted connection's W-1 observation state: its
// PMTU tracker (created in the trace factory, before the handshake)
// and the qlog file path (empty when -qlog-dir is unset).
type connObs struct {
	peer    string
	tracker *realquic.PMTUTracker
	qlog    string
}

// pmtuReport is the -pmtu-out record for one peer address. Field
// names are the Stage C contract; peer_cap_ip is 0 when
// peer_cap_known is false (no handshake parameters_set observed).
type pmtuReport struct {
	TargetIP              int  `json:"target_ip"`
	StackEnforcedTargetIP int  `json:"stack_enforced_target_ip"`
	ValidatedIP           int  `json:"validated_ip"`
	PeerCapIP             int  `json:"peer_cap_ip"`
	PeerCapKnown          bool `json:"peer_cap_known"`
	PMTUDone              bool `json:"pmtu_done"`
	CeilingIP             int  `json:"ceiling_ip"`
}

func pmtuReportFrom(t *realquic.PMTUTracker) pmtuReport {
	capIP, known := t.PeerCapIP()
	return pmtuReport{
		TargetIP:              t.TargetIP(),
		StackEnforcedTargetIP: t.StackEnforcedTargetIP(),
		ValidatedIP:           t.ValidatedIP(),
		PeerCapIP:             capIP,
		PeerCapKnown:          known,
		PMTUDone:              t.Done(),
		CeilingIP:             t.CeilingIP(),
	}
}

func main() {
	listen := flag.String("listen", "10.200.1.2:24443", "UDP listen address (pilot lab address; never 8443/443/1443)")
	qlogDir := flag.String("qlog-dir", "", "directory for one qlog file per connection (empty: no qlog files)")
	eventsOut := flag.String("events-out", "", "path for DownEventsByAddr JSON at shutdown (empty: not written)")
	pmtuOut := flag.String("pmtu-out", "", "path for per-address PMTU JSON at shutdown (empty: not written)")
	flag.Parse()
	key, err := decodeKey(os.Getenv("MIST_KEY"))
	if err != nil {
		log.Fatalf("labserver: %v", err)
	}
	if *qlogDir != "" {
		if err := os.MkdirAll(*qlogDir, 0o755); err != nil {
			log.Fatalf("labserver: create qlog dir: %v", err)
		}
	}
	var obsMu sync.Mutex
	var obs []*connObs
	traceFactory := func(_ context.Context, connID quic.ConnectionID, peer net.Addr) qlogwriter.Trace {
		peerStr := ""
		if peer != nil {
			peerStr = peer.String()
		}
		tracker := realquic.NewPMTUTracker(isIPv6Addr(peer), 0, 0)
		var fileSeq *qlogwriter.FileSeq
		qlogPath := ""
		if *qlogDir != "" {
			qlogPath = filepath.Join(*qlogDir, fmt.Sprintf("%s_%s.sqlog", connID.String(), sanitizePeer(peerStr)))
			f, ferr := os.Create(qlogPath)
			if ferr != nil {
				log.Printf("labserver: create qlog %s: %v (continuing PMTU-only)", qlogPath, ferr)
				qlogPath = ""
			} else {
				fileSeq = qlogwriter.NewConnectionFileSeq(f, false, connID, []string{qlog.EventSchema})
				go fileSeq.Run()
			}
		}
		obsMu.Lock()
		obs = append(obs, &connObs{peer: peerStr, tracker: tracker, qlog: qlogPath})
		obsMu.Unlock()
		if fileSeq == nil {
			return realquic.NewTeeTrace(nil, realquic.NewPMTUQlogTrace(tracker))
		}
		return realquic.NewTeeTrace(fileSeq, realquic.NewPMTUQlogTrace(tracker))
	}
	srv, err := realquic.NewServer(realquic.ServerConfig{Key: key, RotationMin: 0, TraceFactory: traceFactory})
	if err != nil {
		log.Fatalf("labserver: new server: %v", err)
	}
	issued := srv.IssuedProfile()
	log.Printf("labserver buildCommit=%s listen=%s issuedProfileVersion=%d issuedProfileHash=%s rotation=off qlog-dir=%s events-out=%s pmtu-out=%s",
		buildCommit, *listen, issued.Version, profileHash12(issued), *qlogDir, *eventsOut, *pmtuOut)
	pc, err := net.ListenUDP("udp", mustUDPAddr(*listen))
	if err != nil {
		log.Fatalf("labserver: listen: %v", err)
	}
	writeOutputs := func() {
		if *eventsOut != "" {
			byAddr := srv.DownEventsByAddr()
			data, merr := json.Marshal(byAddr)
			if merr != nil {
				log.Printf("labserver: marshal events: %v", merr)
			} else if werr := os.WriteFile(*eventsOut, data, 0o644); werr != nil {
				log.Printf("labserver: write events-out: %v", werr)
			} else {
				total := 0
				for _, evs := range byAddr {
					total += len(evs)
				}
				log.Printf("labserver: wrote events-out=%s addrs=%d events=%d", *eventsOut, len(byAddr), total)
			}
		}
		if *pmtuOut != "" {
			obsMu.Lock()
			snapshot := append([]*connObs{}, obs...)
			obsMu.Unlock()
			byAddr := map[string]pmtuReport{}
			for _, o := range snapshot {
				// Last connection wins on a repeated peer address;
				// the smoke and window runs use a fresh ephemeral
				// port per session, so keys do not collide there.
				byAddr[o.peer] = pmtuReportFrom(o.tracker)
			}
			data, merr := json.Marshal(byAddr)
			if merr != nil {
				log.Printf("labserver: marshal pmtu: %v", merr)
			} else if werr := os.WriteFile(*pmtuOut, data, 0o644); werr != nil {
				log.Printf("labserver: write pmtu-out: %v", werr)
			} else {
				log.Printf("labserver: wrote pmtu-out=%s addrs=%d", *pmtuOut, len(byAddr))
			}
		}
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.ServePacketConn(pc) }()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	select {
	case s := <-sig:
		log.Printf("labserver: signal %v, stopping", s)
		_ = srv.Close()
		_ = pc.Close()
		<-serveErr
	case err := <-serveErr:
		writeOutputs()
		if err != nil {
			log.Fatalf("labserver: serve: %v", err)
		}
		log.Printf("labserver: stopped")
		return
	}
	writeOutputs()
	log.Printf("labserver: stopped")
}

func mustUDPAddr(s string) *net.UDPAddr {
	addr, err := net.ResolveUDPAddr("udp", s)
	if err != nil {
		log.Fatalf("labserver: bad listen address %q: %v", s, err)
	}
	return addr
}
