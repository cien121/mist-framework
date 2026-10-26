// Command labserver is the pilot-only real-QUIC lab server for Stage 3
// pilot Tier 1. It wraps mist/realquic.NewServer with rotation disabled
// (single cycle, PLAN D4) and serves one UDP PacketConn. The pilot key
// comes only from the MIST_KEY environment variable (hex of 32 bytes);
// it is never written to code, logs, reports, or the command line.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

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

func main() {
	listen := flag.String("listen", "10.200.1.2:24443", "UDP listen address (pilot lab address; never 8443/443/1443)")
	flag.Parse()
	key, err := decodeKey(os.Getenv("MIST_KEY"))
	if err != nil {
		log.Fatalf("labserver: %v", err)
	}
	srv, err := realquic.NewServer(realquic.ServerConfig{Key: key, RotationMin: 0})
	if err != nil {
		log.Fatalf("labserver: new server: %v", err)
	}
	issued := srv.IssuedProfile()
	log.Printf("labserver buildCommit=%s listen=%s issuedProfileVersion=%d issuedProfileHash=%s rotation=off",
		buildCommit, *listen, issued.Version, profileHash12(issued))
	pc, err := net.ListenUDP("udp", mustUDPAddr(*listen))
	if err != nil {
		log.Fatalf("labserver: listen: %v", err)
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
		if err != nil {
			log.Fatalf("labserver: serve: %v", err)
		}
	}
	log.Printf("labserver: stopped")
}

func mustUDPAddr(s string) *net.UDPAddr {
	addr, err := net.ResolveUDPAddr("udp", s)
	if err != nil {
		log.Fatalf("labserver: bad listen address %q: %v", s, err)
	}
	return addr
}
