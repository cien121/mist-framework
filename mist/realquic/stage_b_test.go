package realquic

import (
	"testing"
)

// Stage B (B2, REALQUIC-DESIGN-v3 §4.3 rule 2): issued-profile burst
// default-on + missing-parameter self-check alert. These tests pin
// the issuance boundary (newIssuedFrom) and the adoption boundary
// (adoptProfile / applyProfile / Auth). They deliberately do NOT
// touch shaper unit semantics (BurstEnabled, Validate, uniform tail
// pacing for a directly-constructed burst-off profile) or the
// bootstrap contract: those are unchanged and are covered by the
// pre-existing tests.

func TestStageBIssuedBurstDefaultOn(t *testing.T) {
	srv, err := NewServer(ServerConfig{Key: make([]byte, 32)})
	if err != nil {
		t.Fatal(err)
	}
	issued := srv.IssuedProfile()
	if issued.Version != 1 {
		t.Fatalf("issued version=%d, want 1", issued.Version)
	}
	if !issued.Steady.BurstEnabled() {
		t.Fatalf("default server issuance has burst off, want default-on (Stage B B2)")
	}
	rotated := srv.RotateProfile()
	if rotated.Version != 2 {
		t.Fatalf("rotated version=%d, want 2", rotated.Version)
	}
	if !rotated.Steady.BurstEnabled() {
		t.Fatalf("rotated issuance lost burst, want default-on preserved across rotation")
	}
}

func TestStageBIssuedFillsMissingBurstPreservesOperatorBurst(t *testing.T) {
	// A burst-less operator base (the bootstrap shape) is issued WITH
	// the default burst filled in, not as-is.
	base := BootstrapProfile()
	srv, err := NewServer(ServerConfig{Key: make([]byte, 32), Profile: &base})
	if err != nil {
		t.Fatal(err)
	}
	if !srv.IssuedProfile().Steady.BurstEnabled() {
		t.Fatalf("burst-less base issued burst-less, want default filled in")
	}
	// An operator base that already carries burst parameters is
	// issued unchanged: issuance fills a missing burst, it never
	// overwrites an operator's burst.
	custom := BootstrapProfile()
	custom.Steady.Burst = SteadyBurst{
		MinPackets: 4,
		MaxPackets: 4,
		GapDist:    Distribution{Kind: "fixed", Min: 0, Max: 0, Mean: 0},
		IdleDist:   Distribution{Kind: "fixed", Min: 100, Max: 100, Mean: 100},
		AckLenMax:  50,
	}
	srv2, err := NewServer(ServerConfig{Key: make([]byte, 32), Profile: &custom})
	if err != nil {
		t.Fatal(err)
	}
	got := srv2.IssuedProfile().Steady.Burst
	if got.MinPackets != 4 || got.MaxPackets != 4 || got.AckLenMax != 50 {
		t.Fatalf("operator burst overwritten at issuance: got %+v, want 4/4 ack 50", got)
	}
}

func TestStageBBootstrapBurstStillOff(t *testing.T) {
	// FINALIZED (P2 scope), untouched by Stage B: the bootstrap
	// profile (Version 0) keeps burst off. Default-on applies to
	// issuance only, never to the bootstrap itself.
	boot := BootstrapProfile()
	if boot.Version != 0 {
		t.Fatalf("bootstrap version=%d, want 0", boot.Version)
	}
	if boot.Steady.BurstEnabled() {
		t.Fatalf("bootstrap burst on, want off (FINALIZED)")
	}
}

func TestStageBAdoptMissingBurstRefusesAndAlerts(t *testing.T) {
	c := &Client{}
	burstLess := newIssuedFrom(BootstrapProfile())
	// Undo the issuance fill to simulate a burst-less issued profile
	// from an old / misconfigured server reaching the client.
	burstLess.Steady.Burst = SteadyBurst{}
	if burstLess.Version != 1 || burstLess.Steady.BurstEnabled() {
		t.Fatalf("test setup: want burst-less version 1, got version %d enabled %v", burstLess.Version, burstLess.Steady.BurstEnabled())
	}
	if err := c.adoptProfile(burstLess); err == nil {
		t.Fatalf("adopting a burst-less issued profile succeeded, want loud refusal")
	}
	if c.ProfileAlert() == nil {
		t.Fatalf("adopt refusal left no queryable alert, want ProfileAlert() != nil")
	}
	if got := c.ActiveProfile().Version; got != 0 {
		t.Fatalf("refused profile changed active profile to version %d, want unchanged 0", got)
	}
	// A good issued profile adopts and clears the alert.
	if err := c.adoptProfile(newIssuedFrom(BootstrapProfile())); err != nil {
		t.Fatalf("adopting a burst-carrying issued profile failed: %v", err)
	}
	if c.ProfileAlert() != nil {
		t.Fatalf("successful adoption left a stale alert: %v", c.ProfileAlert())
	}
	if got := c.ActiveProfile().Version; got != 1 {
		t.Fatalf("active version=%d, want 1 after good adoption", got)
	}
}

func TestStageBAdoptBootstrapExempt(t *testing.T) {
	// Version 0 is exempt from the self-check: burst-off is the
	// bootstrap contract, not a configuration error.
	c := &Client{}
	if err := c.adoptProfile(BootstrapProfile()); err != nil {
		t.Fatalf("adopting bootstrap (version 0, burst off) failed: %v (want exempt)", err)
	}
	if c.ProfileAlert() != nil {
		t.Fatalf("bootstrap adoption set an alert: %v (want none)", c.ProfileAlert())
	}
}

func TestStageBApplyPushMissingBurstRejectedWithAlert(t *testing.T) {
	c := &Client{}
	if err := c.adoptProfile(newIssuedFrom(BootstrapProfile())); err != nil {
		t.Fatal(err)
	}
	pushed := newIssuedFrom(BootstrapProfile())
	pushed.Version = 2
	pushed.Steady.Burst = SteadyBurst{}
	if c.applyProfile(pushed) {
		t.Fatalf("burst-less push applied, want rejection")
	}
	if c.ProfileAlert() == nil {
		t.Fatalf("burst-less push rejection left no alert, want ProfileAlert() != nil")
	}
	if got := c.ActiveProfile().Version; got != 1 {
		t.Fatalf("rejected push moved active profile to version %d, want 1", got)
	}
	// A good push still applies and clears the alert.
	good := newIssuedFrom(BootstrapProfile())
	good.Version = 2
	if !c.applyProfile(good) {
		t.Fatalf("good push rejected, want applied")
	}
	if c.ProfileAlert() != nil {
		t.Fatalf("good push left a stale alert: %v", c.ProfileAlert())
	}
}

func TestStageBAuthAdoptsDefaultBurstEndToEnd(t *testing.T) {
	env := setupEnv(t)
	if _, _, _, err := env.cli.Auth(env.ctx(t)); err != nil {
		t.Fatalf("auth: %v", err)
	}
	active := env.cli.ActiveProfile()
	if active.Version != 1 {
		t.Fatalf("post-AUTH active version=%d, want issued 1", active.Version)
	}
	if !active.Steady.BurstEnabled() {
		t.Fatalf("post-AUTH active profile has burst off, want default-on from issuance")
	}
	if env.cli.ProfileAlert() != nil {
		t.Fatalf("post-AUTH alert set: %v (want none for a well-issued profile)", env.cli.ProfileAlert())
	}
	if got := env.cli.Shaper().EffectiveProfile().Version; got != 1 {
		t.Fatalf("post-AUTH shaper version=%d, want window 1", got)
	}
	if !env.cli.Shaper().EffectiveProfile().Steady.BurstEnabled() {
		t.Fatalf("post-AUTH shaper profile has burst off, want burst-on in window 1")
	}
	// The session still works after AUTH: the default-on change must
	// not break ordinary post-AUTH traffic.
	cs, err := env.cli.Connect(env.ctx(t), startTCPEchoServer(t))
	if err != nil {
		t.Fatalf("CONNECT after AUTH: %v", err)
	}
	defer cs.Close()
	msg := []byte("stage-b-post-auth")
	if _, err := cs.Write(msg); err != nil {
		t.Fatalf("CONNECT write: %v", err)
	}
	if got := readFullFromConnect(t, cs, len(msg)); string(got) != string(msg) {
		t.Fatalf("CONNECT echo %q, want %q", got, msg)
	}
}
