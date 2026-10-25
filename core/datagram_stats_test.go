package core

import (
	"encoding/base64"
	"testing"
)

func TestDatagramStatsSendError(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	c, err := NewMistUDPClient(MistConfig{
		Server:   "127.0.0.1:1",
		ClientID: "0123456789abcdef0123456789abcdef",
		AuthKey:  key,
	})
	if err != nil {
		t.Fatalf("NewMistUDPClient: %v", err)
	}
	sent, sendErrs, recv := c.DatagramStats()
	if sent != 0 || sendErrs != 0 || recv != 0 {
		t.Fatalf("fresh client stats = (%d, %d, %d), want (0, 0, 0)", sent, sendErrs, recv)
	}
	// Unconnected: no scheduler, must fail and count one send error.
	if err := c.SendDatagram("8.8.8.8:53", []byte{0x12, 0x34}); err == nil {
		t.Fatal("SendDatagram on unconnected client should fail")
	}
	sent, sendErrs, recv = c.DatagramStats()
	if sent != 0 || sendErrs != 1 || recv != 0 {
		t.Fatalf("after failed send stats = (%d, %d, %d), want (0, 1, 0)", sent, sendErrs, recv)
	}
	// Bad target also counts as a send error, without changing behavior.
	if err := c.SendDatagram("not-an-ip:53", []byte{}); err == nil {
		t.Fatal("SendDatagram with non-IP target should fail")
	}
	_, sendErrs, _ = c.DatagramStats()
	if sendErrs != 2 {
		t.Fatalf("after bad target sendErrs = %d, want 2", sendErrs)
	}
	// Engine.Stats surfaces the same numbers via DatagramStatser.
	e := NewEngineForMobile(newMockTUN(), c)
	s := e.Stats()
	if s.DatagramsSent != 0 || s.DatagramsSendErrors != 2 || s.DatagramsReceived != 0 {
		t.Fatalf("engine stats = (%d, %d, %d), want (0, 2, 0)",
			s.DatagramsSent, s.DatagramsSendErrors, s.DatagramsReceived)
	}
}
