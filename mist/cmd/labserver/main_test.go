package main

import (
	"strings"
	"testing"
)

func TestDecodeKey(t *testing.T) {
	key, err := decodeKey(strings.Repeat("ab", 32))
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != 32 || key[0] != 0xab {
		t.Fatalf("decoded key wrong: len=%d first=%x", len(key), key[0])
	}
	for _, bad := range []string{"", "zz", strings.Repeat("ab", 16), strings.Repeat("ab", 33), "abc"} {
		if _, err := decodeKey(bad); err == nil {
			t.Fatalf("decodeKey(%q) unexpectedly succeeded", bad)
		}
	}
}
