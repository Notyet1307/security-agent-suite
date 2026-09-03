package id

import (
	"strings"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	now := time.UnixMilli(123456789)
	first, err := New("run", now)
	if err != nil {
		t.Fatal(err)
	}
	second, err := New("run", now)
	if err != nil {
		t.Fatal(err)
	}
	if first == second || !strings.HasPrefix(first, "run_123456789_") {
		t.Fatalf("unexpected IDs: %q %q", first, second)
	}
}
