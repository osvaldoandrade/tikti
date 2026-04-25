package saml

import (
	"testing"
	"time"
)

func TestFakeClock_AdvanceMonotonic(t *testing.T) {
	fc := NewFakeClock()

	expected := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if got := fc.Now(); !got.Equal(expected) {
		t.Fatalf("initial time: got %v, want %v", got, expected)
	}

	fc.Advance(5 * time.Minute)
	t1 := fc.Now()

	fc.Advance(10 * time.Second)
	t2 := fc.Now()

	if !t2.After(t1) {
		t.Errorf("expected %v after %v", t2, t1)
	}
	if !t1.After(expected) {
		t.Errorf("expected %v after %v", t1, expected)
	}
}

func TestFakeClock_SincePositive(t *testing.T) {
	fc := NewFakeClock()

	past := fc.Now()
	fc.Advance(3 * time.Second)

	d := fc.Since(past)
	if d <= 0 {
		t.Errorf("expected positive duration, got %v", d)
	}
	if d != 3*time.Second {
		t.Errorf("expected 3s, got %v", d)
	}
}
