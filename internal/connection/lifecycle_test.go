package connection

import "testing"

func TestLifecycle(t *testing.T) {
	untested := Connection{ID: "c1", Status: ConnectionStatusUntested}
	active, err := untested.Activate()
	if err != nil {
		t.Fatalf("activate untested: %v", err)
	}
	if active.Status != ConnectionStatusActive {
		t.Errorf("status = %q, want active", active.Status)
	}
	if untested.Status != ConnectionStatusUntested {
		t.Errorf("receiver mutated: status = %q", untested.Status)
	}
	if _, err := active.Activate(); err != nil {
		t.Errorf("re-activate: %v", err)
	}
	disabled, err := active.Disable()
	if err != nil {
		t.Fatalf("disable active: %v", err)
	}
	if disabled.Status != ConnectionStatusDisabled {
		t.Errorf("status = %q, want disabled", disabled.Status)
	}
	if _, err := disabled.Disable(); err != nil {
		t.Errorf("re-disable: %v", err)
	}
	reenabled, err := disabled.Activate()
	if err != nil {
		t.Fatalf("activate disabled: %v", err)
	}
	if reenabled.Status != ConnectionStatusActive {
		t.Errorf("status = %q, want active", reenabled.Status)
	}
	if _, err := untested.Disable(); err == nil {
		t.Errorf("disable untested: expected rejection, got nil error")
	}
	bogus := Connection{ID: "c9", Status: "bogus"}
	if _, err := bogus.Activate(); err == nil {
		t.Errorf("activate bogus: expected rejection, got nil error")
	}
	if _, err := bogus.Disable(); err == nil {
		t.Errorf("disable bogus: expected rejection, got nil error")
	}
}
