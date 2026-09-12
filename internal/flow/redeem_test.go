package flow_test

import (
	"context"
	"testing"
	"time"

	"keyway/internal/flow"
	"keyway/internal/normalize"
)

func TestRedeemBindsRedirect(t *testing.T) {
	ctx := context.Background()
	store := testStore(t)
	svc := testService(t, store)
	now := time.Now()
	code, err := flow.NewAuthCode("acme", normalize.Identity{Email: "ada@example.com"}, "https://app.example/callback", now)
	if err != nil {
		t.Fatalf("NewAuthCode: %v", err)
	}
	if err := store.IssueCode(ctx, code); err != nil {
		t.Fatalf("IssueCode: %v", err)
	}
	identity, err := svc.Redeem(ctx, code.Code, "https://app.example/callback")
	if err != nil {
		t.Fatalf("Redeem: %v", err)
	}
	if identity.Email != "ada@example.com" {
		t.Errorf("Email = %q", identity.Email)
	}

	code2, err := flow.NewAuthCode("acme", normalize.Identity{Email: "ada@example.com"}, "https://app.example/callback", now)
	if err != nil {
		t.Fatalf("NewAuthCode: %v", err)
	}
	if err := store.IssueCode(ctx, code2); err != nil {
		t.Fatalf("IssueCode: %v", err)
	}
	if _, err := svc.Redeem(ctx, code2.Code, "https://evil.example/callback"); err == nil {
		t.Errorf("redirect mismatch: expected rejection, got nil error")
	}
	if _, err := svc.Redeem(ctx, "no-such-code", "https://app.example/callback"); err == nil {
		t.Errorf("unknown code: expected rejection, got nil error")
	}
}
