package opauth

import (
	"context"
	"testing"
)

func TestStaticStore_VerifySucceedsForAKnownToken(t *testing.T) {
	store := NewStaticStore(map[string]string{"tok-bogdan": "bogdan"})
	op, err := store.Verify(context.Background(), "tok-bogdan")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if op.Name != "bogdan" {
		t.Fatalf("Name = %q, want bogdan", op.Name)
	}
}

func TestStaticStore_VerifyRejectsAnUnknownToken(t *testing.T) {
	store := NewStaticStore(map[string]string{"tok-bogdan": "bogdan"})
	_, err := store.Verify(context.Background(), "tok-someone-else")
	if err != ErrInvalidToken {
		t.Fatalf("err = %v, want ErrInvalidToken", err)
	}
}

func TestStaticStore_VerifyRejectsAnEmptyToken(t *testing.T) {
	store := NewStaticStore(map[string]string{"tok-bogdan": "bogdan"})
	_, err := store.Verify(context.Background(), "")
	if err != ErrInvalidToken {
		t.Fatalf("err = %v, want ErrInvalidToken", err)
	}
}

func TestStaticStore_DoesNotRetainThePlaintextToken(t *testing.T) {
	store := NewStaticStore(map[string]string{"tok-bogdan": "bogdan"})
	for digest := range store.byDigest {
		if digest == "tok-bogdan" {
			t.Fatalf("byDigest is keyed by the plaintext token, want a SHA-256 digest")
		}
	}
}

func TestStaticStore_TwoDifferentOperatorsResolveIndependently(t *testing.T) {
	store := NewStaticStore(map[string]string{
		"tok-bogdan": "bogdan",
		"tok-ci":     "ci-pipeline",
	})
	bogdan, err := store.Verify(context.Background(), "tok-bogdan")
	if err != nil || bogdan.Name != "bogdan" {
		t.Fatalf("got %+v, %v, want bogdan", bogdan, err)
	}
	ci, err := store.Verify(context.Background(), "tok-ci")
	if err != nil || ci.Name != "ci-pipeline" {
		t.Fatalf("got %+v, %v, want ci-pipeline", ci, err)
	}
}
