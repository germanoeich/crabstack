package ids

import "testing"

func TestNew(t *testing.T) {
	a := New()
	b := New()

	if len(a) != 32 {
		t.Fatalf("expected 32-char id, got %d", len(a))
	}
	if len(b) != 32 {
		t.Fatalf("expected 32-char id, got %d", len(b))
	}
	if a == b {
		t.Fatalf("expected distinct ids, got duplicates")
	}
}
