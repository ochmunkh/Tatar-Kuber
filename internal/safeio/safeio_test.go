package safeio

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, n int) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(p, make([]byte, n), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestReadFile_UnderAndAtTheLimit(t *testing.T) {
	for _, n := range []int{0, 1, 10} {
		b, err := ReadFile(write(t, n), 10)
		if err != nil || len(b) != n {
			t.Fatalf("n=%d: got %d bytes, err %v", n, len(b), err)
		}
	}
}

func TestReadFile_OverTheLimitIsAnErrorNotATruncation(t *testing.T) {
	b, err := ReadFile(write(t, 11), 10)
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("want ErrTooLarge, got %v", err)
	}
	if b != nil {
		t.Fatal("an oversize file must not be returned, even partly")
	}
}

func TestReadFile_MissingKeepsTheOSError(t *testing.T) {
	_, err := ReadFile(filepath.Join(t.TempDir(), "nope"), 10)
	if !os.IsNotExist(err) {
		t.Fatalf("a missing file must stay a not-exist error (callers test for it), got %v", err)
	}
}
