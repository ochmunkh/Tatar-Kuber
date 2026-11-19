// Package safeio reads files that come from outside the process -- a scanner's
// raw JSON, a scan-result.json handed over by another CI step, a policy or an
// attestation file -- without letting a single huge file exhaust memory.
//
// os.ReadFile has no ceiling: a multi-gigabyte file is read whole. Every input
// here is a document of a few KiB to a few tens of MiB, so a generous cap costs
// real inputs nothing and turns a memory-exhaustion DoS into a plain error.
package safeio

import (
	"errors"
	"fmt"
	"io"
	"os"
)

// Ceilings, by kind of input.
const (
	// MaxScan bounds a scanner's raw JSON and a scan-result.json. A report for a
	// large cluster is tens of MiB.
	MaxScan = 256 << 20
	// MaxConfig bounds a policy, an attestation file, or the canonical registry.
	MaxConfig = 16 << 20
)

// ErrTooLarge — the file is bigger than the ceiling for its kind.
var ErrTooLarge = errors.New("file exceeds the size limit")

// ReadFile is os.ReadFile with a ceiling. A file larger than max is an error
// (it is never returned truncated: a half-read JSON document that happens to
// parse would be worse than no result).
func ReadFile(path string, max int64) ([]byte, error) {
	f, err := os.Open(path) // #nosec G304 -- callers pass operator-chosen paths
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("%s: %w (limit %d MiB)", path, ErrTooLarge, max>>20)
	}
	return data, nil
}
