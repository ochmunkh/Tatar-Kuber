package trivy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ochmunkh/tatar-kuber/internal/canonical"
	"github.com/ochmunkh/tatar-kuber/internal/scanner"
)

// FuzzNormalize feeds arbitrary bytes to the adapter. The scanner's output is
// untrusted (it reflects the scanned manifests); the only requirement is that
// parsing returns, with findings or an error, and never panics.
//
//	go test -fuzz=FuzzNormalize -fuzztime=30s ./internal/scanner/trivy
func FuzzNormalize(f *testing.F) {
	if seed, err := os.ReadFile(filepath.Join("..", "..", "..", "examples", "demo", "trivy.json")); err == nil {
		f.Add(seed)
	}
	f.Add([]byte(`{}`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`null`))
	f.Add([]byte(`{"Results":[{"Misconfigurations":[{}]}]}`))
	reg := fuzzRegistry(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		s := New(reg.NewResolver())
		_, _ = s.Normalize(scanner.RawResult{Scanner: "trivy", Format: "json", Data: data})
	})
}

func fuzzRegistry(f *testing.F) *canonical.Registry {
	f.Helper()
	reg, err := canonical.Load("../../../schema/canonical-controls.yaml")
	if err != nil {
		f.Fatalf("registry: %v", err)
	}
	return reg
}
