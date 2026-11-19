package attest

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzLoadAndValidate — attestations.yaml is user-supplied YAML.
func FuzzLoadAndValidate(f *testing.F) {
	f.Add([]byte("schema_version: \"1.0\"\nattestations: []\n"))
	f.Add([]byte("attestations:\n  - control: TATAR-CON-001\n    expires: nope\n"))
	f.Add([]byte("\x00\x01"))
	f.Add([]byte("a: &a [*a]\n"))
	dir := f.TempDir()
	f.Fuzz(func(t *testing.T, data []byte) {
		p := filepath.Join(dir, "a.yaml")
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Skip()
		}
		file, err := Load(p)
		if err != nil {
			return
		}
		_ = Validate(file, map[string]Control{})
	})
}
