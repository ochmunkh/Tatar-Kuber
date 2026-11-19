package canonical

import (
	"os"
	"testing"
)

// FuzzLoadBytes — the registry is embedded, but `--registry` loads a user file.
func FuzzLoadBytes(f *testing.F) {
	if seed, err := os.ReadFile("../../schema/canonical-controls.yaml"); err == nil {
		f.Add(seed)
	}
	f.Add([]byte("controls: []\n"))
	f.Add([]byte("\xff\xfe"))
	f.Fuzz(func(t *testing.T, data []byte) {
		reg, err := LoadBytes(data)
		if err != nil {
			return
		}
		r := reg.NewResolver()
		_, _ = r.ResolveOne("trivy", "KSV-0001", ResolverContext{})
	})
}

func FuzzNormalizeRuleID(f *testing.F) {
	f.Add("trivy", "AVD-KSV-0001")
	f.Add("", "")
	f.Fuzz(func(t *testing.T, scanner, id string) { _ = NormalizeRuleID(scanner, id) })
}
