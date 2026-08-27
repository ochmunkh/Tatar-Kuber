package cli

import (
	"encoding/json"
	"strings"
)

func jsonUnmarshal(data []byte, v interface{}) error { return json.Unmarshal(data, v) }

// splitCSV — "a, b ,c" -> ["a","b","c"] (хоосныг алгасна).
func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
