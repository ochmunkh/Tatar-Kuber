package finding

import (
	"crypto/sha256"
	"encoding/hex"
)

// StableID — content-hash дээр суурилсан тогтвортой finding ID (Doc #1 §7.1).
// Дараалсан дугаар БИШ тул scan хооронд ижил асуудал ижил ID-тай гарч,
// SARIF/GitHub дедуп ба diff эвдрэхгүй.
//
// Урт: 12 hex (48 бит). v1.0.0-д 6 hex (24 бит) байсан нь ~4 000 finding-тэй
// cluster дээр мөргөлдөх магадлал ~40% (birthday bound) — ID давхцвал dedup,
// SARIF fingerprint, diff бүгд эвдэрнэ. 48 бит: 1 сая finding-д ч <0.2%.
// (v1.0.1-д ID солигдсон — GitHub Code Scanning alert нэг удаа шинээр үүснэ.)
func StableID(canonicalControl, resource, namespace string) string {
	h := sha256.Sum256([]byte(canonicalControl + "|" + resource + "|" + namespace))
	return "TK-" + hex.EncodeToString(h[:])[:12]
}
