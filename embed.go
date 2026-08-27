// Package tatarkuber embeds default assets so a distributed binary is
// self-contained (brew/curl/docker суулгацад schema-г дагалдуулах шаардлагагүй).
package tatarkuber

import _ "embed"

// CanonicalControlsYAML — репозиторийн жинхэнэ canonical-controls.yaml-ийн
// build-цагт шигтгэсэн хувилбар. Файл олдохгүй үед fallback болно.
//
//go:embed schema/canonical-controls.yaml
var CanonicalControlsYAML []byte
