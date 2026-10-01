# TATAR-Kuber
#
# The build is `go build ./...` and the tests are `go test ./...`; this file is
# not a wrapper around either. It exists for the one pair of files that needs a
# command nobody remembers: the six engineering documents, which live as a .docx
# and a .md that has to be regenerated from it (see CONTRIBUTING.md).

.PHONY: docs docs-check

# Regenerate every docs/*.md from its .docx.
docs:
	bash scripts/docs.sh

# Fail if a committed .md differs from what its .docx produces (what CI runs).
docs-check:
	bash scripts/docs.sh --check
