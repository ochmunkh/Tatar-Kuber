package update

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// maxExtracted — total bytes one artefact may unpack to. Checkov's zip is a
// PyInstaller bundle of a few hundred megabytes, so the cap is generous; it
// exists to bound a decompression bomb, not to be tight.
const maxExtracted = 1 << 30

// install — put a verified artefact in place under <tools>/<scanner>/ and
// return the path of the scanner binary inside it.
//
// The whole artefact is unpacked, not just the binary: checkov ships a
// PyInstaller directory whose executable does not run on its own, and trivy's
// tarball carries the licence next to the binary, which is worth keeping.
//
// The unpack happens beside the destination and is renamed over it, so an
// install that fails half way leaves the previous version in place.
func install(artefact string, kind Archive, scanner, toolsDir string) (string, error) {
	staging, rel, err := unpackStaged(artefact, kind, scanner, toolsDir)
	if err != nil {
		return "", err
	}
	defer func() { _ = os.RemoveAll(staging) }()
	return commitStaged(staging, filepath.Join(toolsDir, scanner), rel)
}

// unpackStaged — extract and validate into <toolsDir>/<scanner>.new, and leave
// it there. Nothing outside the staging directory is touched, so a failure here
// cannot disturb an installed scanner.
//
// Split out from install so Apply can unpack EVERY scanner before committing
// ANY of them: installing as it went meant a failure unpacking the third
// scanner left the first two already replaced, i.e. a half-updated toolchain
// reported as an error.
//
// The caller owns the returned staging directory and must remove it.
func unpackStaged(artefact string, kind Archive, scanner, toolsDir string) (staging, rel string, err error) {
	staging = filepath.Join(toolsDir, scanner) + ".new"
	if err = os.RemoveAll(staging); err != nil {
		return "", "", err
	}
	if err = os.MkdirAll(staging, 0o755); err != nil {
		return "", "", err
	}

	switch kind {
	case ArchiveRaw:
		err = copyFile(artefact, filepath.Join(staging, scanner), 0o755)
	case ArchiveTarGz:
		err = extractTarGz(artefact, staging)
	case ArchiveZip:
		err = extractZip(artefact, staging)
	default:
		err = fmt.Errorf("unknown archive kind %q", kind)
	}
	if err != nil {
		_ = os.RemoveAll(staging)
		return "", "", err
	}

	rel, err = findBinary(staging, scanner)
	if err != nil {
		_ = os.RemoveAll(staging)
		return "", "", err
	}
	if err = os.Chmod(filepath.Join(staging, rel), 0o755); err != nil {
		_ = os.RemoveAll(staging)
		return "", "", err
	}
	return staging, rel, nil
}

// commitStaged — move a verified staging directory into place.
//
// This is the only step that touches an installed scanner, and it is kept as
// short as possible for that reason: by the time it runs, every artefact has
// been downloaded, checksummed and unpacked. Rename cannot replace a non-empty
// directory, so the old one goes first; the window between the two is the price
// of not needing a second copy of a few hundred megabytes on disk.
func commitStaged(staging, dest, rel string) (string, error) {
	if err := os.RemoveAll(dest); err != nil {
		return "", err
	}
	if err := os.Rename(staging, dest); err != nil {
		return "", err
	}
	return filepath.Join(dest, rel), nil
}

// findBinary — the scanner's executable inside an unpacked artefact.
//
// Located by name rather than by a per-release path in the catalogue: the four
// projects package their binary at four different depths, and a path recorded
// here would be one more thing to get wrong on every upstream repackaging.
// depth — how many directories deep a relative path sits.
func depth(rel string) int { return strings.Count(rel, string(filepath.Separator)) }

func findBinary(root, name string) (string, error) {
	var found string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || d.Name() != name || !d.Type().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		// The shallowest match wins: a bundle that also ships a library called
		// after the tool keeps the top-level executable. Depth is counted in
		// separators, not string length -- comparing len() made a deeper member
		// with a shorter name ("a/b") beat a top-level one ("trivy-bin"), which
		// is the opposite of what this rule is for.
		if found == "" || depth(rel) < depth(found) ||
			(depth(rel) == depth(found) && len(rel) < len(found)) {
			found = rel
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	if found == "" {
		return "", fmt.Errorf("no %q binary inside the downloaded artefact", name)
	}
	return found, nil
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src) // #nosec G304 -- src is the artefact this package just downloaded
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode) // #nosec G304 -- dst is inside the staging directory
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

func extractTarGz(src, dest string) error {
	f, err := os.Open(src) // #nosec G304 -- src is the artefact this package just downloaded
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer func() { _ = gz.Close() }()

	tr := tar.NewReader(gz)
	budget := int64(maxExtracted)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		target, ok := safeJoin(dest, h.Name)
		if !ok {
			return fmt.Errorf("archive member %q escapes the install directory", h.Name)
		}
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			written, err := writeMember(tr, target, budget)
			if err != nil {
				return err
			}
			budget -= written
		default:
			// Symlinks, devices and hard links are skipped rather than
			// recreated: none of the four releases needs them, and each is a
			// way for an archive to point outside the install directory.
		}
	}
}

func extractZip(src, dest string) error {
	zr, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer func() { _ = zr.Close() }()

	budget := int64(maxExtracted)
	for _, zf := range zr.File {
		target, ok := safeJoin(dest, zf.Name)
		if !ok {
			return fmt.Errorf("archive member %q escapes the install directory", zf.Name)
		}
		if zf.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
			continue
		}
		if !zf.Mode().IsRegular() {
			continue // as above: only regular files are unpacked
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		rc, err := zf.Open()
		if err != nil {
			return err
		}
		written, err := writeMember(rc, target, budget)
		_ = rc.Close()
		if err != nil {
			return err
		}
		budget -= written
	}
	return nil
}

// writeMember — copy one archive member, refusing to exceed what is left of
// the extraction budget.
func writeMember(r io.Reader, target string, budget int64) (int64, error) {
	if budget <= 0 {
		return 0, errors.New("artefact unpacks to more than the 1 GiB limit")
	}
	out, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) // #nosec G304 -- target is inside the staging directory (safeJoin)
	if err != nil {
		return 0, err
	}
	n, err := io.Copy(out, io.LimitReader(r, budget+1))
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return n, err
	}
	if n > budget {
		return n, errors.New("artefact unpacks to more than the 1 GiB limit")
	}
	return n, nil
}

// safeJoin — an archive member's path inside dest, or ok=false when the member
// would land anywhere else ("../..", "/etc/...", a Windows drive letter).
func safeJoin(dest, name string) (string, bool) {
	clean := filepath.Clean(filepath.FromSlash(name))
	if clean == "." || !filepath.IsLocal(clean) {
		return "", false
	}
	return filepath.Join(dest, clean), true
}
