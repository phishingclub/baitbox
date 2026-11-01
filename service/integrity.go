package service

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"github.com/phishingclub/baitbox/manifest"
)

// Archive guards that bound a malicious or malformed archive before anything is
// trusted. The file count and unpacked total are defaults the config can raise;
// the ratio and manifest caps are fixed.
const (
	DefaultMaxArchiveFiles  = 2000
	DefaultMaxUnpackedTotal = 32 << 20 // 32 MiB across the whole archive
	maxCompressionRatio     = 100      // reject archives that expand more than 100x
	maxManifestBytes        = 1 << 20  // baitbox.json is metadata, so 1 MiB is plenty
	// maxArchiveOtherEntries caps directory entries, which carry no bytes.
	maxArchiveOtherEntries = 64
	// streamSlackPerEntry is what the tar stream may hold per entry beyond the
	// file bytes: header, PAX records and block padding.
	streamSlackPerEntry = 4 << 10
)

// errStreamTooLarge is returned once an unpacked tar stream passes its cap.
var errStreamTooLarge = errors.New("archive uncompressed size or compression ratio too large")

// capReader fails once more than left bytes have been read through it. It caps
// the whole unpacked tar stream, so bytes the tar reader skips on its own (PAX
// and long name records, padding) still count.
type capReader struct {
	r    io.Reader
	left int64
}

func (c *capReader) Read(p []byte) (int, error) {
	if c.left <= 0 {
		return 0, errStreamTooLarge
	}
	if int64(len(p)) > c.left {
		p = p[:c.left]
	}
	n, err := c.r.Read(p)
	c.left -= int64(n)
	return n, err
}

// MaxBundleInstallBytes is the unpacked size cap of one bundle install.
// Phishing Club installs a bundle by fetching the bundle and the latest version
// of every package it references and holding them all in memory, and it refuses
// the install past this size. Bait Box refuses the same bundles at publish and
// import, so the value must match Phishing Club. It is fixed, not configurable,
// since a higher value only admits bundles Phishing Club cannot install.
const MaxBundleInstallBytes = 64 << 20

// ArchiveLimits are the caps one package archive must fit: the largest single
// file, the sum of every unpacked file, and the number of files.
type ArchiveLimits struct {
	MaxFile     int64
	MaxUnpacked int64
	MaxFiles    int
}

// withDefaults fills any unset cap with its default.
func (l ArchiveLimits) withDefaults() ArchiveLimits {
	if l.MaxUnpacked <= 0 {
		l.MaxUnpacked = DefaultMaxUnpackedTotal
	}
	if l.MaxFiles <= 0 {
		l.MaxFiles = DefaultMaxArchiveFiles
	}
	if l.MaxFile <= 0 {
		l.MaxFile = l.MaxUnpacked
	}
	return l
}

// allowedTopName reports whether a cleaned archive path is permitted: the
// manifest at the root, or anything under content/ or assets/.
func allowedTopName(name string) bool {
	if name == manifest.FileName {
		return true
	}
	return strings.HasPrefix(name, "content/") || strings.HasPrefix(name, "assets/")
}

// InspectArchiveSize opens the tar.gz at archivePath, enforces the size, count,
// ratio, allowlist and path traversal guards, parses and validates the
// manifest, and verifies that every declared entry is present with a matching
// sha256. When the manifest names a preview image, that file must be a raster
// image that passes the same checks as a gallery upload. The assets block of
// every data.yaml must describe shipped files with settings Phishing Club takes. It returns the
// validated manifest and the sum of the unpacked file sizes, manifest included,
// which is what Phishing Club counts against its bundle install cap. The
// archive bytes are not held in memory beyond one file at a time.
func InspectArchiveSize(archivePath string, lim ArchiveLimits) (*manifest.Manifest, int64, error) {
	lim = lim.withDefaults()
	f, err := os.Open(archivePath)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	compressedSize, err := fileSize(f)
	if err != nil {
		return nil, 0, err
	}

	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, 0, fmt.Errorf("gzip: %w", err)
	}
	defer gz.Close()
	slack := int64(lim.MaxFiles+maxArchiveOtherEntries+1) * streamSlackPerEntry
	tr := tar.NewReader(&capReader{r: gz, left: lim.MaxUnpacked + slack})

	var manifestBytes []byte
	fileShas := map[string]string{}
	// dataDocs holds each content folder data.yaml so its assets block can be
	// checked once the manifest is trusted. Each is bounded by the file cap.
	dataDocs := map[string][]byte{}
	// seen holds every name by its case folded form, so two names that differ
	// only by case clash too. Its size is bounded by the entry caps.
	seen := map[string]bool{}
	var count, others int
	var total int64

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			if errors.Is(err, errStreamTooLarge) {
				return nil, 0, err
			}
			return nil, 0, fmt.Errorf("tar: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			// a directory carries no bytes and is skipped, but its name gets the same
			// path rules as a file, so an extractor that creates it cannot be led
			// outside the root or made to clash with a file of the same name.
			if hdr.Typeflag == tar.TypeDir {
				others++
				if others > maxArchiveOtherEntries {
					return nil, 0, fmt.Errorf("archive has too many directory entries")
				}
				dir := strings.TrimSuffix(hdr.Name, "/")
				if !(dir == "content" || dir == "assets" || manifest.ValidEntryPath(dir)) {
					return nil, 0, fmt.Errorf("archive directory not allowed: %q", hdr.Name)
				}
				if seen[manifest.FoldPath(dir)] {
					return nil, 0, fmt.Errorf("archive has a duplicate entry %q", dir)
				}
				seen[manifest.FoldPath(dir)] = true
				continue
			}
			return nil, 0, fmt.Errorf("archive entry %q is not a regular file", hdr.Name)
		}
		count++
		if count > lim.MaxFiles {
			return nil, 0, fmt.Errorf("archive has too many files")
		}
		name := path.Clean(hdr.Name)
		if strings.HasPrefix(name, "/") || name == ".." ||
			strings.HasPrefix(name, "../") || strings.Contains(name, "/../") {
			return nil, 0, fmt.Errorf("archive path escapes root: %q", hdr.Name)
		}
		// a name must already be in its clean form, so two spellings of one path
		// (a/b and a//b or ./a/b) can never both appear and shadow each other.
		if name != hdr.Name {
			return nil, 0, fmt.Errorf("archive path is not canonical: %q", hdr.Name)
		}
		if !allowedTopName(name) {
			return nil, 0, fmt.Errorf("archive path not allowed: %q", name)
		}
		// each path may appear once. A second copy would let the hashed bytes differ
		// from the bytes a reader that takes the first (or last) copy extracts.
		if seen[manifest.FoldPath(name)] {
			return nil, 0, fmt.Errorf("archive has a duplicate entry %q", name)
		}
		seen[manifest.FoldPath(name)] = true

		limit := lim.MaxFile
		if name == manifest.FileName && limit > maxManifestBytes {
			limit = maxManifestBytes
		}
		h := sha256.New()
		limited := io.LimitReader(tr, limit+1)
		var w io.Writer = h
		var buf *strings.Builder
		if name == manifest.FileName || isDataYAML(name) {
			buf = &strings.Builder{}
			w = io.MultiWriter(h, buf)
		}
		n, err := io.Copy(w, limited)
		if err != nil {
			return nil, 0, err
		}
		if n > limit {
			return nil, 0, fmt.Errorf("archive file %q exceeds size limit", name)
		}
		total += n
		if total > lim.MaxUnpacked {
			return nil, 0, fmt.Errorf("archive exceeds total size limit")
		}
		if name == manifest.FileName {
			manifestBytes = []byte(buf.String())
		} else {
			fileShas[name] = hex.EncodeToString(h.Sum(nil))
			if buf != nil {
				dataDocs[name] = []byte(buf.String())
			}
		}
	}

	if compressedSize > 0 && total/compressedSize > maxCompressionRatio && total > (10<<20) {
		return nil, 0, fmt.Errorf("archive compression ratio too high")
	}
	if manifestBytes == nil {
		return nil, 0, fmt.Errorf("archive missing %s", manifest.FileName)
	}

	m, err := manifest.Parse(manifestBytes)
	if err != nil {
		return nil, 0, err
	}
	if err := m.Validate(); err != nil {
		return nil, 0, err
	}

	// every declared entry must be present with a matching hash.
	for _, e := range m.Entries {
		got, ok := fileShas[path.Clean(e.Path)]
		if !ok {
			return nil, 0, fmt.Errorf("manifest entry %q missing from archive", e.Path)
		}
		if got != e.SHA256 {
			return nil, 0, fmt.Errorf("manifest entry %q hash mismatch", e.Path)
		}
	}
	// every payload file must be declared, so nothing ships unlisted.
	for name := range fileShas {
		if !entryDeclared(m, name) {
			return nil, 0, fmt.Errorf("archive file %q not declared in manifest", name)
		}
	}
	if m.Preview != "" {
		if err := checkArchivePreview(archivePath, m.Preview); err != nil {
			return nil, 0, err
		}
	}
	// the per asset settings (content type, headers, allow deny lists) are checked
	// here so every publish path, an upload, an authored package or an import,
	// refuses the same packages Phishing Club would refuse on install.
	assetFiles := map[string]bool{}
	for name := range fileShas {
		if strings.HasPrefix(name, "assets/") {
			assetFiles[strings.TrimPrefix(name, "assets/")] = true
		}
	}
	if err := validateAssetBlocks(m.Type, dataDocs, assetFiles); err != nil {
		return nil, 0, err
	}
	return m, total, nil
}

// checkArchivePreview reads the manifest preview file from the archive and runs
// the gallery upload checks on it: its bytes must be the raster type its
// extension names, within the byte and pixel caps. The archive already passed
// the structure checks, so this second pass only looks for one path.
func checkArchivePreview(archivePath, name string) error {
	data, err := readArchiveFile(archivePath, name, MaxPreviewBytes+1)
	if err != nil {
		return fmt.Errorf("preview %q: %w", name, err)
	}
	detected, err := checkPreviewImage(data)
	if err != nil {
		return fmt.Errorf("preview %q: %w", name, err)
	}
	if want := manifest.PreviewMediaType(name); detected != want {
		return fmt.Errorf("preview %q: %w: bytes are %s but the name says %s", name, ErrPreviewImage, detected, want)
	}
	return nil
}

// readArchiveFile returns the bytes of one regular file in a tar.gz, reading at
// most limit bytes of it.
func readArchiveFile(archivePath, name string, limit int64) ([]byte, error) {
	f, err := os.Open(archivePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("gzip: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil, fmt.Errorf("file not in archive")
		}
		if err != nil {
			return nil, fmt.Errorf("tar: %w", err)
		}
		if hdr.Typeflag == tar.TypeReg && hdr.Name == name {
			return io.ReadAll(io.LimitReader(tr, limit))
		}
	}
}

// archiveUnpackedSize returns the sum of the regular file sizes in a tar.gz the
// registry built itself, so it only counts bytes; it reads each file so the
// total is the bytes that unpack.
func archiveUnpackedSize(archive io.Reader) (int64, error) {
	gz, err := gzip.NewReader(archive)
	if err != nil {
		return 0, fmt.Errorf("gzip: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	var total int64
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return total, nil
		}
		if err != nil {
			return 0, fmt.Errorf("tar: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		n, err := io.Copy(io.Discard, tr)
		if err != nil {
			return 0, err
		}
		total += n
	}
}

func entryDeclared(m *manifest.Manifest, name string) bool {
	for _, e := range m.Entries {
		if path.Clean(e.Path) == name {
			return true
		}
	}
	return false
}

func fileSize(f *os.File) (int64, error) {
	info, err := f.Stat()
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}
