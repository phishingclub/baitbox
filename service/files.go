package service

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"

	"github.com/phishingclub/baitbox/database"
	"github.com/phishingclub/baitbox/manifest"
)

// VersionContent returns a version's payload files (content/ and assets/) keyed
// by path, plus the parsed manifest, so the UI can load an existing package back
// into the author wizard to publish a new version.
func (s *RegistryService) VersionContent(
	nsName, name, version string,
) (*database.PackageVersion, *manifest.Manifest, map[string][]byte, error) {
	_, _, v, err := s.Resolve(nsName, name, version)
	if err != nil {
		return nil, nil, nil, err
	}
	m, perr := manifest.Parse([]byte(v.Manifest))
	if perr != nil {
		return nil, nil, nil, perr
	}
	rc, err := s.blobs.Open(v.ArchiveBlobSHA256)
	if err != nil {
		return nil, nil, nil, err
	}
	defer rc.Close()
	gz, err := gzip.NewReader(rc)
	if err != nil {
		return nil, nil, nil, err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	files := map[string][]byte{}
	// the whole payload is held in memory, so cap the sum as well as each file.
	var total int64
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, nil, err
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		clean := path.Clean(hdr.Name)
		if !strings.HasPrefix(clean, "content/") && !strings.HasPrefix(clean, "assets/") {
			continue
		}
		b, err := io.ReadAll(io.LimitReader(tr, s.maxFile+1))
		if err != nil {
			return nil, nil, nil, err
		}
		if int64(len(b)) > s.maxFile {
			return nil, nil, nil, fmt.Errorf("archive file %q exceeds size limit", clean)
		}
		total += int64(len(b))
		// the same total cap publish enforced, so a stored version always loads.
		if total > s.limits.MaxUnpacked {
			return nil, nil, nil, fmt.Errorf("package content exceeds total size limit")
		}
		files[clean] = b
	}
	return v, m, files, nil
}

// ReadPackageFile extracts a single file from a version's stored archive, for
// previewing an email or page with its images. relpath must be the manifest or
// a file under content/ or assets/; traversal and other paths are rejected. The
// file is read on demand from the archive blob, nothing is unpacked to disk.
func (s *RegistryService) ReadPackageFile(v *database.PackageVersion, relpath string) ([]byte, error) {
	f, _, err := s.OpenPackageFile(v, relpath, s.maxFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, s.maxFile+1))
}

// ErrFileTooLarge is returned by OpenPackageFile when the file is larger than
// the size the caller allows.
var ErrFileTooLarge = errors.New("file is too large to serve")

// OpenPackageFile opens a single file of a version's stored archive for
// streaming, under the same path rules as ReadPackageFile. It returns the file
// size from the tar header, and ErrFileTooLarge when that is over maxSize. The
// reader holds only the decompressor state, never the whole file.
func (s *RegistryService) OpenPackageFile(
	v *database.PackageVersion, relpath string, maxSize int64,
) (io.ReadCloser, int64, error) {
	clean := path.Clean(strings.TrimPrefix(relpath, "/"))
	if clean == ".." || strings.HasPrefix(clean, "../") ||
		strings.Contains(clean, "/../") || strings.HasPrefix(clean, "/") {
		return nil, 0, ErrNotFound
	}
	if clean != manifest.FileName && !strings.HasPrefix(clean, "content/") && !strings.HasPrefix(clean, "assets/") {
		return nil, 0, ErrNotFound
	}
	rc, err := s.blobs.Open(v.ArchiveBlobSHA256)
	if err != nil {
		return nil, 0, err
	}
	gz, err := gzip.NewReader(rc)
	if err != nil {
		rc.Close()
		return nil, 0, err
	}
	closeAll := func() {
		gz.Close()
		rc.Close()
	}
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			closeAll()
			return nil, 0, err
		}
		if hdr.Typeflag != tar.TypeReg || path.Clean(hdr.Name) != clean {
			continue
		}
		if hdr.Size < 0 || hdr.Size > maxSize {
			closeAll()
			return nil, 0, ErrFileTooLarge
		}
		return &packageFile{r: io.LimitReader(tr, hdr.Size), close: closeAll}, hdr.Size, nil
	}
	closeAll()
	return nil, 0, ErrNotFound
}

// packageFile streams one archive file and closes the archive behind it.
type packageFile struct {
	r     io.Reader
	close func()
}

func (f *packageFile) Read(p []byte) (int, error) { return f.r.Read(p) }

func (f *packageFile) Close() error {
	f.close()
	return nil
}
