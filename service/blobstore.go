package service

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sync"
)

// ErrBlobTooLarge is returned when an upload exceeds the configured cap.
var ErrBlobTooLarge = errors.New("blob exceeds size limit")

// ErrInvalidSHA is returned when a blob is referenced by a name that is not a
// sha256, so the name can never be joined into a path outside the store.
var ErrInvalidSHA = errors.New("invalid blob reference")

// shaRe is the only shape a blob name may take: 64 lowercase hex characters.
var shaRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// BlobStore is a content addressed file store on disk. A blob is named by the
// hex sha256 of its bytes and stored at root/<first2>/<sha256>, so identical
// content (a shared asset across packages) is stored once.
//
// Because content is shared, a blob one operation is about to reference can look
// unreferenced to a cleanup running at the same time (the file exists but the row
// that points at it is not written yet). Put therefore pins the blob it returns,
// the caller calls Release once its row is committed or abandoned, and
// RemoveIfUnreferenced never removes a pinned blob. mu makes the pin, the dedupe
// check and the remove one step each.
type BlobStore struct {
	root string
	mu   sync.Mutex
	pins map[string]int
}

// NewBlobStore creates the store root and returns a BlobStore.
func NewBlobStore(root string) (*BlobStore, error) {
	if err := os.MkdirAll(root, 0o750); err != nil {
		return nil, err
	}
	return &BlobStore{root: root, pins: map[string]int{}}, nil
}

// Path returns the file path on disk for a sha256. A name that is not a sha256
// is rejected so it can never resolve to a file outside the store.
func (b *BlobStore) Path(sha string) (string, error) {
	if !shaRe.MatchString(sha) {
		return "", ErrInvalidSHA
	}
	return b.path(sha), nil
}

// path joins a sha the caller already checked against shaRe into its file path.
func (b *BlobStore) path(sha string) string {
	return filepath.Join(b.root, sha[:2], sha)
}

// Exists reports whether a blob is present.
func (b *BlobStore) Exists(sha string) bool {
	if !shaRe.MatchString(sha) {
		return false
	}
	_, err := os.Stat(b.path(sha))
	return err == nil
}

// Size returns the byte size of a stored blob.
func (b *BlobStore) Size(sha string) (int64, error) {
	if !shaRe.MatchString(sha) {
		return 0, fmt.Errorf("invalid blob name")
	}
	fi, err := os.Stat(b.path(sha))
	if err != nil {
		return 0, err
	}
	return fi.Size(), nil
}

// Put streams r into the store, hashing as it goes and rejecting input larger
// than maxSize. It returns the sha256 and byte size. Writing is atomic: data
// goes to a temp file and is renamed into place only after the hash is known.
// An existing blob with the same hash is left untouched (dedupe). On success the
// returned sha is pinned and the caller must call Release for it exactly once.
func (b *BlobStore) Put(r io.Reader, maxSize int64) (sha string, size int64, err error) {
	tmp, err := os.CreateTemp(b.root, ".upload-*")
	if err != nil {
		return "", 0, err
	}
	tmpName := tmp.Name()
	defer func() {
		tmp.Close()
		if _, statErr := os.Stat(tmpName); statErr == nil {
			_ = os.Remove(tmpName)
		}
	}()

	h := sha256.New()
	// read one byte past the cap so an input over the limit is detected exactly.
	limited := io.LimitReader(r, maxSize+1)
	n, err := io.Copy(io.MultiWriter(tmp, h), limited)
	if err != nil {
		return "", 0, err
	}
	if n > maxSize {
		return "", 0, ErrBlobTooLarge
	}
	if err := tmp.Close(); err != nil {
		return "", 0, err
	}

	sha = hex.EncodeToString(h.Sum(nil))
	dest := b.path(sha)
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.Exists(sha) {
		if err := os.MkdirAll(filepath.Dir(dest), 0o750); err != nil {
			return "", 0, err
		}
		if err := os.Rename(tmpName, dest); err != nil {
			return "", 0, fmt.Errorf("store blob: %w", err)
		}
	}
	b.pins[sha]++
	return sha, n, nil
}

// Release drops one pin taken by Put. Call it after the row that references the
// blob is committed, or after the operation gave up on it.
func (b *BlobStore) Release(sha string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.pins[sha] <= 1 {
		delete(b.pins, sha)
		return
	}
	b.pins[sha]--
}

// RemoveIfUnreferenced deletes a blob file when it is not pinned and referenced
// reports that no row uses it. The check and the delete run under the store lock,
// so a Put of the same bytes cannot slip in between them. onRemoved, when set,
// runs under the same lock after the file is gone (used to drop the blob row). It
// reports whether the blob was removed.
func (b *BlobStore) RemoveIfUnreferenced(
	sha string, referenced func(string) (bool, error), onRemoved func(string),
) bool {
	if !shaRe.MatchString(sha) {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.pins[sha] > 0 {
		return false
	}
	ref, err := referenced(sha)
	if err != nil || ref {
		return false
	}
	if err := os.Remove(b.path(sha)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return false
	}
	if onRemoved != nil {
		onRemoved(sha)
	}
	return true
}

// Open returns a reader for a stored blob. A name that is not a sha256 is
// rejected so it can never resolve to a file outside the store.
func (b *BlobStore) Open(sha string) (io.ReadCloser, error) {
	if !shaRe.MatchString(sha) {
		return nil, ErrInvalidSHA
	}
	return os.Open(b.path(sha))
}
