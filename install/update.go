package install

import (
	"archive/tar"
	"compress/gzip"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/phishingclub/baitbox/embedded"
	"golang.org/x/mod/semver"
)

// releaseAPI is the GitHub latest release endpoint for the published binary.
const releaseAPI = "https://api.github.com/repos/phishingclub/baitbox/releases/latest"

// update size caps.
const (
	maxReleaseDownload = 128 << 20
	maxReleaseFile     = 128 << 20
)

// ErrNoRelease is returned when GitHub has no published release to check.
var ErrNoRelease = errors.New("no release has been published yet")

// errBadSignature is returned when no embedded key verifies the release binary.
var errBadSignature = errors.New("release signature verification failed")

// verifySignature checks sig over data against the embedded signing keys, so a
// primary and a backup key both validate during rotation.
func verifySignature(data, sig []byte) error {
	return verifySignatureWith(data, sig, embedded.SigningKey1, embedded.SigningKey2)
}

// verifySignatureWith reports whether sig over data verifies against any of the
// given ed25519 public keys.
func verifySignatureWith(data, sig []byte, keys ...[]byte) error {
	for _, key := range keys {
		if len(key) == ed25519.PublicKeySize && ed25519.Verify(ed25519.PublicKey(key), data, sig) {
			return nil
		}
	}
	return errBadSignature
}

type ghAsset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
}

type ghRelease struct {
	TagName string    `json:"tag_name"`
	Assets  []ghAsset `json:"assets"`
}

// Release is the latest published release as seen by the update check.
type Release struct {
	// Tag is the release tag, for example v1.2.3.
	Tag string
	// AssetURL is the download for this machine's architecture, empty when the
	// release has none.
	AssetURL string
	// Newer reports whether Tag is newer than the running version.
	Newer bool
}

// CheckLatest asks GitHub for the latest release and compares it with
// currentVersion. It downloads nothing.
func CheckLatest(currentVersion string) (*Release, error) {
	rel, err := fetchLatestRelease()
	if err != nil {
		return nil, err
	}
	wantSuffix := fmt.Sprintf("_linux_%s.tar.gz", runtime.GOARCH)
	out := &Release{Tag: rel.TagName, Newer: releaseIsNewer(rel.TagName, currentVersion)}
	for _, a := range rel.Assets {
		if strings.HasSuffix(a.Name, wantSuffix) {
			out.AssetURL = a.URL
			break
		}
	}
	return out, nil
}

// FetchVerified downloads the release for this architecture and returns the
// binary only if its signature verifies against an embedded key and the release
// is newer than currentVersion.
func FetchVerified(rel *Release, currentVersion string) ([]byte, error) {
	if !releaseIsNewer(rel.Tag, currentVersion) {
		return nil, fmt.Errorf("release %s is not newer than %s", rel.Tag, currentVersion)
	}
	if rel.AssetURL == "" {
		return nil, fmt.Errorf("no release asset for linux/%s", runtime.GOARCH)
	}
	archive, err := download(rel.AssetURL)
	if err != nil {
		return nil, err
	}
	binary, sig, err := extractBinaryAndSig(archive)
	if err != nil {
		return nil, err
	}
	if err := verifySignature(binary, sig); err != nil {
		return nil, err
	}
	return binary, nil
}

// InstalledAsService reports whether this process is the binary the installer
// placed, started by systemd, and able to replace itself. Only then can an
// update run from inside the app: the new binary is swapped in and systemd
// starts it again after the process exits.
func InstalledAsService() bool {
	exe, err := os.Executable()
	if err != nil {
		return false
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	if exe != filepath.Join(installDir, binaryName) {
		return false
	}
	// systemd sets INVOCATION_ID for every unit it starts.
	if os.Getenv("INVOCATION_ID") == "" {
		return false
	}
	// 2 is W_OK: the service user must be able to write the install directory.
	return syscall.Access(installDir, 2) == nil
}

// ApplyInApp swaps in a verified binary from inside the running service. The
// caller then exits the process so systemd starts the new binary.
func ApplyInApp(binary []byte) error {
	if !InstalledAsService() {
		return fmt.Errorf("not running as the installed service")
	}
	return replaceBinary(binary)
}

// Update fetches the latest signed release, verifies it against the embedded
// keys, refuses a downgrade, swaps the installed binary atomically and restarts
// the service. currentVersion is the running build version used for the
// downgrade guard. When no release is newer it does nothing.
func Update(currentVersion string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("update must be run as root")
	}
	if err := checkServiceExists(); err != nil {
		return fmt.Errorf("service check failed: %w", err)
	}

	rel, err := CheckLatest(currentVersion)
	if err != nil {
		return err
	}
	if !rel.Newer {
		fmt.Printf("already up to date (installed %s, latest %s)\n", currentVersion, rel.Tag)
		return nil
	}
	binary, err := FetchVerified(rel, currentVersion)
	if err != nil {
		return err
	}
	if err := replaceBinary(binary); err != nil {
		return err
	}
	// run as root here, so hand the new files back to the service user.
	if err := setPermissions(); err != nil {
		return err
	}
	fmt.Printf("updated to %s, restarting service\n", rel.Tag)
	return exec.Command("systemctl", "restart", serviceName).Run()
}

// releaseIsNewer reports whether tag is a strictly newer semver than current.
// Non semver current (for example "dev") always allows the update.
func releaseIsNewer(tag, current string) bool {
	t := ensureV(tag)
	c := ensureV(current)
	if !semver.IsValid(t) {
		return false
	}
	if !semver.IsValid(c) {
		return true
	}
	return semver.Compare(t, c) > 0
}

func ensureV(s string) string {
	if s == "" {
		return s
	}
	if s[0] != 'v' {
		return "v" + s
	}
	return s
}

func fetchLatestRelease() (*ghRelease, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(releaseAPI)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrNoRelease
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("release api status %d", resp.StatusCode)
	}
	var rel ghRelease
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&rel); err != nil {
		return nil, err
	}
	return &rel, nil
}

func download(url string) ([]byte, error) {
	client := &http.Client{Timeout: 3 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download status %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxReleaseDownload+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxReleaseDownload {
		return nil, fmt.Errorf("release exceeds size limit")
	}
	return data, nil
}

// extractBinaryAndSig reads the release tar.gz and returns the binary and its
// detached .sig, which are the only files allowed in the archive.
func extractBinaryAndSig(archive []byte) (binary, sig []byte, err error) {
	gz, err := gzip.NewReader(strings.NewReader(string(archive)))
	if err != nil {
		return nil, nil, err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, err
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		b, err := io.ReadAll(io.LimitReader(tr, maxReleaseFile+1))
		if err != nil {
			return nil, nil, err
		}
		base := filepath.Base(hdr.Name)
		switch {
		case strings.HasSuffix(base, ".sig"):
			sig = b
		case base == binaryName:
			binary = b
		}
	}
	if binary == nil || sig == nil {
		return nil, nil, fmt.Errorf("release archive missing binary or signature")
	}
	return binary, sig, nil
}

// replaceBinary writes the new binary beside the old one and renames it into
// place, keeping a backup and restoring it on failure.
func replaceBinary(binary []byte) error {
	dest := filepath.Join(installDir, binaryName)
	backup := dest + ".backup"
	if cur, err := os.ReadFile(dest); err == nil {
		_ = os.WriteFile(backup, cur, 0o600)
	}
	tmp := dest + ".new"
	if err := os.WriteFile(tmp, binary, 0o750); err != nil {
		return err
	}
	if err := os.Rename(tmp, dest); err != nil {
		if cur, rerr := os.ReadFile(backup); rerr == nil {
			_ = os.WriteFile(dest, cur, 0o750)
		}
		return err
	}
	return nil
}
