package service

import (
	"errors"
	"log"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/phishingclub/baitbox/install"
)

// updateCheckInterval is how often the background check asks GitHub for a
// newer release.
const updateCheckInterval = 6 * time.Hour

// updateCheckMinGap stops a manual check from asking GitHub more often than
// this; a quicker repeat gets the stored result.
const updateCheckMinGap = 30 * time.Second

// updateManualCommand is what an operator runs on the server when the update
// cannot run from inside the app.
const updateManualCommand = "sudo /opt/baitbox/baitbox -update"

// ErrUpdateRunning is returned when an update is already in progress.
var ErrUpdateRunning = errors.New("an update is already running")

// ErrNoUpdate is returned when there is no newer release to install.
var ErrNoUpdate = errors.New("no newer release is available")

// ErrUpdateNotInApp is returned when this install cannot update itself.
var ErrUpdateNotInApp = errors.New("this install cannot update from the app; run the update command on the server")

// UpdateStatus is the stored result of the last release check.
type UpdateStatus struct {
	CurrentVersion  string     `json:"currentVersion"`
	LatestVersion   string     `json:"latestVersion"`
	UpdateAvailable bool       `json:"updateAvailable"`
	UpdateInApp     bool       `json:"updateInApp"`
	CheckedAt       *time.Time `json:"checkedAt"`
	Error           string     `json:"error"`
	ManualCommand   string     `json:"manualCommand"`
}

// UpdateService checks GitHub for newer signed releases in the background and
// installs one on request when running as the installed systemd service.
type UpdateService struct {
	current string

	// the steps are fields so tests can replace them.
	check  func(current string) (*install.Release, error)
	fetch  func(rel *install.Release, current string) ([]byte, error)
	apply  func(binary []byte) error
	inApp  func() bool
	exit   func()
	now    func() time.Time
	runMu  sync.Mutex
	mu     sync.Mutex
	status UpdateStatus
}

// NewUpdateService builds the service for the running version.
func NewUpdateService(currentVersion string) *UpdateService {
	return &UpdateService{
		current: currentVersion,
		check:   install.CheckLatest,
		fetch:   install.FetchVerified,
		apply:   install.ApplyInApp,
		inApp:   install.InstalledAsService,
		exit:    exitForRestart,
		now:     time.Now,
	}
}

// exitForRestart stops the process so systemd starts the new binary. It runs
// shortly after the update reply is sent.
func exitForRestart() {
	time.Sleep(time.Second)
	log.Printf("exiting so systemd starts the updated binary")
	_ = syscall.Kill(os.Getpid(), syscall.SIGTERM)
}

// StartBackgroundCheck checks for a release shortly after startup and then on
// a fixed interval, for the life of the process.
func (s *UpdateService) StartBackgroundCheck() {
	go func() {
		time.Sleep(time.Minute)
		for {
			s.Check()
			time.Sleep(updateCheckInterval)
		}
	}()
}

// Status returns the stored result of the last check without asking GitHub.
func (s *UpdateService) Status() UpdateStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.status
	st.CurrentVersion = s.current
	st.UpdateInApp = s.inApp()
	st.ManualCommand = updateManualCommand
	return st
}

// Check asks GitHub for the latest release now, unless the last check was
// very recent, and returns the new status.
func (s *UpdateService) Check() UpdateStatus {
	s.mu.Lock()
	recent := s.status.CheckedAt != nil && s.now().Sub(*s.status.CheckedAt) < updateCheckMinGap
	s.mu.Unlock()
	if recent {
		return s.Status()
	}

	rel, err := s.check(s.current)
	now := s.now()
	s.mu.Lock()
	s.status.CheckedAt = &now
	if errors.Is(err, install.ErrNoRelease) {
		s.status.Error = ""
		s.status.LatestVersion = ""
		s.status.UpdateAvailable = false
	} else if err != nil {
		// keep the last known release so one failed check does not hide it.
		s.status.Error = "could not reach GitHub to check for updates"
		log.Printf("update check failed: %v", err)
	} else {
		s.status.Error = ""
		s.status.LatestVersion = rel.Tag
		s.status.UpdateAvailable = rel.Newer
	}
	s.mu.Unlock()
	return s.Status()
}

// Run downloads, verifies and installs the latest release, then exits the
// process so systemd starts it. It returns the installed tag. Only one update
// runs at a time.
func (s *UpdateService) Run() (string, error) {
	if !s.inApp() {
		return "", ErrUpdateNotInApp
	}
	if !s.runMu.TryLock() {
		return "", ErrUpdateRunning
	}
	defer s.runMu.Unlock()

	// always ask GitHub again, so the install uses the current latest release.
	rel, err := s.check(s.current)
	if err != nil {
		return "", err
	}
	if !rel.Newer {
		return "", ErrNoUpdate
	}
	binary, err := s.fetch(rel, s.current)
	if err != nil {
		return "", err
	}
	if err := s.apply(binary); err != nil {
		return "", err
	}
	log.Printf("updated to %s", rel.Tag)
	go s.exit()
	return rel.Tag, nil
}
