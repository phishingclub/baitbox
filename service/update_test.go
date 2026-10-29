package service

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/phishingclub/baitbox/install"
)

// fakeUpdates returns an UpdateService whose steps are recorded fakes.
func fakeUpdates(rel *install.Release, inApp bool) (*UpdateService, *[]string) {
	calls := &[]string{}
	var mu sync.Mutex
	rec := func(s string) { mu.Lock(); *calls = append(*calls, s); mu.Unlock() }
	now := time.Unix(1_800_000_000, 0)
	s := &UpdateService{
		current: "1.0.0",
		check:   func(string) (*install.Release, error) { rec("check"); return rel, nil },
		fetch:   func(*install.Release, string) ([]byte, error) { rec("fetch"); return []byte("bin"), nil },
		apply:   func([]byte) error { rec("apply"); return nil },
		inApp:   func() bool { return inApp },
		exit:    func() { rec("exit") },
		now:     func() time.Time { return now },
	}
	return s, calls
}

func TestUpdateCheckStoresStatusAndThrottles(t *testing.T) {
	s, calls := fakeUpdates(&install.Release{Tag: "v1.1.0", Newer: true}, false)
	st := s.Check()
	if !st.UpdateAvailable || st.LatestVersion != "v1.1.0" || st.CurrentVersion != "1.0.0" || st.CheckedAt == nil {
		t.Fatalf("status after check: %+v", st)
	}
	if st.UpdateInApp || st.ManualCommand == "" {
		t.Fatalf("not in app install must show the manual command: %+v", st)
	}
	s.Check()
	if len(*calls) != 1 {
		t.Fatalf("a repeat check within the gap asked GitHub again: %v", *calls)
	}
}

func TestUpdateCheckFailureKeepsLastRelease(t *testing.T) {
	s, _ := fakeUpdates(&install.Release{Tag: "v1.1.0", Newer: true}, false)
	s.Check()
	s.check = func(string) (*install.Release, error) { return nil, errors.New("offline") }
	later := time.Unix(1_800_001_000, 0)
	s.now = func() time.Time { return later }
	st := s.Check()
	if st.Error == "" || !st.UpdateAvailable || st.LatestVersion != "v1.1.0" {
		t.Fatalf("failed check lost the known release: %+v", st)
	}
}

func TestUpdateRun(t *testing.T) {
	s, _ := fakeUpdates(&install.Release{Tag: "v1.1.0", Newer: true}, false)
	if _, err := s.Run(); !errors.Is(err, ErrUpdateNotInApp) {
		t.Fatalf("run outside the service: got %v", err)
	}

	s, _ = fakeUpdates(&install.Release{Tag: "v1.0.0", Newer: false}, true)
	if _, err := s.Run(); !errors.Is(err, ErrNoUpdate) {
		t.Fatalf("run with nothing newer: got %v", err)
	}

	s, _ = fakeUpdates(&install.Release{Tag: "v1.1.0", Newer: true}, true)
	s.fetch = func(*install.Release, string) ([]byte, error) {
		return nil, errors.New("release signature verification failed")
	}
	applied := false
	s.apply = func([]byte) error { applied = true; return nil }
	if _, err := s.Run(); err == nil || applied {
		t.Fatalf("bad signature must stop before the swap: err=%v applied=%v", err, applied)
	}

	s, calls := fakeUpdates(&install.Release{Tag: "v1.1.0", Newer: true}, true)
	done := make(chan struct{})
	s.exit = func() { close(done) }
	tag, err := s.Run()
	if err != nil || tag != "v1.1.0" {
		t.Fatalf("run: tag=%q err=%v", tag, err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("process was not asked to exit after the swap")
	}
	if got := *calls; len(got) != 3 || got[0] != "check" || got[1] != "fetch" || got[2] != "apply" {
		t.Fatalf("steps out of order: %v", got)
	}

	s, _ = fakeUpdates(&install.Release{Tag: "v1.1.0", Newer: true}, true)
	s.runMu.Lock()
	if _, err := s.Run(); !errors.Is(err, ErrUpdateRunning) {
		t.Fatalf("second concurrent run: got %v", err)
	}
	s.runMu.Unlock()
}

func TestUpdateCheckNoReleaseIsNotAnError(t *testing.T) {
	s, _ := fakeUpdates(nil, false)
	s.check = func(string) (*install.Release, error) { return nil, install.ErrNoRelease }
	st := s.Check()
	if st.Error != "" || st.UpdateAvailable || st.CheckedAt == nil {
		t.Fatalf("no published release should read as up to date: %+v", st)
	}
}
