package service

import (
	"log"
	"sync"
	"time"

	"github.com/phishingclub/baitbox/config"
)

// AdminAccess turns the admin listener off from inside the app. It writes
// administration.disabled to the config file, so the admin stays off after a
// restart until someone with access to the server changes the file or runs
// -enable-admin.
type AdminAccess struct {
	configPath string
	stop       chan struct{}
	once       sync.Once
	// delay lets the reply reach the browser before the listener closes.
	delay time.Duration
}

// NewAdminAccess returns the service for the config file at configPath.
func NewAdminAccess(configPath string) *AdminAccess {
	return &AdminAccess{configPath: configPath, stop: make(chan struct{}), delay: time.Second}
}

// Stopped is closed when the admin listener must close.
func (a *AdminAccess) Stopped() <-chan struct{} { return a.stop }

// Disable writes the config key and then closes the admin listener. Nothing
// changes when the config file cannot be written.
func (a *AdminAccess) Disable() error {
	if err := config.SetAdminDisabled(a.configPath, true); err != nil {
		return err
	}
	go func() {
		time.Sleep(a.delay)
		a.once.Do(func() {
			log.Printf("admin access disabled; closing the admin listener, the registry keeps serving")
			close(a.stop)
		})
	}()
	return nil
}
