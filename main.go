// Command baitbox is the content registry server for Phishing Club.
//
// Lifecycle flags are handled and the process returns before normal startup.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/phishingclub/baitbox/config"
	"github.com/phishingclub/baitbox/database"
	"github.com/phishingclub/baitbox/install"
	"github.com/phishingclub/baitbox/repository"
	"github.com/phishingclub/baitbox/server"
	"github.com/phishingclub/baitbox/service"
	"gorm.io/gorm"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	configPath := flag.String("config", "config.json", "path to config file")
	flagVersion := flag.Bool("version", false, "print the version and exit")
	flagInstall := flag.Bool("install", false,
		"install as a systemd service, asking for the settings interactively")
	flagInstallNonInteractive := flag.Bool("install-non-interactive", false,
		"install as a systemd service with a config template to edit afterwards")
	flagReinstall := flag.Bool("reinstall", false,
		"overwrite the installed binary, unit and config (asks again, keeps all data) after confirmation")
	flagConfigOnly := flag.Bool("config-only", false,
		"ask for the settings interactively and write them to -config without installing")
	flagUpdate := flag.Bool("update", false, "update the installed binary and restart the service")
	flagUninstall := flag.Bool("uninstall", false, "uninstall the service with a confirmation prompt")
	flagUninstallNonInteractive := flag.Bool("uninstall-non-interactive", false,
		"uninstall the service without a confirmation prompt")
	flagResetAdmin := flag.Bool("reset-admin", false,
		"reset the first operator's password (or -username's) and print new credentials")
	flagUsername := flag.String("username", "", "with -reset-admin, the operator to reset")
	flagResetMFA := flag.String("reset-mfa", "",
		"clear the named operator's two factor and passkeys and sign it out, for account recovery")
	flagDisableAdmin := flag.Bool("disable-admin", false,
		"turn off the admin UI and API (sets administration.disabled in the config "+
			"and restarts the installed service)")
	flagEnableAdmin := flag.Bool("enable-admin", false,
		"turn the admin UI and API back on (clears administration.disabled "+
			"and restarts the installed service)")
	flag.Parse()

	// commands run against the installed service use its config unless -config
	// is given.
	configSet := false
	flag.Visit(func(f *flag.Flag) { configSet = configSet || f.Name == "config" })
	againstService := *flagResetAdmin || *flagResetMFA != "" || *flagDisableAdmin || *flagEnableAdmin
	if againstService && !configSet && install.IsInstalled() {
		*configPath = install.ConfigPath()
	}

	if *flagVersion {
		log.Printf("baitbox version %s", version)
		return
	}

	switch {
	case *flagInstall:
		if err := runInstall(false); err != nil {
			log.Fatalf("install: %v", err)
		}
		return
	case *flagReinstall:
		if err := runInstall(true); err != nil {
			log.Fatalf("reinstall: %v", err)
		}
		return
	case *flagInstallNonInteractive:
		if err := install.InstallNonInteractive(); err != nil {
			log.Fatalf("install: %v", err)
		}
		return
	case *flagConfigOnly:
		base := install.DefaultConfig()
		if existing, err := config.Load(*configPath); err == nil {
			base = existing
		}
		cfg, ok, err := install.AskConfig("Bait Box configuration", base)
		if err != nil {
			log.Fatalf("config-only: %v", err)
		}
		if !ok {
			fmt.Println("Cancelled, nothing written.")
			return
		}
		if err := cfg.WriteFile(*configPath); err != nil {
			log.Fatalf("config-only: %v", err)
		}
		fmt.Printf("Configuration written to %s\n", *configPath)
		return
	case *flagUpdate:
		// signed download based update: verifies the release against the
		// embedded Ed25519 keys and refuses a downgrade. See install/update.go.
		if err := install.Update(version); err != nil {
			log.Fatalf("update: %v", err)
		}
		return
	case *flagUninstall:
		if err := install.Uninstall(); err != nil {
			log.Fatalf("uninstall: %v", err)
		}
		return
	case *flagUninstallNonInteractive:
		if err := install.UninstallNonInteractive(); err != nil {
			log.Fatalf("uninstall: %v", err)
		}
		return
	case *flagDisableAdmin, *flagEnableAdmin:
		if *flagDisableAdmin && *flagEnableAdmin {
			log.Fatalf("use -disable-admin or -enable-admin, not both")
		}
		if err := setAdminAccess(*configPath, *flagEnableAdmin); err != nil {
			log.Fatalf("admin access: %v", err)
		}
		return
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	db, err := database.Open(cfg.Database.Path)
	if err != nil {
		log.Fatalf("database: %v", err)
	}

	if *flagResetAdmin {
		username, password, err := service.NewOperatorService(repository.NewOperatorRepository(db)).
			ResetOperatorAudited(service.NewCLIAuditService(), *flagUsername)
		if err != nil {
			log.Fatalf("reset-admin: %v", err)
		}
		printInitialCredentials("Reset operator credentials"+passwordChangeNote(cfg), username, password)
		return
	}

	if *flagResetMFA != "" {
		if err := resetMFA(db, *flagResetMFA); err != nil {
			log.Fatalf("reset-mfa: %v", err)
		}
		return
	}

	operators := service.NewOperatorService(repository.NewOperatorRepository(db))
	username, password, created, err := operators.EnsureOperator()
	if err != nil {
		log.Fatalf("seed operator: %v", err)
	}
	if created {
		// the one time credentials go to stdout only, which is the journal under
		// systemd and the container log in dev. They are never written to a file.
		printInitialCredentials("One time operator credentials"+passwordChangeNote(cfg), username, password)
	}

	engines, err := server.New(cfg, *configPath, db, version)
	if err != nil {
		log.Fatalf("server: %v", err)
	}

	adminOn := cfg.Administration.Address
	if cfg.Administration.Disabled {
		adminOn = "nothing (disabled)"
	}
	log.Printf("baitbox version %s serving in %s mode, registry on %s, admin on %s",
		version, cfg.Env, cfg.Registry.Address, adminOn)
	// SIGTERM comes from systemctl stop or restart and from the in app update,
	// SIGINT from Ctrl+C. Either one stops the listeners, lets requests in flight
	// finish, then closes the database so its WAL is written back to the main file.
	ctx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	// the cleanup job deletes expired sessions every hour. It stops with the same
	// signal and is waited for before the database closes.
	cleanupDone := engines.Cleanup.Start(ctx)
	serveErr := server.Start(ctx, cfg, engines)
	stopSignals()
	// the job stops its database calls when ctx is done, so this wait is short.
	// It is still bounded so a stuck call can never hold up the shutdown.
	select {
	case <-cleanupDone:
	case <-time.After(cleanupStopWait):
		log.Printf("cleanup: job did not stop within %s, closing the database anyway", cleanupStopWait)
	}
	closeDB(db)
	if serveErr != nil {
		log.Printf("server: %v", serveErr)
		os.Exit(1)
	}
	log.Printf("baitbox stopped")
}

// closeDB closes the database connection pool. SQLite writes the WAL back into
// the main database file when the last connection closes.
func closeDB(db *gorm.DB) {
	sqlDB, err := db.DB()
	if err != nil {
		log.Printf("database close: %v", err)
		return
	}
	if err := sqlDB.Close(); err != nil {
		log.Printf("database close: %v", err)
	}
}

// runInstall asks for the settings, lays down the service, seeds the operator
// account and starts the service. A reinstall confirms first, starts from the
// installed config and keeps the data directory, so existing operators stay.
func runInstall(reinstall bool) error {
	if err := install.RequireRoot("installation"); err != nil {
		return err
	}
	base := install.DefaultConfig()
	title := "Bait Box installer"
	if reinstall {
		if !install.IsInstalled() {
			return fmt.Errorf("Bait Box is not installed, run -install")
		}
		if !install.ConfirmReinstall() {
			return fmt.Errorf("reinstallation cancelled")
		}
		installed, err := install.InstalledConfig()
		if err != nil {
			if !install.ConfirmDefaultConfig(err) {
				return fmt.Errorf("reinstallation cancelled, the installed config could not be read: %w", err)
			}
			installed = install.DefaultConfig()
		}
		base = installed
		title = "Bait Box reinstall"
	} else if install.IsInstalled() {
		return fmt.Errorf("Bait Box is already installed; use -reinstall to overwrite it or -update to upgrade")
	}

	// ask everything while the old service still runs, so a failed or cancelled
	// form leaves it as it was.
	cfg, ok, err := install.AskConfig(title, base)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("cancelled")
	}
	if reinstall {
		install.StopService()
	}
	if err := install.Setup(cfg); err != nil {
		return err
	}

	// seed the operator now, as root, so the one time credentials are printed
	// here rather than only in the service log.
	db, err := database.Open(cfg.Database.Path)
	if err != nil {
		return fmt.Errorf("database: %w", err)
	}
	operators := service.NewOperatorService(repository.NewOperatorRepository(db))
	username, password, created, err := operators.EnsureOperator()
	if sqlDB, derr := db.DB(); derr == nil {
		_ = sqlDB.Close()
	}
	if err != nil {
		return fmt.Errorf("seed operator: %w", err)
	}

	if err := install.Finish(); err != nil {
		return err
	}

	fmt.Println()
	fmt.Println("Installer completed successfully!")
	fmt.Println()
	fmt.Printf("Admin UI:      %s\n", cfg.AdminURL())
	fmt.Printf("Registry URL:  %s  (add this in Phishing Club)\n", cfg.RegistryURL())
	if created {
		printInitialCredentials("One time operator credentials"+passwordChangeNote(cfg), username, password)
	} else {
		fmt.Println()
		fmt.Println("Existing operators were kept. Run -reset-admin if you need new credentials.")
		fmt.Println()
	}
	fmt.Printf("Config: %s\n", install.ConfigPath())
	fmt.Println("'journalctl -u baitbox.service -f' to follow the logs")
	fmt.Println("'systemctl status baitbox' to check the service state")
	return nil
}

// resetMFA clears every second factor of the named operator so it can sign in
// with its password alone and enroll again: TOTP is turned off, every passkey is
// deleted and every session is dropped. The password is kept.
func resetMFA(db *gorm.DB, username string) error {
	op, passkeys, err := service.NewOperatorService(repository.NewOperatorRepository(db)).ResetSecondFactors(username)
	if err != nil {
		return err
	}
	service.NewCLIAuditService().Record("Operator.ResetMFA", op.ID, op.Username, "local", true,
		map[string]any{"source": "cli", "totpWasEnabled": op.MFAEnabled, "passkeysRemoved": passkeys})
	fmt.Println()
	was := "off"
	if op.MFAEnabled {
		was = "on"
	}
	fmt.Printf("Second factors cleared for %s\n", op.Username)
	fmt.Println()
	fmt.Printf("Two factor:       turned off (was %s)\n", was)
	fmt.Printf("Passkeys removed: %d\n", passkeys)
	fmt.Println("Sessions:         all signed out")
	fmt.Println()
	fmt.Println("The operator can now sign in with the password alone.")
	fmt.Println()
	return nil
}

// cleanupStopWait is how long shutdown waits for the cleanup job to stop.
const cleanupStopWait = 10 * time.Second

// passwordChangeNote tells whether the issued password must be changed at the
// first login. Only prod forces the change.
func passwordChangeNote(cfg *config.Config) string {
	if cfg.IsProd() {
		return " (you must change the password at first login)"
	}
	return " (dev mode: changing the password at first login is not forced)"
}

// printInitialCredentials prints the operator credentials as a clean multiline
// block (matching the phishingclub installer output), with the username and
// password each on their own labelled line, so they are easy to read and copy
// from a terminal instead of one dense log line.
func printInitialCredentials(header, username, password string) {
	fmt.Println()
	fmt.Println(header)
	fmt.Println()
	fmt.Printf("Username: %s\n", username)
	fmt.Printf("Password: %s\n", password)
	fmt.Println()
}

// setAdminAccess writes administration.disabled to the config and restarts
// the installed service when this config is the one it reads.
func setAdminAccess(configPath string, enable bool) error {
	if _, err := config.Load(configPath); err != nil {
		return err
	}
	if err := config.SetAdminDisabled(configPath, !enable); err != nil {
		return err
	}
	state := "disabled"
	if enable {
		state = "enabled"
	}
	fmt.Printf("Admin access %s in %s\n", state, configPath)
	if !install.IsInstalled() || configPath != install.ConfigPath() {
		fmt.Println("Restart Bait Box for the change to take effect.")
		return nil
	}
	if err := install.RestartService(); err != nil {
		return err
	}
	fmt.Println("Service restarted.")
	return nil
}
