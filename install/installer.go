// Package install manages the baitbox binary as a systemd service. -install
// asks for the settings interactively (interactive.go), -install-non-interactive
// lays down a config template to edit, -reinstall overwrites the binary, unit
// and config while keeping the data, and -uninstall removes it all. The signed
// download based update that -update runs lives in update.go.
package install

import (
	"bufio"
	"bytes"
	"embed"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/phishingclub/baitbox/config"
)

//go:embed systemd.service config.template.json
var installFiles embed.FS

const (
	installDir = "/opt/baitbox"
	binaryName = "baitbox"
	dataDir    = "data"
	configName = "config.json"

	serviceUser  = "baitbox"
	serviceGroup = "baitbox"
	serviceName  = "baitbox"
)

// ConfigPath is where the installed service reads its config.
func ConfigPath() string { return filepath.Join(installDir, configName) }

// RequireRoot fails unless the process runs as root.
func RequireRoot(action string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("%s must be run as root", action)
	}
	return nil
}

// IsInstalled reports whether the systemd unit is present.
func IsInstalled() bool { return checkServiceExists() == nil }

// InstalledConfig returns the current installed config, or an error when it is
// missing or cannot be read.
func InstalledConfig() (*config.Config, error) {
	return config.Load(ConfigPath())
}

// ConfirmDefaultConfig shows why the installed config could not be read and
// returns true only when the operator types YES to start from the defaults.
func ConfirmDefaultConfig(loadErr error) bool {
	fmt.Printf("\nThe installed config %s could not be read:\n  %v\n", ConfigPath(), loadErr)
	fmt.Println("Continuing starts the questions from the default settings, so these reset:")
	fmt.Println("  the database path, which can point the service at a new empty database")
	fmt.Println("  a disabled admin UI, which comes back on")
	fmt.Println("Fix or restore the file and run the reinstall again to keep them.")
	fmt.Print("\nType 'YES' (all caps) to replace it with the defaults: ")
	return readTTYLine() == "YES"
}

// Setup lays down the service user, directories, binary, the given config and
// the unit file. It overwrites an existing config. The service is not started;
// call Finish after seeding the database.
func Setup(cfg *config.Config) error {
	steps := []struct {
		name string
		fn   func() error
	}{
		{"create user and group", createUserAndGroup},
		{"create directories", createDirectories},
		{"install binary", installBinary},
		{"write config", func() error { return cfg.WriteFile(ConfigPath()) }},
		{"install systemd service", installSystemdService},
	}
	return runSteps(steps)
}

// Finish hands the install directory to the service user, then enables and
// starts the service.
func Finish() error {
	return runSteps([]struct {
		name string
		fn   func() error
	}{
		{"set permissions", setPermissions},
		{"enable service", enableService},
		{"start service", startService},
	})
}

// StopService stops the running service, ignoring a service that is not running.
func StopService() {
	_ = exec.Command("systemctl", "stop", serviceName).Run()
}

// RestartService restarts the installed service so it reads its config again.
func RestartService() error {
	if out, err := exec.Command("systemctl", "restart", serviceName).CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl restart %s: %v: %s", serviceName, err, out)
	}
	return nil
}

func runSteps(steps []struct {
	name string
	fn   func() error
}) error {
	for _, step := range steps {
		fmt.Printf("Step: %s\n", step.name)
		if err := step.fn(); err != nil {
			return fmt.Errorf("%s: %w", step.name, err)
		}
	}
	return nil
}

// ConfirmReinstall explains what a reinstall replaces and keeps, and returns
// true only when the operator types YES. It reads the terminal directly, so it
// works when stdin is the piped install script.
func ConfirmReinstall() bool {
	fmt.Println("WARNING: reinstalling Bait Box OVERWRITES:")
	fmt.Println("  the application binary")
	fmt.Println("  the systemd unit file")
	fmt.Printf("  the configuration file %s, including any manual edits\n", ConfigPath())
	fmt.Println("It KEEPS all data: the database, operators, packages, blobs and certificates.")
	fmt.Println("The service keeps running while you answer the questions and is stopped after.")
	fmt.Print("\nType 'YES' (all caps) to confirm reinstallation: ")
	return readTTYLine() == "YES"
}

// readTTYLine reads one line from the terminal, falling back to stdin.
func readTTYLine() string {
	in := os.Stdin
	if tty, err := os.Open("/dev/tty"); err == nil {
		defer tty.Close()
		in = tty
	}
	line, _ := bufio.NewReader(in).ReadString('\n')
	return strings.TrimSpace(line)
}

// InstallNonInteractive lays down the binary, a config template, the service
// user and unit file, then enables and starts the service. It must run as root.
// The template holds placeholders the operator edits before restarting. The
// sqlite driver is compiled into the binary, so there is no host sqlite
// dependency.
func InstallNonInteractive() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("installation must be run as root")
	}
	steps := []struct {
		name string
		fn   func() error
	}{
		{"create user and group", createUserAndGroup},
		{"create directories", createDirectories},
		{"install binary", installBinary},
		{"install config", installConfig},
		{"install systemd service", installSystemdService},
		{"set permissions", setPermissions},
		{"enable service", enableService},
		{"start service", startService},
	}
	for _, step := range steps {
		fmt.Printf("Step: %s\n", step.name)
		if err := step.fn(); err != nil {
			return fmt.Errorf("%s: %w", step.name, err)
		}
	}
	configPath := filepath.Join(installDir, configName)
	fmt.Println()
	fmt.Println("Installer completed successfully!")
	fmt.Println()
	fmt.Printf("Edit %s to set your hosts and ACME email,\n", configPath)
	fmt.Printf("then restart with: systemctl restart %s\n", serviceName)
	fmt.Println()
	fmt.Printf("'journalctl -u %s.service -f' to follow the logs\n", serviceName)
	fmt.Printf("'systemctl status %s' to check the service state\n", serviceName)
	return nil
}

// Uninstall removes every installed component after an interactive confirmation.
func Uninstall() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("uninstallation must be run as root")
	}
	fmt.Println("WARNING: uninstallation removes ALL components of Bait Box, including:")
	fmt.Println("  the application binary and its service")
	fmt.Println("  the configuration file")
	fmt.Println("  ALL data: the database, content blobs and certificates")
	fmt.Println("  the baitbox user and group")
	fmt.Println("\nThis operation CANNOT be undone!")
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("\nType 'YES' (all caps) to confirm uninstallation: ")
	confirmation, _ := reader.ReadString('\n')
	if strings.TrimSpace(confirmation) != "YES" {
		fmt.Println("Uninstallation cancelled.")
		return fmt.Errorf("uninstallation cancelled by user")
	}
	return performUninstall()
}

// UninstallNonInteractive removes every installed component without prompting.
func UninstallNonInteractive() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("uninstallation must be run as root")
	}
	return performUninstall()
}

func checkServiceExists() error {
	servicePath := filepath.Join("/etc/systemd/system", serviceName+".service")
	if _, err := os.Stat(servicePath); os.IsNotExist(err) {
		return fmt.Errorf("service is not installed, run --install first")
	}
	return nil
}

func enableService() error {
	if err := exec.Command("systemctl", "enable", serviceName).Run(); err != nil {
		return fmt.Errorf("failed to enable service: %w", err)
	}
	return nil
}

func startService() error {
	if err := exec.Command("systemctl", "start", serviceName).Run(); err != nil {
		return fmt.Errorf("failed to start service: %w", err)
	}
	return nil
}

func performUninstall() error {
	fmt.Println("Uninstalling Bait Box...")
	if err := exec.Command("systemctl", "stop", serviceName).Run(); err != nil {
		fmt.Printf("Warning: failed to stop service: %v\n", err)
	}
	if err := exec.Command("systemctl", "disable", serviceName).Run(); err != nil {
		fmt.Printf("Warning: failed to disable service: %v\n", err)
	}
	servicePath := filepath.Join("/etc/systemd/system", serviceName+".service")
	if err := os.Remove(servicePath); err != nil && !os.IsNotExist(err) {
		fmt.Printf("Warning: failed to remove service unit file: %v\n", err)
	}
	if err := exec.Command("systemctl", "daemon-reload").Run(); err != nil {
		fmt.Printf("Warning: failed to reload systemd daemon: %v\n", err)
	}
	if err := os.RemoveAll(installDir); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove install directory: %w", err)
	}
	fmt.Printf("Removing user and group: %s\n", serviceUser)
	if err := exec.Command("userdel", serviceUser).Run(); err != nil {
		fmt.Printf("Warning: failed to delete user %s: %v\n", serviceUser, err)
	}
	_ = exec.Command("groupdel", serviceGroup).Run()
	fmt.Println("\nUninstallation completed successfully!")
	return nil
}

func createUserAndGroup() error {
	if err := exec.Command("getent", "group", serviceGroup).Run(); err != nil {
		if err := exec.Command("groupadd", serviceGroup).Run(); err != nil {
			return fmt.Errorf("failed to create group: %w", err)
		}
	}
	if err := exec.Command("getent", "passwd", serviceUser).Run(); err != nil {
		cmd := exec.Command("useradd", "-r", "-g", serviceGroup, "-s", "/bin/false",
			"-m", "-d", "/var/lib/"+serviceUser, serviceUser)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to create user: %w", err)
		}
	}
	return nil
}

func createDirectories() error {
	dirs := []string{
		installDir,
		filepath.Join(installDir, dataDir),
		filepath.Join(installDir, dataDir, "certs"),
		filepath.Join(installDir, dataDir, "blobs"),
	}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0750); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}
	return nil
}

func installBinary() error {
	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}
	binaryPath := filepath.Join(installDir, binaryName)
	if resolved, err := filepath.EvalSymlinks(executable); err == nil {
		executable = resolved
	}
	if executable == binaryPath {
		// a reinstall run from the installed binary: it is already in place.
		return nil
	}
	input, err := os.ReadFile(executable)
	if err != nil {
		return fmt.Errorf("failed to read executable: %w", err)
	}
	// write beside it and rename, so a binary that is still mapped is replaced
	// instead of rewritten in place.
	tmp := binaryPath + ".new"
	if err := os.WriteFile(tmp, input, 0750); err != nil {
		return fmt.Errorf("failed to write binary: %w", err)
	}
	if err := os.Rename(tmp, binaryPath); err != nil {
		return fmt.Errorf("failed to place binary: %w", err)
	}
	return nil
}

func installConfig() error {
	configPath := filepath.Join(installDir, configName)
	if _, err := os.Stat(configPath); err == nil {
		fmt.Printf("Config already exists at %s, leaving it untouched\n", configPath)
		return nil
	}
	tmpl, err := installFiles.ReadFile("config.template.json")
	if err != nil {
		return fmt.Errorf("failed to read config template: %w", err)
	}
	if err := os.WriteFile(configPath, tmpl, 0640); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}
	return nil
}

func installSystemdService() error {
	serviceTemplate, err := installFiles.ReadFile("systemd.service")
	if err != nil {
		return fmt.Errorf("failed to read service template: %w", err)
	}
	data := struct {
		User       string
		Group      string
		InstallDir string
		BinaryPath string
		ConfigPath string
	}{
		User:       serviceUser,
		Group:      serviceGroup,
		InstallDir: installDir,
		BinaryPath: filepath.Join(installDir, binaryName),
		ConfigPath: filepath.Join(installDir, configName),
	}
	tmpl, err := template.New("service").Parse(string(serviceTemplate))
	if err != nil {
		return fmt.Errorf("failed to parse service template: %w", err)
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return fmt.Errorf("failed to execute service template: %w", err)
	}
	servicePath := filepath.Join("/etc/systemd/system", serviceName+".service")
	if err := os.WriteFile(servicePath, buf.Bytes(), 0644); err != nil {
		return fmt.Errorf("failed to write service file: %w", err)
	}
	if err := exec.Command("systemctl", "daemon-reload").Run(); err != nil {
		return fmt.Errorf("failed to reload systemd: %w", err)
	}
	return nil
}

func setPermissions() error {
	cmd := exec.Command("chown", "-R", fmt.Sprintf("%s:%s", serviceUser, serviceGroup), installDir)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set ownership: %w", err)
	}
	return nil
}
