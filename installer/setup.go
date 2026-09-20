//go:build windows

package main

import (
	_ "embed"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

//go:embed payload/DuplicateGuard.exe
var appBinary []byte

const version = "2.1.1"

var (
	user32      = syscall.NewLazyDLL("user32.dll")
	messageBoxW = user32.NewProc("MessageBoxW")
)

func main() {
	uninstall := false
	for _, a := range os.Args[1:] {
		if a == "--uninstall" {
			uninstall = true
		}
	}
	local := os.Getenv("LOCALAPPDATA")
	if local == "" {
		fail("LOCALAPPDATA is unavailable.")
		return
	}
	installDir := filepath.Join(local, "Programs", "DuplicateGuard")
	if uninstall {
		runUninstall(installDir)
		return
	}
	if err := runInstall(installDir); err != nil {
		fail(err.Error())
		return
	}
	message("DuplicateGuard", "DuplicateGuard 2.1.1 was installed for this Windows account.\n\nIt will now open in your default browser. No administrator access is required.", 0x40)
}

func runInstall(installDir string) error {
	if err := stopRunningApp(installDir); err != nil {
		return err
	}
	if len(appBinary) < 1024*1024 {
		return fmt.Errorf("the embedded application payload is missing")
	}
	if err := os.MkdirAll(installDir, 0o700); err != nil {
		return err
	}
	target := filepath.Join(installDir, "DuplicateGuard.exe")
	temp := target + ".new"
	_ = os.Remove(temp)
	f, err := os.OpenFile(temp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o700)
	if err != nil {
		return fmt.Errorf("cannot create application file: %w", err)
	}
	if _, err = f.Write(appBinary); err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(temp)
		return fmt.Errorf("cannot write application: %w", err)
	}
	_ = os.Remove(target)
	if err = os.Rename(temp, target); err != nil {
		_ = os.Remove(temp)
		return fmt.Errorf("cannot replace DuplicateGuard.exe. Exit the running app and run Setup again: %w", err)
	}

	self, _ := os.Executable()
	uninstallExe := filepath.Join(installDir, "Uninstall_DuplicateGuard.exe")
	if !samePath(self, uninstallExe) {
		if err := copyFile(self, uninstallExe); err != nil {
			return fmt.Errorf("cannot create uninstaller: %w", err)
		}
	}

	home, _ := os.UserHomeDir()
	desktop := filepath.Join(home, "Desktop", "DuplicateGuard.lnk")
	startMenu := filepath.Join(os.Getenv("APPDATA"), "Microsoft", "Windows", "Start Menu", "Programs", "DuplicateGuard.lnk")
	exitShortcut := filepath.Join(os.Getenv("APPDATA"), "Microsoft", "Windows", "Start Menu", "Programs", "Exit DuplicateGuard.lnk")
	shortcutErrors := []string{}
	for _, link := range []string{desktop, startMenu} {
		if err := createShortcut(link, target, installDir); err != nil {
			shortcutErrors = append(shortcutErrors, err.Error())
		}
	}
	if err := createShortcutArgs(exitShortcut, target, installDir, "--exit", "Close DuplicateGuard and stop scheduled protection"); err != nil {
		shortcutErrors = append(shortcutErrors, err.Error())
	}
	if err := registerUninstall(installDir, target, uninstallExe); err != nil {
		return err
	}
	if err := exec.Command(target).Start(); err != nil {
		return fmt.Errorf("installed, but could not launch DuplicateGuard: %w", err)
	}
	if len(shortcutErrors) > 0 {
		message("DuplicateGuard", "The app was installed, but one or more shortcuts could not be created. Open it directly from:\n"+target, 0x30)
	}
	return nil
}

func runUninstall(installDir string) {
	answer := message("Uninstall DuplicateGuard", "Remove DuplicateGuard from this Windows account?\n\nQuarantined files and settings will be preserved in Local AppData so they can still be recovered.", 0x24)
	if answer != 6 {
		return
	}
	_ = exec.Command("taskkill.exe", "/IM", "DuplicateGuard.exe", "/T", "/F").Run()
	home, _ := os.UserHomeDir()
	_ = os.Remove(filepath.Join(home, "Desktop", "DuplicateGuard.lnk"))
	_ = os.Remove(filepath.Join(os.Getenv("APPDATA"), "Microsoft", "Windows", "Start Menu", "Programs", "DuplicateGuard.lnk"))
	_ = os.Remove(filepath.Join(os.Getenv("APPDATA"), "Microsoft", "Windows", "Start Menu", "Programs", "Exit DuplicateGuard.lnk"))
	_ = exec.Command("reg.exe", "delete", `HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\DuplicateGuard`, "/f").Run()
	message("DuplicateGuard", "DuplicateGuard was uninstalled.\n\nRecovery data was preserved at:\n"+filepath.Join(os.Getenv("LOCALAPPDATA"), "DuplicateGuard"), 0x40)
	cmd := fmt.Sprintf(`ping 127.0.0.1 -n 3 >nul & rmdir /S /Q "%s"`, installDir)
	_ = exec.Command("cmd.exe", "/C", cmd).Start()
}

func stopRunningApp(installDir string) error {
	target := filepath.Join(installDir, "DuplicateGuard.exe")
	if !processRunning() {
		return nil
	}

	// Newer builds understand --exit and close through the tray window.
	if _, err := os.Stat(target); err == nil {
		_ = exec.Command(target, "--exit").Start()
	}
	requestHTTPShutdown()
	if waitForProcessExit(3 * time.Second) {
		return nil
	}

	// Older builds did not expose a tray command, so force-close only as a fallback.
	_ = exec.Command("taskkill.exe", "/IM", "DuplicateGuard.exe", "/T", "/F").Run()
	if waitForProcessExit(5 * time.Second) {
		return nil
	}
	return fmt.Errorf("DuplicateGuard is still running. Close it from the notification-area icon or Task Manager, then run Setup again")
}

func requestHTTPShutdown() {
	client := &http.Client{Timeout: 900 * time.Millisecond}
	resp, err := client.Get("http://127.0.0.1:18473/")
	if err != nil {
		return
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512<<10))
	_ = resp.Body.Close()
	const marker = "const TOKEN='"
	text := string(body)
	start := strings.Index(text, marker)
	if start < 0 {
		return
	}
	start += len(marker)
	end := strings.IndexByte(text[start:], '\'')
	if end <= 0 {
		return
	}
	token := text[start : start+end]
	req, err := http.NewRequest(http.MethodPost, "http://127.0.0.1:18473/api/shutdown", nil)
	if err != nil {
		return
	}
	req.Header.Set("X-DG-Token", token)
	res, err := client.Do(req)
	if err == nil && res.Body != nil {
		_ = res.Body.Close()
	}
}

func processRunning() bool {
	out, _ := exec.Command("tasklist.exe", "/FI", "IMAGENAME eq DuplicateGuard.exe", "/NH").CombinedOutput()
	return strings.Contains(strings.ToLower(string(out)), "duplicateguard.exe")
}

func waitForProcessExit(timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if !processRunning() {
			return true
		}
		time.Sleep(150 * time.Millisecond)
	}
	return !processRunning()
}

func registerUninstall(installDir, target, uninstallExe string) error {
	key := `HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\DuplicateGuard`
	values := [][3]string{
		{"DisplayName", "REG_SZ", "DuplicateGuard"}, {"DisplayVersion", "REG_SZ", version},
		{"Publisher", "REG_SZ", "Fantest"}, {"InstallLocation", "REG_SZ", installDir},
		{"DisplayIcon", "REG_SZ", target}, {"UninstallString", "REG_SZ", `"` + uninstallExe + `" --uninstall`},
		{"NoModify", "REG_DWORD", "1"}, {"NoRepair", "REG_DWORD", "1"},
	}
	for _, v := range values {
		out, err := exec.Command("reg.exe", "add", key, "/v", v[0], "/t", v[1], "/d", v[2], "/f").CombinedOutput()
		if err != nil {
			return fmt.Errorf("cannot register the uninstaller: %s", strings.TrimSpace(string(out)))
		}
	}
	return nil
}

func createShortcut(link, target, workDir string) error {
	return createShortcutArgs(link, target, workDir, "", "Safe duplicate-file management")
}

func createShortcutArgs(link, target, workDir, args, description string) error {
	if err := os.MkdirAll(filepath.Dir(link), 0o700); err != nil {
		return err
	}
	q := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
	script := `$w=New-Object -ComObject WScript.Shell; $s=$w.CreateShortcut(` + q(link) + `); $s.TargetPath=` + q(target) + `; $s.WorkingDirectory=` + q(workDir) + `; $s.Arguments=` + q(args) + `; $s.Description=` + q(description) + `; $s.Save()`
	out, err := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script).CombinedOutput()
	if err != nil {
		return fmt.Errorf("shortcut %s: %s", link, strings.TrimSpace(string(out)))
	}
	return nil
}

func copyFile(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	tmp := dst + ".new"
	if err = os.WriteFile(tmp, b, 0o700); err != nil {
		return err
	}
	_ = os.Remove(dst)
	return os.Rename(tmp, dst)
}

func samePath(a, b string) bool { return strings.EqualFold(filepath.Clean(a), filepath.Clean(b)) }
func fail(text string)          { message("DuplicateGuard Setup", text, 0x10) }
func message(title, text string, flags uintptr) int {
	t, _ := syscall.UTF16PtrFromString(title)
	x, _ := syscall.UTF16PtrFromString(text)
	r, _, _ := messageBoxW.Call(0, uintptr(unsafe.Pointer(x)), uintptr(unsafe.Pointer(t)), flags)
	time.Sleep(50 * time.Millisecond)
	return int(r)
}
