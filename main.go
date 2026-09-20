package main

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

//go:embed web/index.html
var webFS embed.FS

var (
	homeTemplate *template.Template
	httpServer   *http.Server
)

func init() {
	b, err := webFS.ReadFile("web/index.html")
	if err != nil {
		panic(err)
	}
	homeTemplate = template.Must(template.New("home").Parse(string(b)))
}

func main() {
	background := false
	exitRequested := false
	for _, arg := range os.Args[1:] {
		switch arg {
		case "--background":
			background = true
		case "--exit":
			exitRequested = true
		}
	}
	if exitRequested {
		if !platformRequestExistingExit() {
			requestExistingHTTPShutdown()
		}
		return
	}

	dataDir, err := appDataDir()
	if err != nil {
		log.Fatal(err)
	}
	if err = ensureDataLayout(dataDir); err != nil {
		log.Fatal(err)
	}
	exe, _ := os.Executable()
	state = AppState{
		config: defaultConfig(), hashCache: map[string]HashCacheEntry{}, token: randomToken(),
		dataDir: dataDir, exePath: exe, background: background, monitorWake: make(chan struct{}, 1),
		health: HealthStatus{Version: appVersion},
	}

	_, cfgRecovered, _ := loadJSONWithRecovery(filepath.Join(dataDir, "config.json"), &state.config)
	_, qRecovered, _ := loadJSONWithRecovery(filepath.Join(dataDir, "quarantine.json"), &state.quarantine)
	_, cacheRecovered, _ := loadJSONWithRecovery(filepath.Join(dataDir, "hash_cache.json"), &state.hashCache)
	_, _, _ = loadJSONWithRecovery(filepath.Join(dataDir, "last_scan.json"), &state.summary)
	runtimeFound, _, _ := loadJSONWithRecovery(filepath.Join(dataDir, "runtime.json"), &state.runtime)
	if state.hashCache == nil {
		state.hashCache = map[string]HashCacheEntry{}
	}
	state.config = normalizeConfig(state.config)
	state.health.ConfigRecovered = cfgRecovered
	state.health.QuarantineRecovered = qRecovered
	state.health.CacheRecovered = cacheRecovered
	state.health.PreviousInterrupted = runtimeFound && (!state.runtime.CleanShutdown || state.runtime.RunningScanID != "")
	if state.health.PreviousInterrupted {
		state.status.Interrupted = true
		state.status.Phase = "recovered"
		state.status.Message = "Previous session ended unexpectedly. State was recovered; run a fresh scan before cleanup."
		state.summary.Partial = true
	}
	state.runtime.CleanShutdown = false
	state.runtime.RunningScanID = ""
	_ = saveRuntime()
	reconcileQuarantine()
	state.health.DataDirWritable = checkWritable(dataDir)
	state.health.QuarantineWritable = checkWritable(filepath.Join(dataDir, "Quarantine"))

	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", defaultPort))
	if err != nil {
		existingURL := fmt.Sprintf("http://127.0.0.1:%d", defaultPort)
		if isExistingInstance(existingURL) {
			if !background {
				openBrowser(existingURL)
			}
			return
		}
		ln, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			log.Fatal(err)
		}
	}
	port := ln.Addr().(*net.TCPAddr).Port
	state.serverURL = fmt.Sprintf("http://127.0.0.1:%d", port)
	state.health.ServerURL = state.serverURL

	mux := http.NewServeMux()
	mux.HandleFunc("/", serveHome)
	mux.HandleFunc("/api/ping", apiPing)
	mux.HandleFunc("/api/status", apiStatus)
	mux.HandleFunc("/api/scan", apiScan)
	mux.HandleFunc("/api/cancel", apiCancel)
	mux.HandleFunc("/api/config", apiConfig)
	mux.HandleFunc("/api/quarantine", apiQuarantine)
	mux.HandleFunc("/api/restore", apiRestore)
	mux.HandleFunc("/api/purge", apiPurge)
	mux.HandleFunc("/api/export", apiExport)
	mux.HandleFunc("/api/diagnostics", apiDiagnostics)
	mux.HandleFunc("/api/pick-folder", apiPickFolder)
	mux.HandleFunc("/api/reveal", apiReveal)
	mux.HandleFunc("/api/open-data", apiOpenData)
	mux.HandleFunc("/api/shutdown", apiShutdown)

	httpServer = &http.Server{
		Handler: secureLocalOnly(mux), ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 30 * time.Second, WriteTimeout: 0, IdleTimeout: 60 * time.Second,
	}

	platformStartTray()
	go monitorLoop()
	go handleSignals()
	if !background {
		go func() { time.Sleep(350 * time.Millisecond); openBrowser(state.serverURL) }()
	}
	_ = audit("app_started", map[string]any{"background": background, "server": state.serverURL})
	if err := httpServer.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

func handleSignals() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	<-ch
	shutdownApp()
}

func secureLocalOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.Host)
		if err != nil {
			host = r.Host
		}
		if host != "127.0.0.1" && host != "localhost" && host != "[::1]" && host != "::1" {
			http.Error(w, "Local access only", http.StatusForbidden)
			return
		}
		remoteHost, _, _ := net.SplitHostPort(r.RemoteAddr)
		ip := net.ParseIP(remoteHost)
		if ip == nil || !ip.IsLoopback() {
			http.Error(w, "Local access only", http.StatusForbidden)
			return
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

func requireToken(w http.ResponseWriter, r *http.Request) bool {
	token := r.Header.Get("X-DG-Token")
	if token == "" {
		token = r.URL.Query().Get("token")
	}
	if token == "" || token != state.token {
		jsonError(w, "Invalid local session token", http.StatusForbidden)
		return false
	}
	return true
}

func serveHome(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = homeTemplate.Execute(w, struct{ Token, Version string }{state.token, appVersion})
}

func apiPing(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{"app": appName, "version": appVersion})
}

func apiStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	if !requireToken(w, r) {
		return
	}
	updateHealth()
	state.mu.RLock()
	out := map[string]any{
		"version": appVersion, "config": state.config, "status": state.status,
		"summary": state.summary, "quarantine": state.quarantine,
		"dataDir": state.dataDir, "health": state.health,
	}
	state.mu.RUnlock()
	writeJSON(w, out)
}

func apiScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if !requireToken(w, r) {
		return
	}
	var cfg Config
	if err := decodeJSONBody(r, &cfg, 2<<20); err != nil {
		jsonError(w, "Invalid scan settings", 400)
		return
	}
	cfg = normalizeConfig(cfg)
	if len(cfg.Roots) == 0 {
		jsonError(w, "Add at least one personal folder", 400)
		return
	}
	if err := validateConfigRoots(cfg); err != nil {
		jsonError(w, err.Error(), 400)
		return
	}

	state.mu.Lock()
	if state.status.Running {
		state.mu.Unlock()
		jsonError(w, "A scan is already running", 409)
		return
	}
	state.config = cfg
	state.mu.Unlock()
	if err := saveConfig(); err != nil {
		jsonError(w, "Could not save settings: "+sanitizeError(err), 500)
		return
	}
	startScan("manual")
	writeJSON(w, map[string]any{"ok": true})
}

func startScan(trigger string) bool {
	state.mu.Lock()
	if state.status.Running {
		state.mu.Unlock()
		return false
	}
	cfg := state.config
	ctx, cancel := context.WithCancel(context.Background())
	scanID := randomID("scan")
	state.cancelScan = cancel
	state.status = JobStatus{Running: true, ScanID: scanID, Phase: "indexing", Message: "Indexing selected folders", StartedAt: time.Now()}
	state.runtime.RunningScanID = scanID
	state.runtime.ScanStartedAt = time.Now()
	state.runtime.CleanShutdown = false
	state.mu.Unlock()
	_ = saveRuntime()
	_ = audit("scan_started", map[string]any{"scanId": scanID, "trigger": trigger, "roots": cfg.Roots})

	go func() {
		summary := scanFolders(ctx, cfg)
		summary.ScanID = scanID
		state.mu.Lock()
		state.summary = summary
		state.status.Running = false
		state.status.LastScanAt = summary.FinishedAt
		state.status.Phase = "complete"
		state.status.Message = fmt.Sprintf("Found %d duplicate groups", summary.Groups)
		if summary.Cancelled {
			state.status.Phase = "cancelled"
			state.status.Message = "Scan cancelled"
		}
		state.status.Interrupted = false
		if !summary.Partial {
			state.health.PreviousInterrupted = false
		}
		state.cancelScan = nil
		state.runtime.RunningScanID = ""
		state.mu.Unlock()
		_ = saveSummary()
		_ = saveRuntime()
		_ = audit("scan_completed", map[string]any{"scanId": scanID, "trigger": trigger, "groups": summary.Groups, "duplicates": summary.DuplicateFiles, "recoverable": summary.Recoverable, "partial": summary.Partial, "errors": len(summary.Errors)})
	}()
	return true
}

func apiCancel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if !requireToken(w, r) {
		return
	}
	state.mu.Lock()
	if state.cancelScan != nil {
		state.cancelScan()
	}
	state.mu.Unlock()
	_ = audit("scan_cancel_requested", nil)
	writeJSON(w, map[string]any{"ok": true})
}

func apiConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if !requireToken(w, r) {
		return
	}
	var cfg Config
	if err := decodeJSONBody(r, &cfg, 2<<20); err != nil {
		jsonError(w, "Invalid settings", 400)
		return
	}
	cfg = normalizeConfig(cfg)
	if err := validateConfigRoots(cfg); err != nil {
		jsonError(w, err.Error(), 400)
		return
	}
	if cfg.AutoQuarantine && len(cfg.AutoRoots) == 0 {
		jsonError(w, "Choose at least one approved automatic-cleanup folder", 400)
		return
	}

	state.mu.RLock()
	oldStartup := state.config.StartWithWindows
	state.mu.RUnlock()
	if cfg.StartWithWindows != oldStartup {
		if err := setWindowsStartup(cfg.StartWithWindows); err != nil {
			jsonError(w, sanitizeError(err), 500)
			return
		}
	}
	cfg.FirstRunCompleted = true
	state.mu.Lock()
	state.config = cfg
	state.mu.Unlock()
	if err := saveConfig(); err != nil {
		jsonError(w, "Could not save settings: "+sanitizeError(err), 500)
		return
	}
	select {
	case state.monitorWake <- struct{}{}:
	default:
	}
	_ = audit("config_saved", map[string]any{"monitor": cfg.MonitorEnabled, "autoQuarantine": cfg.AutoQuarantine, "autoPurge": cfg.AutoPurgeExpired, "startup": cfg.StartWithWindows})
	writeJSON(w, map[string]any{"ok": true})
}

type pathsRequest struct {
	Paths       []string `json:"paths"`
	IDs         []string `json:"ids"`
	ExpiredOnly bool     `json:"expiredOnly"`
	Confirm     string   `json:"confirm"`
}

func apiQuarantine(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if !requireToken(w, r) {
		return
	}
	var req pathsRequest
	if err := decodeJSONBody(r, &req, 2<<20); err != nil {
		jsonError(w, "Invalid cleanup request", 400)
		return
	}
	if len(req.Paths) == 0 {
		jsonError(w, "No duplicates selected", 400)
		return
	}
	state.mu.RLock()
	running := state.status.Running
	state.mu.RUnlock()
	if running {
		jsonError(w, "Wait for the active scan to finish", 409)
		return
	}
	moved, errs := quarantinePaths(req.Paths, false)
	code := 200
	if len(moved) == 0 && len(errs) > 0 {
		code = 400
	}
	writeJSONStatus(w, code, map[string]any{"ok": len(moved) > 0, "moved": moved, "errors": errs})
}

func apiRestore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if !requireToken(w, r) {
		return
	}
	var req pathsRequest
	if err := decodeJSONBody(r, &req, 1<<20); err != nil {
		jsonError(w, "Invalid restore request", 400)
		return
	}
	restored, errs := restoreRecords(req.IDs)
	writeJSON(w, map[string]any{"ok": len(restored) > 0, "restored": restored, "errors": errs})
}

func apiPurge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if !requireToken(w, r) {
		return
	}
	var req pathsRequest
	if err := decodeJSONBody(r, &req, 1<<20); err != nil {
		jsonError(w, "Invalid purge request", 400)
		return
	}
	if req.Confirm != "PURGE" {
		jsonError(w, "Permanent deletion requires the confirmation word PURGE", 400)
		return
	}
	if !req.ExpiredOnly && len(req.IDs) == 0 {
		jsonError(w, "No quarantined files selected", 400)
		return
	}
	purged, errs := purgeRecords(req.IDs, req.ExpiredOnly, false)
	writeJSON(w, map[string]any{"ok": len(purged) > 0, "purged": purged, "errors": errs})
}

func apiExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	if !requireToken(w, r) {
		return
	}
	state.mu.RLock()
	s := state.summary
	state.mu.RUnlock()
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="DuplicateGuard_Report.csv"`)
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"Scan ID", "Group", "SHA-256", "Category", "Size bytes", "Decision", "Auto eligible", "Reason", "Modified", "Path"})
	for _, g := range s.Results {
		for _, f := range g.Files {
			decision := "QUARANTINE"
			reason := f.AutoReason
			if f.Keep {
				decision = "KEEP"
				reason = f.KeepReason
			}
			_ = cw.Write([]string{s.ScanID, g.GroupID, g.Hash, g.Category, strconv.FormatInt(g.Size, 10), decision, strconv.FormatBool(f.AutoEligible), reason, f.ModTime.Format(time.RFC3339), f.Path})
		}
	}
	cw.Flush()
}

func apiDiagnostics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	if !requireToken(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="DuplicateGuard_Diagnostics.zip"`)
	if err := diagnosticZip(w); err != nil {
		_ = audit("diagnostic_export_failed", map[string]any{"error": sanitizeError(err)})
	}
}

func apiPickFolder(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if !requireToken(w, r) {
		return
	}
	if runtime.GOOS != "windows" {
		jsonError(w, "Folder picker is available in the Windows build", 501)
		return
	}
	script := `Add-Type -AssemblyName System.Windows.Forms; $d=New-Object System.Windows.Forms.FolderBrowserDialog; $d.Description='Select a personal folder for DuplicateGuard'; $d.ShowNewFolderButton=$false; if($d.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK){[Console]::OutputEncoding=[Text.Encoding]::UTF8; Write-Output $d.SelectedPath}`
	out, err := exec.Command("powershell.exe", "-NoProfile", "-STA", "-Command", script).Output()
	if err != nil {
		jsonError(w, "Folder selection was cancelled", 400)
		return
	}
	p := strings.TrimSpace(string(out))
	if p == "" {
		jsonError(w, "No folder selected", 400)
		return
	}
	if isProtectedPath(p) || isDriveRoot(p) {
		jsonError(w, "Choose a personal folder, not a system folder or entire drive", 400)
		return
	}
	writeJSON(w, map[string]any{"path": p})
}

func apiReveal(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if !requireToken(w, r) {
		return
	}
	var req struct {
		Path string `json:"path"`
	}
	if err := decodeJSONBody(r, &req, 1<<20); err != nil {
		jsonError(w, "Invalid path", 400)
		return
	}
	p, err := filepath.Abs(req.Path)
	if err != nil || !isKnownUserPath(p) {
		jsonError(w, "Path is not part of the current app data", 403)
		return
	}
	if runtime.GOOS == "windows" {
		if _, err := os.Stat(p); err == nil {
			_ = exec.Command("explorer.exe", "/select,", p).Start()
		} else {
			_ = exec.Command("explorer.exe", filepath.Dir(p)).Start()
		}
	}
	writeJSON(w, map[string]any{"ok": true})
}

func apiOpenData(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if !requireToken(w, r) {
		return
	}
	if runtime.GOOS == "windows" {
		_ = exec.Command("explorer.exe", state.dataDir).Start()
	}
	writeJSON(w, map[string]any{"ok": true})
}

func apiShutdown(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if !requireToken(w, r) {
		return
	}
	writeJSON(w, map[string]any{"ok": true})
	go func() { time.Sleep(150 * time.Millisecond); shutdownApp() }()
}

func monitorLoop() {
	for {
		state.mu.RLock()
		cfg := state.config
		running := state.status.Running
		state.mu.RUnlock()
		if !cfg.MonitorEnabled || len(cfg.Roots) == 0 {
			select {
			case <-state.monitorWake:
				continue
			case <-time.After(time.Minute):
				continue
			}
		}
		interval := time.Duration(cfg.MonitorMinutes) * time.Minute
		if interval < 15*time.Minute {
			interval = 15 * time.Minute
		}
		timer := time.NewTimer(interval)
		select {
		case <-timer.C:
		case <-state.monitorWake:
			timer.Stop()
			continue
		}
		if running || !startScan("scheduled") {
			continue
		}
		for {
			time.Sleep(time.Second)
			state.mu.RLock()
			stillRunning := state.status.Running
			sum := state.summary
			currentCfg := state.config
			state.mu.RUnlock()
			if stillRunning {
				continue
			}
			if !sum.Partial && currentCfg.AutoQuarantine {
				paths := []string{}
				for _, g := range sum.Results {
					for _, f := range g.Files {
						if !f.Keep && f.AutoEligible {
							paths = append(paths, f.Path)
						}
					}
				}
				moved, errs := quarantinePaths(paths, true)
				if currentCfg.Notifications && (len(moved) > 0 || len(errs) > 0) {
					platformNotify(appName, fmt.Sprintf("Scheduled cleanup quarantined %d files; %d were skipped.", len(moved), len(errs)))
				}
			} else if currentCfg.Notifications {
				platformNotify(appName, fmt.Sprintf("Scheduled scan found %d duplicate groups (%s after purge).", sum.Groups, formatBytes(sum.Recoverable)))
			}
			if currentCfg.AutoPurgeExpired {
				purged, errs := purgeRecords(nil, true, true)
				if currentCfg.Notifications && (len(purged) > 0 || len(errs) > 0) {
					platformNotify(appName, fmt.Sprintf("Retention cleanup permanently removed %d expired quarantined files.", len(purged)))
				}
			}
			break
		}
	}
}

func validateConfigRoots(cfg Config) error {
	for _, root := range append(append([]string{}, cfg.Roots...), append(cfg.PreferredRoots, cfg.AutoRoots...)...) {
		if isDriveRoot(root) {
			return fmt.Errorf("entire-drive scanning is blocked: %s", root)
		}
		if isProtectedPath(root) || samePathOrInside(root, state.dataDir) {
			return fmt.Errorf("protected folder cannot be selected: %s", root)
		}
	}
	return nil
}

func isKnownUserPath(path string) bool {
	state.mu.RLock()
	defer state.mu.RUnlock()
	for _, g := range state.summary.Results {
		for _, f := range g.Files {
			if normalizePath(f.Path) == normalizePath(path) {
				return true
			}
		}
	}
	for _, q := range state.quarantine {
		if normalizePath(q.OriginalPath) == normalizePath(path) || normalizePath(q.QuarantinedPath) == normalizePath(path) || normalizePath(q.RestoredPath) == normalizePath(path) {
			return true
		}
	}
	return samePathOrInside(path, state.dataDir)
}

func setWindowsStartup(enabled bool) error {
	if runtime.GOOS != "windows" {
		return nil
	}
	var cmd *exec.Cmd
	if enabled {
		value := fmt.Sprintf(`"%s" --background`, state.exePath)
		cmd = exec.Command("reg.exe", "add", `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, "/v", appName, "/t", "REG_SZ", "/d", value, "/f")
	} else {
		cmd = exec.Command("reg.exe", "delete", `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, "/v", appName, "/f")
	}
	out, err := cmd.CombinedOutput()
	if err != nil && !enabled && strings.Contains(strings.ToLower(string(out)), "unable to find") {
		return nil
	}
	if err != nil {
		return fmt.Errorf("could not update Windows startup: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func shutdownApp() {
	platformStopTray()
	state.mu.Lock()
	if state.cancelScan != nil {
		state.cancelScan()
	}
	state.runtime.RunningScanID = ""
	state.runtime.LastShutdown = time.Now()
	state.runtime.CleanShutdown = true
	state.mu.Unlock()
	_ = saveRuntime()
	_ = saveHashCache()
	_ = saveQuarantine()
	_ = saveConfig()
	_ = audit("app_stopped", nil)
	if httpServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		_ = httpServer.Shutdown(ctx)
		cancel()
	}
	os.Exit(0)
}

func isExistingInstance(url string) bool {
	c := http.Client{Timeout: 700 * time.Millisecond}
	r, err := c.Get(url + "/api/ping")
	if err != nil {
		return false
	}
	defer r.Body.Close()
	var v map[string]any
	return json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&v) == nil && v["app"] == appName
}

func requestExistingHTTPShutdown() bool {
	base := fmt.Sprintf("http://127.0.0.1:%d", defaultPort)
	client := http.Client{Timeout: 900 * time.Millisecond}
	resp, err := client.Get(base + "/")
	if err != nil {
		return false
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512<<10))
	_ = resp.Body.Close()
	const marker = "const TOKEN='"
	text := string(body)
	start := strings.Index(text, marker)
	if start < 0 {
		return false
	}
	start += len(marker)
	end := strings.IndexByte(text[start:], '\'')
	if end <= 0 {
		return false
	}
	req, err := http.NewRequest(http.MethodPost, base+"/api/shutdown", nil)
	if err != nil {
		return false
	}
	req.Header.Set("X-DG-Token", text[start:start+end])
	res, err := client.Do(req)
	if err != nil {
		return false
	}
	_ = res.Body.Close()
	return res.StatusCode == http.StatusOK
}

func randomToken() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
func randomID(prefix string) string {
	return prefix + "_" + time.Now().UTC().Format("20060102T150405.000000000Z") + "_" + randomToken()[:8]
}

func decodeJSONBody(r *http.Request, v any, max int64) error {
	return json.NewDecoder(io.LimitReader(r.Body, max)).Decode(v)
}
func writeJSON(w http.ResponseWriter, v any) { writeJSONStatus(w, http.StatusOK, v) }
func writeJSONStatus(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
func jsonError(w http.ResponseWriter, msg string, code int) {
	writeJSONStatus(w, code, map[string]any{"error": msg})
}
func methodNotAllowed(w http.ResponseWriter) {
	jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
}
func updateStatus(phase, message string) {
	state.mu.Lock()
	state.status.Phase = phase
	state.status.Message = message
	state.mu.Unlock()
}

func openBrowser(url string) {
	switch runtime.GOOS {
	case "windows":
		_ = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		_ = exec.Command("open", url).Start()
	default:
		_ = exec.Command("xdg-open", url).Start()
	}
}
