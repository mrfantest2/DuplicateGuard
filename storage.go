package main

import (
	"archive/zip"
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

var storageMu sync.Mutex

func appDataDir() (string, error) {
	if runtime.GOOS == "windows" {
		if p := os.Getenv("LOCALAPPDATA"); p != "" {
			return filepath.Join(p, appName), nil
		}
	}
	p, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(p, appName), nil
}

func ensureDataLayout(dataDir string) error {
	for _, p := range []string{
		dataDir,
		filepath.Join(dataDir, "Backups"),
		filepath.Join(dataDir, "Logs"),
		filepath.Join(dataDir, "Quarantine"),
		filepath.Join(dataDir, "Diagnostics"),
	} {
		if err := os.MkdirAll(p, 0o700); err != nil {
			return err
		}
	}
	return nil
}

func statePath(name string) string { return filepath.Join(state.dataDir, name) }

func saveConfig() error {
	state.mu.RLock()
	v := state.config
	state.mu.RUnlock()
	return saveJSONAtomic(statePath("config.json"), v)
}

func saveSummary() error {
	state.mu.RLock()
	v := state.summary
	state.mu.RUnlock()
	return saveJSONAtomic(statePath("last_scan.json"), v)
}

func saveQuarantine() error {
	state.mu.RLock()
	v := append([]QuarantineRecord(nil), state.quarantine...)
	state.mu.RUnlock()
	return saveJSONAtomic(statePath("quarantine.json"), v)
}

func saveHashCache() error {
	state.mu.RLock()
	v := make(map[string]HashCacheEntry, len(state.hashCache))
	cutoff := time.Now().AddDate(0, 0, -120)
	for k, e := range state.hashCache {
		if e.LastSeen.After(cutoff) {
			v[k] = e
		}
	}
	state.mu.RUnlock()
	return saveJSONAtomic(statePath("hash_cache.json"), v)
}

func saveRuntime() error {
	state.mu.RLock()
	v := state.runtime
	state.mu.RUnlock()
	return saveJSONAtomic(statePath("runtime.json"), v)
}

func saveJSONAtomic(path string, value any) error {
	storageMu.Lock()
	defer storageMu.Unlock()

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err = enc.Encode(value); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}

	if _, statErr := os.Stat(path); statErr == nil {
		if err := rotateBackupLocked(path); err != nil {
			_ = os.Remove(tmp)
			return err
		}
	}
	if err := replaceFile(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func rotateBackupLocked(path string) error {
	backupDir := filepath.Join(filepath.Dir(path), "Backups")
	if err := os.MkdirAll(backupDir, 0o700); err != nil {
		return err
	}
	base := filepath.Base(path)
	stamp := time.Now().UTC().Format("20060102T150405.000000000Z")
	dst := filepath.Join(backupDir, base+"."+stamp+".bak")
	if err := copyFileDurable(path, dst, false); err != nil {
		return err
	}
	matches, _ := filepath.Glob(filepath.Join(backupDir, base+".*.bak"))
	sort.Strings(matches)
	if len(matches) > maxStateBackups {
		for _, old := range matches[:len(matches)-maxStateBackups] {
			_ = os.Remove(old)
		}
	}
	return nil
}

func replaceFile(tmp, final string) error {
	if err := os.Rename(tmp, final); err == nil {
		return nil
	}
	_ = os.Remove(final)
	return os.Rename(tmp, final)
}

func loadJSONWithRecovery(path string, value any) (found, recovered bool, err error) {
	decode := func(p string) error {
		f, e := os.Open(p)
		if e != nil {
			return e
		}
		defer f.Close()
		dec := json.NewDecoder(bufio.NewReader(f))
		if e = dec.Decode(value); e != nil {
			return e
		}
		return nil
	}
	if err = decode(path); err == nil {
		return true, false, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		_ = audit("state_corrupt", map[string]any{"path": path, "error": err.Error()})
	}

	backupDir := filepath.Join(filepath.Dir(path), "Backups")
	matches, _ := filepath.Glob(filepath.Join(backupDir, filepath.Base(path)+".*.bak"))
	sort.Sort(sort.Reverse(sort.StringSlice(matches)))
	for _, b := range matches {
		if e := decode(b); e == nil {
			_ = copyFileDurable(b, path, true)
			_ = audit("state_recovered", map[string]any{"path": path, "backup": b})
			return true, true, nil
		}
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, false, nil
	}
	return false, false, err
}

func copyFileDurable(src, dst string, replace bool) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	flags := os.O_CREATE | os.O_WRONLY
	if replace {
		flags |= os.O_TRUNC
	} else {
		flags |= os.O_EXCL
	}
	out, err := os.OpenFile(dst, flags, 0o600)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, in)
	syncErr := out.Sync()
	closeErr := out.Close()
	if copyErr != nil {
		_ = os.Remove(dst)
		return copyErr
	}
	if syncErr != nil {
		_ = os.Remove(dst)
		return syncErr
	}
	if closeErr != nil {
		_ = os.Remove(dst)
		return closeErr
	}
	return nil
}

func audit(action string, details map[string]any) error {
	if state.dataDir == "" {
		return nil
	}
	storageMu.Lock()
	defer storageMu.Unlock()

	logDir := filepath.Join(state.dataDir, "Logs")
	if err := os.MkdirAll(logDir, 0o700); err != nil {
		return err
	}
	path := filepath.Join(logDir, "audit.jsonl")
	if st, err := os.Stat(path); err == nil && st.Size() > 10*1024*1024 {
		_ = os.Remove(path + ".1")
		_ = os.Rename(path, path+".1")
	}
	rec := map[string]any{
		"time":    time.Now().UTC().Format(time.RFC3339Nano),
		"version": appVersion,
		"action":  action,
		"details": details,
	}
	b, _ := json.Marshal(rec)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		state.mu.Lock()
		state.health.LastAuditError = err.Error()
		state.mu.Unlock()
		return err
	}
	_, err = f.Write(append(b, '\n'))
	if syncErr := f.Sync(); err == nil {
		err = syncErr
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		state.mu.Lock()
		state.health.LastAuditError = err.Error()
		state.mu.Unlock()
	}
	return err
}

func checkWritable(dir string) bool {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return false
	}
	p := filepath.Join(dir, ".write_test_"+randomToken())
	if err := os.WriteFile(p, []byte("ok"), 0o600); err != nil {
		return false
	}
	_ = os.Remove(p)
	return true
}

func diagnosticZip(w io.Writer) error {
	zw := zip.NewWriter(w)
	defer zw.Close()

	state.mu.RLock()
	cfg := state.config
	sum := state.summary
	status := state.status
	q := append([]QuarantineRecord(nil), state.quarantine...)
	health := state.health
	state.mu.RUnlock()

	writeJSONEntry := func(name string, v any) error {
		zf, err := zw.Create(name)
		if err != nil {
			return err
		}
		enc := json.NewEncoder(zf)
		enc.SetIndent("", "  ")
		return enc.Encode(v)
	}
	if err := writeJSONEntry("config.json", cfg); err != nil {
		return err
	}
	if err := writeJSONEntry("last_scan.json", sum); err != nil {
		return err
	}
	if err := writeJSONEntry("status.json", status); err != nil {
		return err
	}
	if err := writeJSONEntry("quarantine_metadata.json", q); err != nil {
		return err
	}
	if err := writeJSONEntry("health.json", health); err != nil {
		return err
	}
	if err := writeJSONEntry("system.json", map[string]any{
		"os": runtime.GOOS, "arch": runtime.GOARCH, "go": runtime.Version(),
		"appVersion": appVersion, "createdAt": time.Now().UTC(),
	}); err != nil {
		return err
	}

	for _, name := range []string{"audit.jsonl", "audit.jsonl.1"} {
		p := filepath.Join(state.dataDir, "Logs", name)
		st, err := os.Stat(p)
		if err != nil || st.Size() > 20*1024*1024 {
			continue
		}
		in, err := os.Open(p)
		if err != nil {
			continue
		}
		zf, err := zw.Create(filepath.ToSlash(filepath.Join("logs", name)))
		if err == nil {
			_, err = io.Copy(zf, in)
		}
		_ = in.Close()
		if err != nil {
			return err
		}
	}

	readme, _ := zw.Create("README.txt")
	_, _ = fmt.Fprintln(readme, "DuplicateGuard diagnostic package")
	_, _ = fmt.Fprintln(readme, "Contains configuration, scan metadata, quarantine metadata, health information, and audit logs.")
	_, _ = fmt.Fprintln(readme, "It does not contain the contents of scanned or quarantined files.")
	return nil
}

func sanitizeError(err error) string {
	if err == nil {
		return ""
	}
	s := strings.TrimSpace(err.Error())
	if len(s) > 800 {
		s = s[:800] + "…"
	}
	return s
}
