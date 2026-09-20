package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

func quarantinePaths(paths []string, automatic bool) ([]QuarantineRecord, []string) {
	state.mu.RLock()
	summary := state.summary
	cfg := state.config
	state.mu.RUnlock()
	if summary.Partial || summary.Cancelled || summary.ScanID == "" {
		return nil, []string{"Cleanup is disabled because the current scan is incomplete. Run a complete scan first."}
	}

	byPath := map[string]struct {
		group DuplicateGroup
		file  FileEntry
	}{}
	for _, g := range summary.Results {
		for _, f := range g.Files {
			byPath[normalizePath(f.Path)] = struct {
				group DuplicateGroup
				file  FileEntry
			}{g, f}
		}
	}
	selected := map[string]bool{}
	for _, p := range paths {
		if a, err := filepath.Abs(p); err == nil {
			selected[normalizePath(a)] = true
		}
	}

	moved := []QuarantineRecord{}
	errs := []string{}
	qdir := filepath.Join(state.dataDir, "Quarantine", time.Now().Format("2006-01"), time.Now().Format("2006-01-02"))
	if err := os.MkdirAll(qdir, 0o700); err != nil {
		return nil, []string{"Cannot create quarantine: " + sanitizeError(err)}
	}

	for _, requested := range paths {
		p, err := filepath.Abs(requested)
		if err != nil {
			errs = append(errs, requested+": invalid path")
			continue
		}
		p = filepath.Clean(p)
		key := normalizePath(p)
		item, ok := byPath[key]
		if !ok {
			errs = append(errs, p+": not in current verified results")
			continue
		}
		if item.file.Keep {
			errs = append(errs, p+": the retained copy cannot be quarantined")
			continue
		}
		if automatic && !item.file.AutoEligible {
			errs = append(errs, p+": not eligible for unattended cleanup")
			continue
		}
		if isProtectedPath(p) || samePathOrInside(p, state.dataDir) {
			errs = append(errs, p+": protected location")
			continue
		}

		info, err := os.Stat(p)
		if err != nil || !info.Mode().IsRegular() {
			errs = append(errs, p+": file is no longer available")
			continue
		}
		if fileFingerprint(info) != item.file.ScanFingerprint {
			errs = append(errs, p+": size, date, or attributes changed; rescan required")
			continue
		}
		flags, _ := platformFileFlags(p)
		if flags.Offline || flags.Recall || flags.Reparse {
			errs = append(errs, p+": cloud or reparse file requires manual handling")
			continue
		}

		keeper := ""
		for _, f := range item.group.Files {
			fk := normalizePath(f.Path)
			if selected[fk] || fk == key {
				continue
			}
			if st, e := os.Stat(f.Path); e == nil && st.Mode().IsRegular() {
				keeper = f.Path
				break
			}
		}
		if keeper == "" {
			errs = append(errs, p+": no verified copy would remain")
			continue
		}

		hp, e := hashFile(context.Background(), p)
		if e != nil || hp != item.group.Hash {
			errs = append(errs, p+": content changed; rescan required")
			continue
		}
		hk, e := hashFile(context.Background(), keeper)
		if e != nil || hk != item.group.Hash {
			errs = append(errs, p+": retained copy failed final verification")
			continue
		}

		id := randomID("q")
		target := filepath.Join(qdir, id+"_"+safeName(filepath.Base(p)))
		if err := ensureMoveCapacity(p, target, info.Size()); err != nil {
			errs = append(errs, p+": "+err.Error())
			continue
		}
		rec := QuarantineRecord{
			ID: id, GroupID: item.group.GroupID, OriginalPath: p, QuarantinedPath: target,
			Hash: item.group.Hash, Size: info.Size(), OriginalModTime: info.ModTime(),
			QuarantinedAt: time.Now(), PurgeAfter: time.Now().AddDate(0, 0, cfg.RetentionDays),
			Status: "pending", Automatic: automatic,
		}
		appendQuarantineRecord(rec)
		if err := saveQuarantine(); err != nil {
			setQuarantineStatus(id, "failed", "Could not persist transaction before moving the file")
			errs = append(errs, p+": could not persist recovery transaction")
			continue
		}

		if err := moveFileVerified(p, target, item.group.Hash, info.ModTime(), info.Mode()); err != nil {
			setQuarantineStatus(id, "failed", sanitizeError(err))
			_ = saveQuarantine()
			errs = append(errs, p+": "+sanitizeError(err))
			_ = audit("quarantine_failed", map[string]any{"id": id, "path": p, "error": sanitizeError(err), "automatic": automatic})
			continue
		}
		setQuarantineStatus(id, "quarantined", "")
		_ = saveQuarantine()
		state.mu.RLock()
		for _, r := range state.quarantine {
			if r.ID == id {
				moved = append(moved, r)
				break
			}
		}
		state.mu.RUnlock()
		_ = audit("quarantined", map[string]any{"id": id, "path": p, "size": info.Size(), "automatic": automatic})
	}

	if len(moved) > 0 {
		removeMovedFromSummary(moved)
		_ = saveSummary()
		updateHealth()
	}
	return moved, errs
}

func appendQuarantineRecord(rec QuarantineRecord) {
	state.mu.Lock()
	state.quarantine = append([]QuarantineRecord{rec}, state.quarantine...)
	state.mu.Unlock()
}

func setQuarantineStatus(id, status, errText string) {
	state.mu.Lock()
	defer state.mu.Unlock()
	for i := range state.quarantine {
		if state.quarantine[i].ID == id {
			state.quarantine[i].Status = status
			state.quarantine[i].Error = errText
			return
		}
	}
}

func removeMovedFromSummary(records []QuarantineRecord) {
	removed := map[string]bool{}
	for _, r := range records {
		removed[normalizePath(r.OriginalPath)] = true
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	next := make([]DuplicateGroup, 0, len(state.summary.Results))
	state.summary.DuplicateFiles = 0
	state.summary.Recoverable = 0
	for _, g := range state.summary.Results {
		files := make([]FileEntry, 0, len(g.Files))
		for _, f := range g.Files {
			if !removed[normalizePath(f.Path)] {
				files = append(files, f)
			}
		}
		if len(files) < 2 {
			continue
		}
		g.Files = files
		g.Waste = g.Size * int64(len(files)-1)
		next = append(next, g)
		state.summary.DuplicateFiles += len(files) - 1
		state.summary.Recoverable += g.Waste
	}
	state.summary.Results = next
	state.summary.Groups = len(next)
}

func restoreRecords(ids []string) ([]QuarantineRecord, []string) {
	wanted := map[string]bool{}
	for _, id := range ids {
		wanted[id] = true
	}
	restored, errs := []QuarantineRecord{}, []string{}

	state.mu.RLock()
	snapshot := append([]QuarantineRecord(nil), state.quarantine...)
	state.mu.RUnlock()
	for _, rec := range snapshot {
		if !wanted[rec.ID] || rec.Status != "quarantined" {
			continue
		}
		if !samePathOrInside(rec.QuarantinedPath, filepath.Join(state.dataDir, "Quarantine")) {
			errs = append(errs, rec.OriginalPath+": invalid quarantine path")
			continue
		}
		h, err := hashFile(context.Background(), rec.QuarantinedPath)
		if err != nil || h != rec.Hash {
			errs = append(errs, rec.OriginalPath+": quarantine verification failed")
			setQuarantineStatus(rec.ID, "corrupt", "Quarantine hash verification failed")
			continue
		}
		target := rec.OriginalPath
		if _, err = os.Stat(target); err == nil {
			target = availableRestoreName(target)
		}
		if err = os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			errs = append(errs, target+": "+sanitizeError(err))
			continue
		}
		if err = ensureMoveCapacity(rec.QuarantinedPath, target, rec.Size); err != nil {
			errs = append(errs, target+": "+err.Error())
			continue
		}
		if err = moveFileVerified(rec.QuarantinedPath, target, rec.Hash, rec.OriginalModTime, 0o600); err != nil {
			errs = append(errs, target+": "+sanitizeError(err))
			continue
		}
		state.mu.Lock()
		for i := range state.quarantine {
			if state.quarantine[i].ID == rec.ID {
				state.quarantine[i].Status = "restored"
				state.quarantine[i].RestoredAt = time.Now()
				state.quarantine[i].RestoredPath = target
				state.quarantine[i].Error = ""
				restored = append(restored, state.quarantine[i])
				break
			}
		}
		state.mu.Unlock()
		_ = audit("restored", map[string]any{"id": rec.ID, "original": rec.OriginalPath, "restoredPath": target})
	}
	_ = saveQuarantine()
	cleanupEmptyQuarantineDirs()
	updateHealth()
	return restored, errs
}

func purgeRecords(ids []string, expiredOnly, automatic bool) ([]QuarantineRecord, []string) {
	wanted := map[string]bool{}
	for _, id := range ids {
		wanted[id] = true
	}
	purged, errs := []QuarantineRecord{}, []string{}
	now := time.Now()

	state.mu.RLock()
	snapshot := append([]QuarantineRecord(nil), state.quarantine...)
	state.mu.RUnlock()
	for _, rec := range snapshot {
		if rec.Status != "quarantined" {
			continue
		}
		if expiredOnly {
			if rec.PurgeAfter.After(now) {
				continue
			}
		} else if !wanted[rec.ID] {
			continue
		}
		if !samePathOrInside(rec.QuarantinedPath, filepath.Join(state.dataDir, "Quarantine")) {
			errs = append(errs, rec.OriginalPath+": invalid quarantine path")
			continue
		}
		h, err := hashFile(context.Background(), rec.QuarantinedPath)
		if err != nil || h != rec.Hash {
			errs = append(errs, rec.OriginalPath+": hash verification failed; not deleted")
			setQuarantineStatus(rec.ID, "corrupt", "Hash verification failed before purge")
			continue
		}
		if err = os.Remove(rec.QuarantinedPath); err != nil {
			errs = append(errs, rec.OriginalPath+": "+sanitizeError(err))
			continue
		}
		state.mu.Lock()
		for i := range state.quarantine {
			if state.quarantine[i].ID == rec.ID {
				state.quarantine[i].Status = "purged"
				state.quarantine[i].PurgedAt = time.Now()
				state.quarantine[i].Error = ""
				purged = append(purged, state.quarantine[i])
				break
			}
		}
		state.mu.Unlock()
		_ = audit("purged", map[string]any{"id": rec.ID, "path": rec.OriginalPath, "size": rec.Size, "automatic": automatic})
	}
	_ = saveQuarantine()
	cleanupEmptyQuarantineDirs()
	updateHealth()
	return purged, errs
}

func reconcileQuarantine() {
	changed := false
	state.mu.Lock()
	for i := range state.quarantine {
		rec := &state.quarantine[i]
		if rec.Status == "pending" {
			_, srcErr := os.Stat(rec.OriginalPath)
			_, dstErr := os.Stat(rec.QuarantinedPath)
			srcExists, dstExists := srcErr == nil, dstErr == nil
			switch {
			case !srcExists && dstExists:
				if h, err := hashFile(context.Background(), rec.QuarantinedPath); err == nil && h == rec.Hash {
					rec.Status, rec.Error = "quarantined", "Recovered a completed move after an interrupted operation"
				} else {
					rec.Status, rec.Error = "corrupt", "Interrupted move could not be verified"
				}
			case srcExists && !dstExists:
				rec.Status, rec.Error = "failed", "No move occurred before interruption"
			case srcExists && dstExists:
				rec.Status, rec.Error = "conflict", "Both original and quarantine copies exist; preserved for manual review"
			default:
				rec.Status, rec.Error = "missing", "Both original and quarantine copies are missing"
			}
			changed = true
		} else if rec.Status == "quarantined" {
			if _, err := os.Stat(rec.QuarantinedPath); err != nil {
				rec.Status, rec.Error = "missing", "Quarantined file is missing"
				changed = true
			}
		}
	}
	state.mu.Unlock()
	if changed {
		_ = saveQuarantine()
		_ = audit("quarantine_reconciled", map[string]any{"changed": true})
	}
	updateHealth()
}

func moveFileVerified(src, dst, expectedHash string, modTime time.Time, mode os.FileMode) error {
	if src == "" || dst == "" {
		return errors.New("invalid move path")
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	if _, err := os.Stat(dst); err == nil {
		return errors.New("destination already exists")
	}

	if sameVolume(src, dst) {
		if err := os.Rename(src, dst); err == nil {
			h, verifyErr := hashFile(context.Background(), dst)
			if verifyErr == nil && h == expectedHash {
				return nil
			}
			if rollbackErr := os.Rename(dst, src); rollbackErr != nil {
				return fmt.Errorf("verification failed and rollback failed: %v / %v", verifyErr, rollbackErr)
			}
			return errors.New("moved file failed verification and was rolled back")
		}
	}

	tmp := dst + ".part"
	_ = os.Remove(tmp)
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	st, statErr := in.Stat()
	if statErr != nil {
		_ = in.Close()
		return statErr
	}
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		_ = in.Close()
		return err
	}
	_, copyErr := io.Copy(out, in)
	syncErr := out.Sync()
	closeOutErr := out.Close()
	closeInErr := in.Close()
	if copyErr != nil || syncErr != nil || closeOutErr != nil || closeInErr != nil {
		_ = os.Remove(tmp)
		for _, e := range []error{copyErr, syncErr, closeOutErr, closeInErr} {
			if e != nil {
				return e
			}
		}
	}
	if mode == 0 {
		mode = st.Mode()
	}
	_ = os.Chmod(tmp, mode.Perm())
	if modTime.IsZero() {
		modTime = st.ModTime()
	}
	_ = os.Chtimes(tmp, modTime, modTime)
	h, err := hashFile(context.Background(), tmp)
	if err != nil || h != expectedHash {
		_ = os.Remove(tmp)
		return errors.New("copied file failed SHA-256 verification")
	}
	if err = os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err = os.Remove(src); err != nil {
		_ = os.Remove(dst)
		return fmt.Errorf("source could not be removed after verified copy: %w", err)
	}
	return nil
}

func ensureMoveCapacity(src, dst string, size int64) error {
	if sameVolume(src, dst) {
		return nil
	}
	free, err := platformFreeSpace(filepath.Dir(dst))
	if err != nil {
		return fmt.Errorf("cannot verify destination free space: %w", err)
	}
	margin := uint64(256 * 1024 * 1024)
	required := uint64(size)
	if required > ^uint64(0)-margin {
		return errors.New("file is too large")
	}
	required += margin
	if free < required {
		return fmt.Errorf("destination needs %s free including safety reserve; only %s is available", formatBytes(int64(required)), formatBytes(int64(free)))
	}
	return nil
}

func sameVolume(a, b string) bool {
	va, vb := strings.ToLower(filepath.VolumeName(filepath.Clean(a))), strings.ToLower(filepath.VolumeName(filepath.Clean(b)))
	if runtime.GOOS == "windows" {
		return va != "" && va == vb
	}
	aDir, bDir := filepath.Dir(a), filepath.Dir(b)
	ai, ae := os.Stat(aDir)
	bi, be := os.Stat(bDir)
	return ae == nil && be == nil && os.SameFile(ai, bi)
}

func availableRestoreName(path string) string {
	ext := filepath.Ext(path)
	base := strings.TrimSuffix(path, ext)
	for i := 1; i < 10000; i++ {
		p := fmt.Sprintf("%s_restored_%d%s", base, i, ext)
		if _, err := os.Stat(p); os.IsNotExist(err) {
			return p
		}
	}
	return base + "_restored_" + time.Now().Format("20060102150405") + ext
}

func cleanupEmptyQuarantineDirs() {
	root := filepath.Join(state.dataDir, "Quarantine")
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || !d.IsDir() || path == root {
			return nil
		}
		entries, readErr := os.ReadDir(path)
		if readErr == nil && len(entries) == 0 {
			_ = os.Remove(path)
		}
		return nil
	})
}

func updateHealth() {
	state.mu.Lock()
	defer state.mu.Unlock()
	var bytes int64
	active, expired := 0, 0
	now := time.Now()
	for _, r := range state.quarantine {
		if r.Status == "quarantined" {
			active++
			bytes += r.Size
			if !r.PurgeAfter.IsZero() && !r.PurgeAfter.After(now) {
				expired++
			}
		}
	}
	state.health.QuarantineBytes = bytes
	state.health.ActiveQuarantine = active
	state.health.ExpiredQuarantine = expired
}

func formatBytes(n int64) string {
	if n < 1024 {
		return fmt.Sprintf("%d B", n)
	}
	units := []string{"KB", "MB", "GB", "TB"}
	v := float64(n)
	for _, u := range units {
		v /= 1024
		if v < 1024 {
			return fmt.Sprintf("%.1f %s", v, u)
		}
	}
	return fmt.Sprintf("%.1f PB", v/1024)
}
