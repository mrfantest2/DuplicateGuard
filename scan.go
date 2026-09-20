package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type hashResult struct {
	file     FileEntry
	hash     string
	cacheHit bool
	err      error
}

func scanFolders(ctx context.Context, cfg Config) ScanSummary {
	cfg = normalizeConfig(cfg)
	sum := ScanSummary{
		ScanID: randomID("scan"), StartedAt: time.Now(),
		Roots:   append([]string(nil), cfg.Roots...),
		Results: []DuplicateGroup{}, Errors: []string{}, Warnings: []string{},
	}
	sizeMap := map[int64][]FileEntry{}
	seen := map[string]bool{}
	var sumMu sync.Mutex

	updateStatus("indexing", "Indexing selected folders")
	for _, root := range cfg.Roots {
		if ctx.Err() != nil {
			break
		}
		root = filepath.Clean(root)
		if isProtectedPath(root) || samePathOrInside(root, state.dataDir) || isDriveRoot(root) {
			sum.SkippedProtected++
			sum.Warnings = appendLimited(sum.Warnings, fmt.Sprintf("Protected location skipped: %s", root))
			continue
		}
		if isUnderAny(root, cfg.ExcludedRoots) {
			sum.Warnings = appendLimited(sum.Warnings, fmt.Sprintf("Excluded root skipped: %s", root))
			continue
		}
		kind := platformDriveKind(root)
		if (kind == "removable" || kind == "cdrom") && !cfg.AllowExternalDrives {
			sum.SkippedExternal++
			sum.Warnings = appendLimited(sum.Warnings, fmt.Sprintf("External drive skipped: %s", root))
			continue
		}
		if kind == "network" && !cfg.AllowNetworkDrives {
			sum.SkippedNetwork++
			sum.Warnings = appendLimited(sum.Warnings, fmt.Sprintf("Network location skipped: %s", root))
			continue
		}
		if cfg.ProtectCloud && isKnownCloudPath(root) {
			sum.SkippedCloud++
			sum.Warnings = appendLimited(sum.Warnings, fmt.Sprintf("Cloud folder skipped: %s", root))
			continue
		}
		info, err := os.Stat(root)
		if err != nil || !info.IsDir() {
			sum.Errors = appendLimited(sum.Errors, fmt.Sprintf("Cannot scan %s", root))
			continue
		}

		walkErr := filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
			if ctx.Err() != nil {
				return context.Canceled
			}
			if walkErr != nil {
				sumMu.Lock()
				sum.Errors = appendLimited(sum.Errors, walkErr.Error())
				sumMu.Unlock()
				if d != nil && d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if path != root && (isProtectedPath(path) || samePathOrInside(path, state.dataDir) || isUnderAny(path, cfg.ExcludedRoots)) {
				if d.IsDir() {
					sumMu.Lock()
					sum.SkippedProtected++
					sumMu.Unlock()
					return filepath.SkipDir
				}
				return nil
			}
			flags, flagErr := platformFileFlags(path)
			if flagErr == nil {
				if flags.Reparse {
					if d.IsDir() {
						return filepath.SkipDir
					}
					return nil
				}
				if cfg.ProtectCloud && (flags.Offline || flags.Recall || isKnownCloudPath(path)) {
					sumMu.Lock()
					sum.SkippedCloud++
					sumMu.Unlock()
					if d.IsDir() {
						return filepath.SkipDir
					}
					return nil
				}
				if !cfg.IncludeHidden && (flags.Hidden || flags.System) {
					sumMu.Lock()
					sum.SkippedHidden++
					sumMu.Unlock()
					if d.IsDir() {
						return filepath.SkipDir
					}
					return nil
				}
			} else if d.Type()&os.ModeSymlink != 0 {
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if d.IsDir() {
				return nil
			}
			if d.Type()&os.ModeSymlink != 0 {
				return nil
			}
			info, err := d.Info()
			if err != nil || !info.Mode().IsRegular() {
				return nil
			}

			visited := atomic.AddInt64(&sum.FilesVisited, 1)
			state.mu.Lock()
			state.status.FilesVisited = visited
			state.mu.Unlock()

			if info.Size() < cfg.MinSize || (cfg.MaxSize > 0 && info.Size() > cfg.MaxSize) {
				return nil
			}
			if cfg.MinFileAgeMinutes > 0 && time.Since(info.ModTime()) < time.Duration(cfg.MinFileAgeMinutes)*time.Minute {
				atomic.AddInt64(&sum.SkippedRecent, 1)
				return nil
			}
			if matchesExcludedPattern(path, cfg.ExcludePatterns) {
				atomic.AddInt64(&sum.SkippedPatterns, 1)
				return nil
			}
			abs, err := filepath.Abs(path)
			if err != nil {
				return nil
			}
			key := normalizePath(abs)
			if seen[key] {
				return nil
			}
			seen[key] = true

			rootForFile := containingRoot(abs, cfg.Roots)
			ff, _ := platformFileFlags(abs)
			entry := FileEntry{
				Path: abs, Name: filepath.Base(abs), Size: info.Size(), ModTime: info.ModTime(),
				Category: fileCategory(abs), Root: rootForFile,
				ReadOnly: info.Mode().Perm()&0o200 == 0,
				Hidden:   ff.Hidden || ff.System, Cloud: ff.Offline || ff.Recall || isKnownCloudPath(abs),
				DriveKind: kind, ScanFingerprint: fileFingerprint(info),
			}
			sizeMap[info.Size()] = append(sizeMap[info.Size()], entry)
			return nil
		})
		if walkErr != nil && ctx.Err() == nil {
			sum.Errors = appendLimited(sum.Errors, fmt.Sprintf("%s: %v", root, walkErr))
		}
	}

	candidates := make([]FileEntry, 0)
	for _, files := range sizeMap {
		if len(files) < 2 {
			continue
		}
		unique, skipped := collapseHardLinks(files)
		sum.SkippedHardLinks += int64(skipped)
		if len(unique) > 1 {
			candidates = append(candidates, unique...)
		}
	}
	sum.CandidateFiles = int64(len(candidates))
	state.mu.Lock()
	state.status.CandidateFiles = sum.CandidateFiles
	state.status.Phase = "hashing"
	state.status.Message = "Verifying exact content with SHA-256"
	state.mu.Unlock()

	hashMap := map[string][]FileEntry{}
	workers := cfg.ScanWorkers
	if workers < 1 {
		workers = 1
	}
	if workers > 8 {
		workers = 8
	}
	jobs := make(chan FileEntry)
	results := make(chan hashResult)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for f := range jobs {
				h, cacheHit, err := contentHash(ctx, f, cfg.UseHashCache)
				select {
				case results <- hashResult{file: f, hash: h, cacheHit: cacheHit, err: err}:
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	go func() {
		defer close(results)
		for _, f := range candidates {
			select {
			case jobs <- f:
			case <-ctx.Done():
				close(jobs)
				wg.Wait()
				return
			}
		}
		close(jobs)
		wg.Wait()
	}()

	for r := range results {
		if r.err != nil {
			if ctx.Err() == nil {
				sum.Errors = appendLimited(sum.Errors, fmt.Sprintf("%s: %v", r.file.Path, r.err))
			}
			continue
		}
		if r.cacheHit {
			sum.CacheHits++
		} else {
			sum.HashedFiles++
		}
		state.mu.Lock()
		state.status.HashedFiles = sum.HashedFiles
		state.status.CacheHits = sum.CacheHits
		state.mu.Unlock()
		key := strconv.FormatInt(r.file.Size, 10) + ":" + r.hash
		hashMap[key] = append(hashMap[key], r.file)
	}

	for key, files := range hashMap {
		if len(files) < 2 {
			continue
		}
		hash := strings.SplitN(key, ":", 2)[1]
		keepReason := chooseKeep(files, cfg.PreferredRoots)
		for i := range files {
			if files[i].Keep {
				files[i].KeepReason = keepReason
			}
		}
		group := DuplicateGroup{
			Hash: hash, Size: files[0].Size, Waste: files[0].Size * int64(len(files)-1),
			Files: files, GroupID: hash[:12], Category: files[0].Category, Risk: "review",
		}
		markAutoEligibility(&group, cfg)
		sum.Results = append(sum.Results, group)
		sum.DuplicateFiles += len(files) - 1
		sum.Recoverable += group.Waste
	}
	sort.Slice(sum.Results, func(i, j int) bool {
		if sum.Results[i].Waste != sum.Results[j].Waste {
			return sum.Results[i].Waste > sum.Results[j].Waste
		}
		return sum.Results[i].GroupID < sum.Results[j].GroupID
	})
	sum.Groups = len(sum.Results)
	sum.FinishedAt = time.Now()
	if ctx.Err() != nil {
		sum.Partial, sum.Cancelled = true, true
		sum.Warnings = appendLimited(sum.Warnings, "The scan was cancelled. Results are incomplete and cleanup is disabled until a complete scan finishes.")
	}
	if sum.SkippedHardLinks > 0 {
		sum.Warnings = appendLimited(sum.Warnings, fmt.Sprintf("%d hard-link aliases were ignored because they do not consume duplicate disk space.", sum.SkippedHardLinks))
	}
	if cfg.UseHashCache {
		_ = saveHashCache()
	}
	return sum
}

func contentHash(ctx context.Context, f FileEntry, allowCache bool) (string, bool, error) {
	quick, err := quickHashFile(ctx, f.Path, f.Size)
	if err != nil {
		return "", false, err
	}
	key := normalizePath(f.Path)
	if allowCache {
		state.mu.RLock()
		ce, ok := state.hashCache[key]
		state.mu.RUnlock()
		if ok && ce.Size == f.Size && ce.ModUnixNano == f.ModTime.UnixNano() && ce.QuickHash == quick && ce.FullHash != "" {
			ce.LastSeen = time.Now()
			state.mu.Lock()
			state.hashCache[key] = ce
			state.mu.Unlock()
			return ce.FullHash, true, nil
		}
	}
	full, err := hashFile(ctx, f.Path)
	if err != nil {
		return "", false, err
	}
	if allowCache {
		state.mu.Lock()
		state.hashCache[key] = HashCacheEntry{Path: f.Path, Size: f.Size, ModUnixNano: f.ModTime.UnixNano(), QuickHash: quick, FullHash: full, LastSeen: time.Now()}
		state.mu.Unlock()
	}
	return full, false, nil
}

func quickHashFile(ctx context.Context, path string, size int64) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	_, _ = io.WriteString(h, strconv.FormatInt(size, 10)+":")
	const chunk = int64(64 * 1024)
	first := chunk
	if size < first {
		first = size
	}
	if first > 0 {
		if _, err = io.CopyN(h, f, first); err != nil {
			return "", err
		}
	}
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	if size > chunk {
		start := size - chunk
		if _, err = f.Seek(start, io.SeekStart); err != nil {
			return "", err
		}
		if _, err = io.CopyN(h, f, chunk); err != nil {
			return "", err
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func hashFile(ctx context.Context, path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	buf := make([]byte, 1024*1024)
	for {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		n, er := f.Read(buf)
		if n > 0 {
			_, _ = h.Write(buf[:n])
		}
		if er == io.EOF {
			break
		}
		if er != nil {
			return "", er
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func collapseHardLinks(files []FileEntry) ([]FileEntry, int) {
	unique := make([]FileEntry, 0, len(files))
	infos := make([]os.FileInfo, 0, len(files))
	skipped := 0
	for _, f := range files {
		info, err := os.Stat(f.Path)
		if err != nil {
			continue
		}
		same := false
		for _, prev := range infos {
			if os.SameFile(info, prev) {
				same = true
				break
			}
		}
		if same {
			skipped++
			continue
		}
		unique = append(unique, f)
		infos = append(infos, info)
	}
	return unique, skipped
}

func chooseKeep(files []FileEntry, preferred []string) string {
	sort.Slice(files, func(i, j int) bool {
		pi, pj := pathPreference(files[i].Path, preferred), pathPreference(files[j].Path, preferred)
		if pi != pj {
			return pi > pj
		}
		if !files[i].ModTime.Equal(files[j].ModTime) {
			return files[i].ModTime.Before(files[j].ModTime)
		}
		if len(files[i].Path) != len(files[j].Path) {
			return len(files[i].Path) < len(files[j].Path)
		}
		return normalizePath(files[i].Path) < normalizePath(files[j].Path)
	})
	for i := range files {
		files[i].Keep = i == 0
	}
	if isUnderAny(files[0].Path, preferred) {
		return "Preferred master folder"
	}
	if !duplicateName(files[0].Name) {
		return "Original-looking name and oldest modified copy"
	}
	return "Oldest verified copy"
}

func markAutoEligibility(g *DuplicateGroup, cfg Config) {
	keeper := FileEntry{}
	for _, f := range g.Files {
		if f.Keep {
			keeper = f
			break
		}
	}
	allExtrasEligible := true
	for i := range g.Files {
		f := &g.Files[i]
		if f.Keep {
			continue
		}
		f.AutoEligible, f.AutoReason = autoEligibility(*f, keeper, cfg)
		if !f.AutoEligible {
			allExtrasEligible = false
		}
	}
	g.AutoEligible = allExtrasEligible
	if allExtrasEligible {
		g.Risk = "low"
	}
}

func autoEligibility(f, keeper FileEntry, cfg Config) (bool, string) {
	if len(cfg.AutoRoots) == 0 || !isUnderAny(f.Path, cfg.AutoRoots) {
		return false, "Outside approved automatic folders"
	}
	if f.Cloud {
		return false, "Cloud-managed file"
	}
	if f.ReadOnly {
		return false, "Read-only file"
	}
	if f.DriveKind != "" && f.DriveKind != "fixed" {
		return false, "Not on a fixed local drive"
	}
	if cfg.AutoMaxFileSize > 0 && f.Size > cfg.AutoMaxFileSize {
		return false, "Above automatic size limit"
	}
	if time.Since(f.ModTime) < time.Duration(cfg.AutoMinAgeDays)*24*time.Hour {
		return false, "Too recent for unattended cleanup"
	}
	if unsafeAutoExtension(filepath.Ext(f.Path)) {
		return false, "Sensitive file type requires review"
	}
	if isUnderAny(keeper.Path, cfg.PreferredRoots) {
		return true, "Verified copy exists in a preferred master folder"
	}
	if duplicateName(f.Name) {
		return true, "Duplicate-style filename with a verified retained copy"
	}
	return false, "Requires manual review"
}

func unsafeAutoExtension(ext string) bool {
	switch strings.ToLower(ext) {
	case ".pst", ".ost", ".db", ".sqlite", ".sqlite3", ".vhd", ".vhdx", ".iso", ".img", ".bak", ".wallet", ".key", ".pem", ".pfx", ".cer":
		return true
	}
	return false
}

func normalizeConfig(cfg Config) Config {
	cfg.Roots = compactRoots(cleanRoots(cfg.Roots))
	cfg.PreferredRoots = cleanRoots(cfg.PreferredRoots)
	cfg.ExcludedRoots = compactRoots(cleanRoots(cfg.ExcludedRoots))
	cfg.AutoRoots = compactRoots(cleanRoots(cfg.AutoRoots))
	if cfg.MinSize < 0 {
		cfg.MinSize = 0
	}
	if cfg.MaxSize < 0 {
		cfg.MaxSize = 0
	}
	if cfg.MinFileAgeMinutes < 0 {
		cfg.MinFileAgeMinutes = 0
	}
	if cfg.ScanWorkers < 1 {
		cfg.ScanWorkers = 2
	}
	if cfg.ScanWorkers > 8 {
		cfg.ScanWorkers = 8
	}
	if cfg.MonitorMinutes < 15 {
		cfg.MonitorMinutes = 15
	}
	if cfg.MonitorMinutes > 10080 {
		cfg.MonitorMinutes = 10080
	}
	if cfg.AutoMinAgeDays < 1 {
		cfg.AutoMinAgeDays = 7
	}
	if cfg.AutoMinAgeDays > 3650 {
		cfg.AutoMinAgeDays = 3650
	}
	if cfg.RetentionDays < 7 {
		cfg.RetentionDays = 30
	}
	if cfg.RetentionDays > 3650 {
		cfg.RetentionDays = 3650
	}
	return cfg
}

func defaultConfig() Config {
	roots, auto := []string{}, []string{}
	if home, err := os.UserHomeDir(); err == nil {
		for _, name := range []string{"Downloads", "Desktop", "Documents", "Pictures", "Videos"} {
			p := filepath.Join(home, name)
			if st, err := os.Stat(p); err == nil && st.IsDir() {
				roots = append(roots, p)
			}
			if name == "Downloads" && stExistsDir(p) {
				auto = append(auto, p)
			}
		}
	}
	return Config{
		Roots: roots, AutoRoots: auto,
		ExcludePatterns: []string{"*.tmp", "~$*", "*.part", "*.crdownload", "*.download"},
		MinSize:         1024, MinFileAgeMinutes: 10, ScanWorkers: 2,
		ProtectCloud: true, UseHashCache: true,
		MonitorMinutes: 1440, AutoMinAgeDays: 7, AutoMaxFileSize: 10 * 1024 * 1024 * 1024,
		RetentionDays: 30, Notifications: true,
	}
}

func stExistsDir(path string) bool { st, err := os.Stat(path); return err == nil && st.IsDir() }

func cleanRoots(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, p := range in {
		p = strings.TrimSpace(strings.Trim(p, `"`))
		if p == "" {
			continue
		}
		a, err := filepath.Abs(p)
		if err != nil {
			continue
		}
		a = filepath.Clean(a)
		k := normalizePath(a)
		if !seen[k] {
			seen[k] = true
			out = append(out, a)
		}
	}
	return out
}

func compactRoots(in []string) []string {
	sort.Slice(in, func(i, j int) bool { return len(in[i]) < len(in[j]) })
	out := []string{}
	for _, p := range in {
		if !isUnderAny(p, out) {
			out = append(out, p)
		}
	}
	return out
}

func normalizePath(path string) string {
	p := filepath.Clean(path)
	if runtime.GOOS == "windows" {
		p = strings.ToLower(p)
	}
	return p
}

func samePathOrInside(path, root string) bool {
	if strings.TrimSpace(root) == "" {
		return false
	}
	p, r := normalizePath(path), normalizePath(root)
	if p == r {
		return true
	}
	sep := string(os.PathSeparator)
	return strings.HasPrefix(p, strings.TrimSuffix(r, sep)+sep)
}

func isUnderAny(path string, roots []string) bool {
	for _, r := range roots {
		if samePathOrInside(path, r) {
			return true
		}
	}
	return false
}

func containingRoot(path string, roots []string) string {
	best := ""
	for _, r := range roots {
		if samePathOrInside(path, r) && len(r) > len(best) {
			best = r
		}
	}
	return best
}

func isDriveRoot(path string) bool {
	p := filepath.Clean(path)
	vol := filepath.VolumeName(p)
	if vol == "" {
		return p == string(os.PathSeparator)
	}
	rest := strings.Trim(strings.TrimPrefix(p, vol), `\/`)
	return rest == ""
}

func isProtectedPath(path string) bool {
	p := strings.ToLower(filepath.Clean(path))
	vol := strings.ToLower(filepath.VolumeName(p))
	trim := strings.TrimLeft(strings.TrimPrefix(p, vol), `\/`)
	parts := strings.FieldsFunc(trim, func(r rune) bool { return r == '\\' || r == '/' })
	for _, part := range parts {
		switch strings.ToLower(part) {
		case "windows", "program files", "program files (x86)", "programdata", "appdata", "$recycle.bin", "system volume information", "recovery", "boot", "msocache":
			return true
		}
	}
	return false
}

func isKnownCloudPath(path string) bool {
	if path == "" {
		return false
	}
	for _, env := range []string{"OneDrive", "OneDriveConsumer", "OneDriveCommercial", "Dropbox", "GoogleDrive", "iCloudDrive"} {
		if r := strings.TrimSpace(os.Getenv(env)); r != "" && samePathOrInside(path, r) {
			return true
		}
	}
	parts := strings.FieldsFunc(strings.ToLower(filepath.Clean(path)), func(r rune) bool { return r == '\\' || r == '/' })
	for _, part := range parts {
		switch part {
		case "onedrive", "dropbox", "google drive", "google drive streaming", "icloud drive", "iclouddrive":
			return true
		}
	}
	return false
}

func matchesExcludedPattern(path string, patterns []string) bool {
	base := strings.ToLower(filepath.Base(path))
	full := strings.ToLower(filepath.ToSlash(path))
	for _, pattern := range patterns {
		pattern = strings.TrimSpace(strings.ToLower(filepath.ToSlash(pattern)))
		if pattern == "" {
			continue
		}
		if ok, _ := filepath.Match(pattern, base); ok {
			return true
		}
		if ok, _ := filepath.Match(pattern, full); ok {
			return true
		}
		if strings.HasPrefix(pattern, "*") && strings.HasSuffix(full, strings.TrimPrefix(pattern, "*")) {
			return true
		}
	}
	return false
}

func fileFingerprint(info os.FileInfo) string {
	return strconv.FormatInt(info.Size(), 10) + ":" + strconv.FormatInt(info.ModTime().UnixNano(), 10) + ":" + strconv.FormatUint(uint64(info.Mode()), 10)
}

func pathPreference(path string, preferred []string) int {
	if isUnderAny(path, preferred) {
		return 100
	}
	lower := strings.ToLower(filepath.ToSlash(path))
	score := 0
	if strings.Contains(lower, "/documents/") {
		score += 6
	}
	if strings.Contains(lower, "/pictures/") {
		score += 5
	}
	if strings.Contains(lower, "/videos/") {
		score += 4
	}
	if strings.Contains(lower, "/desktop/") {
		score += 1
	}
	if strings.Contains(lower, "/downloads/") {
		score -= 5
	}
	if duplicateName(filepath.Base(path)) {
		score -= 8
	}
	return score
}

func duplicateName(name string) bool {
	n := strings.ToLower(strings.TrimSuffix(name, filepath.Ext(name)))
	markers := []string{" - copy", " copy", "copy of ", "(copy)", "_copy", " duplicate"}
	for _, m := range markers {
		if strings.Contains(n, m) {
			return true
		}
	}
	for _, suffix := range []string{" (1)", " (2)", " (3)", " (4)", " (5)"} {
		if strings.HasSuffix(n, suffix) {
			return true
		}
	}
	return false
}

func fileCategory(path string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".heic", ".tif", ".tiff", ".raw", ".dng":
		return "Photos"
	case ".mp4", ".mkv", ".mov", ".avi", ".wmv", ".webm", ".m4v", ".3gp":
		return "Videos"
	case ".mp3", ".wav", ".flac", ".aac", ".m4a", ".ogg", ".opus", ".wma":
		return "Audio"
	case ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".rtf", ".csv", ".odt":
		return "Documents"
	case ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz":
		return "Archives"
	default:
		return "Other"
	}
}

func safeName(s string) string {
	bad := `<>:"/\\|?*`
	return strings.Map(func(r rune) rune {
		if strings.ContainsRune(bad, r) || r < 32 {
			return '_'
		}
		return r
	}, s)
}

func appendLimited(xs []string, s string) []string {
	if len(xs) < 200 {
		return append(xs, s)
	}
	return xs
}
