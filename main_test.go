package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testState(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	if err := ensureDataLayout(d); err != nil {
		t.Fatal(err)
	}
	state = AppState{
		dataDir: d, hashCache: map[string]HashCacheEntry{}, token: "test",
		config: normalizeConfig(defaultConfig()), monitorWake: make(chan struct{}, 1),
		health: HealthStatus{Version: appVersion},
	}
	return d
}

func writeTestFile(t *testing.T, path string, content []byte, age time.Duration) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	when := time.Now().Add(-age)
	if err := os.Chtimes(path, when, when); err != nil {
		t.Fatal(err)
	}
}

func basicConfig(root string) Config {
	return normalizeConfig(Config{
		Roots: []string{root}, MinSize: 0, MinFileAgeMinutes: 0, ScanWorkers: 2,
		UseHashCache: false, RetentionDays: 30, AutoMinAgeDays: 7,
		AutoMaxFileSize: 10 * 1024 * 1024 * 1024,
	})
}

func TestExactDuplicateDetectionAndPreferredKeep(t *testing.T) {
	testState(t)
	root := t.TempDir()
	preferred := filepath.Join(root, "Master")
	original := filepath.Join(preferred, "original.bin")
	copy1 := filepath.Join(root, "Downloads", "original (1).bin")
	copy2 := filepath.Join(root, "Other", "renamed.bin")
	different := filepath.Join(root, "Other", "different.bin")
	writeTestFile(t, original, []byte("0123456789ABCDEF"), 72*time.Hour)
	writeTestFile(t, copy1, []byte("0123456789ABCDEF"), 48*time.Hour)
	writeTestFile(t, copy2, []byte("0123456789ABCDEF"), 24*time.Hour)
	writeTestFile(t, different, []byte("FEDCBA9876543210"), 24*time.Hour)

	cfg := basicConfig(root)
	cfg.PreferredRoots = []string{preferred}
	got := scanFolders(context.Background(), cfg)
	if got.Groups != 1 {
		t.Fatalf("groups=%d, want 1; errors=%v", got.Groups, got.Errors)
	}
	if got.DuplicateFiles != 2 {
		t.Fatalf("duplicate files=%d, want 2", got.DuplicateFiles)
	}
	if len(got.Results[0].Files) != 3 {
		t.Fatalf("group files=%d, want 3", len(got.Results[0].Files))
	}
	var kept FileEntry
	for _, f := range got.Results[0].Files {
		if f.Keep {
			kept = f
		}
	}
	if kept.Path != original {
		t.Fatalf("kept %q, want preferred %q", kept.Path, original)
	}
	if got.Results[0].Hash == "" || len(got.Results[0].Hash) != 64 {
		t.Fatal("missing SHA-256")
	}
}

func TestHashCacheUsesQuickRevalidation(t *testing.T) {
	testState(t)
	root := t.TempDir()
	a, b := filepath.Join(root, "a.bin"), filepath.Join(root, "b.bin")
	content := []byte(strings.Repeat("cache-test-", 20000))
	writeTestFile(t, a, content, 48*time.Hour)
	writeTestFile(t, b, content, 48*time.Hour)
	cfg := basicConfig(root)
	cfg.UseHashCache = true

	first := scanFolders(context.Background(), cfg)
	if first.Groups != 1 || first.HashedFiles != 2 {
		t.Fatalf("first scan=%+v", first)
	}
	second := scanFolders(context.Background(), cfg)
	if second.Groups != 1 || second.CacheHits != 2 {
		t.Fatalf("second cache hits=%d, want 2", second.CacheHits)
	}

	st, _ := os.Stat(b)
	changed := append([]byte(nil), content...)
	changed[0] ^= 0xff
	if err := os.WriteFile(b, changed, 0o600); err != nil {
		t.Fatal(err)
	}
	_ = os.Chtimes(b, st.ModTime(), st.ModTime()) // same size and timestamp; quick fingerprint must still catch it.
	third := scanFolders(context.Background(), cfg)
	if third.Groups != 0 {
		t.Fatal("cache trusted changed bytes with same size and timestamp")
	}
}

func TestHardLinksDoNotCountAsDuplicateStorage(t *testing.T) {
	testState(t)
	root := t.TempDir()
	a, b := filepath.Join(root, "a.bin"), filepath.Join(root, "b.bin")
	writeTestFile(t, a, []byte("same physical file"), 48*time.Hour)
	if err := os.Link(a, b); err != nil {
		t.Skipf("hard links unsupported: %v", err)
	}
	got := scanFolders(context.Background(), basicConfig(root))
	if got.Groups != 0 {
		t.Fatal("hard-link aliases were counted as duplicate disk usage")
	}
	if got.SkippedHardLinks != 1 {
		t.Fatalf("skipped hardlinks=%d, want 1", got.SkippedHardLinks)
	}
}

func TestQuarantineSafetyRestoreAndPurge(t *testing.T) {
	testState(t)
	root := t.TempDir()
	a, b := filepath.Join(root, "original.txt"), filepath.Join(root, "original (1).txt")
	writeTestFile(t, a, []byte("same-content"), 48*time.Hour)
	writeTestFile(t, b, []byte("same-content"), 48*time.Hour)
	cfg := basicConfig(root)
	sum := scanFolders(context.Background(), cfg)
	state.config, state.summary = cfg, sum

	moved, errs := quarantinePaths([]string{a, b}, false)
	if len(moved) != 0 || len(errs) == 0 {
		t.Fatalf("all-copy safety failed moved=%d errs=%v", len(moved), errs)
	}

	extra := ""
	for _, f := range sum.Results[0].Files {
		if !f.Keep {
			extra = f.Path
		}
	}
	moved, errs = quarantinePaths([]string{extra}, false)
	if len(moved) != 1 || len(errs) != 0 {
		t.Fatalf("quarantine moved=%d errs=%v", len(moved), errs)
	}
	if _, err := os.Stat(extra); !os.IsNotExist(err) {
		t.Fatalf("source still present: %v", err)
	}
	if _, err := os.Stat(moved[0].QuarantinedPath); err != nil {
		t.Fatalf("quarantine missing: %v", err)
	}

	restored, errs := restoreRecords([]string{moved[0].ID})
	if len(restored) != 1 || len(errs) != 0 {
		t.Fatalf("restore=%d errs=%v", len(restored), errs)
	}
	if _, err := os.Stat(extra); err != nil {
		t.Fatalf("restored path missing: %v", err)
	}

	// Quarantine again and permanently purge.
	sum = scanFolders(context.Background(), cfg)
	state.summary = sum
	extra = ""
	for _, f := range sum.Results[0].Files {
		if !f.Keep {
			extra = f.Path
		}
	}
	moved, errs = quarantinePaths([]string{extra}, false)
	if len(moved) != 1 || len(errs) != 0 {
		t.Fatalf("second quarantine=%d errs=%v", len(moved), errs)
	}
	purged, errs := purgeRecords([]string{moved[0].ID}, false, false)
	if len(purged) != 1 || len(errs) != 0 {
		t.Fatalf("purge=%d errs=%v", len(purged), errs)
	}
	if _, err := os.Stat(moved[0].QuarantinedPath); !os.IsNotExist(err) {
		t.Fatalf("purged file still exists: %v", err)
	}
}

func TestCleanupRevalidatesChangedFile(t *testing.T) {
	testState(t)
	root := t.TempDir()
	a, b := filepath.Join(root, "a.txt"), filepath.Join(root, "b.txt")
	writeTestFile(t, a, []byte("1234567890"), 48*time.Hour)
	writeTestFile(t, b, []byte("1234567890"), 48*time.Hour)
	cfg := basicConfig(root)
	sum := scanFolders(context.Background(), cfg)
	state.config, state.summary = cfg, sum
	extra := ""
	for _, f := range sum.Results[0].Files {
		if !f.Keep {
			extra = f.Path
		}
	}
	writeTestFile(t, extra, []byte("abcdefghij"), 48*time.Hour) // same size, different bytes.
	moved, errs := quarantinePaths([]string{extra}, false)
	if len(moved) != 0 || len(errs) == 0 {
		t.Fatal("changed file was quarantined without revalidation")
	}
	if _, err := os.Stat(extra); err != nil {
		t.Fatal("changed source was removed")
	}
}

func TestAutoEligibilityIsConservative(t *testing.T) {
	root := t.TempDir()
	downloads := filepath.Join(root, "Downloads")
	master := filepath.Join(root, "Documents", "Master")
	cfg := basicConfig(root)
	cfg.AutoRoots = []string{downloads}
	cfg.PreferredRoots = []string{master}
	cfg.AutoMinAgeDays = 7
	keeper := FileEntry{Path: filepath.Join(master, "photo.jpg"), Name: "photo.jpg", ModTime: time.Now().Add(-30 * 24 * time.Hour), DriveKind: "fixed"}
	extra := FileEntry{Path: filepath.Join(downloads, "photo (1).jpg"), Name: "photo (1).jpg", ModTime: time.Now().Add(-10 * 24 * time.Hour), DriveKind: "fixed", Size: 100}
	ok, _ := autoEligibility(extra, keeper, cfg)
	if !ok {
		t.Fatal("expected old duplicate-style Downloads copy with master keeper to be auto-eligible")
	}
	extra.ModTime = time.Now().Add(-24 * time.Hour)
	if ok, _ = autoEligibility(extra, keeper, cfg); ok {
		t.Fatal("recent file became auto-eligible")
	}
	extra.ModTime = time.Now().Add(-10 * 24 * time.Hour)
	extra.Path = filepath.Join(root, "Desktop", extra.Name)
	if ok, _ = autoEligibility(extra, keeper, cfg); ok {
		t.Fatal("outside approved auto root became eligible")
	}
}

func TestStateBackupRecovery(t *testing.T) {
	d := testState(t)
	state.config.MinSize = 111
	if err := saveConfig(); err != nil {
		t.Fatal(err)
	}
	state.config.MinSize = 222
	if err := saveConfig(); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(d, "config.json")
	if err := os.WriteFile(p, []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	var recovered Config
	found, fromBackup, err := loadJSONWithRecovery(p, &recovered)
	if err != nil || !found || !fromBackup {
		t.Fatalf("found=%v backup=%v err=%v", found, fromBackup, err)
	}
	if recovered.MinSize != 111 {
		t.Fatalf("recovered MinSize=%d, want prior valid backup 111", recovered.MinSize)
	}
}

func TestProtectedAndCloudLocations(t *testing.T) {
	protected := []string{`C:\Windows\System32`, `C:\Program Files\Example`, `C:\Users\User\AppData\Local`, `D:\$Recycle.Bin`}
	for _, p := range protected {
		if !isProtectedPath(p) {
			t.Errorf("expected protected: %s", p)
		}
	}
	cloud := []string{`C:\Users\User\OneDrive\Photos`, `C:\Users\User\Dropbox\A`, `C:\Users\User\Google Drive\B`}
	for _, p := range cloud {
		if !isKnownCloudPath(p) {
			t.Errorf("expected cloud path: %s", p)
		}
	}
	if isProtectedPath(filepath.Join(t.TempDir(), "Documents")) {
		t.Fatal("ordinary personal folder marked protected")
	}
}

func TestDuplicateNameAndSafeName(t *testing.T) {
	if !duplicateName("photo (1).jpg") || !duplicateName("report - Copy.pdf") {
		t.Fatal("duplicate naming heuristic not recognized")
	}
	if duplicateName("original.jpg") {
		t.Fatal("ordinary name marked duplicate")
	}
	if !strings.Contains(strings.ToLower(safeName(`bad:name?.txt`)), "bad_name_.txt") {
		t.Fatal("safeName failed")
	}
}
