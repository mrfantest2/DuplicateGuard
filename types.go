package main

import (
	"context"
	"sync"
	"time"
)

const (
	appName         = "DuplicateGuard"
	appVersion      = "2.1.1"
	defaultPort     = 18473
	maxStateBackups = 5
)

type Config struct {
	Roots               []string `json:"roots"`
	PreferredRoots      []string `json:"preferredRoots"`
	ExcludedRoots       []string `json:"excludedRoots"`
	AutoRoots           []string `json:"autoRoots"`
	ExcludePatterns     []string `json:"excludePatterns"`
	MinSize             int64    `json:"minSize"`
	MaxSize             int64    `json:"maxSize"`
	MinFileAgeMinutes   int      `json:"minFileAgeMinutes"`
	ScanWorkers         int      `json:"scanWorkers"`
	ProtectCloud        bool     `json:"protectCloud"`
	IncludeHidden       bool     `json:"includeHidden"`
	AllowExternalDrives bool     `json:"allowExternalDrives"`
	AllowNetworkDrives  bool     `json:"allowNetworkDrives"`
	UseHashCache        bool     `json:"useHashCache"`
	MonitorEnabled      bool     `json:"monitorEnabled"`
	MonitorMinutes      int      `json:"monitorMinutes"`
	AutoQuarantine      bool     `json:"autoQuarantine"`
	AutoMinAgeDays      int      `json:"autoMinAgeDays"`
	AutoMaxFileSize     int64    `json:"autoMaxFileSize"`
	RetentionDays       int      `json:"retentionDays"`
	AutoPurgeExpired    bool     `json:"autoPurgeExpired"`
	Notifications       bool     `json:"notifications"`
	StartWithWindows    bool     `json:"startWithWindows"`
	FirstRunCompleted   bool     `json:"firstRunCompleted"`
}

type FileEntry struct {
	Path            string    `json:"path"`
	Name            string    `json:"name"`
	Size            int64     `json:"size"`
	ModTime         time.Time `json:"modTime"`
	Keep            bool      `json:"keep"`
	KeepReason      string    `json:"keepReason,omitempty"`
	Category        string    `json:"category"`
	Root            string    `json:"root"`
	ReadOnly        bool      `json:"readOnly"`
	Hidden          bool      `json:"hidden"`
	Cloud           bool      `json:"cloud"`
	DriveKind       string    `json:"driveKind"`
	AutoEligible    bool      `json:"autoEligible"`
	AutoReason      string    `json:"autoReason,omitempty"`
	ScanFingerprint string    `json:"scanFingerprint"`
}

type DuplicateGroup struct {
	Hash         string      `json:"hash"`
	Size         int64       `json:"size"`
	Waste        int64       `json:"waste"`
	Files        []FileEntry `json:"files"`
	GroupID      string      `json:"groupId"`
	Category     string      `json:"category"`
	AutoEligible bool        `json:"autoEligible"`
	Risk         string      `json:"risk"`
}

type ScanSummary struct {
	ScanID           string           `json:"scanId"`
	StartedAt        time.Time        `json:"startedAt"`
	FinishedAt       time.Time        `json:"finishedAt"`
	Roots            []string         `json:"roots"`
	FilesVisited     int64            `json:"filesVisited"`
	CandidateFiles   int64            `json:"candidateFiles"`
	HashedFiles      int64            `json:"hashedFiles"`
	CacheHits        int64            `json:"cacheHits"`
	DuplicateFiles   int              `json:"duplicateFiles"`
	Groups           int              `json:"groups"`
	Recoverable      int64            `json:"recoverable"`
	SkippedProtected int64            `json:"skippedProtected"`
	SkippedCloud     int64            `json:"skippedCloud"`
	SkippedHidden    int64            `json:"skippedHidden"`
	SkippedExternal  int64            `json:"skippedExternal"`
	SkippedNetwork   int64            `json:"skippedNetwork"`
	SkippedRecent    int64            `json:"skippedRecent"`
	SkippedPatterns  int64            `json:"skippedPatterns"`
	SkippedHardLinks int64            `json:"skippedHardLinks"`
	Partial          bool             `json:"partial"`
	Cancelled        bool             `json:"cancelled"`
	Errors           []string         `json:"errors"`
	Warnings         []string         `json:"warnings"`
	Results          []DuplicateGroup `json:"results"`
}

type JobStatus struct {
	Running        bool      `json:"running"`
	ScanID         string    `json:"scanId"`
	Phase          string    `json:"phase"`
	Message        string    `json:"message"`
	FilesVisited   int64     `json:"filesVisited"`
	CandidateFiles int64     `json:"candidateFiles"`
	HashedFiles    int64     `json:"hashedFiles"`
	CacheHits      int64     `json:"cacheHits"`
	StartedAt      time.Time `json:"startedAt"`
	LastScanAt     time.Time `json:"lastScanAt"`
	LastError      string    `json:"lastError"`
	Interrupted    bool      `json:"interrupted"`
}

type QuarantineRecord struct {
	ID              string    `json:"id"`
	GroupID         string    `json:"groupId"`
	OriginalPath    string    `json:"originalPath"`
	QuarantinedPath string    `json:"quarantinedPath"`
	Hash            string    `json:"hash"`
	Size            int64     `json:"size"`
	OriginalModTime time.Time `json:"originalModTime"`
	QuarantinedAt   time.Time `json:"quarantinedAt"`
	PurgeAfter      time.Time `json:"purgeAfter"`
	RestoredAt      time.Time `json:"restoredAt,omitempty"`
	RestoredPath    string    `json:"restoredPath,omitempty"`
	PurgedAt        time.Time `json:"purgedAt,omitempty"`
	Status          string    `json:"status"`
	Error           string    `json:"error,omitempty"`
	Automatic       bool      `json:"automatic"`
}

type HashCacheEntry struct {
	Path        string    `json:"path"`
	Size        int64     `json:"size"`
	ModUnixNano int64     `json:"modUnixNano"`
	QuickHash   string    `json:"quickHash"`
	FullHash    string    `json:"fullHash"`
	LastSeen    time.Time `json:"lastSeen"`
}

type RuntimeState struct {
	RunningScanID string    `json:"runningScanId"`
	ScanStartedAt time.Time `json:"scanStartedAt"`
	LastShutdown  time.Time `json:"lastShutdown"`
	CleanShutdown bool      `json:"cleanShutdown"`
}

type HealthStatus struct {
	Version             string `json:"version"`
	DataDirWritable     bool   `json:"dataDirWritable"`
	QuarantineWritable  bool   `json:"quarantineWritable"`
	ConfigRecovered     bool   `json:"configRecovered"`
	QuarantineRecovered bool   `json:"quarantineRecovered"`
	CacheRecovered      bool   `json:"cacheRecovered"`
	PreviousInterrupted bool   `json:"previousInterrupted"`
	QuarantineBytes     int64  `json:"quarantineBytes"`
	ActiveQuarantine    int    `json:"activeQuarantine"`
	ExpiredQuarantine   int    `json:"expiredQuarantine"`
	LastAuditError      string `json:"lastAuditError,omitempty"`
	ServerURL           string `json:"serverUrl"`
}

type AppState struct {
	mu          sync.RWMutex
	config      Config
	summary     ScanSummary
	status      JobStatus
	quarantine  []QuarantineRecord
	hashCache   map[string]HashCacheEntry
	runtime     RuntimeState
	health      HealthStatus
	cancelScan  context.CancelFunc
	token       string
	dataDir     string
	exePath     string
	serverURL   string
	background  bool
	monitorWake chan struct{}
}

var state AppState
