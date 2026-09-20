//go:build !windows

package main

import (
	"os"
	"syscall"
)

type PlatformFileFlags struct {
	Hidden  bool
	System  bool
	Reparse bool
	Offline bool
	Recall  bool
}

func platformFileFlags(path string) (PlatformFileFlags, error) {
	st, err := os.Lstat(path)
	if err != nil {
		return PlatformFileFlags{}, err
	}
	return PlatformFileFlags{Reparse: st.Mode()&os.ModeSymlink != 0}, nil
}

func platformDriveKind(path string) string { return "fixed" }

func platformFreeSpace(path string) (uint64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, err
	}
	return st.Bavail * uint64(st.Bsize), nil
}

func platformNotify(title, body string) {}

func platformStartTray()                {}
func platformStopTray()                 {}
func platformRequestExistingExit() bool { return false }
