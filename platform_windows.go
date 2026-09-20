//go:build windows

package main

import (
	"fmt"
	"log"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

type PlatformFileFlags struct {
	Hidden  bool
	System  bool
	Reparse bool
	Offline bool
	Recall  bool
}

const (
	fileAttributeHidden             = 0x00000002
	fileAttributeSystem             = 0x00000004
	fileAttributeReparsePoint       = 0x00000400
	fileAttributeOffline            = 0x00001000
	fileAttributeRecallOnOpen       = 0x00040000
	fileAttributeRecallOnDataAccess = 0x00400000

	wmDestroy       = 0x0002
	wmClose         = 0x0010
	wmCommand       = 0x0111
	wmLButtonUp     = 0x0202
	wmLButtonDblClk = 0x0203
	wmRButtonUp     = 0x0205
	wmContextMenu   = 0x007B
	wmUser          = 0x0400
	ninSelect       = wmUser
	ninKeySelect    = wmUser + 1
	wmApp           = 0x8000
	trayCallbackMsg = wmApp + 1
	trayExitMsg     = wmApp + 2

	nimAdd    = 0x00000000
	nimModify = 0x00000001
	nimDelete = 0x00000002
	nimSetVer = 0x00000004

	nifMessage = 0x00000001
	nifIcon    = 0x00000002
	nifTip     = 0x00000004
	nifShowTip = 0x00000080

	notifyIconVersion4 = 4
	idiApplication     = 32512
	idcArrow           = 32512

	mfString    = 0x00000000
	mfSeparator = 0x00000800
	tpmRightBtn = 0x00000002
	tpmReturn   = 0x00000100

	mbYesNo        = 0x00000004
	mbIconQuestion = 0x00000020
	idYes          = 6

	trayCmdOpen = 41001
	trayCmdData = 41002
	trayCmdExit = 41003
)

var (
	kernel32                = syscall.NewLazyDLL("kernel32.dll")
	procGetDriveTypeW       = kernel32.NewProc("GetDriveTypeW")
	procGetDiskFreeSpaceExW = kernel32.NewProc("GetDiskFreeSpaceExW")
	procGetModuleHandleW    = kernel32.NewProc("GetModuleHandleW")

	user32                  = syscall.NewLazyDLL("user32.dll")
	procRegisterClassExW    = user32.NewProc("RegisterClassExW")
	procCreateWindowExW     = user32.NewProc("CreateWindowExW")
	procDefWindowProcW      = user32.NewProc("DefWindowProcW")
	procGetMessageW         = user32.NewProc("GetMessageW")
	procTranslateMessage    = user32.NewProc("TranslateMessage")
	procDispatchMessageW    = user32.NewProc("DispatchMessageW")
	procPostQuitMessage     = user32.NewProc("PostQuitMessage")
	procDestroyWindow       = user32.NewProc("DestroyWindow")
	procPostMessageW        = user32.NewProc("PostMessageW")
	procFindWindowW         = user32.NewProc("FindWindowW")
	procLoadIconW           = user32.NewProc("LoadIconW")
	procLoadCursorW         = user32.NewProc("LoadCursorW")
	procCreatePopupMenu     = user32.NewProc("CreatePopupMenu")
	procAppendMenuW         = user32.NewProc("AppendMenuW")
	procTrackPopupMenu      = user32.NewProc("TrackPopupMenu")
	procDestroyMenu         = user32.NewProc("DestroyMenu")
	procGetCursorPos        = user32.NewProc("GetCursorPos")
	procSetForegroundWindow = user32.NewProc("SetForegroundWindow")
	procMessageBoxW         = user32.NewProc("MessageBoxW")

	shell32              = syscall.NewLazyDLL("shell32.dll")
	procShellNotifyIconW = shell32.NewProc("Shell_NotifyIconW")

	trayMu      sync.Mutex
	trayHWND    uintptr
	trayNID     notifyIconData
	trayWndProc = syscall.NewCallback(trayWindowProc)
)

const trayWindowClass = "DuplicateGuardTrayWindow"

type point struct {
	X int32
	Y int32
}

type msg struct {
	HWnd     uintptr
	Message  uint32
	WParam   uintptr
	LParam   uintptr
	Time     uint32
	Pt       point
	LPrivate uint32
}

type wndClassEx struct {
	CbSize        uint32
	Style         uint32
	LpfnWndProc   uintptr
	CbClsExtra    int32
	CbWndExtra    int32
	HInstance     uintptr
	HIcon         uintptr
	HCursor       uintptr
	HbrBackground uintptr
	LpszMenuName  *uint16
	LpszClassName *uint16
	HIconSm       uintptr
}

type guid struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

type notifyIconData struct {
	CbSize           uint32
	HWnd             uintptr
	UID              uint32
	UFlags           uint32
	UCallbackMessage uint32
	HIcon            uintptr
	SzTip            [128]uint16
	DwState          uint32
	DwStateMask      uint32
	SzInfo           [256]uint16
	UVersion         uint32
	SzInfoTitle      [64]uint16
	DwInfoFlags      uint32
	GuidItem         guid
	HBalloonIcon     uintptr
}

func platformFileFlags(path string) (PlatformFileFlags, error) {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return PlatformFileFlags{}, err
	}
	attrs, err := syscall.GetFileAttributes(p)
	if err != nil {
		return PlatformFileFlags{}, err
	}
	return PlatformFileFlags{
		Hidden:  attrs&fileAttributeHidden != 0,
		System:  attrs&fileAttributeSystem != 0,
		Reparse: attrs&fileAttributeReparsePoint != 0,
		Offline: attrs&fileAttributeOffline != 0,
		Recall:  attrs&(fileAttributeRecallOnOpen|fileAttributeRecallOnDataAccess) != 0,
	}, nil
}

func platformDriveKind(path string) string {
	volume := filepath.VolumeName(filepath.Clean(path))
	if volume == "" {
		return "unknown"
	}
	root := volume
	if !strings.HasSuffix(root, `\`) {
		root += `\`
	}
	p, err := syscall.UTF16PtrFromString(root)
	if err != nil {
		return "unknown"
	}
	r, _, _ := procGetDriveTypeW.Call(uintptr(unsafe.Pointer(p)))
	switch uint32(r) {
	case 2:
		return "removable"
	case 3:
		return "fixed"
	case 4:
		return "network"
	case 5:
		return "cdrom"
	case 6:
		return "ramdisk"
	default:
		return "unknown"
	}
}

func platformFreeSpace(path string) (uint64, error) {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	var freeAvailable, totalBytes, totalFree uint64
	r, _, callErr := procGetDiskFreeSpaceExW.Call(
		uintptr(unsafe.Pointer(p)),
		uintptr(unsafe.Pointer(&freeAvailable)),
		uintptr(unsafe.Pointer(&totalBytes)),
		uintptr(unsafe.Pointer(&totalFree)),
	)
	if r == 0 {
		return 0, fmt.Errorf("GetDiskFreeSpaceExW: %v", callErr)
	}
	return freeAvailable, nil
}

func platformNotify(title, body string) {
	title = strings.ReplaceAll(title, "'", "''")
	body = strings.ReplaceAll(body, "'", "''")
	script := fmt.Sprintf(`Add-Type -AssemblyName System.Windows.Forms; Add-Type -AssemblyName System.Drawing; $n=New-Object System.Windows.Forms.NotifyIcon; $n.Icon=[System.Drawing.SystemIcons]::Information; $n.BalloonTipTitle='%s'; $n.BalloonTipText='%s'; $n.Visible=$true; $n.ShowBalloonTip(5000); Start-Sleep -Seconds 6; $n.Dispose()`, title, body)
	_ = exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", script).Start()
}

func platformStartTray() {
	go trayMessageLoop()
}

func platformStopTray() {
	trayMu.Lock()
	hwnd := trayHWND
	nid := trayNID
	trayMu.Unlock()
	if nid.HWnd != 0 {
		procShellNotifyIconW.Call(nimDelete, uintptr(unsafe.Pointer(&nid)))
	}
	if hwnd != 0 {
		procPostMessageW.Call(hwnd, wmClose, 0, 0)
	}
}

func platformRequestExistingExit() bool {
	className, _ := syscall.UTF16PtrFromString(trayWindowClass)
	hwnd, _, _ := procFindWindowW.Call(uintptr(unsafe.Pointer(className)), 0)
	if hwnd == 0 {
		return false
	}
	procPostMessageW.Call(hwnd, trayExitMsg, 0, 0)
	return true
}

func trayMessageLoop() {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	className, _ := syscall.UTF16PtrFromString(trayWindowClass)
	hInstance, _, _ := procGetModuleHandleW.Call(0)
	hIcon, _, _ := procLoadIconW.Call(0, idiApplication)
	hCursor, _, _ := procLoadCursorW.Call(0, idcArrow)
	wc := wndClassEx{
		CbSize:        uint32(unsafe.Sizeof(wndClassEx{})),
		LpfnWndProc:   trayWndProc,
		HInstance:     hInstance,
		HIcon:         hIcon,
		HCursor:       hCursor,
		LpszClassName: className,
		HIconSm:       hIcon,
	}
	atom, _, regErr := procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))
	if atom == 0 {
		// ERROR_CLASS_ALREADY_EXISTS is harmless when a prior instance is exiting.
		log.Printf("tray class registration: %v", regErr)
	}
	windowName, _ := syscall.UTF16PtrFromString(appName)
	hwnd, _, createErr := procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(windowName)),
		0,
		0, 0, 0, 0,
		0, 0, hInstance, 0,
	)
	if hwnd == 0 {
		log.Printf("tray window creation failed: %v", createErr)
		return
	}

	nid := notifyIconData{
		CbSize:           uint32(unsafe.Sizeof(notifyIconData{})),
		HWnd:             hwnd,
		UID:              1,
		UFlags:           nifMessage | nifIcon | nifTip | nifShowTip,
		UCallbackMessage: trayCallbackMsg,
		HIcon:            hIcon,
	}
	copyUTF16(nid.SzTip[:], "DuplicateGuard — click to open; right-click to exit")
	if ok, _, addErr := procShellNotifyIconW.Call(nimAdd, uintptr(unsafe.Pointer(&nid))); ok == 0 {
		log.Printf("tray icon creation failed: %v", addErr)
		procDestroyWindow.Call(hwnd)
		return
	}
	nid.UVersion = notifyIconVersion4
	procShellNotifyIconW.Call(nimSetVer, uintptr(unsafe.Pointer(&nid)))
	trayMu.Lock()
	trayHWND = hwnd
	trayNID = nid
	trayMu.Unlock()

	var m msg
	for {
		r, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(r) <= 0 {
			break
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		procDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
	}

	trayMu.Lock()
	trayHWND = 0
	trayNID = notifyIconData{}
	trayMu.Unlock()
}

func trayWindowProc(hwnd uintptr, message uint32, wParam, lParam uintptr) uintptr {
	switch message {
	case trayCallbackMsg:
		switch uint32(lParam & 0xffff) {
		case wmLButtonUp, wmLButtonDblClk, ninSelect, ninKeySelect:
			openBrowser(state.serverURL)
			return 0
		case wmRButtonUp, wmContextMenu:
			showTrayMenu(hwnd)
			return 0
		}
	case trayExitMsg:
		go shutdownApp()
		return 0
	case wmCommand:
		switch uint32(wParam & 0xffff) {
		case trayCmdOpen:
			openBrowser(state.serverURL)
		case trayCmdData:
			_ = exec.Command("explorer.exe", state.dataDir).Start()
		case trayCmdExit:
			if trayConfirmExit(hwnd) {
				go shutdownApp()
			}
		}
		return 0
	case wmClose:
		trayMu.Lock()
		nid := trayNID
		trayMu.Unlock()
		if nid.HWnd != 0 {
			procShellNotifyIconW.Call(nimDelete, uintptr(unsafe.Pointer(&nid)))
		}
		procDestroyWindow.Call(hwnd)
		return 0
	case wmDestroy:
		procPostQuitMessage.Call(0)
		return 0
	}
	r, _, _ := procDefWindowProcW.Call(hwnd, uintptr(message), wParam, lParam)
	return r
}

func showTrayMenu(hwnd uintptr) {
	menu, _, _ := procCreatePopupMenu.Call()
	if menu == 0 {
		return
	}
	defer procDestroyMenu.Call(menu)
	appendTrayMenu(menu, mfString, trayCmdOpen, "Open DuplicateGuard / فتح DuplicateGuard")
	appendTrayMenu(menu, mfString, trayCmdData, "Open recovery folder / فتح مجلد الاسترداد")
	procAppendMenuW.Call(menu, mfSeparator, 0, 0)
	appendTrayMenu(menu, mfString, trayCmdExit, "Exit DuplicateGuard / إغلاق DuplicateGuard")
	var p point
	procGetCursorPos.Call(uintptr(unsafe.Pointer(&p)))
	procSetForegroundWindow.Call(hwnd)
	cmd, _, _ := procTrackPopupMenu.Call(menu, tpmRightBtn|tpmReturn, uintptr(p.X), uintptr(p.Y), 0, hwnd, 0)
	if cmd != 0 {
		trayWindowProc(hwnd, wmCommand, cmd, 0)
	}
}

func appendTrayMenu(menu uintptr, flags uint32, id uint32, text string) {
	p, _ := syscall.UTF16PtrFromString(text)
	procAppendMenuW.Call(menu, uintptr(flags), uintptr(id), uintptr(unsafe.Pointer(p)))
}

func trayConfirmExit(hwnd uintptr) bool {
	text, _ := syscall.UTF16PtrFromString("Exit DuplicateGuard?\n\nScheduled protection stops until the app starts again.\n\nهل تريد إغلاق DuplicateGuard؟")
	title, _ := syscall.UTF16PtrFromString(appName)
	r, _, _ := procMessageBoxW.Call(hwnd, uintptr(unsafe.Pointer(text)), uintptr(unsafe.Pointer(title)), mbYesNo|mbIconQuestion)
	return int(r) == idYes
}

func copyUTF16(dst []uint16, text string) {
	s, _ := syscall.UTF16FromString(text)
	if len(s) > len(dst) {
		s = s[:len(dst)]
		s[len(s)-1] = 0
	}
	copy(dst, s)
}
