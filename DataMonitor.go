package main

import (
	"crypto/md5"
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"

	"github.com/codeyourweb/gominhook"
	"golang.org/x/sys/windows"
)

/*
#include <windows.h>
#include <winbase.h>

typedef HANDLE (WINAPI *GETCLIPBOARDDATA)(UINT);
typedef HANDLE (WINAPI *SETCLIPBOARDDATA)(UINT, HANDLE);
typedef HRESULT (WINAPI *COPYFILE2)(PCWSTR, PCWSTR, COPYFILE2_EXTENDED_PARAMETERS);
typedef BOOL (WINAPI *MOVEFILEEXW)(LPCWSTR, LPCWSTR, DWORD);
*/
import "C"

// Define types for C functions
type UINT uint32
type WCHAR uint16
type HRESULT uint32
type HANDLE C.HANDLE
type BOOL uint32
type DWORD uint32
type LPCWSTR *uint16
type PCWSTR *uint16
type COPYFILE2_EXTENDED_PARAMETERS *C.COPYFILE2_EXTENDED_PARAMETERS

// Clipboard formats constants
const (
	CF_TEXT           = 1
	CF_UNICODETEXT    = 13
	CF_HDROP          = 15
	CF_DATAOBJECT     = 49161
	CF_OLEPRIVATEDATA = 49171
)

// Internal monitoring thresholds
const (
	CURRENT_ACTIVE_WINDOW_MONITOR_THRESHOLD = 200 * time.Millisecond
	CLIPBOARD_MONITOR_THRESHOLD             = 200 * time.Millisecond
)

// default parameters for the Data Monitor
var (
	APP_LOGLEVEL            = LOGLEVEL_INFO
	LOG_FILE_PATH           = os.Getenv("TEMP") + "\\clipboard_monitor.log"
	REDACTED_TEXT_CLIPBOARD = true
	HOOKED_FUNCTIONS        = "GetClipboardData|SetClipboardData|MoveFileExW|CopyFile2"
)

// Define function pointers for WINAPI functions
var (
	user32     = syscall.MustLoadDLL("user32.dll")
	kernel32   = syscall.MustLoadDLL("kernel32.dll")
	kernelbase = syscall.MustLoadDLL("kernelbase.dll")
	shell32    = syscall.MustLoadDLL("shell32.dll")

	procGetClipboardData    = user32.MustFindProc("GetClipboardData")
	procSetClipboardData    = user32.MustFindProc("SetClipboardData")
	procGetClipboardOwner   = user32.MustFindProc("GetClipboardOwner")
	procGetForegroundWindow = user32.MustFindProc("GetForegroundWindow")
	procGetWindowTextW      = user32.MustFindProc("GetWindowTextW")
	procGlobalLock          = kernel32.MustFindProc("GlobalLock")
	procGlobalUnlock        = kernel32.MustFindProc("GlobalUnlock")
	procGlobalSize          = kernel32.MustFindProc("GlobalSize")
	procMoveFileExW         = kernel32.MustFindProc("MoveFileExW")
	procCopyFile2           = kernelbase.MustFindProc("CopyFile2")
	procDragQueryFile       = shell32.MustFindProc("DragQueryFileW")

	fpGetClipboardData C.GETCLIPBOARDDATA
	fpSetClipboardData C.SETCLIPBOARDDATA
	fpCopyFile2        C.COPYFILE2
	fpMoveFileExW      C.MOVEFILEEXW
)

// Define clipboard internal monitoring variables
var (
	lastClipboardOwnerTime   time.Time
	lastGetClipboardDataTime time.Time
	lastSetClipboardDataTime time.Time

	lastClipboardOwnerHwnd    string
	lastForegroundWindowTitle string

	currentSetFilesClipboardHash string
	currentGetFilesClipboardHash string

	exitHookChannel = make(chan struct{})
)

// check for current clipboard owner and foreground window
func MonitorForegroundWindow() {
	for {
		ret, _, _ := procGetClipboardOwner.Call()
		currentClipboardOwnerHwnd := fmt.Sprintf("%x", ret)

		if lastClipboardOwnerHwnd != currentClipboardOwnerHwnd {
			lastClipboardOwnerTime = time.Now()
			lastClipboardOwnerHwnd = currentClipboardOwnerHwnd
		}

		foregroundWindowHwnd, _, _ := procGetForegroundWindow.Call()
		windowOwnerTitle := getWindowText(syscall.Handle(foregroundWindowHwnd))
		if windowOwnerTitle == "" {
			lastForegroundWindowTitle = "Unknown Window"
		} else {
			lastForegroundWindowTitle = windowOwnerTitle
		}

		time.Sleep(CURRENT_ACTIVE_WINDOW_MONITOR_THRESHOLD)
	}
}

//export GetClipboardDataOverride
func GetClipboardDataOverride(uFormat UINT) uintptr {
	ret, _, err := syscall.SyscallN(uintptr(unsafe.Pointer(fpGetClipboardData)), uintptr(uFormat), 0, 0)

	// get a handle to the clipboard owner
	handle := HANDLE(unsafe.Pointer(ret))
	if unsafe.Pointer(handle) == nil {
		logMessage(LOGLEVEL_DEBUG, fmt.Sprintf("GetClipboardData failed: %v", err))
		return uintptr(0)
	}

	ptr := globalLock(syscall.Handle(uintptr(unsafe.Pointer(handle))))
	if ptr == nil {
		logMessage(LOGLEVEL_ERROR, "GlobalLock failed for GetClipboardData")
		return ret
	}
	defer globalUnlock(syscall.Handle(uintptr(unsafe.Pointer(handle))))

	size := globalSize(syscall.Handle(uintptr(unsafe.Pointer(handle))))
	if size == 0 {
		logMessage(LOGLEVEL_ERROR, "GlobalSize failed for GetClipboardData")
		return ret
	}

	// read the clipboard data based on the format
	switch uintptr(uFormat) {
	case uintptr(CF_TEXT):
		data := C.GoBytes(ptr, C.int(size))
		encoding := "ANSI"

		clipboardText := strings.ReplaceAll(string(data), "\x00", "")
		if REDACTED_TEXT_CLIPBOARD {
			clipboardText = fmt.Sprintf("%x (%d characters)", md5.Sum([]byte(clipboardText)), len(clipboardText))
		}

		if time.Since(lastGetClipboardDataTime) >= CLIPBOARD_MONITOR_THRESHOLD {
			logMessage(LOGLEVEL_INFO, fmt.Sprintf("GetClipboardData - Data (%s): %s - Owner Window: %s", encoding, clipboardText, lastForegroundWindowTitle))
			lastGetClipboardDataTime = time.Now()
		}
	case uintptr(CF_UNICODETEXT):
		encoding := "Unicode"
		if size%2 != 0 {
			logMessage(LOGLEVEL_ERROR, fmt.Sprintf("Invalid UTF-16 data size: %d", size))
			return ret
		} else {
			utf16Data := unsafe.Slice((*uint16)(ptr), size/2)
			decodedString := utf16.Decode(utf16Data)
			clipboardText := strings.ReplaceAll(string(decodedString), "\x00", "")

			if REDACTED_TEXT_CLIPBOARD {
				clipboardText = fmt.Sprintf("%x (%d characters)", md5.Sum([]byte(clipboardText)), len(clipboardText))
			}

			if time.Since(lastGetClipboardDataTime) >= CLIPBOARD_MONITOR_THRESHOLD {
				logMessage(LOGLEVEL_INFO, fmt.Sprintf("GetClipboardData: Data (%s): %s - Owner Window: %s", encoding, clipboardText, lastForegroundWindowTitle))
				lastGetClipboardDataTime = time.Now()
			}
		}
	case uintptr(CF_DATAOBJECT):
		// handle file clipboard formats. This function will be used for GetClipboardData and SetClipboardData as SetClipboardData will call GetClipboardData first

		clipboardFiles, err := GetClipboardFilePaths(true)

		if err != nil {
			logMessage(LOGLEVEL_DEBUG, fmt.Sprintf("GetClipboardFilePaths failed: %v", err))
			return ret
		}

		if len(clipboardFiles) == 0 {
			return ret
		}

		// Calculate the checksum of the file paths in the clipboard
		concatenated := strings.Join(clipboardFiles, "|")
		h := md5.Sum([]byte(concatenated))
		clipboardFilePathsChecksum := fmt.Sprintf("%x", h)
		realClipboardMethod := ""
		clipboardUsed := false

		// if the checksum is new, it means the clipboard has changed, so we assume SetClipboardData was called
		if currentSetFilesClipboardHash != clipboardFilePathsChecksum {
			currentSetFilesClipboardHash = clipboardFilePathsChecksum
			realClipboardMethod = "SetClipboardData"
			clipboardUsed = true
			lastGetClipboardDataTime = time.Now()
		} else {
			// GetClipboardData could be called several times with the same data (for many reasons), so we check if the time since the last call is greater than the threshold
			realClipboardMethod = "GetClipboardData"
			if currentGetFilesClipboardHash == clipboardFilePathsChecksum {
				return ret
			}

			if time.Since(lastGetClipboardDataTime) >= CLIPBOARD_MONITOR_THRESHOLD && time.Since(lastClipboardOwnerTime) >= CLIPBOARD_MONITOR_THRESHOLD {
				lastGetClipboardDataTime = time.Now()
				currentGetFilesClipboardHash = clipboardFilePathsChecksum
				clipboardUsed = true
			}
		}

		// if the clipboard has changed both for SetClipboardData and GetClipboardData, we log the action
		if clipboardUsed {
			for _, file := range clipboardFiles {
				logMessage(LOGLEVEL_INFO, fmt.Sprintf("%s Format: CF_DATAOBJECT (%d) - File %v - Owner Window: %s", realClipboardMethod, uFormat, file, lastForegroundWindowTitle))
			}
		}

	case uintptr(CF_OLEPRIVATEDATA):
		// CF_OLEPRIVATEDATA intentionally left blank - generally handled in CF_DATAOBJECT
	case uintptr(CF_HDROP):
		// override to HDROP intentionally left blank - generally handled in CF_DATAOBJECT
	default:
		logMessage(LOGLEVEL_DEBUG, fmt.Sprintf("GetClipboardData Unhandled format: %d - Owner Window: %s", uFormat, lastForegroundWindowTitle))
	}

	return ret
}

//export SetClipboardDataOverride
func SetClipboardDataOverride(uFormat UINT, hMem HANDLE) uintptr {
	// handle SetClipboardData only for CF_TEXT, CF_UNICODETEXT. Files are handled in GetClipboardData
	ret, _, _ := syscall.SyscallN(
		uintptr(unsafe.Pointer(fpSetClipboardData)),
		uintptr(uFormat),
		uintptr(unsafe.Pointer(hMem)),
	)

	if unsafe.Pointer(hMem) != nil {
		switch uintptr(uFormat) {
		case uintptr(CF_TEXT), uintptr(CF_UNICODETEXT):
			ptr := globalLock(syscall.Handle(uintptr(unsafe.Pointer(hMem))))
			if ptr != nil {
				defer globalUnlock(syscall.Handle(uintptr(unsafe.Pointer(hMem))))
				size := globalSize(syscall.Handle(uintptr(unsafe.Pointer(hMem))))
				data := C.GoBytes(ptr, C.int(size))
				encoding := ""
				clipboardText := ""
				if uFormat == UINT(CF_UNICODETEXT) {
					encoding = "Unicode"

					utf16Data := unsafe.Slice((*uint16)(ptr), size/2)
					decodedString := utf16.Decode(utf16Data)
					clipboardText = string(decodedString)
				} else {
					encoding = "ANSI"
					clipboardText = string(data)
				}

				clipboardText = strings.ReplaceAll(string(clipboardText), "\x00", "")
				if REDACTED_TEXT_CLIPBOARD {
					clipboardText = fmt.Sprintf("%x (%d characters)", md5.Sum([]byte(clipboardText)), len(clipboardText))
				}
				if time.Since(lastGetClipboardDataTime) >= CLIPBOARD_MONITOR_THRESHOLD {
					logMessage(LOGLEVEL_INFO, fmt.Sprintf("SetClipboardData - Data (%s): %s - Owner Window: %s", encoding, clipboardText, lastForegroundWindowTitle))
				}
			} else {
				logMessage(LOGLEVEL_ERROR, "GlobalLock failed for SetClipboardData with CF_TEXT / CF_UNICODE")
			}

			// update the last clipboard data time (also used for GetClipboardData to avoid duplicate logs)
			lastSetClipboardDataTime = time.Now()
			lastGetClipboardDataTime = time.Now()
		default:
			logMessage(LOGLEVEL_DEBUG, fmt.Sprintf("SetClipboardData Unhandled format: %d - Owner Window: %s", uFormat, lastForegroundWindowTitle))
		}
	}

	return ret
}

//export MoveFileExWOverride
func MoveFileExWOverride(lpExistingFileName LPCWSTR, lpNewFileName LPCWSTR, dwFlags DWORD) uintptr {
	ret, _, err := syscall.SyscallN(
		uintptr(unsafe.Pointer(fpMoveFileExW)),
		uintptr(unsafe.Pointer(lpExistingFileName)),
		uintptr(unsafe.Pointer(lpNewFileName)),
		uintptr(dwFlags),
	)

	oldPath := windows.UTF16PtrToString((*uint16)(unsafe.Pointer(lpExistingFileName)))
	newPath := windows.UTF16PtrToString((*uint16)(unsafe.Pointer(lpNewFileName)))

	if err != 0 {
		logMessage(LOGLEVEL_ERROR, fmt.Sprintf("MoveFileExWOverride error: %v, Old Path: %s, New Path: %s", err, oldPath, newPath))
	} else {
		logMessage(LOGLEVEL_INFO, fmt.Sprintf("File Moved: From '%s' to '%s'", oldPath, newPath))
	}

	return ret
}

//export CopyFile2Override
func CopyFile2Override(lpExistingFileName PCWSTR, lpNewFileName PCWSTR, pExtendedParameters COPYFILE2_EXTENDED_PARAMETERS) uintptr {
	ret, _, err := syscall.SyscallN(
		uintptr(unsafe.Pointer(fpCopyFile2)),
		uintptr(unsafe.Pointer(lpExistingFileName)),
		uintptr(unsafe.Pointer(lpNewFileName)),
		uintptr(unsafe.Pointer(pExtendedParameters)),
	)

	sourcePath := windows.UTF16PtrToString((*uint16)(unsafe.Pointer(lpExistingFileName)))
	destinationPath := windows.UTF16PtrToString((*uint16)(unsafe.Pointer(lpNewFileName)))

	if err != 0 {
		logMessage(LOGLEVEL_ERROR, fmt.Sprintf("CopyFile2Override error: %v, Source: %s, Destination: %s", err, sourcePath, destinationPath))
	} else {
		logMessage(LOGLEVEL_INFO, fmt.Sprintf("File Copied: From '%s' to '%s'", sourcePath, destinationPath))
	}

	return ret
}

//export DataMonitor
func DataMonitor() {
	// dll entry point for the Data Monitor - should be called when injected into a process
	InitLogger(APP_LOGLEVEL)
	SetLogToFile(LOG_FILE_PATH)
	logMessage(LOGLEVEL_DEBUG, "Starting Data Monitor")

	var blockingChannel = make(chan int)
	var err error

	// current clipboard owner and foreground window monitoring
	go MonitorForegroundWindow()

	// api hooking initialization using minhook
	err = gominhook.Initialize()
	if err != nil {
		logMessage(LOGLEVEL_ERROR, fmt.Sprintf("Failing initializing minhook: %v", err))
		return
	}
	defer gominhook.Uninitialize()

	if strings.Contains(HOOKED_FUNCTIONS, "GetClipboardData") {
		err = gominhook.CreateHook(procGetClipboardData.Addr(), syscall.NewCallback(GetClipboardDataOverride), uintptr(unsafe.Pointer(&fpGetClipboardData)))
		if err != nil {
			logMessage(LOGLEVEL_ERROR, fmt.Sprintf("Failing create hook for user32:GetClipboardData() : %v", err))
			return
		} else {
			logMessage(LOGLEVEL_DEBUG, "Hooking GetClipboardData API")
		}
	}

	if strings.Contains(HOOKED_FUNCTIONS, "SetClipboardData") {
		err = gominhook.CreateHook(procSetClipboardData.Addr(), syscall.NewCallback(SetClipboardDataOverride), uintptr(unsafe.Pointer(&fpSetClipboardData)))
		if err != nil {
			logMessage(LOGLEVEL_ERROR, fmt.Sprintf("Failing create hook for user32:SetClipboardData() : %v", err))
			return
		} else {
			logMessage(LOGLEVEL_DEBUG, "Hooking SetClipboardData API")
		}
	}

	if strings.Contains(HOOKED_FUNCTIONS, "MoveFileExW") {
		err = gominhook.CreateHook(procMoveFileExW.Addr(), syscall.NewCallback(MoveFileExWOverride), uintptr(unsafe.Pointer(&fpMoveFileExW)))
		if err != nil {
			logMessage(LOGLEVEL_ERROR, fmt.Sprintf("Failing create hook for kernelbase:MoveFileExW() : %v", err))
			return
		} else {
			logMessage(LOGLEVEL_DEBUG, "Hooking MoveFileExW API")
		}
	}

	if strings.Contains(HOOKED_FUNCTIONS, "CopyFile2") {
		err = gominhook.CreateHook(procCopyFile2.Addr(), syscall.NewCallback(CopyFile2Override), uintptr(unsafe.Pointer(&fpCopyFile2)))
		if err != nil {
			logMessage(LOGLEVEL_ERROR, fmt.Sprintf("Failing create hook for kernelbase:CopyFile2() : %v", err))
			return
		} else {
			logMessage(LOGLEVEL_DEBUG, "Hooking CopyFile2 API")
		}
	}

	err = gominhook.EnableHook(gominhook.AllHooks)
	if err != nil {
		logMessage(LOGLEVEL_ERROR, fmt.Sprintf("Failing activating hooks: %v", err))
		return
	}

	// Wait for exit signal before cleaning up
	<-blockingChannel

	err = gominhook.DisableHook(gominhook.AllHooks)
	if err != nil {
		logMessage(LOGLEVEL_ERROR, fmt.Sprintf("Fail disabling windows hooks: %v", err))
	}

	err = gominhook.RemoveHook(gominhook.AllHooks)
	if err != nil {
		logMessage(LOGLEVEL_ERROR, fmt.Sprintf("Fail deleting windows hooks: %v", err))
	}

	CloseLogger()
}

// unused function to prevent "no main" error in Go
func main() {}
