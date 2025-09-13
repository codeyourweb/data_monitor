package main

import (
	"crypto/md5"
	"fmt"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

/*
#include <windows.h>
#include <winbase.h>
#include <wingdi.h>
#include <winuser.h>

typedef HANDLE (WINAPI *GETCLIPBOARDDATA)(UINT);
typedef HANDLE (WINAPI *SETCLIPBOARDDATA)(UINT, HANDLE);
typedef HRESULT (WINAPI *COPYFILE2)(PCWSTR, PCWSTR, COPYFILE2_EXTENDED_PARAMETERS);
typedef BOOL (WINAPI *MOVEFILEEXW)(LPCWSTR, LPCWSTR, DWORD);
typedef BOOL (WINAPI *BITBLT)(HDC, int, int, int, int, HDC, int, int, DWORD);
typedef BOOL (WINAPI *PRINTWINDOW)(HWND, HDC, UINT);
*/
import "C"

// Define function pointers for WINAPI functions
var (
	user32     = syscall.MustLoadDLL("user32.dll")
	kernel32   = syscall.MustLoadDLL("kernel32.dll")
	kernelbase = syscall.MustLoadDLL("kernelbase.dll")
	shell32    = syscall.MustLoadDLL("shell32.dll")
	gdi32      = syscall.MustLoadDLL("gdi32.dll")

	procGetClipboardData    = user32.MustFindProc("GetClipboardData")
	procSetClipboardData    = user32.MustFindProc("SetClipboardData")
	procGetClipboardOwner   = user32.MustFindProc("GetClipboardOwner")
	procGetForegroundWindow = user32.MustFindProc("GetForegroundWindow")
	procGetWindowTextW      = user32.MustFindProc("GetWindowTextW")
	procPrintWindow         = user32.MustFindProc("PrintWindow")
	procGlobalLock          = kernel32.MustFindProc("GlobalLock")
	procGlobalUnlock        = kernel32.MustFindProc("GlobalUnlock")
	procGlobalSize          = kernel32.MustFindProc("GlobalSize")
	procMoveFileExW         = kernel32.MustFindProc("MoveFileExW")
	procCopyFile2           = kernelbase.MustFindProc("CopyFile2")
	procDragQueryFile       = shell32.MustFindProc("DragQueryFileW")
	procBitBlt              = gdi32.MustFindProc("BitBlt")

	fpGetClipboardData C.GETCLIPBOARDDATA
	fpSetClipboardData C.SETCLIPBOARDDATA
	fpCopyFile2        C.COPYFILE2
	fpMoveFileExW      C.MOVEFILEEXW
	fpBitBlt           C.BITBLT
	fpPrintWindow      C.PRINTWINDOW
)

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
			addNewPacketToQueue("Telemetry", "Clipboard", "GetClipboardData", fmt.Sprintf("Text data (%s): %s", encoding, clipboardText), fmt.Sprintf("Owner Window: %s", lastForegroundWindowTitle))
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
				addNewPacketToQueue("Telemetry", "Clipboard", "GetClipboardData", fmt.Sprintf("Text data (%s): %s", encoding, clipboardText), fmt.Sprintf("Owner Window: %s", lastForegroundWindowTitle))
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
				addNewPacketToQueue("Telemetry", "Clipboard", realClipboardMethod, fmt.Sprintf("File: %s", file), fmt.Sprintf("Owner Window: %s", lastForegroundWindowTitle))
			}
		}

	case uintptr(CF_BITMAP), uintptr(CF_DIB), uintptr(CF_DIBV5), uintptr(CF_BITMAPV5HEADER), uintptr(CF_DSPBITMAP):
		logMessage(LOGLEVEL_INFO, fmt.Sprintf("Format: CF_BITMAP(%d) - Owner Window: %s", uFormat, lastForegroundWindowTitle))
		addNewPacketToQueue("Telemetry", "Clipboard", "GetClipboardData", "Bitmap image data paste", fmt.Sprintf("Owner Window: %s", lastForegroundWindowTitle))

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
					addNewPacketToQueue("Telemetry", "Clipboard", "SetClipboardData", fmt.Sprintf("Data (%s): %s", encoding, clipboardText), fmt.Sprintf("Owner Window: %s", lastForegroundWindowTitle))
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
		addNewPacketToQueue("Telemetry", "FileTransfer", "MoveFileExW", oldPath, newPath)
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
		addNewPacketToQueue("Telemetry", "FileTransfer", "CopyFile2", sourcePath, destinationPath)
	}

	return ret
}

//export PrintWindowOverride
func PrintWindowOverride(hwnd HWND, hdcBlt HDC, nFlags UINT) uintptr {
	ret, _, err := syscall.SyscallN(
		uintptr(unsafe.Pointer(procPrintWindow)),
		uintptr(unsafe.Pointer(hwnd)),
		uintptr(unsafe.Pointer(hdcBlt)),
		uintptr(nFlags),
	)

	if err != 0 {
		logMessage(LOGLEVEL_ERROR, fmt.Sprintf("PrintWindow error: %v", err))
	} else {
		if time.Since(lastPrintScreenTime) > PRINTSCREEN_MONITOR_THRESHOLD {
			lastPrintScreenTime = time.Now()
			logMessage(LOGLEVEL_INFO, fmt.Sprintf("print screen (PrintWindow) succeeded"))
			addNewPacketToQueue("Telemetry", "PrintScreen", "PrintWindow", fmt.Sprintf("%s - PrintScreen", lastForegroundWindowTitle), "")
		}
	}

	return ret
}

//export BitBltOverride
func BitBltOverride(hdcDest HDC, nXDest int32, nYDest int32, nWidth int32, nHeight int32, hdcSrc HDC, nXSrc int32, nYSrc int32, dwRop DWORD) uintptr {
	ret, _, err := syscall.SyscallN(
		uintptr(unsafe.Pointer(fpBitBlt)),
		uintptr(unsafe.Pointer(hdcDest)),
		uintptr(nXDest),
		uintptr(nYDest),
		uintptr(nWidth),
		uintptr(nHeight),
		uintptr(unsafe.Pointer(hdcSrc)),
		uintptr(nXSrc),
		uintptr(nYSrc),
		uintptr(dwRop),
	)

	if err != 0 {
		logMessage(LOGLEVEL_ERROR, fmt.Sprintf("BitBlt error: %v", err))
	} else {
		if time.Since(lastPrintScreenTime) > PRINTSCREEN_MONITOR_THRESHOLD {
			lastPrintScreenTime = time.Now()
			logMessage(LOGLEVEL_INFO, fmt.Sprintf("print screen (BitBlt) succeeded"))
			addNewPacketToQueue("Telemetry", "PrintScreen", "BitBlt", fmt.Sprintf("%s - PrintScreen", lastForegroundWindowTitle), "")
		}
	}
	return ret
}
