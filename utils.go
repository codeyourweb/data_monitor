package main

import (
	"fmt"
	"os"
	"syscall"
	"time"
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

func fileExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !info.IsDir()
}
