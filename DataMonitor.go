package main

import (
	"fmt"
	"log"
	"os"
	"strings"
	"syscall"
	"time"
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
	APP_LOGLEVEL            = LOGLEVEL_DEBUG
	LOG_FILE_PATH           = os.Getenv("TEMP") + "\\data_monitor.log"
	REDACTED_TEXT_CLIPBOARD = true
	HOOKED_FUNCTIONS        = "GetClipboardData|SetClipboardData|MoveFileExW|CopyFile2"
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

//export DataMonitor
func DataMonitor(argsPtr unsafe.Pointer) {
	// if optional configuration file passed in arguments - load custom parameters
	var configFilePath string
	if argsPtr != nil {
		configFilePath = windows.UTF16PtrToString((*uint16)(argsPtr))
	}

	if len(configFilePath) != 0 {
		if !fileExists(configFilePath) {
			log.Fatalln(fmt.Errorf("configuration file does not exist: %s", configFilePath))
		}

		err := LoadConfig(configFilePath)
		if err != nil {
			log.Fatalln(fmt.Errorf("error loading configuration: %v", err))
		}

		switch AppConfig.DataMonitorLogLevel {
		case "LOGLEVEL_DEV_DEBUG_VERBOSE":
			APP_LOGLEVEL = LOGLEVEL_DEV_DEBUG_VERBOSE
		case "LOGLEVEL_DEBUG":
			APP_LOGLEVEL = LOGLEVEL_DEBUG
		case "LOGLEVEL_WARN":
			APP_LOGLEVEL = LOGLEVEL_WARN
		case "LOGLEVEL_ERROR":
			APP_LOGLEVEL = LOGLEVEL_ERROR
		case "LOGLEVEL_FATAL":
			APP_LOGLEVEL = LOGLEVEL_FATAL
		default:
			APP_LOGLEVEL = LOGLEVEL_INFO
		}

		LOG_FILE_PATH = AppConfig.DataMonitorLogFile
		REDACTED_TEXT_CLIPBOARD = AppConfig.DataMonitorRedactedTextClipboard
		HOOKED_FUNCTIONS = AppConfig.DataMonitorHookedFunctions

		// http forwarding configuration
		if AppConfig.DataMonitorHTTPForwardEvents.Enabled {
			go func() {
				for {
					nbMessages, err := sendPacketToUrlAddress(AppConfig.DataMonitorHTTPForwardEvents.URL, AppConfig.DataMonitorHTTPForwardEvents.Headers)
					if err != nil {
						logMessage(LOGLEVEL_ERROR, fmt.Sprintf("HTTP Forward - Error sending api telemetry to URL: %v", err))
					} else {
						if nbMessages > 0 {
							logMessage(LOGLEVEL_INFO, fmt.Sprintf("HTTP Forward - Successfully sent %d messages to %s", nbMessages, AppConfig.DataMonitorHTTPForwardEvents.URL))
						} else {
							logMessage(LOGLEVEL_DEV_DEBUG_VERBOSE, "HTTP Forward - No messages to send to external URL")
						}
					}

					time.Sleep(time.Duration(AppConfig.DataMonitorHTTPForwardEvents.DataBatchSendInterval) * time.Second)
				}
			}()
		}
	}

	// initialize logger
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
