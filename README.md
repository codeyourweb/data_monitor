# Data Monitor for Windows

This Go program acts as a user data monitor for Windows systems. It leverages API hooking to observe and log actions related to clipboard usage (copy/paste of text and files) and file operations (moving and copying files). This kind of program could be used for security monitoring, data loss prevention, or auditing purposes.

## Features

### Clipboard Monitoring:
* Logs when text (ANSI and Unicode) is copied to or retrieved from the clipboard.
* Logs when files are copied to or retrieved from the clipboard (e.g., drag-and-drop operations).
*  Optionally redacts text data, replacing it with an MD5 hash and character count for privacy or to reduce log size while still indicating activity.

### File Operation Monitoring:
* Logs MoveFileExW calls, showing the original and new paths of moved files.
* Logs CopyFile2 calls, showing the source and destination paths of copied files.

### Active Window Context:
* Monitors the foreground window and includes its title in the logs, providing context for the observed operations.

### Configurable Logging:
* Logs events to a file (defaulting to %TEMP%\clipboard_monitor.log).
* Supports different log levels (e.g., INFO, DEBUG, ERROR).

### API Hooking:
* Utilizes the gominhook library to intercept Windows API calls.

## How It Works
The program operates by hooking into specific Windows API functions. When a hooked function is called by any process where this monitor is injected, the program's custom "override" function is executed instead of the original API function. Inside the override, the relevant data is extracted and logged, and then the original API function is called to allow the operation to complete normally.

The key hooked functions are:

* GetClipboardData: Intercepts attempts to retrieve data from the clipboard.
* SetClipboardData: Intercepts attempts to place data onto the clipboard.
* MoveFileExW: Intercepts file move operations.
* CopyFile2: Intercepts file copy operations.

## Configuration

The behavior of the monitor can be adjusted through global variables:
* APP_LOGLEVEL: Controls the verbosity of the logs (e.g., LOGLEVEL_INFO, LOGLEVEL_DEBUG).
* LOG_FILE_PATH: Specifies the path for the log file. By default, it uses the system's temporary directory.
* REDACTED_TEXT_CLIPBOARD: If true, text clipboard content will be replaced by its MD5 hash and character count in the logs. If false, the full text content will be logged.
* HOOKED_FUNCTIONS: A pipe-separated string (|) listing the specific API functions to hook (e.g., "GetClipboardData|SetClipboardData|MoveFileExW|CopyFile2").

## Usage

This program is designed to be injected into a target process (e.g., a running application or the operating system itself) as a DLL. Once injected and the DataMonitor function is called, it will begin monitoring the configured operations and logging them to the specified file.

**Note**: This program requires administrator privileges to inject into system processes and perform API hooking effectively.

## Building

To build this program, you will need the Go toolchain, C compiler and win32 devtools. Then compile the code as a windows DLL (see make.bat).

## Dependencies
This program relies on Minhook library. Minhook.x64.dll should be inside a folder referenced in your PATH (for example in %systemroot%)