package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"
)

// retrieve a window's title text from its handle
func getWindowText(hwnd syscall.Handle) string {
	const maxTitleLen = 256
	buf := make([]uint16, maxTitleLen)

	ret, _, _ := syscall.SyscallN(
		procGetWindowTextW.Addr(),
		uintptr(hwnd),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(maxTitleLen),
	)
	if ret == 0 {
		return ""
	}
	return syscall.UTF16ToString(buf[:ret])
}

// dragQueryFile retrieves the file name from an HDROP handle
func dragQueryFile(hDrop syscall.Handle, iFile uint32, lpszFile *uint16, cch int) uint32 {
	ret, _, _ := procDragQueryFile.Call(
		uintptr(hDrop),
		uintptr(iFile),
		uintptr(unsafe.Pointer(lpszFile)),
		uintptr(cch),
	)
	return uint32(ret)
}

// the original GetClipboardData function (for using in GetClipboardFilePaths)
func getClipboardData(format uint32) syscall.Handle {
	ret, _, _ := procGetClipboardData.Call(uintptr(format))
	return syscall.Handle(ret)
}

// retrieve file paths from the clipboard with CF_HDROP format
func GetClipboardFilePaths(recursive bool) ([]string, error) {
	hdrop := getClipboardData(CF_HDROP)
	if hdrop == 0 {
		return nil, fmt.Errorf("clipboard format CF_HDROP cannot return files list")
	}

	fileCount := dragQueryFile(hdrop, ^uint32(0), nil, 0)
	if fileCount == 0 {
		return []string{}, nil
	}

	filePaths := make([]string, 0)
	for i := uint32(0); i < fileCount; i++ {
		bufferSize := dragQueryFile(hdrop, i, nil, 0)
		if bufferSize == 0 {
			continue
		}
		bufferSize++

		buffer := make([]uint16, bufferSize)
		dragQueryFile(hdrop, i, &buffer[0], int(bufferSize))

		p := syscall.UTF16ToString(buffer)

		if recursive {
			info, err := os.Stat(p)
			if err != nil {
				fmt.Printf("Warning: Could not get info for path %s: %v\n", p, err)
				continue
			}
			if info.IsDir() {
				err := filepath.Walk(p, func(path string, info os.FileInfo, err error) error {
					if err != nil {
						return err
					}
					if !info.IsDir() {
						filePaths = append(filePaths, path)
					}
					return nil
				})
				if err != nil {
					filePaths = append(filePaths, p)
				}
			} else {
				filePaths = append(filePaths, p)
			}
		} else {
			filePaths = append(filePaths, p)
		}
	}

	return filePaths, nil
}

// globalLock locks the memory block pointed to by hMem
func globalLock(hMem syscall.Handle) unsafe.Pointer {
	ret, _, _ := syscall.SyscallN(procGlobalLock.Addr(), uintptr(unsafe.Pointer(hMem)), 0)
	return unsafe.Pointer(ret)
}

// globalUnlock releases the memory block pointed to by hMem
func globalUnlock(hMem syscall.Handle) bool {
	ret, _, _ := syscall.SyscallN(procGlobalUnlock.Addr(), uintptr(unsafe.Pointer(hMem)), 0)
	return ret != 0
}

// globalSize returns the size of the memory block pointed to by hMem
func globalSize(hMem syscall.Handle) uintptr {
	ret, _, _ := syscall.SyscallN(procGlobalSize.Addr(), uintptr(unsafe.Pointer(hMem)), 0)
	return ret
}
