set GOARCH=amd64
set CGO_ENABLED=1
del DataMonitor.dll
del DataMonitor.h
go build -ldflags="-H=windowsgui -s -w" -tags=dll_export --buildmode=c-shared -o DataMonitor.dll .
pause