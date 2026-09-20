@echo off
setlocal
cd /d "%~dp0"
where go >nul 2>nul || (echo Go is required. Install it from go.dev & pause & exit /b 1)
if not exist dist mkdir dist
if not exist installer\payload mkdir installer\payload
set CGO_ENABLED=0
set GOOS=windows
set GOARCH=amd64
go test ./... || exit /b 1
go vet ./... || exit /b 1
go build -trimpath -ldflags="-s -w -H=windowsgui" -o dist\DuplicateGuard.exe . || exit /b 1
copy /y dist\DuplicateGuard.exe installer\payload\DuplicateGuard.exe >nul || exit /b 1
pushd installer
go build -trimpath -ldflags="-s -w -H=windowsgui" -o ..\dist\DuplicateGuard_Setup.exe setup.go || (popd & exit /b 1)
popd
echo Built dist\DuplicateGuard.exe and dist\DuplicateGuard_Setup.exe
pause
