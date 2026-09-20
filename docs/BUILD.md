# Build and validation

## Toolchain

The recovered `go.mod` specifies Go 1.23 and no third-party Go modules.

## Standard Windows build

Run:

```bat
build_windows.bat
```

The script performs:

1. `go test ./...`
2. `go vet ./...`
3. Windows x64 GUI build of `DuplicateGuard.exe`
4. Copy of the app into `installer/payload/`
5. Windows x64 GUI build of `DuplicateGuard_Setup.exe`

## Recovered-source validation performed during repository migration

On 2026-09-21 the v2.1.1 source was revalidated with:

```bash
go test ./...
go vet ./...
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w -H=windowsgui" -o DuplicateGuard.exe .
```

The installer source also cross-compiled successfully for Windows amd64 after placing the app executable at `installer/payload/DuplicateGuard.exe`.

## CI

`.github/workflows/ci.yml` repeats tests, vet, and Windows amd64 cross-builds on pushes and pull requests. CI output is validation-only and must not be confused with the recovered signed/official historical binaries.
