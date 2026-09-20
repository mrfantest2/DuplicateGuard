# Architecture overview

DuplicateGuard is a local Go application with an embedded browser UI.

## Main components

- `main.go` — application lifecycle, HTTP server, API handlers, configuration, local session authentication.
- `scan.go` — duplicate discovery and content-verification workflow.
- `quarantine.go` — quarantine, restore, purge, metadata and safety checks.
- `storage.go` — storage-related helpers used by the recovered source generation.
- `types.go` — shared application state/configuration structures.
- `platform_windows.go` — Windows-specific lifecycle/integration behavior.
- `platform_other.go` — non-Windows stubs/compatibility.
- `web/index.html` — embedded local dashboard.
- `installer/setup.go` — custom Go installer.

## Network boundary

The HTTP listener binds to `127.0.0.1`. API calls that mutate state require the random local `X-DG-Token` session token (or equivalent local query token path in the recovered source).

## File-safety model

The recovered documentation and code implement layered verification: size grouping, hashing, final content revalidation before quarantine, retained-copy protection, recovery metadata, restore conflict avoidance, and explicit separation between reversible quarantine and permanent purge.
