module github.com/agent-receipts/ar/daemon

// Pin the exact patch in the go directive (ADR-0031): reproducible-build
// attestation requires every builder use the same compiler bytes. `setup-go`
// installs exactly this version from go-version-file, so CI never floats to a
// later 1.26.x. A standalone `toolchain go1.26.1` directive would duplicate this
// patch-level go line; `go mod tidy` strips it as redundant, which also makes
// `-mod=readonly` builds (the release path, GOWORK=off) demand a tidy. So the go
// directive itself is the pin.
go 1.26.1

require (
	github.com/BurntSushi/toml v1.6.0
	github.com/agent-receipts/ar/sdk/go v0.20.0-alpha.1
	golang.org/x/sys v0.43.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/cloudflare/circl v1.6.3 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	golang.org/x/crypto v0.45.0 // indirect
	modernc.org/libc v1.72.3 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
	modernc.org/sqlite v1.52.0 // indirect
)
