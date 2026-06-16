module github.com/agent-receipts/ar/cross-sdk-tests

go 1.26.1

// Local sdk/go is wired in via the repo-root go.work workspace.
require github.com/agent-receipts/ar/sdk/go v0.19.0

require github.com/santhosh-tekuri/jsonschema/v5 v5.3.1

require (
	github.com/cloudflare/circl v1.6.3 // indirect
	github.com/google/uuid v1.6.0 // indirect
	golang.org/x/crypto v0.45.0 // indirect
	golang.org/x/sys v0.43.0 // indirect
)
