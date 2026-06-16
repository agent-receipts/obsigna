<div align="center">

# sdk-go

### Go SDK for the Agent Receipts protocol

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.26+-00ADD8?logo=go&logoColor=white)](https://go.dev/)

**Cryptographically signed audit trails for AI agent actions.**

[Spec](https://github.com/agent-receipts/spec) &bull; [TypeScript SDK](https://github.com/agent-receipts/obsigna/tree/main/sdk/ts) &bull; [Python SDK](https://github.com/agent-receipts/obsigna/tree/main/sdk/py)

</div>

---

## Install

```sh
go get github.com/agent-receipts/ar/sdk/go
```

## Packages

| Package | Description |
|---------|-------------|
| `emitter` | Daemon-socket client: forwards tool-call events to a local `obsigna-daemon`, which holds the signing key and constructs, signs, and chains the receipt |
| `receipt` | Create, sign (Ed25519), verify, and hash-chain Agent Receipts (W3C Verifiable Credentials) |
| `taxonomy` | Built-in action type registry (15 types), tool call classification, custom mappings |
| `store` | SQLite-backed receipt persistence, query, stats, and chain verification |
| `emitters` | Signed-receipt delivery to a remote collector (`HttpEmitter`, `CompositeEmitter`, `BufferingEmitter`, `WALEmitter`) |

## Quick start

The canonical deployment shape is **daemon-mediated signing**: your app sends
tool-call events to a local `obsigna-daemon` over a Unix socket, and the
daemon holds the Ed25519 signing key and constructs, signs, and chains the
receipt. Keeping the key out of the agent process is what makes a receipt
evidence rather than a self-reported claim — anything with code execution in
your app cannot reach the key or forge receipts.

Start the daemon, then emit events from your app:

<!-- snippet-check: no-run -->
```go
package main

import (
	"context"
	"log"

	"github.com/agent-receipts/ar/sdk/go/emitter"
)

func main() {
	// The daemon owns the signing key and the chain. Construct the emitter
	// once; it uses AGENTRECEIPTS_SOCKET or the per-OS default socket path.
	e, err := emitter.NewDaemon()
	if err != nil {
		log.Fatal(err)
	}
	defer e.Close()

	// Forward one tool-call event. The daemon canonicalises, signs, and
	// persists the receipt — the SDK does no crypto here.
	err = e.Emit(context.Background(), emitter.Event{
		Channel:  "my-app",
		Tool:     emitter.Tool{Name: "filesystem.file.read"},
		Decision: "allowed",
	})
	if err != nil {
		log.Fatal(err)
	}
}
```

By default `emitter.Emit` surfaces transport failure (ADR-0025): if the daemon
is unreachable it logs at debug level and returns a non-nil error wrapping
`emitter.ErrTransport` rather than dropping silently, so start the daemon before
your app. The call stays non-blocking (bounded by the dial + write timeout).
Pass `emitter.WithBestEffort()` to opt into loss-tolerant emission (`Emit`
returns nil on transport failure). See the
[Daemon Setup guide](https://agentreceipts.ai/getting-started/daemon-setup/) for
running the daemon and verifying the chain.

## In-process signing (tutorial and testing only)

> **Not for production.** This pattern keeps the signing key inside the agent
> process. Anyone with code execution in the agent can forge receipts. For real
> deployments, use the [daemon-mediated path](#quick-start).

The `receipt`, `taxonomy`, and `store` packages let you create, sign, verify,
and persist receipts entirely in-process. This is useful as a learning aid and
in tests, where holding the key in the calling process is acceptable.

```go
package main

import (
	"fmt"
	"log"

	"github.com/agent-receipts/ar/sdk/go/receipt"
	"github.com/agent-receipts/ar/sdk/go/store"
	"github.com/agent-receipts/ar/sdk/go/taxonomy"
)

func main() {
	// Generate an Ed25519 key pair
	kp, err := receipt.GenerateKeyPair()
	if err != nil {
		log.Fatal(err)
	}

	// Classify a tool call
	mappings := []taxonomy.TaxonomyMapping{
		{ToolName: "read_file", ActionType: "filesystem.file.read"},
	}
	class := taxonomy.ClassifyToolCall("read_file", mappings)

	// Create an unsigned receipt
	unsigned := receipt.Create(receipt.CreateInput{
		Issuer:    receipt.Issuer{ID: "did:agent:my-proxy"},
		Principal: receipt.Principal{ID: "did:user:alice"},
		Action:    receipt.Action{Type: class.ActionType, RiskLevel: class.RiskLevel},
		Outcome:   receipt.Outcome{Status: receipt.StatusSuccess},
		Chain:     receipt.Chain{Sequence: 1, ChainID: "session-001"},
	})

	// Sign it
	signed, err := receipt.Sign(unsigned, kp.PrivateKey, "did:agent:my-proxy#key-1")
	if err != nil {
		log.Fatal(err)
	}

	// Verify the signature
	valid, err := receipt.Verify(signed, kp.PublicKey)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Signature valid: %v\n", valid)

	// Persist to SQLite
	s, err := store.Open("receipts.db")
	if err != nil {
		log.Fatal(err)
	}
	defer s.Close()

	hash, _ := receipt.HashReceipt(signed)
	if err := s.Insert(signed, hash); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Receipt %s stored\n", signed.ID)
}
```

## Enterprise / multi-host: collector delivery

Use the `emitters` package when the agent host and the receipt-storage host
differ, or when you are aggregating receipts from multiple agents across
multiple hosts. Unlike the daemon emitter (which forwards *unsigned events* for
daemon-side signing), `emitters` deliver *already-signed* `receipt.AgentReceipt`
values — sign client-side (or accept pre-signed receipts), then POST them to a
deployed `obsigna-collector`.

<!-- snippet-check: no-run -->
```go
package main

import (
	"context"
	"log"
	"os"

	"github.com/agent-receipts/ar/sdk/go/emitters"
	"github.com/agent-receipts/ar/sdk/go/receipt"
)

func deliver(signed receipt.AgentReceipt) {
	e, err := emitters.NewHTTP(emitters.HttpEmitterConfig{
		Endpoint: "https://collector.example.com/receipts",
		Auth:     emitters.BearerAuth{Token: os.Getenv("AGENTRECEIPTS_TOKEN")},
	})
	if err != nil {
		log.Fatal(err)
	}

	// Emit takes a fully signed, already-chained receipt.
	if err := e.Emit(context.Background(), signed); err != nil {
		log.Fatal(err)
	}
}
```

`HttpEmitter` defaults to the `"sync"` strategy (at-least-once up to the retry
budget). For batching, fan-out, or write-ahead durability across collector
outages, compose it with `BufferingEmitter`, `CompositeEmitter`, or
`WALEmitter` from the same package.

## Sequential receipt construction (parallel tool calls)

Hash chaining is inherently sequential: receipt *N* must be fully signed and its
hash computed **before** receipt *N+1* is constructed, or the
`previous_receipt_hash` link cannot be formed. A single-goroutine agent
satisfies this for free, but an agent that fires **parallel tool calls** would
race on the shared chain head (`Sequence` + `PreviousReceiptHash`) and produce
colliding sequence numbers or a forked chain.

`chain.ReceiptChain` owns that head and serialises the whole build → sign →
hash → link → deliver pipeline under a mutex, so concurrent `Emit` calls are
sequenced **at the receipt layer** even when the tool calls that triggered them
ran in parallel. Concurrent emission is not supported as parallel chains in v1
(a future ADR may add forked sub-chains); overlapping calls block until the
in-flight one completes, and the first overlap logs a one-shot warning so the
misuse is visible.

```go
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/agent-receipts/ar/sdk/go/chain"
	"github.com/agent-receipts/ar/sdk/go/emitters"
	"github.com/agent-receipts/ar/sdk/go/receipt"
)

func main() {
	kp, err := receipt.GenerateKeyPair()
	if err != nil {
		log.Fatal(err)
	}

	// One ReceiptChain per logical chain (e.g. per agent session). It owns the
	// chain head; pass any emitters.Emitter — here the in-memory test double, in
	// production an HttpEmitter or a WAL-backed emitter.
	rc, err := chain.New(chain.Options{
		ChainID:            "session-001",
		PrivateKeyPEM:      kp.PrivateKey,
		VerificationMethod: "did:agent:my-agent#key-1",
		Emitter:            emitters.NewInMemory(),
	})
	if err != nil {
		log.Fatal(err)
	}

	// Every Emit is sequenced: receipt N is signed and hashed before N+1 is
	// built, even if your tool calls run in parallel.
	signed, err := rc.Emit(context.Background(), chain.EmitInput{
		Issuer:    receipt.Issuer{ID: "did:agent:my-agent"},
		Principal: receipt.Principal{ID: "did:user:alice"},
		Action:    receipt.Action{Type: "filesystem.file.read", RiskLevel: receipt.RiskLow},
		Outcome:   receipt.Outcome{Status: receipt.StatusSuccess},
	})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("emitted sequence %d\n", signed.CredentialSubject.Chain.Sequence)
}
```

The head advances as soon as a receipt is signed and hashed — *before* delivery
— so a transient emitter failure does not fork or stall the chain; wrap a
`WALEmitter` around your transport for at-least-once delivery.

## License

Apache 2.0
