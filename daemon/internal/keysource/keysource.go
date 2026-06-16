// Package keysource defines the interface the daemon uses to sign receipts.
// The shape (Sign / PublicKey / Init / Teardown) follows ADR-0015 so PKCS#11
// and cloud-KMS adapters land later as new types implementing this interface,
// not as a redesign of the daemon's signing path. Key rotation is daemon-level
// (daemon.RotateKey), not a KeySource method — see the note below the interface.
//
// Phase 1 ships only the file-backed adapter (file.go).
package keysource

// KeySource signs canonical receipt bytes and exposes the matching public key.
// Implementations MUST be safe for concurrent use; the daemon signs from many
// goroutines.
type KeySource interface {
	// Init loads or wires up key material. Called once at daemon startup.
	// Implementations MUST fail loudly when keys are missing or malformed —
	// silently signing with a default-generated key would defeat the audit
	// property.
	Init() error

	// Sign returns the Ed25519 signature over message. The signature is the
	// raw 64-byte form; the caller multibase-encodes it.
	Sign(message []byte) ([]byte, error)

	// PublicKey returns the PEM-encoded SPKI public key for verifiers.
	PublicKey() (string, error)

	// VerificationMethod returns the DID URL or other reference verifiers use
	// to look up the public key. Daemon embeds this in proof.verificationMethod.
	VerificationMethod() string

	// Teardown wipes any in-memory key material. Called on graceful daemon
	// shutdown.
	Teardown() error
}

// Rotation is deliberately NOT a KeySource method. A key_rotated receipt's
// signature covers the whole receipt envelope — including chain fields the
// KeySource has no knowledge of — and the file backend needs the public-key
// path and the receipt store, neither of which a KeySource holds. Rotation is
// therefore orchestrated by the daemon (the chain owner) in daemon.RotateKey
// (ADR-0015 Phase A), with the KeySource staying focused on the live signing
// path. A future live-rotation design against a real second backend (HSM/KMS)
// can grow a prepare/commit pair here once there is a concrete backend to shape
// it against.
