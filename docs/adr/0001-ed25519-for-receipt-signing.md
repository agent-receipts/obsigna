# ADR-0001: Ed25519 for Receipt Signing

## Status

Accepted

## Context

The Agent Receipts protocol requires a digital signature algorithm for signing all receipts. Receipts form chains where each receipt references its predecessor, so key and signature sizes compound across the chain. The protocol also needs strong cross-language support since SDKs exist in Go, Python, and TypeScript, and verification performance matters when auditing large receipt chains.

We evaluated the following alternatives:

- **ECDSA (secp256k1 / P-256):** Widely deployed. Vanilla ECDSA is non-deterministic, and nonce reuse has caused real-world key compromise in other systems. Deterministic ECDSA (RFC 6979) is now the default in most modern libraries (Go `crypto/ecdsa` since 1.20, OpenSSL 3.x), but Ed25519's determinism is inherent to the algorithm rather than an opt-in mitigation.
- **RSA (2048/4096):** Ubiquitous in enterprise environments, but keys (256–512 bytes) and signatures (256–512 bytes) are an order of magnitude larger than Ed25519. This is prohibitive for receipt chains.
- **Ed448:** Offers a higher classical security margin (224-bit vs 128-bit for Ed25519) but has significantly less library support, larger keys (57 bytes) and signatures (114 bytes), and slower operations. Both Ed25519 and Ed448 are equally vulnerable to quantum attack via Shor's algorithm, so Ed448 provides no quantum advantage. The trade-offs are not justified by a compelling threat model today.

Related: #20 (parent issue), #39.

## Decision

Use Ed25519 (RFC 8032) as the sole signature algorithm for all receipt signing in the Agent Receipts protocol.

Key reasons:

- **Deterministic signatures** — no nonce reuse risk, eliminating an entire class of implementation vulnerabilities present in ECDSA.
- **Compact keys (32 bytes) and signatures (64 bytes)** — critical for receipt chains where every byte compounds.
- **Fast verification and batch verification** — important when auditing large receipt chains. Ed25519 supports batch verification, allowing N signatures to be verified faster than N individual verifications.
- **Excellent cross-language support** — available in Go stdlib (`crypto/ed25519`), libsodium, the Web Crypto API, and Python via either `cryptography` (which the Python SDK uses) or PyNaCl.
- **W3C VC ecosystem alignment** — Ed25519 is a first-class algorithm in the Verifiable Credentials ecosystem, which aligns with our envelope format and `Ed25519Signature2020` proof type.
- **No patent encumbrances.**
- **Designed for constant-time implementation** — the algorithm structure facilitates timing side-channel resistance, though this property ultimately depends on each library's implementation (see Security Considerations).

## Security Considerations

### Signature malleability

Ed25519 has known malleability concerns: some implementations accept non-canonical signatures where the S component is not fully reduced. All Agent Receipts SDK implementations MUST perform strict verification as specified in RFC 8032 §5.1.7, rejecting non-canonical signatures. This is especially important because we ship three SDK implementations (Go, Python, TypeScript) using different underlying libraries — a signature accepted by one SDK but rejected by another would break cross-language receipt verification.

Note that Go's `crypto/ed25519` performs cofactored verification by default (stricter than §5.1.7), while some libraries do not. SDK implementations should document which verification behavior they use and include [Wycheproof test vectors](https://github.com/google/wycheproof) to cover Ed25519 edge cases beyond malleability.

### Canonicalization dependency

The security of receipt signatures depends on RFC 8785 (JSON Canonicalization Scheme) producing identical byte sequences across all implementations. If two SDKs canonicalize the same receipt differently, signatures will not verify cross-language. This is a real attack surface: any divergence in canonicalization could allow an attacker to present a receipt that verifies under one SDK but not another. Cross-language test vectors (see `sdk/py/tests/fixtures/ts_vectors.json`) mitigate this but are not a substitute for thorough fuzz testing of canonicalization edge cases.

### Hash function scope

This ADR covers only the signature algorithm. Receipt chain linkage uses SHA-256 for `previous_receipt_hash` (and for `parameters_hash`, `response_hash`, and key fingerprints). SHA-256 does **not** share Ed25519's quantum exposure. Shor's algorithm breaks Ed25519 outright: a quantum adversary recovers the private key from the public key. Against SHA-256 the best known quantum attack is Grover's algorithm, which only roughly halves preimage security (about 2^128 work remains), and quantum collision search gives no practical advantage over classical. SHA-256 is retained. Post-quantum migration work (#32) covers the signature algorithm and the disclosure KEM, not the chain hash. (Corrected 2026-11-25; see *Amendments*.)

### Encoding

Receipt `proofValue` uses multibase base64url encoding (`u` prefix) rather than the W3C Data Integrity default of base58btc (`z` prefix), as documented in spec §10.2. Encoding mismatches between implementations are a realistic source of cross-SDK verification failures. All SDKs must use base64url with no padding and the `u` multibase prefix.

### Key lifecycle

This ADR does not address key rotation, revocation, or compromise recovery. A compromised signing key can forge receipts that retroactively poison a chain. Key lifecycle management will be addressed separately (see spec §9.6) but is critical to the overall security of the protocol and should not be deferred indefinitely.

### Timing side-channels

The Ed25519 algorithm is designed to facilitate constant-time implementations, and the libraries used by our SDKs (Go `crypto/ed25519`, Python `cryptography`/OpenSSL, Node.js `crypto`) are believed to provide constant-time operations. However, this property is an implementation characteristic, not an inherent guarantee of the algorithm specification. SDK implementers should verify constant-time behavior when updating or replacing cryptographic dependencies.

## Known Risks

- **Not quantum-resistant.** Ed25519 provides ~128-bit classical security but is fully broken by Shor's algorithm on a cryptographically relevant quantum computer — as are all elliptic curve schemes including Ed448 and ECDSA. This is acknowledged and tracked in #32 (algorithm agility). NIST recommends migrating to ML-DSA by 2030, with quantum-ready cryptography mandatory for government use after 2035. The planned algorithm agility mechanism will allow migration to a post-quantum algorithm as standards mature.
- **No algorithm agility in v0.1.** The current wire format hardcodes `Ed25519Signature2020` as the proof type and does not include a separate algorithm identifier, negotiation field, or algorithm dispatch mechanism. Old verifiers will need a strategy for handling receipts signed with future algorithms. Algorithm agility (#32) is a prerequisite for v1.0 — receipts are long-lived signed records exposed to "harvest now, break later" attacks, so the protocol must support post-quantum algorithms before leaving beta. The algorithm agility design must address how v0.1 receipts are treated when new algorithms are introduced — at minimum, v0.1 receipts should be considered implicitly tagged as Ed25519.
- **Less ubiquitous in enterprise environments than RSA.** Adoption has grown substantially and Ed25519 is supported in all modern TLS and SSH implementations.
- **Single curve means no negotiation flexibility.** Mitigated by the planned algorithm agility mechanism, which will allow adding algorithms without breaking existing receipts.

## Consequences

- All SDKs (Go, Python, TypeScript) must implement Ed25519 signing and verification with strict RFC 8032 verification.
- Receipt envelope format is simpler — no algorithm negotiation fields needed initially.
- Receipt chains benefit from compact signatures, reducing storage and bandwidth overhead.
- Enterprise integrations that only support RSA will need a compatibility layer or must adopt Ed25519.
- Cross-language canonicalization and encoding conformance testing is a hard requirement, not optional.
- Algorithm agility (#32) is a prerequisite for v1.0 and should be the next cryptographic ADR, covering the signature algorithm (the chain hash stays SHA-256; see *Hash function scope*). Receipts signed today may need to remain trustworthy for years, making this a blocking concern for protocol stability.

## Amendments

### 2026-11-25: Correction to *Hash function scope*

The original text said SHA-256 "has the same quantum-resistance limitations as Ed25519" and suggested the hash function be revisited alongside algorithm agility. That was wrong. Shor's algorithm breaks elliptic-curve signatures completely. Grover's algorithm only roughly halves SHA-256 preimage security (to about 128 bits), and quantum collision search offers no practical speed-up over classical. The paragraph and the matching *Consequences* bullet have been corrected, and SHA-256 stays as the chain hash. Tracked in #1208, part of the post-quantum migration epic #32.
