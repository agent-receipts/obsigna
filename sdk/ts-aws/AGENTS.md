# AGENTS.md

AWS adapter for the TypeScript SDK. Implements the ADR-0018 `Signer`
abstraction backed by AWS KMS (`KMSSigner`), so an Ed25519 private key can sign
receipts without ever leaving KMS. Separate npm package
(`@obsigna/sdk-ts-aws`): the core `@obsigna/sdk-ts` package stays free of
AWS dependencies.

## Getting started

```sh
pnpm install
pnpm run build       # tsc
pnpm run typecheck   # tsc --noEmit
pnpm run lint        # biome check
pnpm test            # vitest — mocked KMS client, no network or credentials
```

## Project structure

```
src/signer.ts            # KMSSigner: sign, getPublicKey, the narrow KMSClient seam
src/signer.test.ts       # unit tests against a mocked KMSClient
src/integration.test.ts  # real-KMS test, skipped unless AGENTRECEIPTS_AWS_KMS_INTEGRATION_KEY_ARN is set
src/index.ts             # public exports
```

## Conventions

- All changes go through pull requests — never push directly to main.
- This package must not depend on `@obsigna/sdk-ts`; the `Signer` interface is
  declared locally (mirrors the Go SDK's `aws` module).
- Use AWS SDK v3 (`@aws-sdk/client-kms`).
- KMS signing uses `SigningAlgorithm=ED25519_SHA_512` + `MessageType=RAW`
  (pure Ed25519, RFC 8032). Do not switch to `ED25519_PH_SHA_512`.
- Surface AWS SDK errors verbatim — callers distinguish throttling, access
  denied, and key-not-found.
- Do not add a retry layer; the AWS SDK already retries.
- Tests must not require live AWS — gate integration tests behind the env var.
- ESM only; `import type` for type-only imports (`verbatimModuleSyntax`).

## Reference files

- `src/signer.ts` — the `KMSClient` interface is the seam for mocking; keep it
  minimal.
- `src/signer.test.ts` — `MockKMS` is backed by an in-test Ed25519 key so
  signatures produced by `sign` verify against `getPublicKey`.
