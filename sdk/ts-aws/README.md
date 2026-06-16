# @obsigna/sdk-ts-aws

AWS KMS `Signer` for the [Agent Receipts](https://github.com/agent-receipts/obsigna)
TypeScript SDK.

`KMSSigner` is an Ed25519 [`Signer`](./src/signer.ts) (ADR-0018) whose private
key never leaves AWS KMS. Signature operations are delegated to `kms:Sign`; the
public key is fetched once via `kms:GetPublicKey` and cached for the signer's
lifetime. This is the production key story for client-side signing on AWS
(Lambda, Fargate, ECS) where the receipt is signed before it is emitted to a
collector — the private key is not extractable, not present in process memory,
and revocable via IAM.

The core `@obsigna/sdk-ts` package has zero cloud dependencies; install this
package only when you sign with KMS.

## Install

```sh
npm install @obsigna/sdk-ts-aws
# peer: AWS credentials from the ambient provider chain (instance role, IRSA,
# environment, shared profile) — the signer takes no static credentials.
```

## Usage

```ts
import { KMSSigner } from "@obsigna/sdk-ts-aws";

// keyId: a key ID, key ARN, alias name, or alias ARN. The key must be an
// ECC_NIST_EDWARDS25519 (Ed25519) key with SIGN_VERIFY usage.
const signer = new KMSSigner("arn:aws:kms:us-east-1:111122223333:key/abc…", {
	region: "us-east-1",
	timeoutMs: 5_000,
});

const publicKey = await signer.getPublicKey(); // raw 32 bytes (RFC 8032)
const signature = await signer.sign(canonicalReceiptBytes);
```

`sign` calls `kms:Sign` with `SigningAlgorithm=ED25519_SHA_512` and
`MessageType=RAW` — standard (pure) Ed25519, so the signature verifies against
the public key from `getPublicKey`. AWS SDK errors propagate unchanged.

## Configuration

| Option      | Default                    | Notes                                                                 |
| ----------- | -------------------------- | --------------------------------------------------------------------- |
| `client`    | built from the AWS SDK     | Inject a custom/mocked `KMSClient`; primarily for tests.              |
| `region`    | AWS SDK default resolution | Region for the default client. Ignored when `client` is provided.     |
| `timeoutMs` | `0` (SDK defaults)         | Per-request deadline via `AbortSignal`. The AWS SDK already retries.   |

## Testing & development

```sh
pnpm install
pnpm test        # mocked KMS client, no network or credentials
pnpm run check   # typecheck + lint
```

The integration test in `src/integration.test.ts` is skipped unless
`AGENTRECEIPTS_AWS_KMS_INTEGRATION_KEY_ARN` is set to a real
`ECC_NIST_EDWARDS25519` KMS key ARN.

## References

- [ADR-0018](../../docs/adr/0018-signer-abstraction-and-cloud-agnostic-keyprovider-design.md)
  — the `Signer` abstraction
- [Go `aws` module](../go/aws) — reference implementation
