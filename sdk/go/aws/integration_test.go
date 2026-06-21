package aws_test

import (
	"context"
	"crypto/ed25519"
	"os"
	"testing"
	"time"

	awssigner "obsigna.dev/sdk/go/aws"
)

// envIntegrationKeyARN names the KMS key the integration test signs with. The
// test is skipped unless it is set, so CI stays offline by default. Run it
// locally against a real ECC_NIST_EDWARDS25519 KMS key:
//
//	AGENTRECEIPTS_AWS_KMS_INTEGRATION_KEY_ARN=arn:aws:kms:...:key/... \
//	    go test ./... -run TestIntegration -v
//
// Ambient AWS credentials (profile, SSO, instance role, ...) must be able to
// call kms:Sign and kms:GetPublicKey on that key.
const envIntegrationKeyARN = "AGENTRECEIPTS_AWS_KMS_INTEGRATION_KEY_ARN"

func TestIntegrationSignAndVerify(t *testing.T) {
	keyARN := os.Getenv(envIntegrationKeyARN)
	if keyARN == "" {
		t.Skipf("set %s to run the AWS KMS integration test", envIntegrationKeyARN)
	}

	ctx := context.Background()
	signer, err := awssigner.NewKMSSigner(ctx, keyARN, awssigner.WithTimeout(15*time.Second))
	if err != nil {
		t.Fatalf("NewKMSSigner: %v", err)
	}

	pub, err := signer.GetPublicKey()
	if err != nil {
		t.Fatalf("GetPublicKey: %v", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		t.Fatalf("public key length = %d, want %d (is the key ECC_NIST_EDWARDS25519?)", len(pub), ed25519.PublicKeySize)
	}

	msg := []byte("agent-receipts kms integration test message")
	sig, err := signer.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), msg, sig) {
		t.Fatal("KMS signature did not verify against the KMS public key")
	}
}
