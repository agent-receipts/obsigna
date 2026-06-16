"""AWS adapters for the Agent Receipts SDK.

Install the optional ``aws`` extra (``pip install obsigna[aws]``) to use
the default boto3-backed client; injecting your own ``client`` needs no AWS SDK.
"""

from __future__ import annotations

from obsigna.aws.kms import KMSClient, KMSSigner, KMSSignerError, Signer

__all__ = ["KMSClient", "KMSSigner", "KMSSignerError", "Signer"]
