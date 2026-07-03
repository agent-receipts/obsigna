"""Cross-SDK did:key resolution vectors (ADR-0007, issue #956).

Asserts that the Python SDK reproduces the pinned ``did`` and
``did_document`` values in ``spec/test-vectors/did-key/vectors.json``
byte-for-byte, matching the Go and TypeScript SDKs.
"""

from __future__ import annotations

import json
from pathlib import Path

from obsigna.did import from_public_key, resolve

VECTORS = (
    Path(__file__).parent.parent.parent.parent
    / "spec"
    / "test-vectors"
    / "did-key"
    / "vectors.json"
)


def _load_vectors() -> dict:
    with open(VECTORS, encoding="utf-8") as f:
        return json.load(f)


class TestDIDKeyVectors:
    def test_all_vectors(self) -> None:
        data = _load_vectors()
        vectors = data["vectors"]
        assert vectors, "did-key vectors.json: no vectors found"

        for vector in vectors:
            pub = bytes.fromhex(vector["public_key_hex"])

            got_did = from_public_key(pub)
            assert got_did == vector["did"], vector["name"]

            doc = resolve(vector["did"])
            assert doc.to_dict() == vector["did_document"], vector["name"]
