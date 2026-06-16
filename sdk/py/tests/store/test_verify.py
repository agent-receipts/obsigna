"""Tests for verifying stored receipt chains."""

from __future__ import annotations

from obsigna.receipt.hash import hash_receipt
from obsigna.receipt.signing import sign_receipt
from obsigna.store.store import open_store
from obsigna.store.verify import verify_stored_chain
from tests.conftest import TEST_PRIVATE_KEY, TEST_PUBLIC_KEY, make_unsigned


def test_verify_stored_chain_valid() -> None:
    store = open_store(":memory:")

    u1 = make_unsigned(sequence=1, previous_hash=None, chain_id="vc1")
    r1 = sign_receipt(u1, TEST_PRIVATE_KEY, "did:agent:test#key-1")
    h1 = hash_receipt(r1)
    store.insert(r1, h1)

    u2 = make_unsigned(sequence=2, previous_hash=h1, chain_id="vc1")
    r2 = sign_receipt(u2, TEST_PRIVATE_KEY, "did:agent:test#key-1")
    h2 = hash_receipt(r2)
    store.insert(r2, h2)

    u3 = make_unsigned(sequence=3, previous_hash=h2, chain_id="vc1")
    r3 = sign_receipt(u3, TEST_PRIVATE_KEY, "did:agent:test#key-1")
    h3 = hash_receipt(r3)
    store.insert(r3, h3)

    result = verify_stored_chain(store, "vc1", TEST_PUBLIC_KEY)
    assert result.valid is True
    assert result.length == 3
    store.close()


def test_verify_stored_chain_empty() -> None:
    store = open_store(":memory:")
    result = verify_stored_chain(store, "nonexistent", TEST_PUBLIC_KEY)
    assert result.valid is True
    assert result.length == 0
    store.close()


def test_verify_stored_chain_wrong_key() -> None:
    store = open_store(":memory:")

    u1 = make_unsigned(sequence=1, previous_hash=None, chain_id="wk1")
    r1 = sign_receipt(u1, TEST_PRIVATE_KEY, "did:agent:test#key-1")
    store.insert(r1, hash_receipt(r1))

    from obsigna.receipt.signing import generate_key_pair

    other_keys = generate_key_pair()

    result = verify_stored_chain(store, "wk1", other_keys.public_key)
    assert result.valid is False
    store.close()
