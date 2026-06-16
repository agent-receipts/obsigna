"""RFC 8785 JSON canonicalization and SHA-256 hashing."""

from __future__ import annotations

import hashlib
import json
import math
from typing import TYPE_CHECKING, Any, cast

if TYPE_CHECKING:
    from obsigna.receipt.types import AgentReceipt


def _utf16_sort_key(s: str) -> list[int]:
    """Sort key using UTF-16 code unit order per RFC 8785.

    Returns a list of 16-bit unsigned integers representing the string in
    UTF-16 encoding. BMP characters (U+0000–U+FFFF) map to a single code
    unit equal to their code point. Supplementary-plane characters
    (U+10000–U+10FFFF) map to a surrogate pair (two code units).

    Using ``encode("utf-16-le")`` and treating it as raw bytes is WRONG:
    for a BMP character U+00FF the LE bytes are 0xFF 0x00, whereas U+0100
    produces 0x00 0x01 — byte-sorting would incorrectly put U+0100 first.
    We must compare 16-bit words (0x00FF < 0x0100), not individual bytes.
    """
    result: list[int] = []
    for char in s:
        cp = ord(char)
        if cp <= 0xFFFF:
            result.append(cp)
        else:
            # Surrogate pair for supplementary-plane characters
            cp -= 0x10000
            result.append(0xD800 + (cp >> 10))
            result.append(0xDC00 + (cp & 0x3FF))
    return result


def canonicalize(value: Any) -> str:  # noqa: ANN401
    """Serialize a value to canonical JSON per RFC 8785.

    Key rules:
    - Object keys are sorted lexicographically
    - Numbers use shortest representation
    - No whitespace between tokens
    - Strings use minimal escaping
    - null, boolean, and string values serialized per JSON spec
    """
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return _canonicalize_number(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, list):
        items = cast("list[Any]", value)
        return "[" + ",".join(canonicalize(item) for item in items) + "]"
    if isinstance(value, dict):
        d = cast("dict[str, Any]", value)
        keys = sorted(d.keys(), key=_utf16_sort_key)
        entries = [
            f"{json.dumps(k, ensure_ascii=False)}:{canonicalize(d[k])}" for k in keys
        ]
        return "{" + ",".join(entries) + "}"
    msg = f"RFC 8785: unsupported type: {type(value).__name__}"
    raise TypeError(msg)


def _canonicalize_number(n: float) -> str:
    """RFC 8785 number serialization matching ES6 Number.toString().

    ES6 Number.toString() uses:
    - Fixed notation when -6 ≤ exponent ≤ 20 (for non-fractional values,
      "exponent" means the number of digits minus 1; for values like 1e20 it
      uses fixed; for 1e21 it switches to exponential).
    - Specifically: fixed notation when the integer is < 10^21 and ≥ 10^-6.
    - Exponential notation with mandatory +/- sign, no leading zeros in exponent.

    In practice the threshold rules from RFC 8785 §3.2.2 / ES §7.1.12.1:
    - n < 1e-6  (and n > 0) → exponential, e.g. 1e-7
    - 1e-6 ≤ n < 1e21       → fixed, e.g. 0.000001, 100000000000000000000
    - n ≥ 1e21               → exponential, e.g. 1e+21
    (negatives symmetric)
    """
    if not math.isfinite(n):
        msg = f"RFC 8785: non-finite numbers are not valid JSON: {n}"
        raise ValueError(msg)
    if n == 0.0:
        return "0"
    abs_n = abs(n)
    # Use Python's shortest repr to get the mantissa/exponent.
    s = repr(n)
    if "e" not in s:
        # Already in fixed notation — strip trailing '.0' for whole numbers.
        if s.endswith(".0"):
            s = s[:-2]
        return s
    # Parse the repr exponent.
    mantissa, exp_str = s.split("e")
    exp = int(exp_str)
    # Reconstruct the full decimal value from mantissa digits + exponent,
    # then decide whether ES6 would render it as fixed or exponential.
    # Remove sign and decimal point from mantissa to get raw digits.
    sign = "-" if n < 0 else ""
    mantissa_digits = mantissa.lstrip("-").replace(".", "")
    dot_pos = mantissa.lstrip("-").find(".")
    if dot_pos == -1:
        dot_pos = len(mantissa.lstrip("-"))
    # Number of significant digits and effective decimal exponent.
    # repr gives the mantissa as e.g. "1.5" with exponent e+20, meaning
    # the number is 1.5 * 10^20 = 150000000000000000000.
    # In terms of a coefficient (integer of significant digits) and decimal
    # point position: coefficient = 15, point shift = 20-1 = 19 digits right.
    # ES6 decides based on the n value directly — easiest is to check the
    # magnitude boundaries.
    if abs_n >= 1e21 or abs_n < 1e-6:
        # Exponential notation: normalise exponent formatting (no leading zeros,
        # mandatory sign).
        exp_sign = "+" if exp >= 0 else "-"
        exp_digits = str(abs(exp))
        return f"{sign}{mantissa.lstrip('-')}e{exp_sign}{exp_digits}"
    # Fixed notation: reconstruct the full decimal string.
    # mantissa_digits holds the significant digits (e.g. "15" for 1.5e20).
    # We need to place the decimal point correctly.
    # Number of digits before decimal in the repr mantissa:
    int_part_len = dot_pos  # digits before '.' in the mantissa
    # After applying the exponent, the digit string represents:
    # digits * 10^(exp - (len(mantissa_digits) - int_part_len))
    # i.e., the decimal point in the final number is at position:
    # int_part_len + exp from the start of mantissa_digits.
    decimal_point_pos = int_part_len + exp  # index in mantissa_digits
    if decimal_point_pos >= len(mantissa_digits):
        # All digits are before the decimal point, pad with zeros.
        result = mantissa_digits + "0" * (decimal_point_pos - len(mantissa_digits))
    elif decimal_point_pos <= 0:
        # All digits are after the decimal point, prepend "0.000...".
        result = "0." + "0" * (-decimal_point_pos) + mantissa_digits
    else:
        left = mantissa_digits[:decimal_point_pos]
        right = mantissa_digits[decimal_point_pos:]
        result = f"{left}.{right}"
    return sign + result


def _strip_optional_nulls(obj: Any) -> Any:  # noqa: ANN401
    """Recursively remove null values from optional fields (ADR-0009 Rule 2).

    Optional fields MUST NOT appear as null in the canonical form — they are
    normalised to absent.  This function strips every null value from dicts
    and recurses into nested dicts and lists.

    ``previous_receipt_hash`` is the only required-nullable field; callers
    re-insert it after calling this function when it is absent.
    """
    if isinstance(obj, dict):
        d = cast("dict[str, Any]", obj)
        return {k: _strip_optional_nulls(v) for k, v in d.items() if v is not None}
    if isinstance(obj, list):
        lst = cast("list[Any]", obj)
        return [_strip_optional_nulls(item) for item in lst]
    return obj


def hash_receipt(receipt: AgentReceipt | dict[str, Any]) -> str:
    """Compute SHA-256 hash of a receipt, excluding the proof field.

    Accepts either an AgentReceipt Pydantic model or a plain dict.
    Returns the hash in ``sha256:<hex>`` format.

    Applies ADR-0009 Rule 2 before canonicalising:
    - Optional fields with null values are normalised to absent.
    - ``previous_receipt_hash`` (required-nullable) is always emitted as
      ``null`` when absent/None.
    """
    from obsigna.receipt.types import AgentReceipt

    if isinstance(receipt, AgentReceipt):
        d: dict[str, Any] = receipt.model_dump(by_alias=True, exclude_none=True)
    else:
        # Strip optional nulls from plain-dict receipts. _strip_optional_nulls
        # also drops previous_receipt_hash when its value is None; the
        # re-insertion below restores it as the required-nullable field.
        d = _strip_optional_nulls(dict(receipt))

    d.pop("proof", None)

    # Ensure previous_receipt_hash is preserved as null when None.
    # Use setdefault so an injected nested dict actually attaches to `d` —
    # `.get(key, {})` returns a temporary that mutations would discard.
    cs: dict[str, Any] = d.setdefault("credentialSubject", {})
    chain: dict[str, Any] = cs.setdefault("chain", {})
    if "previous_receipt_hash" not in chain:
        chain["previous_receipt_hash"] = None

    canonical = canonicalize(d)
    return sha256(canonical)


def sha256(data: str) -> str:
    """Compute SHA-256 hash of arbitrary data.

    Returns ``sha256:<hex>`` format.
    """
    h = hashlib.sha256(data.encode("utf-8")).hexdigest()
    return f"sha256:{h}"
