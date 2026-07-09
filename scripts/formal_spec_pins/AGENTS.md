# formal_spec_pins

Guards against `formal/chain-invariants/chain-tamper-evidence.als` silently
drifting from the spec clauses it claims to encode.

The Alloy model does not parse `spec/v<X.Y.Z>/spec.md` — it is a hand-written
formalization with prose citations (§3.2, §4.3.2, §7.3, ...). Nothing forces it
to change when those clauses do, so a spec edit under a modeled clause can
land, merge, and leave the model quietly describing a spec that no longer
exists. Re-running `formal/chain-invariants/run.sh` after such an edit would
not catch this either — the Alloy source is unchanged, so it re-proves the
same (now possibly stale) claim and passes.

## Layout

| File | Role |
|------|------|
| `check.py` | Extracts the live text of each pinned clause from the current spec (the highest-versioned `spec/v<X.Y.Z>/spec.md` on disk) and compares it to the text pinned in `formal/chain-invariants/spec-pins.json`. |
| `test_check.py` | Unit tests for the extraction/comparison core against a fake spec fragment, plus one test that runs the real manifest against the real spec.md. |

## Run locally

```sh
python3 scripts/formal_spec_pins/test_check.py     # unit tests
python3 scripts/formal_spec_pins/check.py           # fail if any pin has drifted
python3 scripts/formal_spec_pins/check.py --write   # re-pin everything to current spec text
```

## The manifest

`formal/chain-invariants/spec-pins.json` lists one entry per spec clause the
model depends on:

- `anchor` — the clause's numeral (e.g. `"7.3.5"`), matched against the leading
  number in a markdown heading. The pinned text runs from that heading to the
  next heading of *any* level, so a parent clause's own body doesn't swallow
  its subsections.
- `row` (optional) — for the `credentialSubject` schema table (§4.3.2), pins a
  single row by its first cell (e.g. `` "`chain.chain_id`" ``) instead of the
  whole table, so an edit to an unrelated field (`outcome.response_hash`, say)
  doesn't trip the gate.
- `stop_before` (optional) — truncates the pinned text before a literal marker
  string, for a section that mixes modeled and unmodeled prose. §7.3.5 pins
  only the contiguity paragraph via `stop_before: "**Store trust model.**"`,
  excluding the trailing operational-controls prose the model doesn't
  formalize — an edit there shouldn't trip the gate. If the marker text itself
  drifts, extraction fails loudly (same as a missing anchor) rather than
  silently including everything.
- `text` — the exact pinned text, maintained by `check.py --write`. Never hand-edit
  this field.

## On a CI failure

The gate (`.github/workflows/formal-spec-pins.yml`) fails a spec PR the moment
a pinned clause's text changes. To fix it:

1. Read the new clause text and decide whether
   `formal/chain-invariants/chain-tamper-evidence.als` still holds.
2. If it doesn't, update the model and re-run `formal/chain-invariants/run.sh`.
3. Run `check.py --write` to re-pin the manifest, and commit it alongside
   whatever else changed.

This gate only detects that the spec moved out from under a pin — it has no
opinion on whether the model still needs a change. That judgment call is the
point of making it a required, blocking step rather than a silent re-pin.

`--write` re-pins every entry it can and reports (with a non-zero exit) any
pin whose anchor or row no longer resolves — e.g. a clause was renumbered —
rather than aborting before writing anything. Fix those pins' `anchor`/`row`
by hand, then re-run `--write` to pick up the rest.

## Spec version resolution

`check.py` targets the highest-versioned `spec/v<X.Y.Z>/spec.md` under `spec/`
— not a hardcoded version — so cutting a new spec version directory doesn't
require editing this script. If a version bump also renumbers or restructures
a pinned clause, the pin will (correctly) report drift against the new file.
