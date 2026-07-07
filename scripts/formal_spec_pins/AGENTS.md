# formal_spec_pins

Guards against `formal/chain-invariants/chain-tamper-evidence.als` silently
drifting from the spec clauses it claims to encode.

The Alloy model does not parse `spec/v0.5.0/spec.md` — it is a hand-written
formalization with prose citations (§3.2, §4.3.2, §7.3, ...). Nothing forces it
to change when those clauses do, so a spec edit under a modeled clause can
land, merge, and leave the model quietly describing a spec that no longer
exists. Re-running `formal/chain-invariants/run.sh` after such an edit would
not catch this either — the Alloy source is unchanged, so it re-proves the
same (now possibly stale) claim and passes.

## Layout

| File | Role |
|------|------|
| `check.py` | Extracts the live text of each pinned clause from `spec/v0.5.0/spec.md` and compares it to the text pinned in `formal/chain-invariants/spec-pins.json`. |
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

## Known limitation

`DEFAULT_SPEC` hardcodes `spec/v0.5.0/spec.md`. If a future spec revision
supersedes v0.5.0 in a new directory, this script's target (and every pin) will
need reconciling against the new file — a larger, one-time migration, not
something this gate can automate away.
