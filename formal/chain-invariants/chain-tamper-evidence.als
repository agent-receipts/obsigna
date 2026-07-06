/*
 * ============================================================================
 *  AARP Receipt Chain — Tamper-Evidence Invariants (Alloy 6)
 * ============================================================================
 *
 *  Formalizes and machine-checks the tamper-evidence property of the Agent
 *  Receipt Protocol receipt chain, as specified in:
 *
 *     spec/v0.5.0/spec.md  §3 (Core Concepts), §4.3.2 (chain{} object),
 *                          §7 (Receipt Chain Verification)
 *
 *  See the companion README.md for how to run this, and ADR-0039 for the
 *  decision record, threat model, and honest statement of guarantee.
 *
 *  ---------------------------------------------------------------------------
 *  WHAT THIS PROVES (in one sentence)
 *  ---------------------------------------------------------------------------
 *  Given collision-resistant hashing and unforgeable signatures, any receipt
 *  sequence that passes the §7.3 verification algorithm is a genuine chain the
 *  issuer signed — in the issuer's order — possibly with a truncated tail. No
 *  modification, insertion, interior deletion, reordering, or cross-chain
 *  splice by a party WITHOUT the issuer's key can produce a different sequence
 *  that still verifies. The single residual (tail truncation of a non-terminal
 *  chain) is the documented floor of §7.3.1 / ADR-0008, reproduced here as an
 *  explicit, machine-checked fact rather than a hidden gap.
 *
 *  ---------------------------------------------------------------------------
 *  THREAT MODEL (encoded below; see ADR-0039 for prose)
 *  ---------------------------------------------------------------------------
 *  Adversary: any party WITHOUT the issuer's private key, who wants to modify,
 *  insert, delete, or reorder receipts in a stored chain and still have it
 *  verify.
 *
 *  Crypto is modeled as ABSTRACTIONS, not primitives:
 *    * Hash  — an injective function Receipt -> Hash. Injectivity IS the
 *              collision-resistance assumption (fact CollisionResistance).
 *              SHA-256 internals are NOT modeled.
 *    * Signature — a receipt is "validly signed by the issuer" iff it is a
 *              member of `IssuerSigned`. The adversary cannot enlarge this set
 *              (EUF-CMA unforgeability). Ed25519 internals are NOT modeled.
 *
 *  EXPLICITLY OUT OF SCOPE (the boundary — see ADR-0039 and ADR-0019 P2):
 *  a Byzantine issuer who HOLDS the key and signs false-but-valid receipts.
 *  The property proven is integrity against NON-key-holders, not the honesty
 *  of the key-holder. Unauthenticated chain origin (a fabricated genesis under
 *  a fresh attacker keypair, ADR-0019 P2) is likewise out of scope: it is
 *  "valid" only under the attacker's own key, which the verifier must be told
 *  to trust via out-of-band key registration.
 * ============================================================================
 */
module chain_tamper_evidence


/* ==========================================================================
 *  1. ABSTRACT CRYPTOGRAPHIC PRIMITIVES
 * ========================================================================== */

// A Hash value. Stands for a hex SHA-256 digest (§7.3 step 2b). We never model
// SHA-256's bytes — only the algebraic property we depend on (injectivity).
sig Hash {}

// The opaque chain grouping identifier `chain.chain_id` (§4.3.2, §7.3.4, §7.5).
sig ChainId {}

// The `chain.terminal` marker (§4.3.2, ADR-0008 §4). The schema permits only
// the constant `true` or omission — explicit `false` is schema-invalid. We
// model exactly that: a receipt either carries the single Terminal atom
// (terminal == true) or omits it (`no r.terminal`, i.e. "no claim"). There is
// deliberately no False atom.
one sig Terminal {}

/*
 * A Receipt, abstracted to exactly the fields §7 verification depends on.
 * Every field here is part of the RFC 8785 canonical body that is signed and
 * hashed (the `proof` field itself is excluded before hashing/signing per
 * §7.1 / ADR-0002, so it is not modeled as mutable content — a receipt's
 * signed identity IS its atom identity).
 */
sig Receipt {
  // chain.sequence (§4.3.2): monotonically increasing integer, starts at 1.
  seqNum   : one Int,
  // chain.previous_receipt_hash (§4.3.2): a Hash, or absent (`none`) which
  // models the JSON `null` required on the first receipt of a chain (§7.3 step 4).
  prevHash : lone Hash,
  // chain.chain_id (§4.3.2, §7.3.4).
  chainId  : one ChainId,
  // chain.terminal (§4.3.2): present == the constant `true`; absent == no claim.
  terminal : lone Terminal,
  // The SHA-256 of this receipt's RFC 8785 canonical form with `proof` removed
  // (§7.1, §7.3 step 2b). This is the value a SUCCESSOR stores in its own
  // prevHash to link back to this receipt.
  bodyHash : one Hash
}

// Receipts carry positive sequence numbers (schema: sequence starts at 1). This
// also keeps sequence arithmetic inside the Int bitwidth used by the commands.
fact PositiveSequence { all r: Receipt | r.seqNum >= 1 }

// Upper-bound sequence numbers by the size of the receipt universe. A meaningful
// chain never has a sequence higher than the number of receipts that exist, and a
// verifying log forces contiguous 1..k with k <= length <= #Receipt — so this
// bound excludes no counterexample to any Detected/Soundness assert. Its purpose
// is to make the "arithmetic stays in range" assumption EXPLICIT rather than
// emergent: with #Receipt <= scope and bitwidth >= 5, `plus[seqNum,1]` never
// overflows. (Without an upper bound, a fabricated receipt could carry seqNum at
// the Int ceiling and `plus[seqNum,1]` would wrap; that only ever biases
// `verifies` toward FALSE — the safe direction here — but pinning it is cleaner.)
fact SequenceInRange { all r: Receipt | r.seqNum <= #Receipt }

// COLLISION RESISTANCE (the hash assumption): distinct receipts never share a
// body hash. Equivalently, `bodyHash` is injective. An adversary cannot craft a
// second receipt whose canonical form collides with a genuine receipt's hash,
// so a stored `prevHash` unambiguously names its predecessor.
fact CollisionResistance {
  all disj r1, r2: Receipt | r1.bodyHash != r2.bodyHash
}


/* ==========================================================================
 *  2. THE ISSUER AND ITS SIGNATURES (EUF-CMA abstraction)
 * ========================================================================== */

// The set of receipts bearing a valid Ed25519 proof under the issuer's key
// (§7.2). Membership == "the §7.3 step-2a signature check passes for this
// receipt". EUF-CMA UNFORGEABILITY is modeled structurally: the adversary
// (no private key) cannot add any receipt to this set. Only the issuer can,
// and it does so exactly by emitting genuine receipts (fact below).
sig IssuerSigned in Receipt {}

// A GenuineChain is a sequence of receipts the honest issuer actually emitted
// and signed, in emission order. There may be several (e.g. one per session),
// each with a distinct chain_id.
sig GenuineChain { order: seq Receipt }

// The issuer signs EXACTLY the receipts that belong to some genuine chain it
// emitted. Any Receipt atom outside every genuine chain is "fabricated" and is
// NOT in IssuerSigned — it fails the §7.3 step-2a signature check. (This is the
// crux of the EUF-CMA abstraction: fabricating/altering content lands you
// outside IssuerSigned.)
fact IssuerSignsExactlyGenuine {
  IssuerSigned = { r: Receipt | some c: GenuineChain | r in c.order.elems }
}

/*
 * Ground truth: an honest issuer's chain is well-formed. This is NOT the
 * verifier — it is the shape of the data the adversary starts from and then
 * tampers with. Every clause mirrors a chain invariant the issuer maintains
 * at emission time (§4.3.2, §7.3, §7.5).
 */
pred wellFormedGenuine[c: GenuineChain] {
  let o = c.order | {
    some o                                   // a chain has at least one receipt
    o.elems in IssuerSigned                  // every receipt is validly signed (§7.2)
    not o.hasDups                            // each receipt is emitted once
    o.first.seqNum = 1                       // sequence starts at 1 (§4.3.2)
    no o.first.prevHash                      // first receipt: previous hash is null (§7.3 step 4)
    // sequence increments by exactly 1 along the chain (§4.3.2 / §7.3 step 3)
    all i: o.inds - o.lastIdx | o[plus[i,1]].seqNum = plus[o[i].seqNum, 1]
    // each receipt hash-links to its immediate predecessor (§7.3 step 2b/2c)
    all i: o.inds - o.lastIdx | o[plus[i,1]].prevHash = o[i].bodyHash
    // one chain_id across the whole chain (§7.3.4 / §7.5)
    all r: o.elems | r.chainId = o.first.chainId
    // a terminal marker, if present, sits only on the LAST receipt: an honest
    // issuer never emits a receipt after marking the chain terminal (§7.3.2).
    all i: o.inds | some o[i].terminal implies i = o.lastIdx
  }
}

fact GenuineChainsWellFormed { all c: GenuineChain | wellFormedGenuine[c] }

// Distinct genuine chains have distinct chain_ids and share no receipts. (§7.5:
// each chain is a single issuer's authoritative log; a receipt is emitted once.)
fact GenuineChainsDistinct {
  all disj a, b: GenuineChain {
    a.order.first.chainId != b.order.first.chainId
    no (a.order.elems & b.order.elems)
  }
}


/* ==========================================================================
 *  3. THE VERIFIER — the §7.3 chain-integrity algorithm, verbatim
 * ========================================================================== */

// The presented log: the ordered list of receipts a verifier is handed. Its
// contents and order are chosen by the (possibly adversarial) party presenting
// the chain — the solver explores all possibilities.
one sig Presented { log: seq Receipt }

/*
 * verifies[l] — TRUE iff the receipt sequence `l` passes §7.3 chain
 * verification. Each conjunct is annotated with the §7.3 step it implements.
 *
 * NOTE on §7.3 step 1 ("Retrieve all receipts ... ordered by chain.sequence"):
 * the reference SDK verifiers (e.g. sdk/go/receipt/chain.go `VerifyChain`) do
 * NOT sort internally — they check the GIVEN order, so a caller/store that
 * presents receipts out of sequence order fails the step-3 increment check.
 * We model that implemented behaviour (order is checked, not normalized). See
 * README "Interpretation notes" for why this is the security-relevant reading
 * and why the guarantee holds under the alternative sort-first reading too.
 */
pred verifies[l: seq Receipt] {
  // A chain under verification is non-empty.
  some l
  // §7.3 step 2a — every receipt carries a valid issuer signature.
  l.elems in IssuerSigned
  // §7.3 step 4 — the first receipt's previous_receipt_hash is null.
  no l.first.prevHash
  // §7.3 step 2b/2c — each receipt's prevHash equals SHA-256(canonical(prev)).
  all i: l.inds - l.lastIdx | l[plus[i,1]].prevHash = l[i].bodyHash
  // §7.3 step 3 — strict sequence contiguity: each seq is predecessor's + 1.
  all i: l.inds - l.lastIdx | l[plus[i,1]].seqNum = plus[l[i].seqNum, 1]
  // §7.3.4 — chain_id binding: every receipt shares R(0)'s chain_id (automatic,
  // unsuppressable). Blocks cross-chain splicing.
  all r: l.elems | r.chainId = l.first.chainId
  // §7.3.2 — receipt-after-terminal: no receipt may follow a terminal one
  // (automatic, unsuppressable, position-based).
  all i: l.inds | some l[i].terminal implies i = l.lastIdx
  //
  // DEFENSE-IN-DEPTH NOTE (verified by mutation testing): within THIS threat
  // model (adversary without the issuer key), the two conjuncts above are NOT
  // independently load-bearing — deleting either still leaves
  // CrossChainSplice_Detected and AppendAfterTerminal_Detected UNSAT, because a
  // non-key-holder cannot produce a receipt that hash-links and sequences
  // correctly yet carries a foreign chain_id or sits past a terminal (that
  // requires re-signing, i.e. the key). §7.3.4/§7.3.2 exist precisely to catch a
  // BYZANTINE ISSUER who CAN forge a matching hash link — the case this model
  // names as out of scope. They are kept here to encode §7.3 faithfully and to
  // remain sound if a future model widens the adversary. See README/ADR-0039.
}


/* ==========================================================================
 *  4. HELPERS: prefix / proper-prefix relations
 * ========================================================================== */

// l is a prefix of o: same first #l elements, l no longer than o.
pred isPrefixOf[l: seq Receipt, o: seq Receipt] {
  #l <= #o
  all i: l.inds | l[i] = o[i]
}

// l is a STRICT (shorter) prefix of o — i.e. o with a non-empty tail removed.
pred isProperPrefixOf[l: seq Receipt, o: seq Receipt] {
  isPrefixOf[l, o]
  #l < #o
}


/* ==========================================================================
 *  5. SANITY: the model is not vacuous
 * ========================================================================== */

// A genuine, untampered chain DOES verify. Guards against a degenerate model in
// which nothing verifies (which would make every "not verifies" assert trivially
// true). Expected: SAT.
pred genuineVerifies {
  some c: GenuineChain | Presented.log = c.order and verifies[Presented.log]
}
run genuineVerifies for 5 but 5 Int expect 1

// A multi-receipt genuine chain verifies (exercise real hash-linkage). SAT.
pred genuineMultiVerifies {
  some c: GenuineChain | #c.order >= 3 and Presented.log = c.order and verifies[Presented.log]
}
run genuineMultiVerifies for 6 but 5 Int expect 1


/* ==========================================================================
 *  6. ADVERSARY OPERATORS AND THE DETECTION PROPERTIES
 *
 *  Each `tamper_*` predicate constrains `Presented.log` to be the result of one
 *  adversary operation applied to a genuine chain `c`. The paired assertion
 *  states that the tampered log FAILS §7.3 verification. `check` searches for a
 *  counterexample (a tampered-but-verifying log); UNSAT == property holds.
 * ========================================================================== */

/* ---- 6.1 Modification-detection (spec: altering any field breaks it) ------
 * The adversary replaces the receipt at some position with one carrying
 * different signed content. Altering ANY signed field changes the canonical
 * body, so by CollisionResistance + EUF-CMA the replacement is NOT in
 * IssuerSigned. Detected by §7.3 step 2a (and, for hash/seq fields, also by
 * step 2b/3).
 *
 * SCOPE OF THIS OPERATOR: it exercises replacement with an UNSIGNED body (the
 * result of altering any signed field). The related "swap in a DIFFERENT but
 * validly-signed receipt" attack (m in IssuerSigned) is left to the master
 * Soundness theorem (§7.1), which rules out ANY non-genuine-prefix log — a
 * same-position swap to another chain's receipt breaks hash-linkage/chain_id
 * there. It is not folded in here so this operator stays a clean "unsigned
 * modification" witness. */
pred tamper_modify[c: GenuineChain] {
  some i: c.order.inds, m: Receipt {
    m not in IssuerSigned            // a modified body the issuer never signed
    Presented.log = c.order ++ (i -> m)   // override position i with m (length unchanged)
  }
}
assert Modification_Detected {
  all c: GenuineChain | tamper_modify[c] implies not verifies[Presented.log]
}
check Modification_Detected for 5 but 5 Int expect 0
check Modification_Detected for 7 but 6 Int expect 0

/* ---- 6.2 Insertion-detection --------------------------------------------
 * The adversary splices in a receipt that the issuer did not sign-and-chain
 * into THIS chain: either fabricated (∉ IssuerSigned → step 2a) or a genuine
 * receipt from elsewhere (→ chain_id/hash-link/seq checks). */
pred tamper_insert[c: GenuineChain] {
  some i: c.order.inds + #c.order, x: Receipt {   // 0..len (len == append at tail)
    x not in c.order.elems                        // x is not part of this chain
    Presented.log = c.order.insert[i, x]
    #Presented.log = plus[#c.order, 1]            // the insert actually grew the log
  }                                               // (excludes seq-saturation no-ops)
}
assert Insertion_Detected {
  all c: GenuineChain | tamper_insert[c] implies not verifies[Presented.log]
}
check Insertion_Detected for 5 but 5 Int expect 0
check Insertion_Detected for 7 but 6 Int expect 0

/* ---- 6.3 Interior-deletion-detection -------------------------------------
 * The adversary removes an INTERIOR receipt (the head or any middle receipt —
 * anything but the last). §7.3.5 strict sequence contiguity turns the gap into
 * a hard failure; the hash link across the gap also breaks. TAIL deletion is
 * the documented truncation floor (`truncationSurvives`, spec §7.3.1) and is
 * deliberately excluded here. */
pred tamper_deleteInterior[c: GenuineChain] {
  #c.order >= 2
  some i: c.order.inds - c.order.lastIdx | Presented.log = c.order.delete[i]
}
assert Interior_Deletion_Detected {
  all c: GenuineChain | tamper_deleteInterior[c] implies not verifies[Presented.log]
}
check Interior_Deletion_Detected for 5 but 5 Int expect 0
check Interior_Deletion_Detected for 7 but 6 Int expect 0

/* ---- 6.4 Reorder-detection ----------------------------------------------
 * The adversary presents the SAME receipts in a different order. Because each
 * receipt's seqNum and prevHash are signed, any non-genuine adjacency fails the
 * step-3 (increment) and step-2b (hash-link) checks. */
pred tamper_reorder[c: GenuineChain] {
  Presented.log.elems = c.order.elems      // same set of receipts...
  #Presented.log = #c.order                // ...same count...
  not Presented.log.hasDups                // ...a genuine permutation...
  Presented.log != c.order                 // ...but a different order.
}
assert Reorder_Detected {
  all c: GenuineChain | tamper_reorder[c] implies not verifies[Presented.log]
}
check Reorder_Detected for 5 but 5 Int expect 0
check Reorder_Detected for 7 but 6 Int expect 0

/* ---- 6.5 Cross-chain-splice-detection (§7.3.4) ---------------------------
 * The adversary inserts a VALIDLY-SIGNED receipt from a DIFFERENT genuine chain
 * of the same issuer. The chain_id binding check (§7.3.4) rejects the mixed
 * chain_id. Needs >= 2 genuine chains, hence a slightly larger scope. */
pred tamper_crossChainSplice[c: GenuineChain] {
  some d: GenuineChain, i: c.order.inds + #c.order, x: d.order.elems {
    d != c
    Presented.log = c.order.insert[i, x]
    #Presented.log = plus[#c.order, 1]            // the splice actually grew the log
  }
}
assert CrossChainSplice_Detected {
  all c: GenuineChain | tamper_crossChainSplice[c] implies not verifies[Presented.log]
}
check CrossChainSplice_Detected for 6 but 5 Int expect 0
check CrossChainSplice_Detected for 7 but 6 Int expect 0

/* ---- 6.5b Append-after-terminal-detection (§7.3.2) -----------------------
 * If the genuine chain closed with chain.terminal:true, appending ANY receipt
 * (even a validly signed one) is rejected unconditionally by §7.3.2. */
pred tamper_appendAfterTerminal[c: GenuineChain] {
  some c.order.last.terminal
  some x: Receipt {
    Presented.log = c.order.add[x]
    #Presented.log = plus[#c.order, 1]            // the append actually happened
  }                                               // (Alloy's seq.add is a NO-OP at
}                                                 // scope saturation — exclude it)
assert AppendAfterTerminal_Detected {
  all c: GenuineChain | tamper_appendAfterTerminal[c] implies not verifies[Presented.log]
}
check AppendAfterTerminal_Detected for 5 but 5 Int expect 0
check AppendAfterTerminal_Detected for 7 but 6 Int expect 0


/* ---- 6.6 Non-vacuity: every adversary operator is actually reachable -------
 * A "Detected" assert would pass VACUOUSLY if its tamper predicate had no
 * instance in scope. These runs prove each operator is genuinely exercised at
 * EVERY scope its check runs at (each Expected: SAT), so the UNSAT results above
 * are real detections, not empty quantification over an unsatisfiable antecedent.
 * The runner enforces the `expect 1` here: if any operator ever became
 * unreachable, this run flips to UNSAT and fails the suite — which is exactly the
 * signal that its paired `*_Detected` check has gone vacuous. */
pred canModify           { some c: GenuineChain | tamper_modify[c] }
pred canInsert           { some c: GenuineChain | tamper_insert[c] }
pred canDeleteInterior   { some c: GenuineChain | tamper_deleteInterior[c] }
pred canReorder          { some c: GenuineChain | tamper_reorder[c] }
pred canCrossChainSplice { some c: GenuineChain | tamper_crossChainSplice[c] }
pred canAppendTerminal   { some c: GenuineChain | tamper_appendAfterTerminal[c] }
run canModify           for 5 but 5 Int expect 1
run canModify           for 7 but 6 Int expect 1
run canInsert           for 5 but 5 Int expect 1
run canInsert           for 7 but 6 Int expect 1
run canDeleteInterior   for 5 but 5 Int expect 1
run canDeleteInterior   for 7 but 6 Int expect 1
run canReorder          for 5 but 5 Int expect 1
run canReorder          for 7 but 6 Int expect 1
run canCrossChainSplice for 6 but 5 Int expect 1
run canCrossChainSplice for 7 but 6 Int expect 1
run canAppendTerminal   for 5 but 5 Int expect 1
run canAppendTerminal   for 7 but 6 Int expect 1

// Antecedent reachability for the MASTER theorems at their top scopes: a genuine
// chain must actually verify at scopes 7 and 8, else Soundness/Combined (whose
// antecedent is `verifies[...]`) would hold vacuously there. (Expected: SAT.)
run genuineVerifies for 7 but 6 Int expect 1
run genuineVerifies for 8 but 6 Int expect 1
// And a genuine chain must be constructible at the FULL scope length, so the
// "scope 8" label really exercises length-8 chains (not just short ones). SAT.
pred genuineFullLength { some c: GenuineChain | #c.order = 8 }
run genuineFullLength for 8 but 6 Int expect 1


/* ==========================================================================
 *  7. MASTER SOUNDNESS + THE (documented) TRUNCATION FLOOR
 * ========================================================================== */

/* ---- 7.1 Master soundness ------------------------------------------------
 * ANY presented log that verifies is a genuine chain the issuer signed, in the
 * issuer's order, possibly truncated at the tail. This single assertion
 * subsumes every operator above: modify/insert/interior-delete/reorder/splice
 * all produce a log that is NOT a prefix of any genuine chain, so none can
 * verify. Expected: UNSAT (holds in scope). */
assert Soundness_VerifiedIsGenuinePrefix {
  verifies[Presented.log]
    implies (some c: GenuineChain | isPrefixOf[Presented.log, c.order])
}
check Soundness_VerifiedIsGenuinePrefix for 5 but 5 Int expect 0
check Soundness_VerifiedIsGenuinePrefix for 7 but 6 Int expect 0
check Soundness_VerifiedIsGenuinePrefix for 8 but 6 Int expect 0

/* ---- 7.2 Combined: the ONLY surviving tamper is tail truncation -----------
 * If a verifying log is not EXACTLY some genuine chain, then it is a proper
 * prefix of one — i.e. pure tail truncation, and nothing else. This is the
 * precise, honest form of the "no tampered chain verifies" property: it holds
 * modulo the single documented floor. Expected: UNSAT (holds in scope). */
assert Combined_OnlySurvivorIsTailTruncation {
  (verifies[Presented.log] and (all c: GenuineChain | Presented.log != c.order))
    implies (some c: GenuineChain | isProperPrefixOf[Presented.log, c.order])
}
check Combined_OnlySurvivorIsTailTruncation for 5 but 5 Int expect 0
check Combined_OnlySurvivorIsTailTruncation for 7 but 6 Int expect 0
check Combined_OnlySurvivorIsTailTruncation for 8 but 6 Int expect 0

/* ---- 7.3 The truncation floor is REAL (documented limitation) -------------
 * Dropping the final receipt of a genuine, NON-terminal chain still verifies.
 * This is NOT a bug: it is the deliberate floor of §7.3.1 / ADR-0008 — an
 * in-chain field cannot commit to successors the issuer had not yet produced.
 * We surface it as a machine-checked FACT. Expected: SAT (instance exists).
 *
 * Mitigations (out of band or opt-in) are NOT modeled here because they live
 * outside the §7.3 core algorithm: ExpectedLength / ExpectedFinalHash witnesses
 * and the RequireTerminal parameter (§7.3.1, ADR-0008). See README/ADR-0039. */
pred truncationSurvives {
  some c: GenuineChain {
    #c.order >= 2
    no c.order.last.terminal            // the chain was NOT explicitly closed
    Presented.log = c.order.butlast     // drop the final receipt
    verifies[Presented.log]             // ...and it still passes §7.3
  }
}
run truncationSurvives for 5 but 5 Int expect 1
