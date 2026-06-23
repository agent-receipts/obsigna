// UI glue for obsigna.dev/verify.
//
// This file contains NO verification logic. It marshals the user's input into a
// request, hands it to the WebAssembly export `obsignaVerify` (compiled from the
// Go verify core — the same code as `obsigna receipt verify`), and renders the
// JSON verdict it returns. Canonicalization, signature checking, and hash-chain
// walking happen exclusively inside the WASM module. There is intentionally no
// JavaScript reimplementation of any verification step.

(function () {
  "use strict";

  var els = {
    tabSingle: document.getElementById("tab-single"),
    tabChain: document.getElementById("tab-chain"),
    receiptsLabel: document.getElementById("receipts-label"),
    pubkey: document.getElementById("pubkey"),
    receipts: document.getElementById("receipts"),
    anchor: document.getElementById("anchor"),
    anchorKey: document.getElementById("anchor-pubkey"),
    verify: document.getElementById("verify"),
    loadExample: document.getElementById("load-example"),
    clear: document.getElementById("clear"),
    status: document.getElementById("status"),
    result: document.getElementById("result"),
  };

  var mode = "single"; // "single" | "chain"

  function setMode(next) {
    mode = next;
    var single = next === "single";
    els.tabSingle.setAttribute("aria-selected", String(single));
    els.tabChain.setAttribute("aria-selected", String(!single));
    els.receiptsLabel.textContent = single
      ? "Receipt JSON"
      : "Chain — a JSON array of receipts, or one receipt per line (JSONL)";
    els.receipts.placeholder = single
      ? "Paste a single receipt JSON object…"
      : "Paste a JSON array of receipts, or one receipt JSON per line…";
  }

  els.tabSingle.addEventListener("click", function () { setMode("single"); });
  els.tabChain.addEventListener("click", function () { setMode("chain"); });

  els.loadExample.addEventListener("click", function () {
    var ex = window.OBSIGNA_EXAMPLES || {};
    if (mode === "single") {
      // The disclosed single receipt is signed by its own key.
      els.pubkey.value = ex.singlePublicKey || "";
      els.receipts.value = ex.singleReceipt || "";
      // The example checkpoint anchors the chain head (sequence 3), so it does
      // not apply to the single-receipt example; leave the anchor fields empty.
      els.anchor.value = "";
      els.anchorKey.value = "";
    } else {
      els.pubkey.value = ex.publicKey || "";
      els.receipts.value = ex.chain || "";
      els.anchor.value = ex.anchorCheckpoint || "";
      els.anchorKey.value = ex.anchorPublicKey || "";
    }
    els.result.hidden = true;
  });

  els.clear.addEventListener("click", function () {
    els.pubkey.value = "";
    els.receipts.value = "";
    els.anchor.value = "";
    els.anchorKey.value = "";
    els.result.hidden = true;
    els.status.textContent = "";
  });

  els.verify.addEventListener("click", function () {
    if (typeof window.obsignaVerify !== "function") {
      els.status.textContent = "Verifier is still loading…";
      return;
    }
    var request = {
      mode: mode,
      receipts: els.receipts.value,
      public_key: els.pubkey.value,
      anchor: els.anchor.value,
      anchor_public_key: els.anchorKey.value,
    };
    var raw;
    try {
      raw = window.obsignaVerify(JSON.stringify(request));
    } catch (e) {
      raw = JSON.stringify({ ok: false, verdict: "error", error: String(e) });
    }
    var result;
    try {
      result = JSON.parse(raw);
    } catch (e) {
      result = { ok: false, verdict: "error", error: "could not parse verifier output" };
    }
    render(result);
  });

  // ---- rendering ----

  var VERDICT_COPY = {
    full: {
      tag: "Full pass",
      title: "Cryptographically consistent and externally anchored",
      body: "Every signature is valid, the hash chain is unbroken, and an external anchor corroborates the chain head.",
    },
    qualified: {
      tag: "Qualified pass",
      title: "Cryptographically consistent — not externally anchored",
      body: "Every signature is valid, the hash chain is unbroken, and canonicalization is correct. This proves internal consistency only: it is not corroborated by an external anchor.",
    },
    fail: {
      tag: "Fail",
      title: "Not cryptographically consistent",
      body: "The receipt or chain did not verify. See the details below.",
    },
    error: {
      tag: "Could not evaluate",
      title: "The input could not be evaluated",
      body: "Verification did not run — check the public key and input below.",
    },
  };

  function render(result) {
    var verdict = result.verdict || "error";
    var copy = VERDICT_COPY[verdict] || VERDICT_COPY.error;

    var parts = [];
    parts.push(
      '<div class="banner ' + esc(verdict) + '">' +
        '<span class="verdict-tag">' + esc(copy.tag) + "</span>" +
        "<h2>" + esc(copy.title) + "</h2>" +
        "<p>" + esc(result.error ? result.error : copy.body) + "</p>" +
      "</div>"
    );

    parts.push('<div class="rings">');
    parts.push(cryptoRing(result));
    parts.push(anchorRing(result));
    parts.push("</div>");

    var chain = result.crypto && result.crypto.chain;
    if (chain && Array.isArray(chain.receipts) && chain.receipts.length) {
      parts.push(receiptsTable(chain));
    }
    parts.push(chainNotes(result));

    // Only FAIL shows the detail box. On ERROR the same message is already in
    // the banner (errorResult sets Error and crypto.detail to the same string),
    // so repeating it here would just duplicate the line.
    if (result.crypto && result.crypto.detail && verdict === "fail") {
      parts.push('<div class="detail">' + esc(result.crypto.detail) + "</div>");
    }

    els.result.innerHTML = parts.join("");
    els.result.hidden = false;
    els.result.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }

  function cryptoRing(result) {
    var c = result.crypto || {};
    var consistent = !!c.consistent;
    var state, cls;
    if (result.verdict === "error") {
      state = "Not evaluated"; cls = "na";
    } else if (consistent) {
      state = "Pass"; cls = "ok";
    } else {
      state = "Fail"; cls = "bad";
    }
    var sub = "Signatures, hash chain, and JCS canonicalization.";
    if (typeof c.receipt_count === "number" && c.receipt_count > 0) {
      sub += " " + c.receipt_count + (c.receipt_count === 1 ? " receipt." : " receipts.");
    }
    return (
      '<div class="ring">' +
        "<h3>Cryptographic consistency</h3>" +
        '<div class="ring-state ' + cls + '">' + esc(state) + "</div>" +
        "<p>" + esc(sub) + "</p>" +
      "</div>"
    );
  }

  function anchorRing(result) {
    var a = result.anchor || {};
    var state, cls;
    if (result.verdict === "error") {
      // The request was not evaluated at all, so neither ring has a real
      // verdict — mirror the crypto ring rather than implying "not anchored".
      state = "Not evaluated"; cls = "na";
    } else if (a.trusted) {
      state = "Anchored"; cls = "ok";
    } else if (a.checked) {
      // A checkpoint was evaluated but did not corroborate this head (bad
      // signature, wrong key, or a head/sequence/chain mismatch).
      state = "Not anchored"; cls = "warn";
    } else if (a.supplied) {
      // A proof was pasted but could not be evaluated (no anchor key, or it did
      // not parse as a signed checkpoint).
      state = "Not evaluated"; cls = "na";
    } else {
      state = "Not anchored"; cls = "warn";
    }
    return (
      '<div class="ring">' +
        "<h3>External-anchor trust</h3>" +
        '<div class="ring-state ' + cls + '">' + esc(state) + "</div>" +
        "<p>" + esc(a.note || "") + "</p>" +
      "</div>"
    );
  }

  function receiptsTable(chain) {
    var rows = chain.receipts
      .map(function (r) {
        return (
          "<tr>" +
          "<td>" + esc(r.index) + "</td>" +
          '<td class="id">' + esc(r.receipt_id || "") + "</td>" +
          "<td>" + mark(r.signature_valid) + "</td>" +
          "<td>" + mark(r.hash_link_valid) + "</td>" +
          "<td>" + mark(r.sequence_valid) + "</td>" +
          "</tr>"
        );
      })
      .join("");
    return (
      '<table class="receipts">' +
      "<thead><tr><th>#</th><th>Receipt ID</th><th>Signature</th><th>Hash link</th><th>Sequence</th></tr></thead>" +
      "<tbody>" + rows + "</tbody></table>"
    );
  }

  function chainNotes(result) {
    var notes = [];
    var c = result.crypto || {};
    var chain = c.chain;

    if (typeof c.receipt_hash === "string" && c.receipt_hash) {
      notes.push("Canonical receipt hash: " + c.receipt_hash);
    }
    if (chain) {
      if (typeof chain.broken_at === "number" && chain.broken_at >= 0) {
        notes.push("First break at receipt index " + chain.broken_at + ".");
      }
      if (chain.status && chain.status !== "unknown") {
        notes.push("Chain termination status: " + chain.status + ".");
      }
      if (Array.isArray(chain.warnings)) {
        chain.warnings.forEach(function (w) { notes.push(w); });
      }
      if (chain.response_hash_note) { notes.push(chain.response_hash_note); }
      if (chain.incomplete_tool_roundtrip) {
        notes.push("Advisory: the final receipt is a pending tool call whose result never arrived.");
      }
      if (chain.incomplete_session) {
        notes.push("Advisory: PTY session open/close events are imbalanced.");
      }
    }
    if (!notes.length) return "";
    return (
      '<ul class="notes">' +
      notes.map(function (n) { return "<li>" + esc(n) + "</li>"; }).join("") +
      "</ul>"
    );
  }

  function mark(ok) {
    return ok
      ? '<span class="check" title="valid">✓</span>'
      : '<span class="cross" title="invalid">✗</span>';
  }

  function esc(v) {
    return String(v).replace(/[&<>"']/g, function (ch) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[ch];
    });
  }

  // ---- WASM bootstrap ----

  function ready() {
    els.verify.disabled = false;
    els.verify.textContent = "Verify";
    els.status.textContent = "Verifier loaded — offline and ready.";
  }

  function failLoad(err) {
    els.verify.textContent = "Verifier failed to load";
    els.status.textContent = "Could not load the WebAssembly verifier: " + err;
  }

  function loadWasm() {
    if (typeof Go !== "function") {
      failLoad("wasm_exec.js did not load");
      return;
    }
    var go = new Go();
    var url = "obsigna-verify.wasm";

    function start(instance) {
      go.run(instance); // sets window.obsignaVerify, then parks the runtime
      if (typeof window.obsignaVerify === "function") {
        ready();
      } else {
        failLoad("verifier export missing");
      }
    }

    if (WebAssembly.instantiateStreaming) {
      WebAssembly.instantiateStreaming(fetch(url), go.importObject).then(
        function (res) { start(res.instance); },
        function () { instantiateFallback(go, url, start); }
      );
    } else {
      instantiateFallback(go, url, start);
    }
  }

  function instantiateFallback(go, url, start) {
    fetch(url)
      .then(function (resp) { return resp.arrayBuffer(); })
      .then(function (bytes) { return WebAssembly.instantiate(bytes, go.importObject); })
      .then(function (res) { start(res.instance); })
      .catch(function (err) { failLoad(String(err)); });
  }

  setMode("single");
  loadWasm();
})();
