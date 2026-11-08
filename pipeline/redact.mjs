/*
 * Shared secret-redaction core, used by the MCP proxy and its unit test.
 *
 * Goal: mask a listed secret in the forms REA tools typically emit: the full
 * value as text, distinctive text fragments of it (>= 5 characters with a digit
 * and punctuation, opaque secrets only), hex byte runs (any separators, either
 * byte order), 32/64-bit constants (hex or decimal, BE/LE) and base64. Text
 * needles are also matched in their JSON-escaped form (once and twice escaped),
 * because the proxy redacts serialized JSON lines.
 *
 * NOT masked: single bytes, decimal or character arrays, short or digit-less text
 * fragments, and values computed from a secret (see README, "Honest limits").
 */

export const MINWIN = 4;

/** Build the redaction context from a list of secret strings.
 * @param {{value:string,type?:string,opaque?:boolean}[]} secrets
 */
export function buildContext(secrets) {
  const values = [];
  const win4 = new Set(); // hex of every 4-byte window of every secret
  const textWindows = []; // distinctive ASCII windows (opaque secrets only)
  for (const s of secrets) {
    if (!s || !s.value) continue;
    const type = (s.type || "SECRET").toUpperCase();
    values.push({ value: s.value, type, opaque: !!s.opaque });
    const b = Buffer.from(s.value, "utf8");
    for (let i = 0; i + MINWIN <= b.length; i++) {
      win4.add(b.subarray(i, i + MINWIN).toString("hex"));
    }
    if (s.opaque) {
      // Opaque secrets can still embed dictionary words (e.g. the signing key
      // contains "signing"/"seed"). Mask only >=5-char ASCII windows that carry
      // a digit or punctuation -- i.e. genuinely high-entropy fragments -- so we
      // never redact (or falsely flag) a plain English word that merely appears
      // in the secret. Byte/numeric/base64 forms are still caught at 4-byte
      // granularity via win4, independent of this.
      for (let len = 5; len <= b.length; len++) {
        for (let i = 0; i + len <= b.length; i++) {
          const w = s.value.slice(i, i + len);
          // A text window is treated as "distinctive" only if it carries BOTH a
          // digit AND a punctuation char. That excludes dictionary words the
          // secret embeds ("signing", "seed") -- no digit -- AND pure-hex
          // fragments of a hex-bodied secret ("7f3a9") that would collide with
          // benign addresses/constants -- no punctuation. Real byte leaks are
          // caught at 4-byte granularity by win4 regardless of this rule.
          if (/^[\x20-\x7e]+$/.test(w) && /[0-9]/.test(w) && /[^A-Za-z0-9]/.test(w)) {
            textWindows.push({ w, type });
          }
        }
      }
    }
  }
  // Each text needle also in its JSON-escaped forms: the proxy redacts the
  // serialized JSON line, where a secret containing `"`, `\` or a control
  // character appears escaped once (a string value) or twice (JSON inside a
  // string value, e.g. a tool's text content).
  const raw = [
    ...values.map((v) => ({ needle: v.value, repl: `[REDACTED_${v.type}]` })),
    ...textWindows.map((v) => ({ needle: v.w, repl: `[REDACTED_${v.type}]` })),
  ];
  const seen = new Set();
  const literals = [];
  for (const r of raw) {
    const esc1 = jsonEscape(r.needle);
    for (const needle of [r.needle, esc1, jsonEscape(esc1)]) {
      if (seen.has(needle)) continue;
      seen.add(needle);
      literals.push({ needle, repl: r.repl });
    }
  }
  // longest first so full values / longer windows win over their substrings
  literals.sort((a, b) => b.needle.length - a.needle.length);
  return { win4, literals };
}

/** The text of a string as it appears inside a JSON string literal. */
function jsonEscape(str) {
  return JSON.stringify(str).slice(1, -1);
}

/** True if a byte buffer contains any secret 4-byte window (forward order). */
export function bytesHitWindow(buf, win4) {
  for (let i = 0; i + MINWIN <= buf.length; i++) {
    if (win4.has(buf.subarray(i, i + MINWIN).toString("hex"))) return true;
  }
  return false;
}

/** Like bytesHitWindow but also matches byte-swapped (little-endian) windows,
 *  for hex dumps whose byte order (BE vs LE dword) is ambiguous. */
export function bytesHitWindowAnyOrder(buf, win4) {
  for (let i = 0; i + MINWIN <= buf.length; i++) {
    const w = buf.subarray(i, i + MINWIN);
    if (win4.has(w.toString("hex"))) return true;
    if (win4.has(Buffer.from([...w].reverse()).toString("hex"))) return true;
  }
  return false;
}

function uintToBytes(nBig, nBytes, little) {
  const b = Buffer.alloc(nBytes);
  for (let i = 0; i < nBytes; i++) {
    b[little ? i : nBytes - 1 - i] = Number((nBig >> BigInt(8 * i)) & 0xffn);
  }
  return b;
}

/** Does a numeric value, taken as 4- or 8-byte BE/LE, contain a secret window? */
function constHitsWindow(nBig, win4) {
  for (const nb of [4, 8]) {
    if (nBig >= (1n << BigInt(8 * nb))) continue;
    for (const little of [false, true]) {
      if (bytesHitWindow(uintToBytes(nBig, nb, little), win4)) return true;
    }
  }
  // also 4 low bytes regardless of width (covers values printed > 2^32)
  for (const little of [false, true]) {
    if (bytesHitWindow(uintToBytes(nBig & 0xffffffffn, 4, little), win4)) return true;
  }
  return false;
}

const HEXRUN = /(?:0x)?[0-9a-fA-F]{2}(?:[\s,:-]*(?:0x)?[0-9a-fA-F]{2})+/g;
const HEXCONST = /0x[0-9a-fA-F]{8,16}\b/g;
const DECINT = /\b\d{4,20}\b/g;
const B64RUN = /[A-Za-z0-9+/]{8,}={0,2}/g;

/** Redact every secret form from a chunk of text. Returns {out, hits}. */
export function redactText(text, ctx) {
  let out = text;
  const hits = {};
  const bump = (k) => { hits[k] = (hits[k] || 0) + 1; };

  // 1. literal secret values and opaque text windows
  for (const r of ctx.literals) {
    if (!r.needle) continue;
    const parts = out.split(r.needle);
    const n = parts.length - 1;
    if (n > 0) { hits[r.repl] = (hits[r.repl] || 0) + n; out = parts.join(r.repl); }
  }

  // 2. raw hex byte runs -> decode -> mask whole run if it carries a window
  out = out.replace(HEXRUN, (m) => {
    const hex = m.replace(/0x/g, "").replace(/[^0-9a-fA-F]/g, "");
    if (hex.length < 2 * MINWIN || hex.length % 2 !== 0) return m;
    const buf = Buffer.from(hex, "hex");
    if (bytesHitWindowAnyOrder(buf, ctx.win4)) { bump("BYTES"); return `[REDACTED_SECRET_BYTES:${buf.length}]`; }
    return m;
  });

  // 3. numeric constants (hex and decimal) -> BE/LE bytes -> mask
  out = out.replace(HEXCONST, (m) => {
    try { if (constHitsWindow(BigInt(m), ctx.win4)) { bump("CONST"); return "[REDACTED_SECRET_CONST]"; } } catch {}
    return m;
  });
  out = out.replace(DECINT, (m) => {
    try { if (constHitsWindow(BigInt(m), ctx.win4)) { bump("CONST"); return "[REDACTED_SECRET_CONST]"; } } catch {}
    return m;
  });

  // 4. base64 -> decode -> mask
  out = out.replace(B64RUN, (m) => {
    try {
      const buf = Buffer.from(m, "base64");
      if (buf.length >= MINWIN && bytesHitWindow(buf, ctx.win4)) { bump("B64"); return "[REDACTED_SECRET_B64]"; }
    } catch {}
    return m;
  });

  return { out, hits };
}

/** Scan text for ANY surviving secret form. Returns a list of findings. */
export function scanLeaks(text, ctx) {
  const findings = [];
  for (const r of ctx.literals) {
    if (r.needle && text.includes(r.needle)) findings.push({ kind: "text", repl: r.repl, len: r.needle.length });
  }
  let m;
  const hx = new RegExp(HEXRUN.source, "g");
  while ((m = hx.exec(text))) {
    const hex = m[0].replace(/0x/g, "").replace(/[^0-9a-fA-F]/g, "");
    if (hex.length >= 2 * MINWIN && hex.length % 2 === 0 && bytesHitWindowAnyOrder(Buffer.from(hex, "hex"), ctx.win4))
      findings.push({ kind: "hex", sample: m[0].slice(0, 24) });
  }
  const hc = new RegExp(HEXCONST.source, "g");
  while ((m = hc.exec(text))) { try { if (constHitsWindow(BigInt(m[0]), ctx.win4)) findings.push({ kind: "hexconst", sample: m[0] }); } catch {} }
  const di = new RegExp(DECINT.source, "g");
  while ((m = di.exec(text))) { try { if (constHitsWindow(BigInt(m[0]), ctx.win4)) findings.push({ kind: "decconst", sample: m[0] }); } catch {} }
  const b6 = new RegExp(B64RUN.source, "g");
  while ((m = b6.exec(text))) { try { const b = Buffer.from(m[0], "base64"); if (b.length >= MINWIN && bytesHitWindow(b, ctx.win4)) findings.push({ kind: "base64", sample: m[0].slice(0, 24) }); } catch {} }
  return findings;
}
