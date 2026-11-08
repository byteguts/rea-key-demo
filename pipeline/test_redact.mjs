#!/usr/bin/env node
/*
 * Unit test for the redaction core. Feeds crafted tool responses that leak a
 * secret in every encoding we defend against, and asserts (a) redactText removes
 * every secret byte and (b) scanLeaks reports zero afterwards.
 *
 * Run: node pipeline/test_redact.mjs
 */
import assert from "node:assert";
import { buildContext, redactText, scanLeaks } from "./redact.mjs";

// A fake, self-contained secret (not any real one) plus a short opaque one.
const SECRET = "S3cr3t-Signing-Key::abcd1234"; // 28 bytes, opaque
const HOST = "gw-x.internal.corp.local";       // low-entropy
const ctx = buildContext([
  { value: SECRET, type: "signing_key", opaque: true },
  { value: HOST, type: "hostname", opaque: false },
]);

const b = Buffer.from(SECRET, "utf8");
const first4 = b.subarray(0, 4);
const hexBE = first4.toString("hex");                       // "53336372"
const hexLE = Buffer.from([...first4].reverse()).toString("hex");
const spaced = [...first4].map((x) => x.toString(16).padStart(2, "0")).join(" ");
const constBE = "0x" + hexBE;
const constLE = "0x" + hexLE;
const decLE = BigInt("0x" + hexLE).toString(10);
const b64 = Buffer.from(SECRET.slice(0, 12)).toString("base64");

// These are the leak vectors a tool like read_bytes / analyze_function could emit.
const cases = {
  "plain text": `value = "${SECRET}"`,
  "hex joined (the real leak vector)": `bytes: ${hexBE}`,
  "hex spaced": `instr bytes: ba ${spaced}`,
  "hex LE joined": `dword ${hexLE}`,
  "0x const BE": `mov eax, ${constBE}`,
  "0x const LE": `mov edx, ${constLE}`,
  "decimal const": `imm = ${decLE}`,
  "base64": `b64=${b64}`,
  "hostname text": `host ${HOST}`,
  "hostname bytes": `data: ${Buffer.from(HOST).toString("hex")}`,
};

// Benign content that must survive untouched (no over-redaction of real analysis).
const benign = [
  "mov eax, 0x9e3779b1",      // golden-ratio mixing constant (not secret)
  "call FUN_00101350",        // address
  "imul eax, eax, 0x85ebca77",// mixing multiplier
  "ts = 1700000000",          // a timestamp
  "add edx, 0xc2b2ae3d",      // mixing add constant
];

let failures = 0;
for (const [name, text] of Object.entries(cases)) {
  const { out } = redactText(text, ctx);
  const left = scanLeaks(out, ctx);
  const ok = left.length === 0 && out !== text;
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}`);
  if (!ok) { failures++; console.log("   before:", text, "\n   after :", out, "\n   leaks :", JSON.stringify(left)); }
}

for (const text of benign) {
  const { out } = redactText(text, ctx);
  const ok = out === text;
  console.log(`${ok ? "PASS" : "FAIL"}  benign-preserved: ${text}`);
  if (!ok) { failures++; console.log("   became:", out); }
}

// JSON-escaped forms: the proxy redacts serialized JSON lines, where a secret
// containing `"` or `\` appears escaped once (string value) or twice (JSON text
// inside a string value).
const QSECRET = 'Q"uo\\te-K3y!x';                 // fake, contains " and \
const qctx = buildContext([{ value: QSECRET, type: "api_key", opaque: false }]);
const once = JSON.stringify({ text: `key=${QSECRET} end` });
const twice = JSON.stringify({ text: JSON.stringify({ value: QSECRET }) });
const esc1 = JSON.stringify(QSECRET).slice(1, -1);
const esc2 = JSON.stringify(esc1).slice(1, -1);
for (const [name, line, needle] of [["json escaped once", once, esc1], ["json escaped twice", twice, esc2]]) {
  const { out } = redactText(line, qctx);
  let parsedOk = true; try { JSON.parse(out); } catch { parsedOk = false; }
  const ok = !out.includes(needle) && out.includes("[REDACTED_API_KEY]") && parsedOk;
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}`);
  if (!ok) failures++;
}

// Sanity: scanLeaks must DETECT an unredacted secret (no false "clean").
assert(scanLeaks(`raw ${hexBE}`, ctx).length > 0, "scanner should catch raw hex leak");
assert(scanLeaks(`k=${SECRET}`, ctx).length > 0, "scanner should catch text leak");

console.log(`\n${failures === 0 ? "ALL TESTS PASSED" : failures + " TEST(S) FAILED"}`);
process.exit(failures === 0 ? 0 : 1);
