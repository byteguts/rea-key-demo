#!/usr/bin/env node
/*
 * Differential test: the original stripped binary vs. the agent's signer.ts.
 *
 * Usage (README steps 6 and 8):
 *   REA_LOCAL_BIN=target/syncd node pipeline/05_difftest.mjs --archive <signer.ts> [OUT_DIR]
 *
 * N deterministic (seeded) requests are signed by the real binary AND by
 * makeToken from signer.ts (the real key is injected HERE from target/syncd.c,
 * never by the agent) and compared. Writes OUT_DIR/difftest_report.json.
 * signer.ts is imported and executed with your user's rights: read it first.
 *
 * Without REA_LOCAL_BIN the binary runs on REA_SSH_TARGET over ssh
 * (REA_REMOTE_BIN = its path there), as in "How we recorded it".
 */
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { randomBytes } from "node:crypto";
import path from "node:path";
import fs from "node:fs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DEMO = path.resolve(__dirname, "..");
const OUT = path.join(DEMO, "out");
const N = Number(process.env.DIFF_N || 10000);
const SSH = process.env.REA_SSH_TARGET || "user@analysis-host";
const REMOTE_BIN = process.env.REA_REMOTE_BIN || "/opt/rea-demo/target/syncd";
const RUN_ID = randomBytes(6).toString("hex"); // unpredictable remote temp names
const REMOTE_TMP = process.env.REA_REMOTE_TMP || `/tmp/rea-demo-difftest_${RUN_ID}_inputs.tsv`;
const REMOTE_DRIVER = process.env.REA_REMOTE_DRIVER || `/tmp/rea-demo-difftest_${RUN_ID}_driver.sh`;
const shq = (s) => "'" + String(s).replace(/'/g, `'\\''`) + "'"; // POSIX single-quote

// ---- the signer under test ------------------------------------------------
const args = process.argv.slice(2);
if (args[0] !== "--archive" || !args[1]) {
  console.error("usage: node pipeline/05_difftest.mjs --archive <signer.ts> [OUT_DIR]");
  process.exit(2);
}
const SIGNER = path.resolve(args[1]);
const REPORT_DIR = path.resolve(args[2] || path.dirname(SIGNER));
if (!fs.existsSync(SIGNER)) { console.error("signer file not found: " + SIGNER); process.exit(2); }
console.log(`testing signer: ${SIGNER}`);

// ---- deterministic inputs (mulberry32) ----------------------------------
function mulberry32(a) {
  return function () {
    a |= 0; a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const rnd = mulberry32(0x5EED1234);
const METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH"];
const CS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_./";
function rstr(n) { let s = ""; for (let i = 0; i < n; i++) s += CS[Math.floor(rnd() * CS.length)]; return s; }

const inputs = [];
for (let i = 0; i < N; i++) {
  const method = METHODS[Math.floor(rnd() * METHODS.length)];
  const p = "/v1/" + rstr(1 + Math.floor(rnd() * 20));
  const ts = String(1700000000 + Math.floor(rnd() * 90000000));
  const body = rnd() < 0.3 ? "" : rstr(Math.floor(rnd() * 40));
  inputs.push([method, p, ts, body]);
}

// Real signing key from ground truth (NOT from the agent).
const SIGN_KEY = (() => {
  const src = fs.readFileSync(path.join(DEMO, "target", "syncd.c"), "utf8");
  const m = src.match(/SIGN_KEY\[\]\s*=\s*"([^"]+)"/);
  if (!m) throw new Error("could not read SIGN_KEY from ground truth");
  return m[1];
})();

// ---- binary side ----------------------------------------------------------
// Remote (default): one batched ssh call. Local (REA_LOCAL_BIN=<path>): the same
// TSV is piped to a local bash loop, no scp/ssh.
const TSV = inputs.map((r) => r.join("\t")).join("\n") + "\n";
fs.mkdirSync(OUT, { recursive: true });
fs.writeFileSync(path.join(OUT, "difftest_inputs.tsv"), TSV);
const LOCAL_BIN = process.env.REA_LOCAL_BIN;
let binTokens, binMs;
if (LOCAL_BIN) {
  const LOOP = `while IFS=$'\\t' read -r m p t b; do "$BIN" sign "$m" "$p" "$t" "$b"; done`;
  const env = { ...process.env, BIN: LOCAL_BIN };
  // probe first: if the binary cannot run here, stop; never report matches
  const probe = spawnSync("bash", ["-c", '"$BIN" sign GET /probe 1700000000 ""'], { encoding: "utf8", env });
  if (probe.error || probe.status !== 0 || !probe.stdout.trim()) {
    const why = probe.error ? probe.error.message : `exit ${probe.status}: ${(probe.stderr || "").trim() || "no output"}`;
    console.error(`cannot run ${LOCAL_BIN}: ${why}`);
    process.exit(5);
  }
  console.log(`generated ${N} inputs; running local binary ${LOCAL_BIN}...`);
  const t0 = Date.now();
  const run = spawnSync("bash", ["-c", LOOP], { input: TSV, encoding: "utf8", env, maxBuffer: 64 * 1024 * 1024 });
  if (run.status !== 0) { console.error(`cannot run ${LOCAL_BIN}: local run failed: ${run.stderr || run.error}`); process.exit(5); }
  binTokens = run.stdout.trim().split("\n");
  binMs = Date.now() - t0;
} else {
  fs.writeFileSync(path.join(OUT, "difftest_driver.sh"),
    `#!/usr/bin/env bash\nwhile IFS=$'\\t' read -r m p t b; do "${REMOTE_BIN}" sign "$m" "$p" "$t" "$b"; done\n`);
  console.log(`generated ${N} inputs; sending to analysis host...`);
  for (const [f, dst] of [["difftest_inputs.tsv", REMOTE_TMP], ["difftest_driver.sh", REMOTE_DRIVER]]) {
    const r = spawnSync("scp", ["-q", path.join(OUT, f), `${SSH}:${dst}`], { encoding: "utf8" });
    if (r.status !== 0) throw new Error(`scp ${f} failed: ${r.stderr}`);
  }
  const t0 = Date.now();
  const run = spawnSync("ssh", [SSH, `bash ${shq(REMOTE_DRIVER)} < ${shq(REMOTE_TMP)}; rc=$?; rm -f ${shq(REMOTE_DRIVER)} ${shq(REMOTE_TMP)}; exit $rc`], { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
  if (run.status !== 0) throw new Error("remote run failed: " + run.stderr);
  binTokens = run.stdout.trim().split("\n");
  binMs = Date.now() - t0;
}
console.log(`binary signed ${binTokens.length} inputs in ${binMs} ms`);

// ---- TS side ------------------------------------------------------------
const { makeToken } = await import("file://" + SIGNER.replace(/\\/g, "/"));
const t1 = Date.now();
const tsTokens = inputs.map((r) => makeToken(r[0], r[1], r[2], r[3], SIGN_KEY));
const tsMs = Date.now() - t1;

let match = 0; const mismatches = [];
for (let i = 0; i < N; i++) {
  if (binTokens[i] === tsTokens[i]) match++;
  else if (mismatches.length < 10) mismatches.push({ i, input: inputs[i], bin: binTokens[i], ts: tsTokens[i] });
}

const report = {
  signer: SIGNER,
  n: N, matched: match, mismatched: N - match,
  agreement: (100 * match / N).toFixed(4) + "%",
  binary_sign_ms_total: binMs, binary_sign_ms_per: +(binMs / N).toFixed(3),
  ts_sign_ms_total: tsMs, ts_sign_ms_per: +(tsMs / N).toFixed(4),
  seed: "0x5EED1234 (mulberry32)",
  sample_mismatches: mismatches,
};
fs.writeFileSync(path.join(REPORT_DIR, "difftest_report.json"), JSON.stringify(report, null, 1));
console.log("DIFFTEST:", JSON.stringify({ ...report, signer: undefined, sample_mismatches: mismatches.length }, null, 1));
