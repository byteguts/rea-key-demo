#!/usr/bin/env node
// Tests 05_difftest.mjs local mode (REA_LOCAL_BIN). Plain node, exit 1 on failure.
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const DIFF = path.join(HERE, "05_difftest.mjs");

const hasBash = spawnSync("bash", ["-c", "true"]).status === 0;
if (!hasBash) { console.log("SKIP: bash not found on PATH, difftest local mode needs it"); process.exit(0); }

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "difftest-local-"));
const toPosix = (p) => p.split(path.sep).join("/");
let failed = 0;
const check = (ok, msg) => { console.log((ok ? "PASS " : "FAIL ") + msg); if (!ok) failed++; };

// fake binary: always prints 16 zeros; fake signer returns the same
const bin = path.join(tmp, "fakebin.sh");
fs.writeFileSync(bin, '#!/usr/bin/env bash\necho 0000000000000000\n', { mode: 0o755 });
const port = path.join(tmp, "port.mjs");
fs.writeFileSync(port, 'export function makeToken() { return "0000000000000000"; }\n');

function run(localBin, outDir) {
  fs.mkdirSync(outDir, { recursive: true });
  return spawnSync(process.execPath, [DIFF, "--archive", port, outDir], {
    encoding: "utf8", env: { ...process.env, REA_LOCAL_BIN: localBin, DIFF_N: "5" },
  });
}

let out = path.join(tmp, "out1");
let r = run(toPosix(bin), out);
let rep = null;
try { rep = JSON.parse(fs.readFileSync(path.join(out, "difftest_report.json"), "utf8")); } catch {}
check(r.status === 0 && rep && rep.n === 5 && rep.matched === 5, "case 1: n: 5, matched: 5" + (r.status === 0 ? "" : "\n" + r.stderr));

const noexec = path.join(tmp, "not-executable");
fs.writeFileSync(noexec, "just text, not a program\n", { mode: 0o644 });
out = path.join(tmp, "out2");
r = run(toPosix(noexec), out);
check(r.status !== 0 && r.stderr.includes("cannot run"), "case 2: non-executable binary stops with 'cannot run'");
check(!fs.existsSync(path.join(out, "difftest_report.json")), "case 2: no report written (no match claimed)");

fs.rmSync(tmp, { recursive: true, force: true });
if (failed) { console.error(failed + " check(s) failed"); process.exit(1); }
console.log("all difftest local-mode checks passed");
