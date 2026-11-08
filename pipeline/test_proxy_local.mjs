#!/usr/bin/env node
// Tests the proxy's local backend mode (REA_BACKEND_CMD). Plain node, exit 1 on failure.
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const PROXY = path.join(HERE, "rea_redact_proxy.mjs");
const FAKE = path.join(HERE, "fake_mcp_backend.mjs");
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "proxy-local-"));
let failed = 0;
const check = (ok, msg) => { console.log((ok ? "PASS " : "FAIL ") + msg); if (!ok) failed++; };

function runProxy(secretsJson, backendPath, secretsPath) {
  const sf = secretsPath || path.join(tmp, "secrets.json");
  if (!secretsPath) fs.writeFileSync(sf, secretsJson);
  const env = { ...process.env, SECRETS_FILE: sf, REA_BACKEND_CMD: JSON.stringify([process.execPath, backendPath]) };
  delete env.REA_SSH_TARGET; delete env.REA_REMOTE_LAUNCHER;
  return new Promise((resolve) => {
    const p = spawn(process.execPath, [PROXY], { env, stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "", stderr = "", done = false, code = null;
    const finish = (timedOut) => {
      if (done) return; done = true; clearTimeout(timer);
      p.kill(); resolve({ stdout, stderr, timedOut, code });
    };
    const timer = setTimeout(() => finish(true), 10000);
    p.stdout.on("data", (d) => { stdout += d; if (stdout.split("\n").some((l) => { try { return JSON.parse(l).id === 2; } catch { return false; } })) finish(false); });
    p.stderr.on("data", (d) => { stderr += d; });
    p.on("exit", (c) => { code = c; finish(false); });
    p.stdin.write(JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "t", version: "1" } } }) + "\n");
    p.stdin.write(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) + "\n");
    p.stdin.write(JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "read_bytes", arguments: {} } }) + "\n");
  });
}

const SECRET = '[{"value":"r3q-TEST-key-123456","type":"signing_key","opaque":true}]';

let r = await runProxy(SECRET, FAKE);
check(!r.timedOut && r.stdout.includes("[REDACTED_SIGNING_KEY]"), "case 1: secret masked as [REDACTED_SIGNING_KEY]");
check(!r.stdout.includes("r3q-TEST"), "case 1: no raw secret in reply");

r = await runProxy("[]", FAKE);
check(!r.timedOut && r.stdout.includes("r3q-TEST-key-123456"), "case 2: empty secrets list passes data through");
check(r.stderr.includes("no secrets"), "case 2: stderr warns 'no secrets'");

const spaced = path.join(os.tmpdir(), "rea proxy test");
fs.mkdirSync(spaced, { recursive: true });
const spacedFake = path.join(spaced, "fake_mcp_backend.mjs");
fs.copyFileSync(FAKE, spacedFake);
r = await runProxy(SECRET, spacedFake);
check(!r.timedOut && r.stdout.includes("[REDACTED_SIGNING_KEY]"), "case 3: backend path with a space still answers");

r = await runProxy('{"value":"x"}', FAKE);
check(r.code === 2, "case 4: non-array SECRETS_FILE exits with code 2 (got " + r.code + ")");
check(r.stderr.includes("must be a JSON array"), "case 4: stderr says 'must be a JSON array'");
check(r.stdout.trim() === "", "case 4: no reply forwarded");

r = await runProxy('[{"type":"signing_key"}]', FAKE);
check(r.code === 2 && r.stderr.includes("must be a JSON array"), "case 5: entry without string value exits with code 2");

r = await runProxy('[{"value":"r3q-TEST-key-123456", oops', FAKE);
check(r.code === 2 && r.stderr.includes("cannot read SECRETS_FILE"), "case 6: invalid JSON in SECRETS_FILE exits with code 2 (got " + r.code + ")");
check(!r.stderr.includes("r3q-TEST") && !r.stderr.includes("    at "), "case 6: no file content and no stack trace on stderr");
check(r.stdout.trim() === "", "case 6: no reply forwarded");

r = await runProxy("[]", FAKE, path.join(tmp, "does-not-exist.json"));
check(r.code === 2 && r.stderr.includes("cannot read SECRETS_FILE"), "case 7: missing SECRETS_FILE exits with code 2 (got " + r.code + ")");

fs.rmSync(tmp, { recursive: true, force: true });
fs.rmSync(spaced, { recursive: true, force: true });
if (failed) { console.error(failed + " check(s) failed"); process.exit(1); }
console.log("all proxy local-mode checks passed");
