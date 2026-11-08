#!/usr/bin/env node
/*
 * Redacting MCP proxy for the REA demo (fast handshake).
 *
 * Runs LOCALLY. Answers the MCP handshake (initialize + tools/list) INSTANTLY
 * from a cached snapshot, so an MCP client's short connect timeout never races the
 * slow REA-over-ssh catalog. The real REA MCP server is spawned lazily on the
 * first tools/call and handshaked behind the scenes.
 *
 * Every message coming back from REA is scrubbed by the shared redaction core
 * (redact.mjs): the full secret as text (also JSON-escaped), distinctive text
 * fragments, hex byte runs (any separators, BE/LE), 32/64-bit numeric constants
 * (hex/dec, BE/LE) and base64. Single bytes, decimal or character arrays, short
 * text fragments and values computed from a secret are NOT masked. The proxy
 * guards only the REA channel; the client's own tools go around it.
 * REA tool outputSchemas are dropped so a masked (non-hex) value is never
 * rejected by the client's schema validation.
 *
 * Secrets come from a host-side file, never from Claude. Config via env:
 *   SECRETS_FILE (required), [PROXY_LOG]
 * Backend selection:
 *   remote: REA_SSH_TARGET and REA_REMOTE_LAUNCHER both set -> ssh <target> bash <launcher>
 *   local:  otherwise REA_BACKEND_CMD, a JSON array; default ["npx","-y","rea-agents@6.8.0","mcp"]
 *           (the command `rea-agents@6.8.0 setup` writes for Claude Code). JSON keeps arguments
 *           with spaces intact (e.g. C:\Program Files\nodejs\node.exe). REA needs
 *           GHIDRA_INSTALL_DIR and JAVA_HOME in the proxy's environment.
 * An empty secrets list starts anyway and passes data through unmasked (stderr warning).
 */
import { spawn } from "node:child_process";
import { readFileSync, appendFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import readline from "node:readline";
import { buildContext, redactText } from "./redact.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SSH_TARGET = process.env.REA_SSH_TARGET;
const REMOTE_LAUNCHER = process.env.REA_REMOTE_LAUNCHER;
const SECRETS_FILE = process.env.SECRETS_FILE;
const PROXY_LOG = process.env.PROXY_LOG;

if (!SECRETS_FILE) {
  console.error("rea_redact_proxy: missing env (SECRETS_FILE)");
  process.exit(2);
}
const REMOTE_MODE = Boolean(SSH_TARGET && REMOTE_LAUNCHER);
// Default = the command `rea-agents setup --client claude_code` writes (verified on a real install).
const DEFAULT_BACKEND_CMD = ["npx", "-y", "rea-agents@6.8.0", "mcp"];
let BACKEND_CMD = null;
if (!REMOTE_MODE) {
  try {
    BACKEND_CMD = process.env.REA_BACKEND_CMD ? JSON.parse(process.env.REA_BACKEND_CMD) : DEFAULT_BACKEND_CMD;
    if (!Array.isArray(BACKEND_CMD) || BACKEND_CMD.length === 0 || !BACKEND_CMD.every((x) => typeof x === "string")) throw new Error("not a non-empty string array");
  } catch (e) {
    console.error("rea_redact_proxy: REA_BACKEND_CMD must be a JSON array of strings: " + e.message);
    process.exit(2);
  }
}

let secrets;
try {
  secrets = JSON.parse(readFileSync(SECRETS_FILE, "utf8"));
} catch (e) {
  // Only the error kind: a JSON SyntaxError message quotes the file's content.
  console.error("rea_redact_proxy: cannot read SECRETS_FILE as JSON (" + (e.code || e.name) + ")");
  process.exit(2);
}
if (!Array.isArray(secrets) || !secrets.every((e) => e && typeof e.value === "string")) {
  console.error("rea_redact_proxy: SECRETS_FILE must be a JSON array of {value,type,opaque}");
  process.exit(2);
}
if (secrets.length === 0) {
  console.error("rea_redact_proxy: no secrets in SECRETS_FILE, passing through");
}
const ctx = buildContext(secrets);
const initSnapshot = JSON.parse(readFileSync(path.join(HERE, "rea_initialize_snapshot.json"), "utf8"));
const toolsSnapshot = JSON.parse(readFileSync(path.join(HERE, "rea_tools_snapshot.json"), "utf8"));
const log = (s) => { if (PROXY_LOG) { try { appendFileSync(PROXY_LOG, s + "\n"); } catch {} } };

function redact(line) {
  const { out, hits } = redactText(line, ctx);
  for (const [k, n] of Object.entries(hits)) log(`redacted x${n} -> ${k}`);
  return out;
}

const out = (obj) => process.stdout.write(JSON.stringify(obj) + "\n");

// ---- lazy REA backend ---------------------------------------------------
let backend = null;         // child process
let backendReady = false;   // handshake complete
const pending = [];         // client lines queued until backend is ready

function startBackend() {
  if (backend) return;
  const stdio = ["pipe", "pipe", "inherit"];
  backend = REMOTE_MODE
    ? spawn("ssh", [SSH_TARGET, "bash", REMOTE_LAUNCHER], { stdio })
    : spawn(BACKEND_CMD[0], BACKEND_CMD.slice(1), { stdio });
  backend.on("error", (e) => { console.error("rea_redact_proxy: cannot start backend: " + e.message); process.exit(1); });
  backend.on("exit", (code) => process.exit(code ?? 0));
  const brl = readline.createInterface({ input: backend.stdout });
  brl.on("line", (line) => {
    if (!line) return;
    let msg;
    try { msg = JSON.parse(line); } catch { process.stdout.write(redact(line) + "\n"); return; }
    if (msg.id === "_proxy_init") {            // our private handshake reply: consume
      backend.stdin.write(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) + "\n");
      backendReady = true;
      for (const q of pending.splice(0)) backend.stdin.write(q + "\n");
      log("backend ready; flushed " + "queued requests");
      return;
    }
    process.stdout.write(redact(JSON.stringify(msg)) + "\n");  // redact everything REA emits
  });
  // handshake the backend ourselves
  backend.stdin.write(JSON.stringify({
    jsonrpc: "2.0", id: "_proxy_init", method: "initialize",
    params: { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "rea-redact-proxy", version: "1" } },
  }) + "\n");
}

function forwardToBackend(line) {
  startBackend();
  if (backendReady) backend.stdin.write(line + "\n");
  else pending.push(line);
}

// ---- client (MCP client, e.g. Claude Code) side -------------------------------------------
const crl = readline.createInterface({ input: process.stdin });
crl.on("line", (line) => {
  if (!line) return;
  let msg;
  try { msg = JSON.parse(line); } catch { forwardToBackend(line); return; }

  // Serve the handshake instantly from cache; connect REA only when work starts.
  if (msg.method === "initialize") { out({ jsonrpc: "2.0", id: msg.id, result: initSnapshot }); return; }
  if (msg.method === "notifications/initialized") { return; } // ack, nothing to do
  if (msg.method === "tools/list") {
    log(`tools/list served from snapshot (${toolsSnapshot.tools.length} tools)`);
    out({ jsonrpc: "2.0", id: msg.id, result: toolsSnapshot });
    return;
  }
  if (msg.method === "ping") { out({ jsonrpc: "2.0", id: msg.id, result: {} }); return; }
  // tools/call and anything else -> real REA (redacted on the way back)
  forwardToBackend(line);
});

process.on("SIGINT", () => backend?.kill("SIGINT"));
process.on("SIGTERM", () => backend?.kill("SIGTERM"));
