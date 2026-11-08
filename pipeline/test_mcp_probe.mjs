#!/usr/bin/env node
// Tests mcp_probe.mjs against a fake stdio MCP server. Plain node, exit 1 on failure.
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const PROBE = path.join(HERE, "mcp_probe.mjs");
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "mcp-probe-"));
let failed = 0;
const check = (ok, msg) => { console.log((ok ? "PASS " : "FAIL ") + msg); if (!ok) failed++; };

const fake = path.join(tmp, "fake.mjs");
fs.writeFileSync(fake, String.raw`
import readline from "node:readline";
const send = (o) => process.stdout.write(JSON.stringify(o) + "\n");
readline.createInterface({ input: process.stdin }).on("line", (l) => {
  const m = JSON.parse(l);
  if (m.method === "initialize") send({ jsonrpc: "2.0", id: m.id, result: { protocolVersion: "2024-11-05", capabilities: {}, serverInfo: { name: "fake", version: "1" } } });
  else if (m.method === "tools/list") send({ jsonrpc: "2.0", id: m.id, result: { tools: [{ name: "a" }, { name: "b" }] } });
  else if (m.method === "tools/call") send({ jsonrpc: "2.0", id: m.id, result: { content: [{ type: "text", text: m.params.name === "a" ? "ok" : "called " + m.params.name }] } });
});
`);
const silent = path.join(tmp, "silent.mjs");
fs.writeFileSync(silent, `process.stdin.resume(); setInterval(() => {}, 1000);`);

const run = (script, extra = {}) => spawnSync(process.execPath, [PROBE, "--cmd", JSON.stringify([process.execPath, script]), "--call", "a", "--args", "{}"], { encoding: "utf8", env: { ...process.env, ...extra }, timeout: 20000 });

const r = run(fake);
let out = {};
try { out = JSON.parse(r.stdout); } catch {}
check(r.status === 0, "exit code 0");
check(out.serverInfo?.name === "fake", "serverInfo.name === fake");
check(out.toolCount === 2, "toolCount === 2");
check(JSON.stringify(out.tools) === '["a","b"]', "tools lists names");
check(out.callResult?.content?.[0]?.text === "ok", "callResult text is ok");

const outFile = path.join(tmp, "o.json");
spawnSync(process.execPath, [PROBE, "--cmd", JSON.stringify([process.execPath, fake]), "--call", "a", "--args", "{}", "--out", outFile], { encoding: "utf8" });
check(fs.existsSync(outFile) && JSON.parse(fs.readFileSync(outFile, "utf8")).toolCount === 2, "--out writes the result");

const b = spawnSync(process.execPath, [PROBE, "--cmd", JSON.stringify([process.execPath, fake]), "--before", JSON.stringify([{ name: "b", arguments: {} }]), "--call", "a", "--args", "{}"], { encoding: "utf8", timeout: 20000 });
let bo = {};
try { bo = JSON.parse(b.stdout); } catch {}
check(b.status === 0 && bo.beforeResults?.[0]?.result?.content?.[0]?.text === "called b" && bo.callResult?.content?.[0]?.text === "ok", "--before calls run first, then --call");

const s = run(silent, { PROBE_TIMEOUT_MS: "2000" });
check(s.status === 3, "silent server exits 3 (got " + s.status + ")");

fs.rmSync(tmp, { recursive: true, force: true });
process.exit(failed ? 1 : 0);
