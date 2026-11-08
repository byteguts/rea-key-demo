#!/usr/bin/env node
/*
 * Minimal MCP probe client (newline-delimited JSON-RPC over stdio).
 * Spawns a server command, then sends initialize, notifications/initialized,
 * tools/list, optional setup calls (--before) and one tools/call, and prints one JSON object:
 *   { serverInfo, toolCount, tools: string[], beforeResults?, callResult }
 *
 * node pipeline/mcp_probe.mjs --cmd '["npx","-y","rea-agents@6.8.0","mcp"]' --call tool_name --args '{}' [--out file.json]
 *   [--before '[{"name":"open_binary","arguments":{"path":"/abs/target/syncd"}}]']
 * --before: tool calls made first, in order (e.g. open a binary, then search it).
 * Env: PROBE_TIMEOUT_MS (default 60000, per response).
 * Exit: 0 ok, 3 no initialize response in time, 4 later response missing/failed, 2 bad usage.
 */
import { spawn } from "node:child_process";
import { writeFileSync } from "node:fs";
import readline from "node:readline";

const argv = process.argv.slice(2);
const opt = (n) => { const i = argv.indexOf("--" + n); return i >= 0 ? argv[i + 1] : undefined; };
let cmd, args, before;
try {
  cmd = JSON.parse(opt("cmd") ?? "null");
  args = JSON.parse(opt("args") ?? "{}");
  before = JSON.parse(opt("before") ?? "[]");
  if (!Array.isArray(before) || !before.every((c) => c && typeof c.name === "string")) throw new Error("--before must be a JSON array of {name, arguments}");
  if (!Array.isArray(cmd) || !cmd.length || !cmd.every((x) => typeof x === "string")) throw new Error("--cmd must be a non-empty JSON array of strings");
} catch (e) {
  console.error("mcp_probe: " + e.message);
  process.exit(2);
}
const tool = opt("call");
if (!tool) { console.error("mcp_probe: missing --call"); process.exit(2); }
const outFile = opt("out");
const TIMEOUT = Number(process.env.PROBE_TIMEOUT_MS) || 60000;

const child = spawn(cmd[0], cmd.slice(1), { stdio: ["pipe", "pipe", "inherit"] });
child.on("error", (e) => { console.error("mcp_probe: cannot start: " + e.message); process.exit(4); });
const waiting = new Map();
readline.createInterface({ input: child.stdout }).on("line", (line) => {
  let m; try { m = JSON.parse(line); } catch { return; }
  if (m.id !== undefined && waiting.has(m.id)) { waiting.get(m.id)(m); waiting.delete(m.id); }
});
const send = (o) => child.stdin.write(JSON.stringify({ jsonrpc: "2.0", ...o }) + "\n");
const request = (id, method, params) => new Promise((resolve, reject) => {
  const t = setTimeout(() => { waiting.delete(id); reject(new Error("timeout waiting for " + method)); }, TIMEOUT);
  waiting.set(id, (m) => { clearTimeout(t); resolve(m); });
  send({ id, method, params });
});
const finish = (code) => { try { child.kill(); } catch {} process.exit(code); };

let init;
try {
  init = await request(1, "initialize", { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "mcp_probe", version: "1" } });
} catch (e) { console.error("mcp_probe: " + e.message); finish(3); }
try {
  if (init.error) throw new Error("initialize error: " + JSON.stringify(init.error));
  send({ method: "notifications/initialized" });
  const list = await request(2, "tools/list", {});
  if (list.error) throw new Error("tools/list error: " + JSON.stringify(list.error));
  let id = 3;
  const beforeResults = [];
  for (const c of before) {
    const r = await request(id++, "tools/call", { name: c.name, arguments: c.arguments ?? {} });
    beforeResults.push({ name: c.name, result: r.error ? { error: r.error } : r.result });
  }
  const call = await request(id++, "tools/call", { name: tool, arguments: args });
  const tools = (list.result?.tools ?? []).map((t) => t.name);
  const result = { serverInfo: init.result?.serverInfo, toolCount: tools.length, tools, ...(before.length ? { beforeResults } : {}), callResult: call.error ? { error: call.error } : call.result };
  const text = JSON.stringify(result, null, 2);
  if (outFile) writeFileSync(outFile, text + "\n");
  console.log(text);
  finish(0);
} catch (e) { console.error("mcp_probe: " + e.message); finish(4); }
