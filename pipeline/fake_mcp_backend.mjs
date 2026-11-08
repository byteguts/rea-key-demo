#!/usr/bin/env node
// Test fixture: minimal MCP stdio backend. Answers initialize, ignores
// notifications, answers every tools/call with text containing a fake secret.
import readline from "node:readline";
const rl = readline.createInterface({ input: process.stdin });
rl.on("line", (line) => {
  if (!line) return;
  let msg;
  try { msg = JSON.parse(line); } catch { return; }
  if (msg.id === undefined || msg.id === null) return; // notification
  if (msg.method === "initialize") {
    process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result: {
      protocolVersion: "2024-11-05", capabilities: { tools: {} },
      serverInfo: { name: "fake-mcp-backend", version: "0" } } }) + "\n");
  } else if (msg.method === "tools/call") {
    process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result: {
      content: [{ type: "text", text: "the key is r3q-TEST-key-123456 end" }] } }) + "\n");
  }
});
