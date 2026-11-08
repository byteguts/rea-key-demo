// Printable strings (>= 6 characters) of a file, numbered; the first line is their count.
// Usage: node pipeline/strings.mjs target/syncd
import fs from "node:fs";
const b = fs.readFileSync(process.argv[2]); const out = []; let cur = "";
for (const x of b) { if (x >= 0x20 && x < 0x7f) cur += String.fromCharCode(x); else { if (cur.length >= 6) out.push(cur); cur = ""; } }
if (cur.length >= 6) out.push(cur);
console.log(out.length); out.forEach((s, i) => console.log(i + 1, s));
