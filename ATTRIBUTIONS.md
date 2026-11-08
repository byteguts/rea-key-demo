# Attributions

This demo uses several independent open-source projects. It does not include
their code; install each from its official source.

| Tool | Role | License | Source |
|------|------|---------|--------|
| REA ("Reverse Engineer Anything") | MCP server + CLI that drives the analysis engines | MIT | https://github.com/morluto/rea (npm: `rea-agents`) |
| Ghidra | Decompiler/disassembler that REA drives (its Ghidra provider) | Apache-2.0 | https://github.com/NationalSecurityAgency/ghidra |
| Eclipse Temurin (OpenJDK 21) | Java runtime for Ghidra (any full JDK 21+ works; we used Temurin 21.0.13) | GPL-2.0 with Classpath Exception | https://adoptium.net |

## REA tool metadata

`pipeline/rea_initialize_snapshot.json` and `pipeline/rea_tools_snapshot.json`
contain server information and tool metadata (names, descriptions, schemas)
copied from rea-agents 6.8.0. The proxy serves them during the MCP handshake.
They are used under REA's MIT License:

```
MIT License

Copyright (c) 2026 morluto

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Not included

The agent's reconstructed `signer.ts` is deliberately not shipped in this repo:
a finished solution next to the binary would let an agent copy it instead of
analysing the binary.

## Installing REA

Install REA only from the official npm package `rea-agents` (maintainer
`morluto`, source github.com/morluto/rea, site rea.tools), and pin the version
(`rea-agents@6.8.0` is the one we recorded with). As REA's own README notes, a
similar name or a copied README does not make a download official.
