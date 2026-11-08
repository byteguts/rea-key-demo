# Reverse-engineer a binary with REA and Claude Code (and keep your secrets out of the answer)

Companion repo for the Byteguts video about **REA ("Reverse Engineer Anything")**, an open-source MCP server for reverse engineering.
You will follow the same steps as in the video, on a small program we wrote for this purpose.

Video: (link coming with the release)

Byteguts is not affiliated with Anthropic or with the REA project.

## 1. What you will do

`syncd` is a stripped Linux program whose source code is "lost". It signs requests
with a custom algorithm and a secret key. You will:

1. install REA and connect it to Claude Code;
2. ask the agent to explain how `syncd sign` works (Prompt 1);
3. ask it to rebuild the signer in TypeScript (Prompt 2);
4. check the result against the original binary on 10,000 requests;
5. see that the agent's answer contained the signing key in clear text;
6. repeat the run behind a small masking proxy and see what that does and does not buy you.

Everything in the repo is fake and written by us: `syncd`, its key and its other "secrets".
Secret scanners may flag these strings; they are not real credentials.

## 2. Requirements

- An x86-64 Linux machine, or Windows with WSL. The `syncd` binary is a Linux x86-64 ELF: REA's Ghidra provider on Windows accepts only PE files, and the check in step 6 runs the binary. On a Mac, use an x86-64 Linux machine or VM (on Apple Silicon, one with x86-64 emulation). On Windows, install and run Node, Claude Code, REA and the check inside WSL, not in PowerShell.
- On Linux, a procps-compatible `ps` on the `PATH` (REA needs it for Ghidra).
- Node.js 22.23.4+ or 24.22.1+ (what `rea-agents@6.8.0` accepts: `^22.23.4 || ^24.22.1 || >=26.12.1`). We used Node 24.22.2 on the Linux machine.
- Claude Code, logged in (a paid Claude plan or an API account).
- Ghidra 12.1.x and a full JDK 21+, installed by you. REA does not install them; `setup` only detects them (set `GHIDRA_INSTALL_DIR` and `JAVA_HOME` if it does not).
- `git` and `bash` (the check in step 6 runs the binary through `bash`). Optional: `python3` for the secret-list generator in step 8, `gcc` and `make` to rebuild `syncd`.
- Install REA only from the **official** npm package `rea-agents` (maintainer `morluto`, source github.com/morluto/rea, site rea.tools), and pin the version as below.

## 3. Install REA

```bash
npx rea-agents@6.8.0 setup
```

Pick **Claude Code**, read the plan the setup prints (it shows which config file it will change and which skill it installs), confirm, and **restart Claude Code**.
`6.8.0` is the version we recorded with; without the version you get the newest one, whose tools and output may differ.
Without a terminal to confirm in (a script, CI), `setup` stops with `status: needs_confirmation`; add `--client claude_code --yes` to apply the plan.
Our run printed `status: ready`, `appliedActions[2]: configured_claude_code,installed_skill`: it added the `rea` entry (`npx -y rea-agents@6.8.0 mcp`, with `GHIDRA_INSTALL_DIR` and `JAVA_HOME`) to `~/.claude.json` and installed the skill `~/.claude/skills/reverse-engineer-anything`.

## 4. Get the binary

Clone this repo and use the binary from it:

```bash
git clone https://github.com/byteguts/rea-key-demo.git && cd rea-key-demo
sha256sum target/syncd
# a85a6a616817037a20f23569ce554e54f89013ffa0f907ebc226a41d760cc106
chmod +x target/syncd
```

Step 6 runs this binary on your machine. If you would rather not run a downloaded binary, do the whole demo in a VM or WSL, or build it yourself from `target/syncd.c`:
`make -C target -B` (this overwrites `target/syncd`). Ours was built with gcc 11.4.0 on Ubuntu 22.04. A different compiler gives a different binary,
so the hash will differ (and so may the addresses the agent reports). The results below are for the binary with the hash above.

Run the agent in an empty folder **outside** the repo, with only a copy of the binary, so that `signer.ts` lands there:

```bash
mkdir -p ../syncd-plain && cp target/syncd ../syncd-plain/
cd ../syncd-plain
claude
```

Do not run the agent inside the repo: `target/syncd.c` and `pipeline/03_detect_redact.py` hold the key and the other secrets in clear text, and README/PROMPTS describe the algorithm. An agent that reads them (with your approval, or with tools you allowed) no longer works from the binary alone. Our recorded sessions ran in folders where nothing of the repo was reachable.

## 5. Prompt 1 and Prompt 2

Give the agent these two prompts, one after the other (also in [`PROMPTS.md`](PROMPTS.md)).
Replace `<path>` with the absolute path of the folder you created (e.g. `/home/you/syncd-plain`; run `pwd` in that folder).

Prompt 1:

> Use REA to open the binary &lt;path&gt;/syncd. It's a stripped Linux program and its source code has been lost. Explain step by step what its sign command does, and show me the evidence.

Prompt 2:

> Now write a TypeScript file signer.ts in the current directory that exports makeToken(method: string, path: string, ts: string, body: string, signingKey: string): string and produces exactly the same token as syncd sign. Take the key as a parameter, don't hardcode it. Use only Node built-in modules.

Claude Code asks for permission before it uses an REA tool or writes a file. In our recorded plain run (non-interactive, REA tools allowed in advance), Prompt 1 took about 3 minutes and Prompt 2 about 1.5 minutes. Yours will differ, and your agent will write somewhat different code; that is what the check is for.

## 6. Check

**Read `signer.ts` before you run the check.** It is code written by an AI, and `05_difftest.mjs` imports and executes it with your user's rights. Ideally run the check in the same VM or WSL as the analysis.

Go back to the repo root (the paths below are relative to it), copy the agent's `signer.ts` to where the test reads it (`work/signer.ts`), then run the check:

```bash
cd ../rea-key-demo   # back to the repo root
mkdir -p work && cp ../syncd-plain/signer.ts work/signer.ts
REA_LOCAL_BIN=target/syncd node pipeline/05_difftest.mjs --archive work/signer.ts out/
```

It signs 10,000 deterministic requests with the original binary and with your `signer.ts` (the real key is injected by the test, not by the agent) and compares the tokens.
If the binary cannot run on your machine, the script stops with a message; it never reports matches it did not check.
Set `DIFF_N=1000` for a quicker run. The test uses one key and short ASCII inputs, so it shows that the tokens match for this key, not that every edge case is covered.
The check loads `signer.ts` with Node's built-in TypeScript type stripping; if it fails on syntax such as `enum`, run it with `node --experimental-transform-types`.

Our plain run: **10,000 / 10,000** identical tokens. One example: `syncd sign POST /v1/orders 1730000000 '{"qty":1}'` prints `abf83bed078fc221`, and `makeToken` from the agent's file prints the same.

## 7. Where the key went

Look at the answer to Prompt 1. In our plain run it contained the signing key in clear text (the value is replaced here):

> The key is the hardcoded string `"<the signing key, in clear text>"` (29 bytes, at `0x1020a0`).

It appeared twice in that answer, and once more in the test command the agent suggested after Prompt 2. The agent also printed the hash seed (the first 4 bytes of the key, as a number) and put that number in `signer.ts`.
And not only the key: REA's answers carried all seven secrets in the binary to the model. These are the signing key, the API key, the internal host name, the database connection string, and the database user, password and host inside it.

That is the problem. Whatever the tools show the agent ends up in the model's context, in the session history on your disk and in the files the agent writes.
With a real binary, you would have to treat those credentials as exposed.

## 8. Protect it

Idea: put a small proxy between Claude Code and REA. The proxy replaces every secret you listed with a mask (`[REDACTED_SIGNING_KEY]`, `[REDACTED_SECRET_BYTES:4]`) before the answer reaches the agent. It matches the full secret as plain text (also JSON-escaped), distinctive text fragments of it, hex byte runs (any spacing, either byte order), 32/64-bit constants in hex or decimal, and base64. It does not match everything; see "Honest limits". It also lists only 9 REA analysis tools, none of which runs the program (REA does not mark them read-only).

1. **List the secrets.** The proxy needs them as a file `secrets.json`, outside the repo and outside the agent's folder (e.g. `~/rea-secrets/secrets.json`). By hand: copy `secrets.example.json` to that location and add one entry per secret you know about. For `syncd` these are the 7 secrets from step 7: 6 are constants in `target/syncd.c`, and the database host exists only inside the connection string, so give it its own entry. To see the candidates, list the printable strings of the binary: `node pipeline/strings.mjs target/syncd`. Or generate the list from what REA finds: `GHIDRA_INSTALL_DIR=/path/to/ghidra JAVA_HOME=/path/to/jdk bash pipeline/01_extract.sh` (it runs REA via `npx -y rea-agents@6.8.0`), then `python3 pipeline/03_detect_redact.py`, which writes `out/secrets_raw.json` (the 7 entries, format `{value,type,opaque}`) and a masked found-vs-missed summary `out/secret_inventory.json`; move `secrets_raw.json` to that location as `secrets.json`. The seed need not be listed: in hex, numeric and base64 form the proxy masks every 4-byte window of every secret, so the seed (the first 4 bytes of the key, as a number) is covered by the key itself. A malformed or missing file stops the proxy (exit 2); an empty list `[]` starts it as a pass-through with a warning.
2. **Keep the secrets and the source out of the agent's reach.** `secrets.json`, `target/syncd.c` and `pipeline/03_detect_redact.py` all hold the secrets in clear text. Keep `secrets.json` outside the repo (it is in `.gitignore`, but do not commit it anyway). Run the protected session in a new folder outside the repo too, with only a copy of `target/syncd`, so nothing from the repo is reachable. From the repo root:

   ```bash
   mkdir -p ../syncd-protected && cp target/syncd ../syncd-protected/
   ```
3. **Point Claude Code at the proxy instead of REA.** Take `mcp.proxy.example.json`, fill in absolute paths and replace the `rea` entry in your Claude Code MCP config. The proxy starts REA itself (local mode) with `REA_BACKEND_CMD`, a JSON array with the REA start command: `["npx","-y","rea-agents@6.8.0","mcp"]`. It is the command `npx rea-agents@6.8.0 setup` writes for Claude Code, and also the proxy's default. Copy `GHIDRA_INSTALL_DIR` and `JAVA_HOME` from the `env` of the `rea` entry that setup wrote into the proxy entry too: REA needs them to find Ghidra. Restart Claude Code. (Local mode is meant for Linux/WSL. On native Windows, `npx` must be given as `npx.cmd` or as the full path of `node.exe`.)
4. **Take the other channels away.** The proxy only filters REA's answers. Claude Code's own tools (the shell, file reading, web fetch) go around it: an agent with a shell can read the binary, `syncd.c` or `secrets.json` directly. Deny them in Claude Code's permission settings. Our protected run allowed only the 9 REA tools for Prompt 1 (`--tools ""`), and for Prompt 2 the same 9 REA tools plus `Write`, `Edit` and `Read` (inside the working folder), so it could save `signer.ts`; `Bash`, `PowerShell`, `WebFetch`, `WebSearch`, `Glob`, `Grep` and reading outside the folder were denied. To do the same, create `.claude/settings.json` in the protected folder with the absolute path of your clone and of your secrets folder:

   ```json
   {"permissions":{"deny":["Bash","PowerShell","WebFetch","WebSearch","Glob","Grep","NotebookEdit","Task","Agent","Read(//ABSOLUTE/PATH/TO/rea-key-demo/**)","Read(~/rea-secrets/**)"]}}
   ```

   and start Claude Code there with `claude --tools "Write,Edit,Read"` (the REA tools still come from the proxy). Do not deny `Read(~/**)` if the protected folder is under your home directory: that would also block the agent's own folder.
5. **Run Prompt 1 and Prompt 2 again** in that folder.

What happened in our protected run:

- The agent rebuilt the whole algorithm without seeing the key. Our own leak scanner (separate from the proxy's code; not included here) checked everything that reached the model, the agent's answers, the session history and `signer.ts`, and found **0** occurrences of the 7 secrets (full values, longer fragments, hex bytes, 32-bit constants, base64). In the same scan the plain run had all 7, the signing key 8 times in full. The scanner does not look for single bytes; one did get through, see "Honest limits".
- But it could not know the 4-byte hash seed (the proxy masked it), so it did not guess it: `makeToken` takes the seed as an optional 6th argument, or reads it from the env variable `SYNCD_SIGN_SEED`, and throws if neither is set. Without the seed the check stops with that error (no tokens).
- You supply the seed **locally**, and the check passes. In `syncd` the seed is simply the first 4 bytes of the key, read little-endian. Read the protected run's `signer.ts` first, as in step 6. Then, from the repo root, copy it to where the test reads it (this replaces the plain run's file) and, with the key in `target/syncd.c`, run:

```bash
mkdir -p work && cp ../syncd-protected/signer.ts work/signer.ts
export SYNCD_SIGN_SEED=$(node -e 'const m=require("fs").readFileSync("target/syncd.c","utf8").match(/SIGN_KEY\[\]\s*=\s*"([^"]+)"/);console.log("0x"+Buffer.from(m[1]).readUInt32LE(0).toString(16))')
REA_LOCAL_BIN=target/syncd node pipeline/05_difftest.mjs --archive work/signer.ts out/
```

  Result: **10,000 / 10,000**. (How the seed goes in depends on what your agent wrote; ours accepted `SYNCD_SIGN_SEED` as a 32-bit number such as `0x1a2b3c4d`. Set it only in the shell where you run the check, not where the agent runs.)

So the protected result is: the agent understands and rebuilds the logic, the secret values do not reach it, and you plug the values in yourself. It is not "the agent wrote a finished tool with no input from you".

## 9. Honest limits

- Masking hides **only what you listed or found**. A secret you did not know about is not masked.
- It hides **4-byte and longer pieces in hex, numeric and base64 form**, plus the full value and distinctive text fragments (5 or more characters with a digit and punctuation). Single bytes, decimal or character arrays (`83, 51, 99` or `'S','3','c'`) and short or digit-less text fragments get through. In our protected run REA's disassembly still showed the first key character as an instruction operand (`MOV EAX, 0x72`). Values computed from a secret (for example the shuffled table) are not masked either.
- It masks **answers, not questions**. Search tools (strings, byte search) can still confirm a guess: an agent that guesses a value can test whether it occurs in the binary.
- It guards **only the REA channel**. See step 8.4: deny the agent's own shell and file tools, or it can read the secrets directly.
- The proxy shows 9 tools, but it forwards any tool call it receives. The list is not a lock; the permission settings are.
- When it answers the prompts, the agent may **run the binary** (several REA tools can execute a program, e.g. `capture_process_scenario` and the gdb/Frida debug sessions). Allow that only for code you are allowed to analyse, ideally in an isolated virtual machine without access to your network and credentials.
- REA is **not a sandbox**. A malicious binary can contain text that an agent treats as an instruction, and the agent's `signer.ts` then runs in step 6. Analyse only what you trust, and read the code before you run it.
- Install REA only from the official npm package and pin the version (see `ATTRIBUTIONS.md`).
- The numbers above are for **this binary**, this model and these prompts. A real program will be harder, and the agent may be wrong. Always run a check like step 6.
- Legal: reverse-engineer only software you own or have explicit permission to analyse, and send code to a model provider only when you are allowed to. Laws differ by country. Do not use this against DRM, license checks or other people's software. This is not legal advice.

## 10. How we recorded it

- Claude Code 2.1.319, model Opus 5.5 (`claude-opus-5-5`), non-interactive (`claude -p`, stream-json), on a Windows PC, logged in to a Claude subscription (no API key).
- Clean session: a new folder outside any repo, no CLAUDE.md, user settings not loaded (`--setting-sources project`), auto-memory off, no hooks, no plugins beyond Claude Code's built-in ones, only the REA MCP server (`--strict-mcp-config`). The REA skill that setup installs was present in the session (setup ran on the Linux machine, so we copied the skill into the project's `.claude/skills`).
- REA and Ghidra ran on a separate Linux machine (Claude Code on Windows cannot use REA's Ghidra provider for an ELF file). Claude Code reached REA over `ssh`, through a short launcher script on that machine that exports `GHIDRA_INSTALL_DIR` and `JAVA_HOME` and runs exactly the command setup registered (`exec npx -y rea-agents@6.8.0 mcp`). `setup` itself ran on that Linux machine. For the protected run the proxy ran on the Windows machine in remote mode (`REA_SSH_TARGET`, `REA_REMOTE_LAUNCHER`, see `config.example.sh`).
- Plain run: REA tools allowed in advance (`--allowedTools mcp__rea`, plus `Write Edit Read` for Prompt 2); anything else that needs permission was refused, because nobody was there to approve it. That is why the agent did not run its own code.
- Protected run: in the first attempt, Opus 5.5's safety classifier flagged the session on its first response (category "cyber"), and Claude Code answered the rest of Prompt 1 with Opus 4.8 instead. That answer had two mistakes (it called the byte substitution an RC4 keystream and gave a wrong multiplier), which the Opus 5.5 answer to Prompt 2 corrected. A test question about the tool list in the same setup was also answered by Opus 4.8, so the flag was not caused by the reverse-engineering prompt alone. We repeated the run unchanged; the second attempt ran entirely on Opus 5.5, and that is the run described above. Both attempts kept the secrets out (0 in the scan), and both `signer.ts` files pass the check with the seed supplied locally.
- The check (`05_difftest.mjs`) ran on the Linux machine, in a copy of this repo, with the commands in steps 6 and 8, with each run's `signer.ts` copied to `work/signer.ts` first.

Licenses and third-party notes: `LICENSE`, `ATTRIBUTIONS.md`. Claude and Claude Code are trademarks of Anthropic.
