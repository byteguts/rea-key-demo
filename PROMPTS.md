# Prompts used in the video

These are the exact prompts of our recorded English runs (plain and protected), word for word.
The only change: the path. Replace `<path>` with the absolute path of the folder that holds your copy of `syncd`
(e.g. `/home/you/syncd-plain` in README step 4, or `/home/you/syncd-protected` in step 8; run `pwd` in that folder).
In our runs it was a folder on the Linux machine that ran REA.
We added no hints or extra sentences in any recorded run (in protected attempt 1, Claude Code inserted its own notice after the safety-classifier flag; see README section 10).

## Prompt 1 (explain)

> Use REA to open the binary &lt;path&gt;/syncd. It's a stripped Linux program and its source code has been lost. Explain step by step what its sign command does, and show me the evidence.

## Prompt 2 (rebuild)

> Now write a TypeScript file signer.ts in the current directory that exports makeToken(method: string, path: string, ts: string, body: string, signingKey: string): string and produces exactly the same token as syncd sign. Take the key as a parameter, don't hardcode it. Use only Node built-in modules.
