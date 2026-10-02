# SecureComm — Claude as orchestrator, Codex as implementer

Project rules for both agents are in `AGENTS.md` (Codex reads it automatically). This file adds how Claude delegates.

## Roles
- **Claude (this session)**: understands the request, splits it into well-specified tasks, delegates implementation to Codex,
  reviews the diff, runs the checks, and reports. Claude implements directly only trivial edits (a few lines) or when Codex fails twice.
- **Codex**: implements one task at a time in this working tree.

## How to delegate (official plugin `codex@openai-codex`)
```
node ~/.claude/plugins/cache/openai-codex/codex/1.0.6/scripts/codex-companion.mjs task --write --model gpt-6.1-sol --effort medium "<task>"
```
- Long tasks: add `--background`, then `... status` / `... result` (or `/codex:status`, `/codex:result`).
- Correction round: same command with `--resume-last` and the concrete failing output (max 1–2 rounds, same session).
- Model choice (measured 2026-10): **gpt-6.1-sol medium** by default; `gpt-6-luna` only for mechanical edits with an exact spec;
  `gpt-6-astra` for crypto/security-critical code. Never `xhigh`. Always pass `--model`/`--effort` (the global Codex default is a different model).
- Keep the plugin's stop review gate OFF (it burns quota).

## Speed rules (Claude + Codex as one team)
- **Split the work by strength.** Claude does the cheap, fast parts: read/locate code, decide the plan, write a precise brief
  with a file map, review, run tests. Codex only writes the code. A brief with the exact files cuts Codex exploration (its slowest part).
- **Never wait idle.** Send Codex tasks with `--background`; while it runs, prepare the next brief, read related code or tests.
- **Parallel when independent.** Independent tasks go to separate git worktrees, one Codex task each (`git worktree add ../SecureComm-<task>`),
  then Claude merges/reviews.
- **Same thread for chained work.** Follow-ups on the same feature use `--resume-last` (keeps Codex context and cache); unrelated work uses `--fresh`.
- **Right size.** Edits of a few lines: Claude does them directly. Mechanical edits with an exact spec: `--model gpt-6-luna`.
- **Fast checks first.** Run only the tests related to the change (e.g. `pytest <path>`, `vitest related <files>`), full suite once at the end.
- Overhead measured 2026-10-02: first plugin call in a session ~19 s (starts a shared Codex runtime), next calls ~7–9 s.

## Task brief template (what Claude sends)
1. Goal and the exact behaviour required (inputs → outputs, errors), referencing `docs/web-private-contract.md` when relevant.
2. Files/modules likely involved (short map).
3. Acceptance: the commands that must pass (e.g. `.venv/Scripts/python -m pytest -q`, `npm test` in `web/`), and any new test to add.
4. Constraints: follow `AGENTS.md`; no new dependencies without saying so; no destructive git (`reset --hard`, `clean`, `checkout --`, force push); do not commit.
5. JEV: "Use the JEV MCP (`jev_*` tools) at decision points: `jev_decide` for bounded implementation choices, `jev_verify` for claims
   about code behaviour against excerpts, `jev_review` on your patch, `jev_gate` before reporting done. Run deterministic checks
   (tests/typecheck) first; JEV is advisory only. Send only minimal sanitized code snippets — never secrets, keys, vault/session
   material, personal data or conversation contents. Do not retry unchanged input. At the end, list each JEV call: tool, question,
   verdict, whether it agreed with the tests, tokens reported."
   Claude also runs one `jev_gate` on the final diff + test output before reporting to the user.

## After Codex finishes (Claude, every time)
1. Read the diff (`git diff`) — scope matches the task, no unrelated edits, no weakened/skipped tests.
2. Run the acceptance commands myself (build/typecheck + the repo's tests; related tests first for speed).
3. If something fails: one correction round with the real failing output; if it still fails, fix it myself or report.
4. Report to the user: what changed, test output, anything left open. Commit only when the user asks.
