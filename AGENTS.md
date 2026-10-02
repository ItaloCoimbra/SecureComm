# Working on SecureComm

## CodeGraph

When `.codegraph/` exists, use `codegraph_explore` with this project's absolute
path or `codegraph explore` before searching or reading source to understand a
module or prepare an edit. Reuse the source returned by the graph. After source
changes, run `codegraph sync` and verify its status. Keep the local database out
of Git. If the index is absent, do not create it without the user's authorization.

## JEV

Use JEV proactively when an independent semantic review can help with a
non-trivial choice, triage, evidence check, or patch review. Gather source and
test evidence first. Use `jev_decide` for bounded alternatives, `jev_verify` for
claims, and `jev_gate` for a patch plus completion claims. Batch related questions
and send only the smallest sanitized excerpts needed. Never send credentials,
private keys, conversation contents, or personal/customer data.

Consider JEV during task triage and before reporting consequential changes
complete. One call per unchanged input is enough; deterministic checks do not
need semantic approval. JEV is advisory: it cannot authorize work, replace tests,
or prove security. Investigate disagreements, and disclose unavailability or
inconclusive results instead of presenting them as successful verification.

## Project constraints

- The current product direction is `docs/web-private-contract.md`: a browser
  messenger with independent per-contact identity, one-time invitations and no
  application recovery/backup/synchronization. The historical Python CLI uses a
  different global-identity protocol and must never be wired into the web flow.
- Browser state, Olm pickles and attachment keys stay on clients. Build all
  scripts/WASM/fonts locally; no CDNs, analytics or external asset requests.
- Do not promise zero network correlation, remote destruction of recipient
  copies, protection from malicious delivered JavaScript, or forensic erasure.
- This is an experimental E2EE CLI, not an audited production messenger. Default
  entrypoints use client-side Olm and opaque relays; never restore legacy broadcast.
- Keep private account/session material exclusively in client vaults. Keep
  transport encryption distinct from conversation encryption and identity trust.
- Do not invent or replace the cryptographic protocol as a routine refactor.
  Record protocol/product choices and their assumptions before implementation.
- Use an isolated `.venv`; never install into an unrelated global environment.
- Run automated tests, not `__main__` examples, as the default verification.
  Examples may start listeners, log plaintext, or expose ephemeral demo keys.
- Tests and demonstrations must use temporary paths and synthetic data. Do not
  load the tracked `.joblib` files in tests or overwrite the tracked models/CSV.
- Keep ML and legacy log-chain experiments separate from claims of confidentiality.
- External connections/listeners require verified TLS with endpoint binding;
  plaintext transport is restricted to loopback development. TLS is not E2EE.
- Never ACK a message whose durable local persistence failed. Keep text and
  receipt capacity separate, and preserve exact ciphertext across retries.
- Do not discard published private prekeys to reclaim capacity: offline messages
  may depend on them. Expose exhaustion and maintain the documented limits.
- Preserve existing changes and coordinate file ownership when working in parallel.
