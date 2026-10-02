# SecureComm Web: local-only relationships

Status: implementation in progress, 2026-09-26. This supersedes the CLI-only
product direction, not the historical CLI wire format. No production deployment
or independent cryptographic audit is claimed.

## Accepted product requirements

1. Browser messenger, deployable on Linux: text, documents, images, recorded audio.
2. A contact can only be established by an expiring, single-use invitation and
   explicit peer verification. No phone/email directory, global user login or
   automatic identity replacement.
3. Fresh independent Olm account for every relationship. Private state remains
   locally encrypted in the browser. No application backup, export/import,
   synchronization, recovery phrase or server recovery endpoint.
4. Losing the actual local state requires a new invitation and new relationship.
   Losing possession of a device is NOT destruction of its data. Recipient copies,
   OS backups and forensic erasure are outside the application's guarantee.
5. Independent opaque one-way queues with separate read/write capabilities.
   No sender/recipient global identity fields, cookies, analytics, remote fonts
   or external scripts. Users can select independently operated HTTPS relays.
6. Bounded offline retention, durable retry ciphertext, authenticated delivery
   receipts, no network ACK before local persistence, deduplication and safe
   queue rotation confirmed through the existing E2EE relationship.
7. Files and their names/type/keys are encrypted before upload. Media recording,
   previews and decoding run on the client. No server transcoding or scanning.
8. Reduce metadata through fixed-size frames/chunks, per-relationship routing,
   minimal retention, no access logs, and an optional Tor/onion deployment path.
   No claim of zero traffic correlation, anonymity against global observers,
   protection from hostile delivered JavaScript, or guaranteed physical erasure.
9. No blockchain and no new cryptographic ratchet. Existing Python CLI remains
   explicitly separate; its global-identity relay is not used by the web client.

## Crypto decision

Use pinned `@dtelecom/vodozemac-wasm@0.3.0`, a small third-party wrapper of
vodozemac 0.10. Account and Session use standardized Olm v1 (64-bit MAC, not PQ).
Do not silently enable experimental Olm v2. The wrapper's JSON pickles are not
encrypted; encrypt the entire local state using WebCrypto before IndexedDB.
Use a locally generated, non-extractable storage key; deleting the site's data
also loses that key. This is not OS-level key protection or forensic deletion.
Validate actual WASM APIs in automated tests (README examples differ from types).
Authenticate the sender identity returned by inbound-session establishment and
verify the pairing transcript out of band. Never send private keys or pickles to
the relay. Package pinning does not establish binary reproducibility or an audit.

Evidence: upstream wrapper Rust/type declarations, Matrix's February 2026 Olm
security explanation, and current npm metadata. JEV preferred this alternative
over a new local wrapper and a full Matrix adapter; its 0.76-confidence advisory
is not a security approval. Integration tests and independent review are required.

## HTTP relay interface (version 1)

Separate SQLite database, aiohttp adapter. All operations below are POST JSON,
no authentication cookies, tokens in bodies rather than URLs. All IDs and raw
capability tokens are 32 random bytes encoded as 64 lowercase hex characters.
Stored capability hashes are SHA-256 of UTF-8 token text (64 lowercase hex).
No plaintext tokens stored in the database. No identity, prekey or contact table.

- `/v1/queues`: `{read_id, write_id, read_hash, write_hash, ttl, single_use}`.
  Creator generates/persists independent IDs and tokens first. `ttl` 60..2592000
  seconds; default client contact queue 30 days, invitation 10 minutes.
  Repeating an identical creation is idempotent; differing same IDs conflict.
  Returns `{ok:true}`. Single-use admits one unique message, exact retry allowed.
- `/v1/send`: `{write_id, token, id, body}`. `body` is canonical base64 encoding
  exactly 32768 opaque bytes. Returns `{ok:true}`; identical retry is accepted,
  reuse of the same message ID with changed bytes is rejected.
- `/v1/read`: `{read_id, token, limit}`. `limit` 1..16. Returns
  `{items:[{id,body}]}` in creation order. Reading renews non-single-use queues
  to their original TTL; single-use invitation deadlines are never extended.
- `/v1/ack`: `{read_id, token, ids:[...]}` at most 16. Deletes only this queue's
  items. Returns `{ok:true}`. Idempotent, but maintains bounded single-use state.
- `/v1/delete`: `{read_id, token}`. Removes queue/items. Returns `{ok:true}`.
- `/v1/blobs/put`: `{id, token, body}`. Fixed 65536-byte opaque chunk (base64).
  Capability stored hashed; immutable identical retries accepted. Returns
  `{ok:true}`. No name/MIME/contact/attachment ID in the server's blob record.
- `/v1/blobs/get`: `{id, token}` returns `{body}`; `/v1/blobs/delete` removes it.
  Blob lifetime seven days; bounded independent global storage quota.
- `/v1/health`: GET returns only `{ok:true, protocol:"securecomm-web-v1"}`.

Envelopes expire after seven days or earlier queue expiration. Global and
per-queue quotas, finite resource counts, fixed body bounds, admission budget
without persistent IP/user tracking, periodic idle cleanup and cancellation-safe
shutdown are required. Access/error logs must not echo bodies, paths with tokens,
or user content. TLS required outside loopback; Tor reverse proxy is explicitly
loopback-only. CORS is configurable for explicit frontend origins, no credentials.
Static frontend served by web-server entrypoint with strict CSP and no caching
of sensitive responses. No registration/listing/search/reset endpoints.

## Browser module interface

`web/src/core/chat.ts` exports `ChatClient` plus shared public types.
Async factory `ChatClient.open(options?: {storageName?:string})` loads/creates
local state. Public interface:

- `snapshot()` gives contacts, invitations, messages, local settings, no secrets.
- `createInvite(relay:string, label:string)` -> `{id, code, expiresAt}`.
- `acceptInvite(code:string, label:string)` -> contact ID (pending verification).
- `verifyContact(contactId:string, expectedFingerprint:string)` marks verified
  only after exact comparison with the out-of-band transcript fingerprint.
- `sync()` retries pending immutable envelopes, receives/persists then ACKs,
  and processes encrypted control messages. Single-flight and multi-tab safe.
- `sendText(contactId:string,text:string)`; `sendFile(contactId:string,file:File)`.
- `downloadFile(contactId:string,messageId:string)` -> Blob (locally decrypted).
- `rotateQueue(contactId:string,relay?:string)` negotiates migration; old queue
  is removed only after authenticated confirmation over the new queue.
- `removeContact(contactId:string)` locally revokes, removes state and schedules
  best-effort remote queue deletion; no claim of remote recipient erasure.
- `wipe()` removes the entire local profile and reloads fresh state; no restore.
- `close()` releases local resources.

This is the intended integration interface; additions and exact readonly field
types must be coordinated before UI use. Pairing fingerprint must bind both
ephemeral identities and the invitation. A copied invitation does not prove who
used it: explicit verification is required before user messages are accepted.

Attachments: AES-256-GCM with fresh per-file key and unique per-chunk nonce,
authenticated chunk index/file context. Descriptors (name, MIME, size, key,
chunk capabilities) travel only inside verified Olm messages. Strict limits and
safe image/audio previews (no inline HTML/SVG/doc execution). Ciphertext chunks
fixed-size, plaintext final padding discarded only after authentication.

## Verification and completion evidence

- Python existing regression suite; new real HTTP relay/store tests for capability
  separation, bounds, idempotency, single-use admission, TTL, cleanup and restart.
- Real WASM tests for both sides, tampering, prekey sender checks, durable state,
  restart, receipts, duplicates, failed storage, concurrent tabs and local wipe.
- Browser E2E with two isolated profiles and real relay: invite/verify, offline
  send/reload, text/files/images/audio, rotation, deletion, no recovery path.
- Inspect relay DB and recorded synthetic HTTP traffic for forbidden plaintext,
  private material and global identifiers; inspect local DB for plaintext history.
- Production frontend build, Python packaging, Linux container/config validation,
  restrictive headers, no external assets and mobile/keyboard UI verification.
- Security-agent review, JEV evidence review, fix findings, rerun affected tests,
  update CodeGraph and publish truthful run/deployment/limitations documentation.

No checklist item is complete merely because this document exists.
