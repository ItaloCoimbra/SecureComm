# Web implementation evidence

Full goal: implement the agreed browser messenger, not only a relay or a demo.
Current status: in progress. This record is not completion evidence by itself.

## Baseline and decisions

- Windows/Python 3.11 baseline: 140 passed, 1 platform skip (2026-09-26).
- Separate HTTP relay and browser protocol; do not migrate local CLI vaults or
  old identity-bearing relay records into the web product.
- Pin and test actual vodozemac WASM wrapper. No original ratchet.
- No application recovery/backups, no blockchain, no global identity directory.
- Root owns build/deployment/docs/integration; workers own relay, core and UI.

## Completion checklist

- [ ] Browser invite/verification, independent per-contact keys and no recovery.
- [ ] Durable encrypted browser state, atomic retries/receipts and concurrency.
- [ ] Offline text and real files/images/recorded audio end-to-end.
- [ ] Negotiated queue rotation and migration across independent relays.
- [ ] Relay capability separation, TTL, idle cleanup, quotas and no content logs.
- [ ] Frontend XSS defenses, strict headers, local assets, safe media previews.
- [ ] Clear local wipe and contact revocation behavior with honest limitations.
- [ ] Two isolated real browser profiles exercise pairing, messaging and reload.
- [ ] Capture synthetic traffic/storage and verify absence of private/plaintext data.
- [ ] Linux build/runtime smoke, packaging with bundled WASM and web assets.
- [ ] Code/security review and JEV patch/evidence check; fixes retested.
- [ ] Documentation reflects actual interfaces, limits and evidence.

## Evidence accumulated

- Packaging regression written first: new web assets absent from wheel (RED).
  After explicit package data/manifest and entrypoint: targeted test passed.
- npm installation: locked 110 packages, audit reported zero known vulnerabilities
  at installation time. This is not a cryptographic audit.
- Docker Engine 29.6.1 reachable locally; Compose 5.3.1 parsed compose.yaml.
  Parsing configuration is NOT evidence of a successful build or deploy.

## Out of scope for completion claims

Public deployment, third-party security certification, remote CI execution,
zero metadata correlation, protection against hostile client code, recipient
copy destruction, operating-system backups and forensic key erasure.
