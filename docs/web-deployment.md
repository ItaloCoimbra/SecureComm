# SecureComm Web: build and Linux operation

Implementation is being validated; consult [web-progress.md](web-progress.md)
before treating any command or feature as verified. Use synthetic conversations
until an independent review of the entire client/protocol/distribution.

## Build locally

Requires Python >=3.10 and Node >=24. From the repository root:

```sh
python -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
cd web
npm ci --ignore-scripts
npm run typecheck
npm test
npm run build
cd ..
.venv/bin/securecomm-web --host 127.0.0.1 --port 8765 --database .runtime/web.sqlite
```

Windows equivalents use `.venv/Scripts/python.exe` and
`.venv/Scripts/securecomm-web.exe`. Open `http://127.0.0.1:8765` in separate
browser profiles to test two independent participants. The frontend build emits
only generated public assets to `server/web_static`; these assets are also
included when `python -m build` creates a wheel/sdist after the frontend build.
No Node process is required on the runtime server.

`securecomm-server` and `securecomm-client` are the previous CLI protocol. They
do not provide the web interface and must not be substituted for `securecomm-web`.
Use a **new database**, not an existing CLI relay database or client vault.

## Contact creation and storage

Generate a short-lived invitation and exchange it through a trusted channel or
in person. The recipient opens it and both participants compare the complete
verification fingerprint independently before enabling conversation. A copied
invitation is not proof of a person's identity.

There is no application backup, export/import, recovery phrase or remote account
reset. Deleting the actual browser state loses the local relationships. The
other participant's copies are unaffected. A stolen device may still have the
keys, and browser deletion does not guarantee forensic erasure. OS profile
backups, extensions, malicious JavaScript and malware are separate risks.

Browser profiles sharing the same origin share local application state. Use
independent profiles for independent people; two ordinary tabs are not two users.
Server origin changes produce a different browser storage partition and do not
migrate contacts. Do not change domains casually or restore old profile copies.

## Linux with TLS

The application refuses plaintext non-loopback listeners. Obtain a certificate
for your chosen hostname through your own certificate process, then run:

```sh
.venv/bin/securecomm-web --host 0.0.0.0 --port 8443 \
  --database /var/lib/securecomm/relay.sqlite \
  --tls-cert /etc/securecomm/tls/fullchain.pem \
  --tls-key /etc/securecomm/tls/privkey.pem
```

Keep the TLS private key readable only by the service identity. No conversation
private key belongs on the server. Restrict the firewall to the intended HTTPS
port. Do not enable proxy/CDN/access/body logging, analytics or request tracing.
TLS termination at a proxy gives that proxy transport metadata and capability
tokens; it still must not receive E2EE plaintext. Local loopback proxying is an
explicit deployment trust decision, not a source of extra E2EE security.

Container configuration is provided in `Dockerfile` and `compose.yaml`:

```sh
export SECURECOMM_TLS_DIR=/etc/securecomm/tls
docker compose build
docker compose up -d
```

These are instructions, not actions already performed on your server. Runtime
UID/GID is 10001, with no capabilities and a read-only root filesystem. The key
directory must be traversable and the key readable by that identity without
making it world-readable. The only persistent volume is relay ciphertext/state.
Avoid host/cloud snapshots if your retention policy forbids retained metadata.
Container logs are disabled; monitor aggregate health/resource use without
recording individual requests. Certificate renewal needs an explicit restart
procedure and permissions check.

## Optional onion deployment

`deploy/securecomm-web.service` is a hardened **loopback-only** service template;
create a dedicated `securecomm` user and install the project under
`/opt/securecomm` before using it. Review paths and permissions for your server.
`deploy/torrc.example` exposes that listener as a Tor v3 onion service. Install
and administer Tor separately. Do not also publish its HTTP listener to the LAN
or Internet. Use a compatible Tor Browser and verify WebCrypto, IndexedDB and
WebAssembly support/security level before use.

An ordinary browser does not become anonymous merely by selecting a setting in
this application. A Tor/onion deployment reduces direct IP exposure but cannot
guarantee resistance to timing correlation, a global observer, a malicious
operator recording traffic, or malicious frontend JavaScript.

## Retention and privacy boundaries

The relay stores opaque queue addresses, capability hashes, timestamps and
ciphertext. It sees resource access and may correlate IPs/timing. No global user
account, contact name, file name or conversation private key is needed. Distinct
relays should be operated independently if operator separation is a requirement;
two containers on your own VPS do not establish this independence.

Queues have bounded TTL; normal authenticated reads renew contact queues while
invitation deadlines do not renew. Messages and blob chunks expire after at
most seven days. Delivery acknowledgments delete stored message bodies; bounded
deduplication markers may remain until their original expiry. Local queued
outgoing ciphertext can be retried; ciphertext already held by third parties
cannot be recalled. Expiry/deletion does not promise disk/snapshot sanitization.

The local history persists until contact removal/site deletion. Browser storage
quotas can block receiving; the relay must not be acknowledged until durable
local persistence succeeds. Public resource creation has finite admission and
storage budgets, not global identity-based anti-abuse. This is not full DoS
protection.

Olm v1 is not post-quantum and uses 64-bit authentication tags. The third-party
WASM wrapper and application have not gained an audit just because upstream
cryptography has been reviewed. See [web-private-contract.md](web-private-contract.md)
and [runtime dependency notes](../web/THIRD_PARTY.md).
