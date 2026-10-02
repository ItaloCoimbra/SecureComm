# Bundled runtime dependencies

The application bundles dependencies locally; it never loads a remote CDN.

- `@dtelecom/vodozemac-wasm` 0.3.0, Apache-2.0:
  https://github.com/dTelecom/vodozemac-wasm
- upstream vodozemac, Apache-2.0:
  https://github.com/matrix-org/vodozemac
- `qrcode` 1.5.4, MIT:
  https://github.com/soldair/node-qrcode

Dependency trees and integrity checks are pinned in package-lock.json. Source
review, npm integrity and passing tests do not prove reproducible WASM binaries
or constitute an independent cryptographic audit. Olm v1 has a 64-bit MAC and
is not post-quantum. The wrapper's plain JSON pickles must only enter encrypted
local storage, never requests to a relay.

Build tools and their dependencies have additional licenses in node_modules.
Redistribution must retain the applicable licenses supplied with each package.
