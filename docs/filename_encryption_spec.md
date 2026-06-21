# Filename encryption (Level 1) — scheme spec

So any Obsideo client (the CLI, the SDK, a future GUI) encrypts object names
**identically**, and the same account's names are mutually readable across clients.

## Goal
Object keys (folder path + filename) must not reach Obsideo in the clear. Content
is already E2E (AES-256-GCM); this hides the *names*. Level 1 keeps server-side
prefix listing working (so `ls`/`cd` stay fast) at the cost of a small leak.

## Algorithm
```
name_key = HKDF-SHA256(ikm = <account data key, 32 bytes>,
                       salt = none, info = "obsideo-name-key-v1", L = 64 bytes)

token(component) = base64url_nopad( AES-SIV_encrypt(name_key, utf8(component), aad = none) )

encrypt_path(path) = "/".join( token(c) for c in path.split("/") if c )
```
- **AES-SIV** (RFC 5297) — deterministic, misuse-resistant authenticated encryption.
  64-byte key = AES-256-SIV. Deterministic is required so the encrypted prefix is
  stable and the server can list under it; the client decrypts returned tokens.
- Per-component (not whole-path) so directory structure maps 1:1 to encrypted
  prefixes and listing/browse works.
- `base64url` (no padding) keeps tokens valid as single S3 key segments (no `/`).

## Browse flow
- `ls <path>`: client encrypts `<path>` → lists under the encrypted prefix →
  **decrypts** each returned CommonPrefix/Contents token back to the real name.
- `put/get/rm/head <realpath>`: client encrypts the path to the storage key.
- Legacy clear-name objects: decrypt fails → fall back to showing the raw token
  (mixed accounts don't crash; but `get` on a legacy clear object won't resolve —
  re-upload to migrate).

## Threat model / residual leaks (Level 1, by design)
- **Hidden:** file and folder names.
- **Still visible to Obsideo:** directory *structure* (depth, fan-out), object
  *sizes* (ciphertext ≈ plaintext), object *counts*, and timestamps. Also: identical
  names encrypt to identical tokens (deterministic), so Obsideo can see that two
  objects share a name — never what it is.
- **Level 2** (random opaque keys + a synced encrypted manifest) would also hide
  structure; **size-padding** would blunt the size leak. Both are future options.

## Cross-client compatibility (the SDK integration point)
The scheme is fixed; the only thing clients must agree on is the **name-key source**:
- **CLI (`obsideo-cloud`)**: `data_key` = the account data key at `~/.obsideo/data.key`.
- **SDK (`@obsideo/sdk`)**: must derive `name_key` from the **same** secret the user's
  account uses for content (managed mode derives keys from the recovery manifest;
  external mode supplies its own). For a CLI user and an SDK user on the *same account*
  to read each other's names, both must feed the **same `data_key`** (or an agreed
  account-level key) into the HKDF above. Resolve this when wiring the SDK — it's a
  key-management decision, not a change to the scheme.

## Config
`encrypt_names` (default **true**) in `~/.obsideo/config.json`. Off → plaintext keys
(interop/debug). Changing it does not migrate existing objects.
