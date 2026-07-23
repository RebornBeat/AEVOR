# 32 — Subject 1: Wallet and Key Management (complete)

The first subject of the bottom-up plan, and the first genuinely working
user-facing capability in the system. Verified end-to-end against the real binary,
not just by unit test.

---

## 1. What existed before

Checked by reading implementations, per the method in doc 31:

| piece | state before |
|---|---|
| Ed25519 keypair, signing | real (`aevor-crypto`) |
| address derivation (`to_address`) | real |
| `Signer` trait, `sign_transaction` | real |
| key storage / custody | **absent** |
| nonce management | **absent** |
| `aevor keys` CLI | **stub** — printed `"keys command"` and returned |

So the cryptography was sound but nothing let a user *hold* a key or produce a
transaction from one.

## 2. What was built

### `aevor-wallet` — a new crate

- **`Wallet`** — keypair, derived address, nonce position. `generate()` from OS
  entropy, `from_seed()` for recovery. `sign_transaction()` sets the sender
  **before** signing (so the signature commits to it) and advances the nonce only
  once a transaction has actually been produced. `set_next_nonce()` resynchronises
  with the chain after the wallet has been offline.
- **`Keystore`** — encrypted at-rest storage. The passphrase is stretched with
  **Argon2id** (64 MiB, 3 passes) rather than a plain hash or HKDF, because a
  keystore passphrase is low-entropy by nature and a cheap KDF makes offline
  guessing trivial. The derived key encrypts the seed with ChaCha20-Poly1305, whose
  authentication tag is what makes a wrong passphrase fail loudly instead of
  yielding a different key.
- **`Debug` never renders the seed** — a deliberate manual implementation, tested.

### `aevor keys` — now real

`generate`, `import`, `export`, `list` all perform actual work. The passphrase is
read from `AEVOR_KEYSTORE_PASSPHRASE` rather than an argument, because command-line
arguments are visible in the process table.

## 3. End-to-end verification (against the built binary)

```
$ aevor keys generate --keystore-out ks.json
{"address": "7ee6ed73…", "algorithm": "ed25519", "public_key": "3f06a3c6…"}

$ grep '"kdf"' ks.json
"kdf": "argon2id"

$ aevor keys export --keystore ks.json
{"address": "7ee6ed73…", …}          # same identity recovered

$ AEVOR_KEYSTORE_PASSPHRASE=wrong aevor keys export --keystore ks.json
Error: keystore could not be decrypted (wrong passphrase, or the file is corrupt)
```

**A real bug this caught.** The first run panicked inside clap: the command's
`--output` flag collided with the CLI's *global* `--output` (which selects output
format). Renamed to `--keystore-out`. Unit tests could not have found this — it only
appears when the actual binary parses actual arguments, which is precisely why the
method requires end-to-end verification rather than test counts.

## 4. Tests

`aevor-wallet` — 8 tests:

- address is deterministic from the seed; different seeds give different identities
- generated wallets are distinct
- signing advances the nonce, commits to the sender, and verifies
- nonce resynchronises with the chain
- `Debug` never reveals the seed
- keystore round-trips and **rejects a wrong passphrase**
- keystore never stores the seed in plaintext
- **tampering is detected** by the authentication tag

The verification suite gained a wallet section that exercises the real binary:
keystore written, encryption confirmed, identity recovered, wrong passphrase
rejected. A regression that accepted a wrong passphrase would fail the gate loudly.

## 5. What this subject does *not* do

Deliberately scoped:

- **No submission.** A wallet produces a `SignedTransaction` and hands it on;
  reaching the node is Subject 2.
- **No balance queries.** Also Subject 2 — it needs a node interface.
- **No hardware-wallet or multi-signature custody.** The `Signer` trait is the seam
  for both when needed.
- **Ed25519 only.** The crypto layer supports more schemes; the wallet exposes one
  until there is a reason to widen it.

## 6. Status

| item | state |
|---|---|
| `aevor-wallet` crate | complete, 8 tests, clippy clean |
| `aevor keys` CLI | real, end-to-end verified against the binary |
| keystore encryption | Argon2id + ChaCha20-Poly1305, tamper-detecting |
| verification gate | extended — 27 checks, all passing |

**Next: Subject 2 — transaction submission.** Connect the CLI and API to
`NodeEngine::submit` so a signed transaction produced here can actually reach a
node, with confirmation tracking against the security levels. Every subsequent
subject depends on it.
