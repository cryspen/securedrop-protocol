# Lean (Aeneas) extraction of the crypto core

A functional-model extraction of `securedrop-protocol-minimal`'s cryptographic core
to **Lean 4**, via the hax **aeneas-lean** backend (`rustc → charon → aeneas`). This
complements the F\* extraction (`proofs/fstar/`) and the ProVerif symbolic model
(`proofs/proverif/`) with a third, independent lifting of the same Rust.

## What is extracted

The driver mirrors the ProVerif target set — the loop-free SD-APKE / SD-PKE / Ed25519
core and the envelope operations:

| Module | Functions (translated to Lean `def`) |
|---|---|
| `message`  | `auth_enc`, `auth_dec` (SD-APKE), keygen, ciphertext/key types |
| `metadata` | `encrypt`, `decrypt` (SD-PKE), keygen, ciphertext types |
| `sign`     | Ed25519 `sign` / `verify` |
| `encrypt_decrypt` | `encrypt`, `decrypt` (envelope build / open) |

Aeneas cannot yet translate a few constructs; these are made opaque **for the Lean
backend only** via `#[cfg_attr(hax_backend_lean, hax_lib::opaque)]` (F\* and normal
builds are unaffected), and appear as `axiom`s in `Extraction/FunsExternal_Template.lean`:

| Item | Why opaque | Upstream |
|---|---|---|
| `sign::DomainTag::tag` | returns `&'static [u8]` (promoted literal) → "no bottoms in the value" | [AeneasVerif/aeneas#392](https://github.com/AeneasVerif/aeneas/issues/392) |
| `sign::tagged_preimage` | builds the preimage from the opaque tag with `Vec` ops | (same) |
| `encrypt_decrypt::decrypt_with_sender` | trial-decrypt loop over `Vec<&MessageKeyBundle>` (iterator + nested borrows) | [AeneasVerif/aeneas#464](https://github.com/AeneasVerif/aeneas/issues/464) |

## Running

```sh
python3 proofs/proverif/hax.py extract-lean
```

Output lands in `SecuredropProtocolMinimal/Extraction/*.lean` (committed as a snapshot);
`llbc/` and `aeneas-error.log` are diagnostics and git-ignored.

## Toolchain (pending upstream)

The lane depends on two hax changes, injected at extraction time so the committed
manifest stays on crates.io `hax-lib 0.3.7`:

- **[cryspen/hax#2069](https://github.com/cryspen/hax/pull/2069)** — `into aeneas-lean`
  sets target-side `--cfg hax` so `cfg(hax)`-gated dependencies (libcrux) compile.
- **[cryspen/hax#2071](https://github.com/cryspen/hax/pull/2071)** — `hax_lib::opaque` /
  `hax_lib::exclude` emit charon's native `charon::opaque` / `charon::exclude`, so the
  `#[cfg_attr(hax_backend_lean, …)]` markers above take effect.

Point `HAX_LEAN_DIR` (default `~/hax`) at a hax checkout carrying both; `hax.py
extract-lean` uses its `cargo-hax` and injects its `hax-lib` via a temporary
`[patch.crates-io]`. Pinned tool versions (charon `0.1.218`, aeneas
`nightly-2026.07.01`, Lean `v4.30.0-rc2`) come from hax's `pins.toml`.
