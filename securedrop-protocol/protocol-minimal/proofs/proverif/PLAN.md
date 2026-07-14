# Plan — symbolic (ProVerif) analysis of `securedrop-protocol-minimal` via the hax ProVerif backend

Status: proposal / not yet executed. Mirrors the SPQR + Mandrake flagship setups
(`~/SparsePostQuantumRatchet/hax.py`, `~/mandrake/hax.py`) on the hax ProVerif
"Backend A" (rust-engine, `cargo hax into proverif`, opam switch `hax-proverif`).

--------------------------------------------------------------------------------
## 0. Executive summary — how this works and why it's low-risk

- The hax ProVerif backend lifts **plain Rust functions** into ProVerif `letfun`s
  (one `letfun` per fn, structs → `[data]` constructors). There is **no protocol
  DSL to adopt**: the `hax-lib-protocol` state-machine macros exist but the backend
  only *parses* them, it does not render processes/events/queries. Every flagship
  (PSK, SPQR, Bertie, Mandrake) writes the protocol as ordinary Rust and hand-writes
  the ProVerif harness (events, queries, roles, honest run) in `.pv` files that call
  the generated letfuns.
- All ProVerif annotations are gated on **`cfg(hax_backend_proverif)`** (set only by
  hax during `into proverif`) and the dev `hax-lib` (which carries those macros) is
  injected at extraction time via `cargo --config` — **not** a committed
  `[patch.crates-io]`. Consequence: `cargo build`, `cargo test`, and the **existing
  F\* pipeline are completely untouched.** Normal builds never see the annotations.
- The crate is already well-posed for this: `message.rs`/`metadata.rs`/`sign.rs`
  (the SD-APKE / SD-PKE / Ed25519 core) are **loop-free**, and most role/key-setup
  functions (`Source::new`, `Journalist::new`, `from_master_key`, …) are already
  `#[hax_lib::opaque]`, so the backend won't recurse into their rng/Vec/loop bodies
  — we model key setup in the harness instead.

Pipeline (identical shape to PSK/SPQR/Mandrake):

```
cargo hax into -i '<targets>' proverif         # -> proofs/proverif/extraction/{lib.pvl, missingdecl.pvl, lib.pvl.map}
proverif -lib primitives -lib cryptolib -lib sd_crypto \
         -lib missingdecl -lib lib  queries/<prop>.pv
```

--------------------------------------------------------------------------------
## 1. Toolchain (already present locally — verify only)

| Component | Where | Check |
|---|---|---|
| ProVerif 2.05 | `/usr/local/bin/proverif` | `proverif --help \| head -1` |
| hax ProVerif backend | opam switch **`hax-proverif`** (`cargo hax into proverif` present, backend rev `637fc91499`) | `eval $(opam env --switch=hax-proverif); cargo hax into --help \| grep proverif` |
| dev `hax-lib` w/ proverif macros | `~/hax-proverif-backend/hax-lib` (v0.3.7 + `cfg(hax_backend_proverif)` macros) | `ls ~/hax-proverif-backend/hax-lib/proof-libs/proverif/{primitives,cryptolib}.pvl` |
| shared symbolic libs | `~/hax-proverif-backend/hax-lib/proof-libs/proverif/{primitives.pvl, cryptolib.pvl}` | — |

Set once per shell used for extraction:
```sh
export HAX_PROVERIF_DIR=~/hax-proverif-backend      # for primitives.pvl + dev hax-lib path
eval "$(opam env --switch=hax-proverif)"            # cargo-hax + hax-rust-engine + hax-engine (ocaml)
```
No new installs required. (If ProVerif crashes on stats output, apply
`~/hax-proverif-backend/examples/proverif-psk/pv_div_by_zero_fix.diff`.)

--------------------------------------------------------------------------------
## 2. Repo scaffolding (new, all under `protocol-minimal/`)

```
proofs/proverif/
  PLAN.md                      # this file
  hax.py            (NEW)      # driver: extract-proverif / reconstruct-proverif / verify-proverif / check-proverif
  handwritten/
    sd_crypto.pvl   (NEW)      # SecureDrop-specific symbolic crypto: SD-APKE (HPKE-AuthPsk) + SD-PKE (HPKE-Base/X-Wing)
  queries/          (NEW)      # one hand-written .pv per property, each with an (* EXPECTPV … END *) block
    submission_secrecy.pv
    reply_secrecy.pv
    sender_auth.pv
    enrollment_auth.pv
    sanity.pv
    TIMINGS.md
  extraction/       (generated)
    lib.pvl                    # pure hax output — committed as a snapshot (reconstruct path), never hand-edited
    lib.pvl.sha256             # byte-identity pin
    lib.pvl.map                # source map (gitignore)
    missingdecl.pvl            # DIAGNOSTIC — goal: empty (gitignore)
```

Reuse verbatim from `~/hax-proverif-backend/hax-lib/proof-libs/proverif/`:
`primitives.pvl` (preamble: channel `c`, tuples, `Some/None/True/False`, `nat_lit`,
`bitstring_err`) and `cryptolib.pvl` (`crypto__aead_enc/dec`, `crypto__kdf`,
`crypto__hkdf_*`, `crypto__dh_pub/shared` + commutativity, `crypto__kem_pk/encaps/decaps`,
`crypto__vk_of/sign/sig_verify`, `crypto__mac*`, `crypto__serialize*`). Referenced by
`-lib` path; not copied.

`Cargo.toml` edits (crate-local, inert for normal builds):
```toml
[lints.rust]
unexpected_cfgs = { level = "warn", check-cfg = ['cfg(hax_backend_proverif)'] }
```
The dev `hax-lib` is **not** added to `[dependencies]`; `hax.py` injects it at
extraction via `cargo --config patch.crates-io."hax-lib".path=$HAX_PROVERIF_DIR/hax-lib`
(+ `hax-lib-macros`, `hax-lib-macros-types`), backing up/restoring `Cargo.lock` around
the run (SPQR pattern). This keeps the committed manifest on crates.io `hax-lib 0.3.7`
so the F\* lane and CI stay portable.

--------------------------------------------------------------------------------
## 3. Make the crate ProVerif-extractable (source annotations)

All annotations are `#[cfg_attr(hax_backend_proverif, hax_lib::…)]` — invisible to
`cargo build`/`test`/`into fstar`.

### 3a. Crypto boundary — redirect leaves to the symbolic model (`replace_body` / `pv_extern`)

Annotate at the **SecureDrop-semantic wrapper level** (functions/methods that return
owned values), *not* the raw libcrux `&mut`-out-param level. `replace_body` is allowed
on `impl` methods (SPQR does exactly this).

| Rust item (crate = `securedrop_protocol_minimal`) | ProVerif redirect |
|---|---|
| `sign::SigningKey::sign(msg) -> Signature<D>` | `crypto__sign(self, msg)` (self = sk) |
| `sign::VerifyingKey::verify(msg, sig) -> Result<(),_>` | `let (=rust_primitives__hax__Tuple0__Tuple0) = crypto__sig_verify(self, msg, sig) in rust_primitives__hax__Tuple0__Tuple0 else bitstring_err()` |
| `sign::tagged_preimage::<D>(msg)` | `crypto__serialize(rust_primitives__hax__Tuple2__Tuple2(D::tag, msg))` (domain-sep tag; see 3d) |
| `primitives::x25519::dh_shared_secret(pk, sk)` | `crypto__dh_shared(sk, pk)` |
| `primitives::x25519::dh_public_key_from_scalar(sk)` / `generate_dh_keypair` | `crypto__dh_pub(sk)` / `new k; (k, crypto__dh_pub(k))` |
| `message::auth_enc(rng, skS, pkR, m, ad, info)` | `sd_apke__authenc(skS, pkR, m, ad, info)` (see §4) |
| `message::auth_dec(skR, pkS, ct, ad, info)` | `sd_apke__authdec(skR, pkS, ct, ad, info)` (partial-inverse `reduc`) |
| `metadata::encrypt(pkR, m) / decrypt(skR, ct)` | `sd_pke__enc(pkR, m)` / `sd_pke__dec(skR, ct)` |
| `primitives::mlkem::*` / `xwing::*` (if reached) | `crypto__kem_encaps/decaps/pk` |

Redirecting at `auth_enc`/`auth_dec`/`metadata::{encrypt,decrypt}` means the internal
ML-KEM-encaps + HPKE-seal composition is modeled atomically by the `sd_apke`/`sd_pke`
symbolic primitives — the standard symbolic treatment of HPKE. (Phase-2 refinement:
add thin annotatable `provider::hpke::{seal,open}` free-fn wrappers and redirect those
instead, exposing the ML-KEM ⊕ DH-AKEM composition to ProVerif.)

### 3b. Opaque wire/key types

`#[cfg_attr(hax_backend_proverif, hax_lib::opaque)]` on the byte-blob structs so they
collapse to atomic `bitstring` (no field-accessor `reduc`s): `Signature<D>`,
`VerifyingKey`, `SigningKey`, `MessageCiphertext`, `MetadataCiphertext`,
`MessagePublicKey`, `MessagePrivateKey`, `MetadataPublicKey/PrivateKey`, `Envelope`,
`Plaintext`, `KeyBundlePublic`, `SignedLongtermPubKeyBytes`, `Enrollment`,
`JournalistLongTermView`, `WelcomeBundle`. (Several already carry `hax_lib::exclude`
on their serde impls — keep those.)

### 3c. Loops / `Vec` / iterators (backend rejects them)

Only three call-sites loop; handle each by modeling the honest single-item case:
- `encrypt_decrypt::decrypt_with_sender` — `for &bundle in receiver.keybundles()` trial
  decrypt. → `replace_body` to the single-bundle expression, **or** factor a
  `decrypt_one(bundle, env)` helper (loop-free) and iterate with `!` replication in the
  harness. Phase-1: single keybundle.
- `api::handle_welcome` — `for journalist in welcome.journalists` verify. → extract the
  loop-free `verify_long_term` and drive the roster with `!` in the harness.
- `encrypt_decrypt::{compute_fetch_challenges, solve_fetch_challenges}` — fetch-privacy
  loops. **Out of phase-1 scope** (fetch/unlinkability is phase-2); exclude via `-i`.

### 3d. Domain-separated signatures

`sign::sign/verify` prepend `len(tag)||tag||msg`. Model the four `DomainTag`s
(`j-sig-ltk`, `j-sig-eph`, `nr-sig`, `fpf-sig-nr`) as distinct nullary ProVerif consts
and sign over `crypto__serialize((tag, msg))` (3a). This makes cross-domain confusion
unprovable in the symbolic model, matching the type-level `Signature<D>` separation.

### 3e. The `-i` target filter (method-precise, SPQR/Mandrake style)

Start from "exclude all", re-select the protocol roots (their transitive closure pulls
in the crypto leaves, which the redirects cap), keep concrete-crypto/serde/loop trees
out. Draft (tune during M1 against `missingdecl.pvl`):

```
-**
+securedrop_protocol_minimal::message::auth_enc
+securedrop_protocol_minimal::message::auth_dec
+securedrop_protocol_minimal::metadata::encrypt
+securedrop_protocol_minimal::metadata::decrypt
+securedrop_protocol_minimal::encrypt_decrypt::encrypt
+securedrop_protocol_minimal::encrypt_decrypt::decrypt_with_sender
+securedrop_protocol_minimal::sign::**::sign
+securedrop_protocol_minimal::sign::**::verify
+securedrop_protocol_minimal::api::**::verify_long_term
+securedrop_protocol_minimal::api::**::verify_ephemeral
+securedrop_protocol_minimal::keys::**   +securedrop_protocol_minimal::wire::**::*   (types only; prune if they drag serde)
-securedrop_protocol_minimal::storage::**  -securedrop_protocol_minimal::server::**
-securedrop_protocol_minimal::**::compute_fetch_challenges
-securedrop_protocol_minimal::**::solve_fetch_challenges
-libcrux_**::**  -hpke_rs::**  -uuid::**  -bip39::**  -serde::**  -hex::**   (concrete crypto / non-protocol)
```

--------------------------------------------------------------------------------
## 4. SecureDrop symbolic crypto extension (`handwritten/sd_crypto.pvl`)

`cryptolib.pvl` already covers AEAD, KDF/HKDF, DH (+commutativity), KEM, Ed25519
(EUF-CMA), MAC, serialization. Add only the two SecureDrop composite primitives:

```
(* SD-APKE = HPKE(AuthPsk): confidentiality + IMPLICIT SENDER AUTH.
   authdec yields the plaintext only for a ct produced by the matching
   sender sk_S and recipient pk_R (binds both identities + ad + info). *)
fun sd_apke__authenc(bitstring, bitstring, bitstring, bitstring, bitstring): bitstring.
   (* skS, pkR, m, ad, info -> ct *)
reduc forall skS, skR, m, ad, info;
  sd_apke__authdec(skR, crypto__dh_pub(skS),
                   sd_apke__authenc(skS, crypto__dh_pub(skR), m, ad, info), ad, info) = m.

(* SD-PKE = HPKE(Base) over X-Wing: confidentiality only (metadata). *)
fun sd_pke__enc(bitstring, bitstring): bitstring.      (* pkR, m -> ct *)
reduc forall skR, m;
  sd_pke__dec(skR, sd_pke__enc(crypto__dh_pub(skR), m)) = m.
```

(`crypto__dh_pub` doubles as "public key of sk" for the symbolic identity binding; a
phase-2 decomposition can split DH-AKEM vs ML-KEM PSK if a hybrid-downgrade property is
wanted. Add any per-format serialization tags here too.) These may instead be authored
inline in Rust via `#[hax_lib::proverif::before("…")]` on `auth_enc`/`metadata::encrypt`
(Mandrake style) — pick one home for the model; a standalone `.pvl` keeps it auditable.

--------------------------------------------------------------------------------
## 5. Harness — events, queries, roles, honest run (`queries/*.pv`)

Each query file: `nounif` saturation control (for the crypto-heavy ones) + `event`
decls + `free … [private]` secrets + `query …` + `let` role processes calling the
generated letfuns + `process` honest run + a trailing `(* EXPECTPV … END *)` block.

Trust model encoded: FPF vk is a public trust anchor; the DY attacker controls the
network and can register rogue journalists; honest source + ≥1 honest journalist.

Events (declared in the harness, raised inside role processes):
`FpfSignedNewsroom(nr_vk)`, `NewsroomSignedJournalist(j_vk)`,
`SourceSubmitted(msg, j_pk)`, `JournalistReceived(msg, src_pk)`,
`JournalistReplied(reply, src_pk)`, `SourceReceivedReply(reply)`,
`ClientAcceptedJournalist(j_vk)`.

| # | Property | Query (shape) | Expected |
|---|---|---|---|
| 1 | **Submission confidentiality** | `query attacker(SECRET_SUBMISSION).` | `true` (secret) |
| 2 | **Reply confidentiality** | `query attacker(SECRET_REPLY).` | `true` |
| 3 | **Sender authentication** (SD-APKE implicit) | `event(JournalistReceived(m, s)) ==> event(SourceSubmitted(m, s))` (aim injective) | `true` |
| 4 | **Enrollment trust-chain auth** | `event(ClientAcceptedJournalist(jvk)) ==> event(NewsroomSignedJournalist(jvk))` | `true` (no rogue journalist) |
| 5 | **Sanity / reachability** | `query e:…; event(JournalistReceived(...))` and `event(SourceReceivedReply(...))` | `false` (i.e. reachable — honest run completes) |
| — | *(phase-2)* metadata/sender anonymity of `ct^PKE`; fetch-clue `(X,Z)` recipient unlinkability | observational-equivalence / `choice` | stretch |

Role sketch (calls generated letfuns; `<C>=securedrop_protocol_minimal`):
```
let Newsroom(nr_sk, j_vk) =
    (* newsroom signs journalist vk *) event NewsroomSignedJournalist(j_vk);
    out(c, <C>__sign__…__sign(nr_sk, j_vk)).            (* NewsroomOnJournalist sig *)
let Journalist(j_sk, j_apke_sk, j_pke_sk, …) = … receive via <C>__encrypt_decrypt__decrypt_with_sender … reply via <C>__encrypt_decrypt__encrypt …
let Source(src_keys, welcome) =
    (* verify chain *) let (=Tuple0) = <C>__api__…__verify_long_term(view, nr_vk) in
    event ClientAcceptedJournalist(jvk);
    event SourceSubmitted(SECRET_SUBMISSION, j_pk);
    out(c, <C>__encrypt_decrypt__encrypt(src_sk, pt, j_pub)).
process  new fpf_sk; new nr_sk; ( Newsroom(...) | !Journalist(...) | !Source(...) | attacker-registration )
```

EXPECTPV blocks are generated once by `hax.py check-proverif update`, then asserted.

--------------------------------------------------------------------------------
## 6. Driver `proofs/proverif/hax.py` (adapt Mandrake's; SPQR's is the alt template)

Subcommands (ported ~verbatim; the EXPECTPV machinery, RSS/timing sampler, and target
tiers are reusable as-is):
- `extract-proverif` — `cargo hax into -i '<targets>' proverif` with the `cargo --config`
  dev-`hax-lib` injection + `Cargo.lock` backup/restore; copy `extraction/lib.pvl`(+`missingdecl.pvl`);
  load-check the composed libs against `process 0`; pin `lib.pvl.sha256`.
- `reconstruct-proverif` — reassemble/validate from the committed `extraction/` snapshot
  with **no** `cargo hax` (engine-free CI lane).
- `verify-proverif [q…]` — run ProVerif, print `RESULT` lines + wall-clock.
- `check-proverif [update]` — run each `queries/*.pv`, positional diff of `RESULT` lines
  vs its `(* EXPECTPV … END *)`; `n/n match [OK|FAIL]`; nonzero exit on mismatch;
  `update` regenerates the blocks.

Fixed `-lib` load order (declare-before-use):
```
proverif -lib $HAX_PROVERIF_DIR/hax-lib/proof-libs/proverif/primitives.pvl \
         -lib $HAX_PROVERIF_DIR/hax-lib/proof-libs/proverif/cryptolib.pvl \
         -lib handwritten/sd_crypto.pvl \
         -lib extraction/missingdecl.pvl \
         -lib extraction/lib.pvl \
         queries/<prop>.pv
```
Engine discovery: prefer the `hax-proverif` opam switch; honor `HAX_PROVERIF_DIR`.

--------------------------------------------------------------------------------
## 7. Milestones (execution order)

- **M0 — smoke test the toolchain (no crate changes). ✅ DONE.** PSK example verdicts reproduce via the exact `-lib` pipeline.
- **M1 — first extraction of the crypto core. ✅ DONE (2026-07-14).** Added §3a redirects
  + §3b opaque to `message.rs` (`auth_enc`/`auth_dec` → `sd_apke__authenc/authdec`),
  `metadata.rs` (`encrypt`/`decrypt` → `sd_pke__enc/dec`), `sign.rs` (`sign`/`verify` →
  `crypto__sign/sig_verify`); added the `cfg(hax_backend_proverif)` check-cfg to the
  workspace; wrote `hax.py` (extract/verify/check-proverif) and `handwritten/sd_crypto.pvl`.
  **`missingdecl.pvl` is empty** (all hpke/mlkem/libcrux leaves redirected). The composed
  model loads in ProVerif and `submission_secrecy.pv` passes (`attacker(SECRET) is true`).
  Non-regression: `cargo build` succeeds; `proofs/fstar/` byte-identical (untouched).
  Change footprint: +55 lines across 3 src files + Cargo.toml, all cfg-gated.
  **Learnings:** (a) use `opam exec --switch hax-proverif --` to put the OCaml `hax-engine`
  on PATH (parsing `opam env` missed its single-quoted output); (b) redirected `letfun`s
  KEEP dropped params in their signature — `auth_enc` is `auth_enc(rng, sk, pk, m, ad, info)`
  (6 args), so harness/queries must pass a dummy `rng` first.
- **M2 — submission confidentiality + sender auth end-to-end. ✅ DONE (2026-07-14).**
  Chose **Approach A (extract the real `encrypt`)** — confirmed `encrypt_decrypt::encrypt`
  extracts faithfully (trait methods monomorphize to abstract accessors; the
  `decrypt_with_sender` loop even auto-unrolls). Redirected the x25519 DH ops
  (`generate_dh_keypair` → `new sk; (sk, crypto__dh_pub(sk))`, `dh_shared_secret` →
  `crypto__dh_shared`, DH types opaque + `into_bytes` identity) for the fetch hint;
  wrote `handwritten/sd_model.pvl` giving the 5 abstract UserSecret/UserPublic accessors
  meaning over honest `sd_secret`/`sd_public` user terms (the SPQR `model.pvl` pattern);
  taught `hax.py` to filter `missingdecl.pvl` against handwritten definitions.
  `queries/submission.pv` drives the extracted `encrypt` + a primitive-level journalist
  receive. **All 3 properties green** (`check-proverif`: 3/3):
    1. `not attacker(SECRET_SUBMISSION) is true` — confidentiality
    3. `JournalistReceived(m,s) ==> SourceSubmitted(m,s) is true` — sender auth
    5. `not event(JournalistReceived) is false` — sanity (non-vacuous)
  `missingdecl.pvl` clean; `cargo build` + `proofs/fstar/` untouched. Footprint: +75 src lines.
- **M3 — enrollment trust chain. ✅ DONE (2026-07-14).** The `api::verify_long_term`
  blanket-impl doesn't extract (same reason F* excludes `api::**`), so the client
  verification is modeled in the harness driving the REAL extracted `sign`/`verify`.
  Domain separation (fpf-sig-nr / nr-sig / j-sig-ltk) is modeled by signing/verifying
  the tagged message `(TAG, msg)` (mirrors `sign.rs` `tagged_preimage`). `enrollment.pv`
  proves **rogue journalist refuted** (`ClientAcceptedJournalist(jvk) ==>
  NewsroomSignedJournalist(jvk) is true`) + sanity; `enrollment_soundness.pv` proves the
  nr-sig check is load-bearing (a broken client that skips it accepts a rogue —
  `... is false`, guarding against a vacuous proof). **Full suite 6/6 green.** No source
  changes (pure harness). Reply-path secrecy (property 2) deferred to a follow-up.
- **M4 — CI + snapshots. ✅ DONE (2026-07-14).** Vendored `primitives.pvl`/`cryptolib.pvl`
  into `proofs/proverif/lib/` (self-contained + frozen against upstream drift); pinned the
  `extraction/lib.pvl` snapshot via `lib.pvl.sha256`; added `hax.py reconstruct-proverif`
  (engine-free digest check, drift-detecting) and made `proverif_libs()` prefer the vendored
  copies + `proverif` invocation switch-independent. Makefile targets `proverif-check`
  (engine-free reconstruct+check) / `proverif-extract`; CI workflow
  `.github/workflows/proverif.yml` (installs `proverif` via opam, runs the engine-free lane).
  `.gitignore` for `*.pvl.map`. **Verified: `make proverif-check` runs 6/6 green with
  `HAX_PROVERIF_DIR` unset** (true CI simulation); drift detection confirmed load-bearing.

### Follow-ups (post-M4)
- **(a) Reply path. ✅ DONE (2026-07-14).** `queries/reply.pv` drives the extracted
  `encrypt` with roles swapped (journalist=sender, source=recipient). Reply confidentiality
  + journalist authentication (`SourceReceivedReply(m,j) ==> JournalistReplied(m,j)`) +
  sanity all green. **Suite now 9/9.**
- **(c) Fetch-privacy / recipient unlinkability. ✅ DONE (2026-07-14).** `queries/fetch.pv`
  (correctness: intended recipient recovers the id; wrong-recipient + eavesdropper secrecy)
  and `queries/fetch_unlink.pv` (**recipient anonymity** via ProVerif observational
  equivalence — the untrusted server can't tell A from B). **Suite now 13/13.** See
  FETCH-NOTES below for the modeling departure.
- **Full `decrypt_with_sender` extraction. ✅ DONE (2026-07-14).** Both receive directions
  (submission + reply) now drive the REAL extracted `decrypt_with_sender` — its trial-decrypt
  over the key-bundle list, metadata-based sender-key recovery, and `auth_dec` — instead of a
  primitive-level harness model. Needed: identity `MessagePublicKey::from_bytes` +
  `Plaintext::{to_bytes,from_bytes}` (opaque round-trip); opaque `MessageKeyBundle`/
  `MessageKeyPair`/`MetadataKeyPair` so their bundle machinery lives entirely in `sd_model`
  (breaks a lib↔model load-order cycle — ProVerif is single-pass); a receiver model
  (`sd_journalist`/`sd_bundle` + `keybundles`/`fetch_keypair` accessors); and a generalized
  `missingdecl` filter (also drops names defined by the vendored libs, e.g. reduc-defined
  `Tuple2__0/1`). `missingdecl` stays clean; suite still **13/13**. The backend auto-unrolls
  the trial-decrypt loop (fixed bound 3; a single-bundle journalist uses the first iteration).
- HPKE-AuthPsk decomposition; migrate `replace_body`→`pv_model` when the tracing backend lands.

### FETCH-NOTES (the one modeling departure)
Every other property drives the **extracted** Rust. The fetch mechanism is a **3-party DH
clue** (`X=g^x`, `Z=pk_R^x`; server `pmgdh=X^eph`, `mk=Z^eph`; recipient `mk=pmgdh^r_sk`),
i.e. `mk = g^(x·r_sk·eph)`. Two reasons it is modeled by hand rather than extracted:
(1) hax's `crypto__dh_shared` is a 2-party KDF-style op and cannot express the nested
exponentiation; (2) ProVerif does **not terminate** on the general exp-commutativity
equation here. So `fetch*.pv` use dedicated clue constructors (`gen/cluex/cluez/srvp/srvk`)
whose single correctness `reduc` (`reck(srvp(cluex(x),eph), r_sk) = srvk(cluez(gen(r_sk),x),eph)`)
captures exactly the recipient⇄server key agreement — deterministic and fast for ProVerif —
and reuse the shared `crypto__aead_*` for the message-id encryption. A subtle first attempt
had the server as an open oracle re-encrypting one global id onto any hint (a false GotB
"attack"); the fix binds the id to A's genuine entry. Faithfulness caveat: the clue algebra
is hand-modeled, not extracted from `compute_fetch_challenges`/`solve_fetch_challenges`.

## Verified property inventory (13 RESULT lines, all green — `make proverif-check`)
| File | Property | Verdict |
|---|---|---|
| submission.pv | submission confidentiality / sender auth / sanity | secret / agree / reachable |
| reply.pv | reply confidentiality / journalist auth / sanity | secret / agree / reachable |
| enrollment.pv | rogue journalist refuted / sanity | agree / reachable |
| enrollment_soundness.pv | nr-sig check is load-bearing | attack reproduced (false) |
| fetch.pv | recipient recovers id / wrong-recipient + eavesdropper secrecy | reachable / secret / secret |
| fetch_unlink.pv | recipient anonymity (obs-equivalence) | equivalence true |

--------------------------------------------------------------------------------
## 8. Risks / open questions

- **HPKE-AuthPsk fidelity.** Phase-1 models SD-APKE atomically (§4). It captures
  confidentiality + sender-auth but *not* the ML-KEM/DH-AKEM hybrid interior; a
  downgrade/KCI property needs the phase-2 decomposition (wrap `hpke.seal/open`).
- **Loop/`Vec`/`Result` handling.** Backend rejects loops/closures/`&mut`; §3c covers
  the three sites. Watch for `Result`/`?` and `.expect()` in extracted fns — the PSK
  example shows `Result` maps to uniform `bitstring` and failures to `bitstring_err()`,
  but confirm per-fn during M1 (may need `replace_body` on a couple of straight-line
  wrappers).
- **`missingdecl.pvl` leakage.** Const-eval (e.g. length constants) can leak libcrux
  symbols (seen in PSK). Redirect or `pv_stub("nat_lit(0)")` the length helpers; goal =
  empty `missingdecl.pvl`.
- **hax-lib rev drift.** The `hax-proverif` switch backend (`637fc91499`) and the dev
  `hax-lib` path must be the same build (rust-engine ↔ ocaml-engine version match), else
  "ocaml engine crashed". Pin both in `hax.py` and REPRODUCING notes.
- **Trait/generic surface.** `UserSecret`/`UserPublic`/`Api` are generic traits; the
  `-i` filter may pull trait machinery. Prefer concretizing roles in the harness and
  extracting concrete fns (`encrypt`, `auth_enc`) over trait methods where possible.
```
