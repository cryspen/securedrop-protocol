# SecureDrop protocol-minimal — symbolic (ProVerif) verification

Status report for the hax → ProVerif symbolic security analysis of
`securedrop-protocol-minimal`. This is a **symbolic (Dolev–Yao) analysis**: it proves
protocol-level security properties assuming cryptographic primitives are perfect. It
complements — and is independent of — the F\* track (`proofs/fstar/`, panic-freedom /
functional correctness). The F\* extraction is essentially untouched: one
semantically-equivalent refactor to `sign.rs` (to keep the opaque signing key free of
field access) changed a single extracted module (`Sign.fst`, re-committed, still verifies);
all other F\* modules are byte-identical.

- **Run it:** `make proverif-check` (engine-free — needs only a `proverif` binary).
- **Re-extract from Rust:** `make proverif-extract` (needs the `hax-proverif` opam switch).
- **Plan / history:** `proofs/proverif/PLAN.md`.

Result: **13/13 properties verified.**

---

## 1. What is translated to ProVerif, and what is assumed

**Mechanism.** The hax ProVerif backend translates the crate's **actual Rust functions**
into a ProVerif model (`extraction/lib.pvl`). At the bottom, cryptographic and
serialization "leaf" functions are redirected to a symbolic crypto library (via source
annotations gated on `cfg(hax_backend_proverif)`, invisible to normal builds / `cargo
test` / F\* extraction). Hand-written harnesses (`queries/*.pv`) then instantiate honest
participants and an active network attacker that drive those translated functions, and
ProVerif discharges each security query.

So the analysis has three layers — **only the first is *verified*; the other two are
*assumed*:**

**① Translated Rust — the verified protocol logic.** The end-to-end message flow and the
signature construction are translated from the real Rust, so their control/data flow *is*
what ProVerif checks — which key feeds which operation, the associated-data / `info`
binding, the envelope assembly, the trial-decrypt dispatch, the signing preimage:
- `encrypt_decrypt::encrypt` — submission/reply orchestration.
- `encrypt_decrypt::decrypt_with_sender` — receive orchestration (trial-decrypt → recover
  sender key from metadata → authenticated-decrypt).
- `sign` / `verify` / `tagged_preimage` — the domain-separated signing preimage.

**② Idealized cryptography — assumed perfect (standard for symbolic analysis).** Every
cryptographic operation is replaced by a perfect Dolev–Yao abstraction; ProVerif never
reasons about the primitive's internals. This covers the true leaves (Ed25519, X25519)
**and, in the current model, more than the leaves**: the SD-APKE and SD-PKE constructions
(`auth_enc`/`auth_dec`, `metadata::encrypt`/`decrypt`) are modeled **atomically** rather
than decomposed into ML-KEM ⊕ DH-AKEM ⊕ HPKE, and the fetch DH clue uses an idealized
algebra. Serialization is modeled as **identity** (byte layout unverified), and key
generation / passphrase derivation is **not translated at all**.

**③ Hand-written model — assumed faithful.** The honest-participant key model, the roles
and events, the security queries themselves, and the enrollment verification composition
(`api::verify_long_term`, which hax cannot extract) are hand-written ProVerif, trusted to
model the protocol correctly.

The precise, itemized breakdown is in **§5** (fidelity + assumptions); the trust base is
in **§4**. In short: **the protocol *composition* is verified; the crypto *primitives* and
the SD-APKE/SD-PKE/fetch *constructions* are assumed.** Lowering the ② boundary so only
true leaves are idealized is in-progress (§5a, `PLAN.md`).

---

## 2. Verified properties

At a high level, the analysis targets the security goals a SecureDrop-style system needs,
against an active network attacker and an untrusted server (§3):

- **Message confidentiality.** A source's submission — and a journalist's reply — remains
  secret; neither the network attacker nor the untrusted server learns the message.
- **Message authentication (implicit, via SD-APKE).** If a journalist accepts a message as
  coming from a given source, that source really sent it; symmetrically, a source that
  accepts a reply can be sure it came from the journalist. An attacker cannot forge or
  tamper with a message under an honest party's identity.
- **Enrollment trust chain — no rogue journalists.** A client accepts a journalist's keys
  only when the chain of trust holds: FPF (the root anchor) signed the newsroom, and the
  newsroom signed that journalist. An attacker who mints its own journalist keys and
  injects a forged enrollment cannot get a client to accept it. A companion *soundness*
  check demonstrates the newsroom-signature step is load-bearing (removing it reintroduces
  the attack — so the guarantee is not vacuous).
- **Privacy-preserving fetch.** Only the intended recipient can recover a message's id from
  the server's fetch challenges (a wrong recipient and a network eavesdropper cannot); and
  the untrusted server cannot tell **which recipient** a stored message is addressed to —
  *recipient anonymity / unlinkability*.
- **Non-vacuity (sanity).** For each authentication/secrecy goal, the honest run is shown to
  actually reach the relevant event, so the correspondence results above are not vacuously
  true.

Each row below is one ProVerif `RESULT` line (all 13 currently pass — `make proverif-check`):

| Layer | File | Property | ProVerif verdict |
|---|---|---|---|
| **Message — submission** | `submission.pv` | Submission **confidentiality** | `not attacker(SECRET_SUBMISSION) is true` |
| | | **Sender authentication** (`JournalistReceived(m,s) ⇒ SourceSubmitted(m,s)`) | `is true` |
| | | Sanity — honest receive reachable | `not event(JournalistReceived) is false` |
| **Message — reply** | `reply.pv` | Reply **confidentiality** | `not attacker(SECRET_REPLY) is true` |
| | | **Journalist authentication** (`SourceReceivedReply(m,j) ⇒ JournalistReplied(m,j)`) | `is true` |
| | | Sanity — honest reply-receive reachable | `not event(SourceReceivedReply) is false` |
| **Enrollment** | `enrollment.pv` | **Rogue journalist refuted** (`ClientAcceptedJournalist(jvk) ⇒ NewsroomSignedJournalist(jvk)`) | `is true` |
| | | Sanity — honest journalist accepted | `not event(ClientAcceptedJournalist) is false` |
| | `enrollment_soundness.pv` | Newsroom-signature check is **load-bearing** (a client that skips it accepts a rogue) | `... ⇒ NewsroomSignedJournalist is false` |
| **Fetch** | `fetch.pv` | Correctness — intended recipient recovers the id | `not event(GotA(MESSAGE_ID)) is false` |
| | | **Wrong-recipient secrecy** — B never recovers A's id | `not event(GotB(MESSAGE_ID)) is true` |
| | | Eavesdropper secrecy of the id | `not attacker(MESSAGE_ID) is true` |
| | `fetch_unlink.pv` | **Recipient anonymity / unlinkability** — server can't tell A from B | `Observational equivalence is true` |

Interpretation of ProVerif verdicts:
- `not attacker(X) is true` — the attacker can **never** derive `X` (secrecy holds).
- `A ⇒ B is true` — every run reaching `A` also reached `B` (authentication / agreement holds).
- `not event(E) is false` — `E` **is** reachable (a *sanity* check that the honest run
  actually runs and the property above is not vacuous).
- `Observational equivalence is true` — the two biprocess sides (message-to-A vs
  message-to-B) are indistinguishable to the attacker (unlinkability holds).

---

## 3. Threat model

- **Network:** a Dolev–Yao attacker fully controls the public channel — it can read,
  drop, reorder, replay, and inject arbitrary messages, and derive new terms with any
  public operation.
- **Server:** the SecureDrop server is **untrusted**. For fetch, it is modeled as
  honest-but-curious (it follows the protocol but tries to learn the recipient); the
  network attacker subsumes a fully malicious server for the message-layer properties.
- **Trust anchor:** the FPF signing key is the root of trust. Its public key is public;
  its secret key is held by an honest party and only ever signs the honest newsroom.
- **Participants:** an honest source and one or more honest journalists. The attacker may
  additionally mint its own journalist key material and attempt to enroll a **rogue
  journalist** or inject forged enrollment views.
- **Cryptography:** idealized (perfect) — see §4.

---

## 4. Trust base — what is *assumed* vs. what is *proven*

The properties in §2 are **proven** by ProVerif **relative to** the following **trusted**
components. A bug or unsound idealization in any trusted component could invalidate a
result.

### 4a. Trusted: the symbolic cryptographic model (Dolev–Yao idealization)

These are hand-written and assumed to faithfully idealize the real primitives. Perfect
cryptography is assumed — no computational, algebraic, or side-channel attacks exist
beyond the explicitly modeled equations.

| File | Idealizes | Assumption |
|---|---|---|
| `lib/primitives.pvl` (vendored) | hax prelude: channel, tuples, options, booleans, machine ints | Standard hax ProVerif prelude |
| `lib/cryptolib.pvl` (vendored) | AEAD, KDF/HKDF, DH (+commutativity), KEM, Ed25519 (EUF-CMA), serialization | Perfect AEAD; one-way KDF/hash; CDH-style DH; unforgeable signatures; injective encodings |
| `handwritten/sd_crypto.pvl` | **SD-APKE** (`sd_apke__authenc/authdec`) and **SD-PKE** (`sd_pke__enc/dec`) | SD-APKE = authenticated PKE binding sender+recipient identity; SD-PKE = confidential PKE. Modeled **atomically** (see §5). |
| `fetch.pv` / `fetch_unlink.pv` (inline) | the 3-party DH fetch clue (`gen/cluex/cluez/srvp/srvk` + `reck`) | Recipient⇄server key agreement; blinding of the recipient key. Hand-modeled (see §5). |

The vendored `lib/` copies are byte-for-byte from the hax backend
(`hax-lib/proof-libs/proverif/`); see `lib/PROVENANCE.md`.

### 4b. Trusted: the generated model + the toolchain

- `extraction/lib.pvl` is **generated by hax** from the annotated Rust. The hax ProVerif
  backend is trusted to translate Rust semantics soundly. **Caveat:** this backend is a
  work-in-progress (it prints `Experimental backend "proverif" is work in progress`) and
  is not yet upstream — see the pins in §6.
- Each `#[hax_lib::proverif::replace_body(...)]` annotation is an **assumed** claim that
  the Rust body equals the given symbolic term (an impl≈model assumption). These are the
  interface between real code and the trusted crypto model; they are listed in §5b.
- `extraction/lib.pvl.sha256` pins the generated model so drift is detected
  (`reconstruct-proverif`); the committed `lib.pvl` is what the engine-free lane checks.

### 4c. Trusted: the hand-written harness

- `handwritten/sd_model.pvl` — the honest-participant model: how a source/journalist's
  keys relate (`sd_secret`, `sd_public`, `sd_journalist`, the key-bundle model), and the
  trait-accessor meanings the extracted generic code calls. Assumed to model honest
  participants faithfully.
- `queries/*.pv` — the roles, events, top-level runs, and the security queries
  themselves. A mis-stated query proves the wrong thing; the *sanity* rows in §2 guard
  against vacuity, and `enrollment_soundness.pv` guards against a vacuous enrollment proof.

### 4d. Proven (the deliverable)

Given 4a–4c, ProVerif proves the §2 properties hold against the §3 attacker.

---

## 5. Modeling assumptions & caveats

### 5a. Fidelity: what is extracted vs. abstracted vs. harness-modeled

Three distinct categories — be precise about which is which:

**(i) Extracted as real composition** — the actual Rust control/data flow becomes the
ProVerif model; only the leaves it calls are abstracted. This is the verified
protocol/orchestration logic:
- `encrypt_decrypt::encrypt` — the submission/reply orchestration (which key goes to
  which operation, the `NR_ID` associated data, the recipient fetch-pubkey `info`, the
  `(X,Z)` fetch-hint construction, the `Envelope` assembly).
- `encrypt_decrypt::decrypt_with_sender` — the receive orchestration (trial-decrypt over
  the key-bundle list → recover the sender key from the metadata ciphertext → `auth_dec`
  with the recovered key + matching AD/info).
- `sign`/`verify` + `tagged_preimage` — the domain-separated signing-preimage composition
  `len‖tag‖msg` (only the Ed25519 op is a leaf).

**(ii) Abstracted to a symbolic primitive** (the "leaf" boundary, via `replace_body` /
opaque). This is idealized, not verified — as is standard and necessary for symbolic
analysis:
- **Crypto leaves:** `message::{auth_enc,auth_dec}` (SD-APKE modeled **atomically** —
  §5b.1), `metadata::{encrypt,decrypt}` (SD-PKE atomically), the Ed25519 `provider` op,
  the x25519 DH ops, and (in fetch) the DH clue algebra (§5b.2).
- **Serialization leaves:** `Plaintext` / `MessagePublicKey` (de)serialization → identity;
  key / ciphertext / signature / envelope types are opaque bitstrings.

**(iii) Not extracted / harness-modeled:** key generation & passphrase derivation
(`opaque`); `api::verify_long_term`/`verify_ephemeral` (blanket `impl<T>` that hax can't
extract — the harness re-expresses the composition but drives the **real extracted**
`verify`); the honest-user key model and trait accessors; the roles, events, and queries;
the enrollment process wiring + per-domain tags (§5b.3); the fetch DH clue (§5b.2).

**In progress:** pushing the leaf boundary further down — extracting `auth_enc`/`auth_dec`
(SD-APKE) and `metadata` (SD-PKE) so only ML-KEM / HPKE / X-Wing remain leaves. A probe
confirms these compositions extract with ~10 clean leaves; completing it requires
modeling the HPKE-AuthPsk + ML-KEM leaves and a hybrid-key harness (`PLAN.md`).

### 5b. Specific assumptions

1. **SD-APKE is modeled atomically.** HPKE-AuthPsk = DH-AKEM (sender auth) ⊕ ML-KEM (PSK)
   is a single symbolic primitive that captures confidentiality + sender authentication.
   The internal hybrid is *not* decomposed, so a downgrade/KCI property that depends on
   the ML-KEM vs DH-AKEM split is out of scope. (Follow-up in `PLAN.md`.)
2. **The fetch clue uses an idealized 3-party Diffie–Hellman model — this is the
   weakest-assumption part of the analysis.** The clue derives a shared key by nested
   exponentiation, `mk = g^(x·r_sk·eph)` (source ephemeral `x`, recipient fetch secret
   `r_sk`, server per-request `eph`). Two facts force a hand-written model rather than an
   extracted one:
   - hax's `crypto__dh_shared` is a **2-party** operation (`g^(a·b)` with a single
     commutativity equation) and structurally cannot express a 3-fold product.
   - Modeling real DH faithfully needs the general exponent-commutativity **equation**
     `exp(exp(b,x),y) = exp(exp(b,y),x)`; ProVerif **does not terminate** on it here
     (its equational saturation diverges). So under the faithful DH theory, ProVerif
     could not *decide* the fetch properties at all.

   `fetch.pv`/`fetch_unlink.pv` therefore replace DH with **dedicated constructors**
   (`gen`, `cluex`, `cluez`, `srvp`, `srvk`) and a **single `reduc`**,
   `reck(srvp(cluex(x),eph), r_sk) = srvk(cluez(gen(r_sk),x), eph)`, that asserts *only*
   the intended recipient⇄server key agreement. **What this abstraction does NOT capture:**
   - the **algebraic / homomorphic structure** of exponentiation — products, inverses,
     re-blinding/re-randomization of group elements, exponent cancellation, small-subgroup
     or invalid-curve behaviour. The attacker in this model can only combine clue terms
     through the one `reck` rule, not manipulate them as real group elements.
   - consequently the **recipient-unlinkability** (observational-equivalence) result is a
     symbolic **assumption of DDH-like indistinguishability**, not a derivation of it: it
     shows the honest constructors do not *syntactically* leak the recipient, but it does
     **not** rule out an attacker who exploits DH's multiplicative structure. A sound
     unlinkability guarantee would require a **computational** DDH argument, or a validated
     ProVerif equational theory (which, per the non-termination above, we could not run).

   Net: the fetch results are **relative to this idealized clue algebra**, which is a
   stronger and less-audited assumption than the standard `cryptolib` primitives used for
   the message and enrollment layers. The clue algebra is *trusted*, not derived from
   `compute_fetch_challenges`/`solve_fetch_challenges` (which are also not extracted).
3. **Domain-separated signatures: preimage extracted, tags harness-side.** `sign`/`verify`
   and `tagged_preimage` are extracted (the `len‖tag‖msg` preimage is real, only the
   Ed25519 op is a leaf). But the ProVerif backend **erases the type parameter `D`** of the
   generic `DomainTag::tag()` (it does not monomorphize), so all four domains
   (`fpf-sig-nr`/`nr-sig`/`j-sig-ltk`/`j-sig-eph`) collapse to one opaque tag in the
   extracted model. Domain **separation** is therefore restored harness-side, by signing/
   verifying a per-domain-tagged message `(TAG, msg)` on top of the extracted preimage.
4. **Serialization is abstracted to identity** for the atomic-key/plaintext types
   (`MessagePublicKey::from_bytes`, `Plaintext::{to,from}_bytes`): the byte layout is not
   modeled; round-trip is exact. Length/format-confusion attacks are therefore out of
   scope.
5. **Bounded honest topology.** Scenarios use one honest source and one honest journalist
   with a **single** ephemeral key bundle (the backend unrolls the trial-decrypt loop to a
   fixed bound of 3; a single-bundle journalist uses the first iteration). The attacker is
   unbounded (replicated), but multi-bundle / multi-journalist honest topologies are not
   exhaustively modeled.
6. **`api::verify_long_term`/`verify_ephemeral` are not extracted.** They are blanket-impl
   trait methods (`impl<T> Api for T`) that hax cannot extract (the same reason F\*
   excludes `api::**`). The client's verification *composition* is written in the harness,
   but every signature check it performs is the **extracted** `verify`.

### 5c. Out of scope

Computational security (this is symbolic); **algebraic attacks on the fetch
Diffie–Hellman clue** (the 3-party DH is idealized to a single agreement rule, not real
exponentiation — see §5b.2); timing/side channels and traffic analysis beyond the
recipient-unlinkability result; forward secrecy / post-compromise security (keys are
static here); injective agreement / replay protection (only non-injective agreement is
proven); sender-anonymity of the metadata ciphertext beyond recipient unlinkability; and
functional correctness / panic-freedom (the F\* track).

---

## 6. Reproducing the results

There are two levels. **Level 1 needs only public tools; Level 2 additionally needs the
(public but unreleased) hax ProVerif backend.**

### Level 1 — re-check the verdicts (public tools only, no hax)

The generated model (`extraction/lib.pvl`, SHA-pinned in `extraction/lib.pvl.sha256`), the
vendored symbolic libraries (`lib/{primitives,cryptolib}.pvl`), the SecureDrop crypto model
(`handwritten/*.pvl`), and every query (`queries/*.pv`) are all committed. So ProVerif
alone re-checks all 13 properties:

```sh
opam install proverif           # ProVerif 2.05 (public, INRIA); or install it any other way
# from the crate root: securedrop-protocol/protocol-minimal
make proverif-check             # runs reconstruct-proverif (digest check) + all queries
```

`make proverif-check` invokes `proverif` directly (no opam switch, no hax); if `proverif`
is only reachable via opam, use `opam exec -- make proverif-check`. This is exactly what
`.github/workflows/proverif.yml` runs on every push. Trusting (or auditing) the committed
`lib.pvl` — which carries `(* src: <file>:<line> ... *)` provenance comments and a
`lib.pvl.map` source map back to the Rust — is all Level 1 requires.

### Level 2 — re-derive the model from the Rust (needs the hax backend)

To regenerate `lib.pvl` from the Rust source rather than trust the committed snapshot:

- Build the hax ProVerif backend from **`github.com/cryspen/hax`, branch
  `proverif-rust-backend`** (draft PR **#2068**; engine used here: commit
  **`637fc91499`**). This backend is **not merged upstream and not a released tool** — it
  must be built from that branch (it prints `Experimental backend "proverif" is work in
  progress`). See that repo's `setup-local.sh` (installs into a `hax-proverif` opam switch)
  or `setup-hax.sh` (opam-free source build).
- Point `HAX_PROVERIF_DIR` at that checkout and run `make proverif-extract`, then
  `make proverif-check`. Extraction rewrites `lib.pvl` and re-pins its digest; a faithful
  re-extraction leaves the committed model unchanged.

### Pins

- **ProVerif** — 2.05.
- **hax ProVerif backend** — `cryspen/hax` @ `proverif-rust-backend` (PR #2068), engine
  commit `637fc91499`. Vendored `lib/*.pvl` are byte-copies from that tree
  (`hax-lib/proof-libs/proverif/`); see `lib/PROVENANCE.md`.
- **`hax-lib`** — crates.io `0.3.7` for normal builds; the dev `hax-lib` carrying the
  `cfg(hax_backend_proverif)`-gated macros is injected at extraction time via
  `cargo --config` (not a committed patch), so `cargo build` / CI / F\* are unaffected.
- **CI** — `.github/workflows/proverif.yml` runs Level 1 on every push (installs ProVerif
  via opam; no hax build).

## 7. Integrity guarantees of this change

- `cargo build` and `cargo test` are unaffected (all annotations are
  `cfg(hax_backend_proverif)`-gated).
- **`proofs/fstar/` is byte-identical except `Sign.fst`** — the one semantically-equivalent
  `sign.rs` refactor re-extracted that single module (re-committed; still type-checks and
  verifies). Every other F\* module and the verification pipeline are unchanged.
- Source changes are ~80 cfg-gated lines across `message.rs`, `metadata.rs`, `sign.rs`,
  `ciphertext.rs`, `keys.rs`, `primitives/x25519.rs`, plus the workspace `Cargo.toml`
  lint and the crate `Makefile` targets. Everything else is new files under
  `proofs/proverif/`.
