# SecureDrop protocol-minimal — symbolic (ProVerif) verification

Status report for the hax → ProVerif symbolic security analysis of
`securedrop-protocol-minimal`. This is a **symbolic (Dolev–Yao) analysis**: it proves
protocol-level security properties assuming cryptographic primitives are perfect. It
complements — and is independent of — the F\* track (`proofs/fstar/`, panic-freedom /
functional correctness), which is untouched by this work.

- **Run it:** `make proverif-check` (engine-free — needs only a `proverif` binary).
- **Re-extract from Rust:** `make proverif-extract` (needs the `hax-proverif` opam switch).
- **Plan / history:** `proofs/proverif/PLAN.md`.

Result: **13/13 properties verified.**

---

## 1. How it works (one paragraph)

The hax ProVerif backend lifts the crate's **actual Rust functions** into a ProVerif
model (`extraction/lib.pvl`). Cryptographic leaves are redirected to a shared symbolic
crypto library via source annotations gated on `cfg(hax_backend_proverif)` (invisible to
normal builds, `cargo test`, and F\* extraction). Hand-written ProVerif harnesses
(`queries/*.pv`) instantiate honest participants, an active network attacker, and the
security queries, calling the generated functions. ProVerif then discharges each query.

---

## 2. Verified properties (13 RESULT lines)

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

### 5a. Fidelity: what is extracted vs. hand-modeled

**Extracted from the real Rust** (the substance of the analysis):
`message::{auth_enc,auth_dec}`, `metadata::{encrypt,decrypt}`, `sign`/`verify`,
`encrypt_decrypt::encrypt`, **`encrypt_decrypt::decrypt_with_sender`** (the full receive:
trial-decrypt over the key-bundle list → recover the sender key from metadata →
`auth_dec`), the x25519 DH operations, `Plaintext` (de)serialization, and the key /
ciphertext / envelope types.

**Hand-modeled in the harness** (participants and scenarios, not crypto/protocol logic):
the honest-user key model and trait accessors; the role processes, events, and queries;
the enrollment **process wiring** and domain-separation tags (the `sign`/`verify` calls
themselves are extracted); and — the one substantive departure — the **fetch DH clue**.

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
3. **Domain-separated signatures are modeled harness-side.** The four Ed25519 domains
   (`fpf-sig-nr`, `nr-sig`, `j-sig-ltk`, `j-sig-eph`) are represented by signing/verifying
   a tagged message `(TAG, msg)`, mirroring the code's `len(tag)‖tag‖msg` preimage, rather
   than deriving the tags from the `DomainTag` impls.
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

## 6. Reproducibility & pins

- **ProVerif** — any recent 2.0x (developed against the `hax-proverif` opam switch's build).
- **hax ProVerif backend** — the `hax-proverif` opam switch / a `~/hax-proverif-backend`
  checkout (draft PR cryspen/hax#2068). Only needed to **re-extract** (`make
  proverif-extract`); the engine-free `make proverif-check` needs only `proverif`.
- **`hax-lib`** — crates.io `0.3.7` for normal builds; the dev `hax-lib` (with the
  `cfg(hax_backend_proverif)`-gated macros) is injected at extraction time via
  `cargo --config`, never as a committed patch, so `cargo build` / CI / F\* are unaffected.
- **CI** — `.github/workflows/proverif.yml` runs the engine-free lane on every push.

## 7. Integrity guarantees of this change

- `cargo build` and `cargo test` are unaffected (all annotations are
  `cfg(hax_backend_proverif)`-gated).
- **`proofs/fstar/` is byte-identical** — the F\* extraction and verification pipeline is
  untouched.
- Source changes are ~80 cfg-gated lines across `message.rs`, `metadata.rs`, `sign.rs`,
  `ciphertext.rs`, `keys.rs`, `primitives/x25519.rs`, plus the workspace `Cargo.toml`
  lint and the crate `Makefile` targets. Everything else is new files under
  `proofs/proverif/`.
