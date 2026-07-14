# Vendored ProVerif support libraries

`primitives.pvl` and `cryptolib.pvl` are **verbatim copies** of the hax ProVerif
backend's shared symbolic libraries, from:

    ~/hax-proverif-backend/hax-lib/proof-libs/proverif/{primitives,cryptolib}.pvl
    (hax ProVerif backend — draft PR cryspen/hax#2068)

They are vendored here so the ProVerif check (`hax.py check-proverif`) runs
**self-contained** — no hax checkout / opam switch required, only a `proverif`
binary. This is what the engine-free CI lane (`hax.py reconstruct-proverif`) uses,
and it also freezes the trusted crypto model so upstream changes can't silently
alter our verdicts.

- `primitives.pvl` — hax uniform-bitstring prelude (channel `c`, tuple/Option/bool
  constructors, `nat_lit`, `bitstring_err`, machine-int helpers).
- `cryptolib.pvl` — generic Dolev-Yao crypto (`crypto__aead_*`, `crypto__kdf`,
  `crypto__hkdf_*`, `crypto__dh_*`, `crypto__kem_*`, `crypto__vk_of`/`sign`/
  `sig_verify`, `crypto__serialize*`).

**Refresh** (only when the upstream shared libs change): re-copy both files from the
backend checkout, then re-run `hax.py extract-proverif && hax.py check-proverif` and
re-commit if verdicts are unchanged. The SecureDrop-specific composites live
separately in `../handwritten/{sd_crypto,sd_model}.pvl`.
