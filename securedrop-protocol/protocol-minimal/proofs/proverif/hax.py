#!/usr/bin/env python3
"""ProVerif driver for securedrop-protocol-minimal (hax ProVerif backend).

Mirrors the SPQR / Mandrake flagship setups. Subcommands:

  extract-proverif   `cargo hax into -i '<targets>' proverif` -> extraction/lib.pvl
                     (injects the dev hax-lib via `cargo --config`; restores Cargo.lock)
  extract-lean       `cargo hax into aeneas-lean` (charon + aeneas) -> a Lean
                     project under ../aeneas-lean/ for the crypto core. Needs a hax
                     checkout w/ cryspen/hax#2069 + #2071 (HAX_LEAN_DIR, default ~/hax):
                     uses its cargo-hax and injects its hax-lib via a temporary
                     [patch.crates-io] (Cargo.toml/lock restored afterwards).
  verify-proverif    run ProVerif on queries/*.pv, print RESULT lines
  check-proverif     run ProVerif and assert each query's (* EXPECTPV ... END *) block
                     `check-proverif update` regenerates those blocks

Toolchain: the `hax-proverif` opam switch supplies cargo-hax + hax-rust-engine +
hax-engine + proverif. `HAX_PROVERIF_DIR` (default ~/hax-proverif-backend) supplies
the dev hax-lib (proverif macros) and the shared primitives.pvl / cryptolib.pvl.
The ProVerif annotations are gated on cfg(hax_backend_proverif), which hax sets
itself during `into proverif` — so normal builds / `into fstar` are unaffected.
"""
import argparse
import hashlib
import os
import re
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
CRATE = os.path.normpath(os.path.join(HERE, "..", ".."))  # protocol-minimal/
GEN = os.path.join(HERE, "extraction")
HANDWRITTEN = os.path.join(HERE, "handwritten")
VENDORED = os.path.join(HERE, "lib")   # vendored primitives.pvl / cryptolib.pvl
QUERIES = os.path.join(HERE, "queries")
LIB_SHA = os.path.join(GEN, "lib.pvl.sha256")

# Aeneas/Lean lane. hax's aeneas-lean backend (charon + aeneas) writes a whole Lean
# project under <crate>/proofs/aeneas-lean/. Two hax changes are needed and injected at
# extraction time (pending upstream), so the committed manifest stays on crates.io
# hax-lib 0.3.7:
#   * cryspen/hax#2069 (cargo-hax): target-side `--cfg hax` so cfg(hax)-gated deps
#     (libcrux et al.) compile under charon.
#   * cryspen/hax#2071 (hax-lib + cargo-hax): `hax_lib::opaque`/`exclude` emit charon's
#     native attributes, so `#[cfg_attr(hax_backend_lean, hax_lib::opaque)]` markers work.
# HAX_LEAN_DIR (default ~/hax) is a hax checkout carrying both: its `target/{release,
# debug}/cargo-hax` is used, and its hax-lib is injected via a temporary
# [patch.crates-io] (charon does not honor hax's `-C` config, so we patch the manifest).
LEAN_DIR = os.path.normpath(os.path.join(CRATE, "proofs", "aeneas-lean"))
WS = os.path.normpath(os.path.join(CRATE, ".."))   # workspace root (holds Cargo.toml/lock)
HAX_LEAN_DIR = os.environ.get("HAX_LEAN_DIR", os.path.expanduser("~/hax"))

# Crypto core to extract, mirroring the ProVerif targets: SD-APKE (message), SD-PKE
# (metadata), Ed25519 domain-separated signing (sign), and envelope encrypt/decrypt.
# charon translates each item's transitive closure; aeneas-hostile helpers inside it
# (the `&'static` domain tags, the trial-decryption loop) carry
# `#[cfg_attr(hax_backend_lean, hax_lib::opaque)]`. `--charon-args` overrides this.
LEAN_START_FROM = [
    "securedrop_protocol_minimal::message",
    "securedrop_protocol_minimal::metadata",
    "securedrop_protocol_minimal::sign",
    "securedrop_protocol_minimal::encrypt_decrypt::encrypt",
    "securedrop_protocol_minimal::encrypt_decrypt::decrypt",
    "securedrop_protocol_minimal::encrypt_decrypt::decrypt_with_sender",
]

HAX_PROVERIF_DIR = os.environ.get(
    "HAX_PROVERIF_DIR", os.path.expanduser("~/hax-proverif-backend")
)
HAX_OPAM_SWITCH = os.environ.get("HAX_OPAM_SWITCH", "hax-proverif")


def _pvlib_dir():
    """Directory holding primitives.pvl / cryptolib.pvl: the vendored in-repo copy
    (self-contained, engine-free CI) if present, else the hax checkout."""
    if os.path.exists(os.path.join(VENDORED, "primitives.pvl")):
        return VENDORED
    return os.path.join(HAX_PROVERIF_DIR, "hax-lib", "proof-libs", "proverif")

# ProVerif extraction roots. `-**` drops everything; each `+` re-selects a protocol
# entry point and pulls in its transitive closure. Crypto leaves are redirected to
# the symbolic model by source-level cfg(hax_backend_proverif) `replace_body`
# annotations, so their libcrux/hpke internals never reach lib.pvl.
PROVERIF_INCLUDE = " ".join([
    "-**",
    "+securedrop_protocol_minimal::encrypt_decrypt::encrypt",
    "+securedrop_protocol_minimal::encrypt_decrypt::decrypt_with_sender",
    "+securedrop_protocol_minimal::message::auth_enc",
    "+securedrop_protocol_minimal::message::auth_dec",
    "+securedrop_protocol_minimal::metadata::encrypt",
    "+securedrop_protocol_minimal::metadata::decrypt",
    "+securedrop_protocol_minimal::sign::**::sign",
    "+securedrop_protocol_minimal::sign::**::verify",
])

# -lib load order (declare-before-use): generic prelude -> generic crypto ->
# SecureDrop composites -> diagnostic stubs -> generated model -> query file.
def proverif_libs():
    pvlib = _pvlib_dir()
    return [
        "-lib", os.path.join(pvlib, "primitives"),
        "-lib", os.path.join(pvlib, "cryptolib"),
        "-lib", os.path.join(HANDWRITTEN, "sd_crypto"),
        "-lib", os.path.join(HANDWRITTEN, "sd_model"),
        "-lib", os.path.join(GEN, "missingdecl"),
        "-lib", os.path.join(GEN, "lib"),
    ]


def opam_prefix():
    """Command prefix that runs the wrapped command with the hax-proverif switch env
    (cargo-hax + hax-rust-engine + hax-engine on PATH). `opam exec` preserves the base
    PATH, so system cargo / proverif stay available. If opam isn't on PATH we assume
    the caller already `eval`'d the switch env."""
    if _has(["opam", "--version"]):
        return ["opam", "exec", "--switch", HAX_OPAM_SWITCH, "--"]
    return []


def _has(cmd):
    try:
        subprocess.run(cmd, capture_output=True)
        return True
    except FileNotFoundError:
        return False


def child_env():
    env = dict(os.environ)
    env["HAX_PROVERIF_DIR"] = HAX_PROVERIF_DIR
    return env


def cmd_extract(args):
    env = child_env()
    include = args.include if args.include else PROVERIF_INCLUDE
    # Inject the dev hax-lib (proverif macros) via `cargo --config`, NOT a committed
    # [patch.crates-io], so normal builds / CI stay on crates.io hax-lib 0.3.7.
    lib = os.path.join(HAX_PROVERIF_DIR, "hax-lib")
    patch = []
    for crate, path in [
        ("hax-lib", lib),
        ("hax-lib-macros", os.path.join(lib, "macros")),
        ("hax-lib-macros-types", os.path.join(lib, "macros", "types")),
    ]:
        patch += ["--config", 'patch.crates-io."{}".path="{}"'.format(crate, path)]
    # The --config patch rewrites hax-lib's Cargo.lock entry; preserve the committed lock.
    lock = os.path.join(CRATE, "Cargo.lock")
    ws_lock = os.path.normpath(os.path.join(CRATE, "..", "Cargo.lock"))
    backups = {}
    for p in (lock, ws_lock):
        if os.path.exists(p):
            with open(p, "rb") as f:
                backups[p] = f.read()
    try:
        rc = subprocess.run(
            opam_prefix() + ["cargo", "hax", "-C"] + patch + [";", "into", "-i", include, "proverif"],
            cwd=CRATE, env=env,
        ).returncode
    finally:
        for p, data in backups.items():
            with open(p, "wb") as f:
                f.write(data)
    # Pin the generated snapshot so the engine-free `reconstruct-proverif` lane can
    # detect drift (SPQR pattern).
    lib = os.path.join(GEN, "lib.pvl")
    if os.path.exists(lib):
        with open(LIB_SHA, "w") as f:
            f.write(_sha256(lib) + "  lib.pvl\n")
    # cargo-hax exits nonzero on diagnostics but still writes output; filter + report.
    md = os.path.join(GEN, "missingdecl.pvl")
    if os.path.exists(md):
        _filter_missingdecl(md)
        leaked = [l for l in open(md).read().splitlines()
                  if l.strip() and not l.strip().startswith("(*")
                  and "string_lit__" not in l]
        print("\n== missingdecl.pvl: {} non-string-literal external(s) ==".format(len(leaked)))
        for l in leaked:
            print("  " + l)
        if not leaked:
            print("  (clean — only benign string literals remain)")
    return rc


def _inject_hax_lib_patch():
    """Add a temporary [patch.crates-io] to the workspace manifest pointing hax-lib at
    HAX_LEAN_DIR, so charon compiles against the dev hax-lib (charon ignores hax's `-C`
    config, so unlike the ProVerif lane we patch the manifest). Returns {path: original}
    backups (Cargo.toml + Cargo.lock) for the caller to restore; empty if already patched."""
    lib = os.path.join(HAX_LEAN_DIR, "hax-lib")
    entries = (
        'hax-lib = {{ path = "{0}" }}\n'
        'hax-lib-macros = {{ path = "{0}/macros" }}\n'
        'hax-lib-macros-types = {{ path = "{0}/macros/types" }}\n'
    ).format(lib)
    ws_toml = os.path.join(WS, "Cargo.toml")
    ws_lock = os.path.join(WS, "Cargo.lock")
    backups = {p: open(p).read() for p in (ws_toml, ws_lock) if os.path.exists(p)}
    text = backups.get(ws_toml, "")
    if "hax-lib = { path" in text:
        return {}  # already patched (e.g. re-entrant); leave as-is
    marker = "[patch.crates-io]\n"
    text = text.replace(marker, marker + entries, 1) if marker in text \
        else text + "\n" + marker + entries
    with open(ws_toml, "w") as f:
        f.write(text)
    return backups


def cmd_extract_lean(args):
    """Aeneas/Lean lane: `cargo hax into aeneas-lean` runs charon then aeneas to lift the
    Rust into a Lean project under ../aeneas-lean/. Extracts the crypto-core closure
    (LEAN_START_FROM); aeneas-hostile helpers are gated opaque via
    `#[cfg_attr(hax_backend_lean, hax_lib::opaque)]`. Needs a hax checkout with
    cryspen/hax#2069 + #2071 (HAX_LEAN_DIR): its cargo-hax is put on PATH and its hax-lib
    injected as a temporary [patch.crates-io] (Cargo.toml/lock restored afterwards)."""
    env = dict(os.environ)
    # Put HAX_LEAN_DIR's cargo-hax on PATH — the most recently built of release/debug,
    # so a stale build in the other profile can't shadow a fresh one.
    cands = [os.path.join(HAX_LEAN_DIR, "target", s, "cargo-hax") for s in ("release", "debug")]
    cands = [c for c in cands if os.path.exists(c)]
    if cands:
        newest = max(cands, key=os.path.getmtime)
        env["PATH"] = os.path.dirname(newest) + os.pathsep + env.get("PATH", "")
    charon = args.charon_args or " ".join("--start-from " + t for t in LEAN_START_FROM)
    cmd = ["cargo", "hax", "into", "aeneas-lean"]
    if not args.no_lakefile:
        # Idempotent: scaffolds lakefile.toml + lean-toolchain, never overwriting edits.
        cmd += ["--lakefile"]
    # `--flag=value` form: values start with `--` (`--start-from ...`), which the
    # space-separated form would mis-parse as new flags.
    cmd += ["--charon-args=" + charon]
    if args.aeneas_args:
        cmd += ["--aeneas-args=" + args.aeneas_args]
    backups = _inject_hax_lib_patch()
    try:
        rc = subprocess.run(cmd, cwd=CRATE, env=env).returncode
    finally:
        for p, data in backups.items():
            with open(p, "w") as f:
                f.write(data)
    # Report the .lean files aeneas produced (nested under a Lean-package dir).
    leans = sorted(
        os.path.relpath(os.path.join(root, f), LEAN_DIR)
        for root, _dirs, files in os.walk(LEAN_DIR)
        for f in files if f.endswith(".lean")
    )
    where = os.path.relpath(LEAN_DIR, HERE)
    if leans:
        print("\n== aeneas-lean: {} .lean file(s) under {} ==".format(len(leans), where))
        for f in leans:
            print("  " + f)
    else:
        print("\n== aeneas-lean: no .lean produced under {} (see errors above) ==".format(where))
    return rc


# Names of symbols the extracted model references but that are DEFINED by our
# hand-written libs (sd_crypto.pvl, sd_model.pvl). hax can't see those definitions,
# so it lists them in missingdecl.pvl; leaving them there would double-declare the
# symbol at ProVerif load time. Strip them (mandrake computes missingdecl the same
# way: "referenced but not defined by ANY loaded lib").
_DECL_RE = re.compile(r"^\s*(?:fun|letfun|const)\s+([A-Za-z_][A-Za-z0-9_]*)")
_REDUC_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*\(")


def _handwritten_defined():
    # Names DEFINED by any lib loaded alongside the model: our handwritten libs AND
    # the vendored primitives/cryptolib. hax only excludes `fun`/`const` decls from
    # missingdecl, not `reduc`-defined destructors (e.g. Tuple2__0/1 live in
    # primitives.pvl as reducs), so those leak in and would double-declare. Drop them.
    names = set()
    scan = []
    if os.path.isdir(HANDWRITTEN):
        scan += [os.path.join(HANDWRITTEN, f) for f in os.listdir(HANDWRITTEN) if f.endswith(".pvl")]
    pvlib = _pvlib_dir()
    scan += [os.path.join(pvlib, f) for f in ("primitives.pvl", "cryptolib.pvl")
             if os.path.exists(os.path.join(pvlib, f))]
    for path in scan:
        text = open(path).read()
        # fun / letfun / const declarations (line-based)
        for line in text.splitlines():
            m = _DECL_RE.match(line.strip())
            if m:
                names.add(m.group(1))
        # reduc destructor heads: `reduc forall ...; NAME(pat) = rhs.` — the head
        # NAME may sit on a later line than `reduc`, so scan each reduc statement.
        for chunk in text.split("reduc")[1:]:
            semi = chunk.find(";")
            seg = chunk[semi + 1:] if semi >= 0 else chunk
            mm = _REDUC_RE.search(seg)
            if mm:
                names.add(mm.group(1))
    return names


def _filter_missingdecl(md):
    defined = _handwritten_defined()
    kept = []
    for line in open(md).read().splitlines():
        m = _DECL_RE.match(line.strip())
        if m and m.group(1) in defined:
            continue  # defined by a handwritten lib; drop the redundant stub
        kept.append(line)
    with open(md, "w") as f:
        f.write("\n".join(kept) + "\n")


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def cmd_reconstruct(args):
    """Engine-free CI lane: confirm the committed lib.pvl snapshot is intact (matches
    its pinned digest) so ProVerif runs against a known model without rebuilding hax."""
    lib = os.path.join(GEN, "lib.pvl")
    if not os.path.exists(lib):
        print("ERROR: {} missing — run extract-proverif first.".format(lib))
        return 1
    if not os.path.exists(LIB_SHA):
        print("ERROR: {} missing — run extract-proverif to pin it.".format(LIB_SHA))
        return 1
    want = open(LIB_SHA).read().split()[0]
    got = _sha256(lib)
    if want != got:
        print("MISMATCH: lib.pvl digest\n  pinned:  {}\n  current: {}".format(want, got))
        print("The committed model drifted from its pin. Re-run extract-proverif and "
              "re-verify verdicts before committing.")
        return 1
    pvlib = _pvlib_dir()
    print("reconstruct-proverif: lib.pvl matches pin ({}…); libs from {}.".format(
        got[:12], "vendored lib/" if pvlib == VENDORED else pvlib))
    return 0


_EXPECTPV_RE = re.compile(r"\(\*\s*EXPECTPV\b.*?\bEND\s*\*\)", re.DOTALL)


def _proverif_prefix():
    # ProVerif is a plain binary — the check/verify lanes must NOT depend on the
    # hax-proverif opam switch (CI installs only `proverif`). Use it directly if on
    # PATH; else fall back to the switch (local dev where it lives only there).
    return [] if shutil.which("proverif") else opam_prefix()


def _run_proverif(env, query):
    cmd = _proverif_prefix() + ["proverif"] + proverif_libs() + [os.path.join(QUERIES, query)]
    out = subprocess.run(cmd, cwd=HERE, env=env, capture_output=True, text=True)
    combined = out.stdout + out.stderr
    return combined, [l.strip() for l in combined.splitlines() if l.strip().startswith("RESULT")]


def _expected(query):
    text = open(os.path.join(QUERIES, query)).read()
    m = _EXPECTPV_RE.search(text)
    if not m:
        return None
    return [l.strip() for l in m.group(0).splitlines() if l.strip().startswith("RESULT")]


def _queries():
    if not os.path.isdir(QUERIES):
        return []
    return sorted(f for f in os.listdir(QUERIES) if f.endswith(".pv"))


def cmd_verify(args):
    env = child_env()
    targets = args.queries if args.queries else _queries()
    for q in targets:
        combined, results = _run_proverif(env, q)
        print("== {} ==".format(q))
        for r in results:
            print("  " + r)
    return 0


def cmd_check(args):
    env = child_env()
    targets = args.queries if args.queries else _queries()
    grand_ok = grand_total = 0
    failed = False
    for q in targets:
        combined, actual = _run_proverif(env, q)
        if args.update:
            _write_expectpv(q, actual)
            print("  {:<28} updated ({} RESULT lines)".format(q, len(actual)))
            continue
        expected = _expected(q)
        if expected is None:
            print("  {:<28} NO EXPECTPV BLOCK".format(q))
            failed = True
            continue
        n = min(len(expected), len(actual))
        ok = sum(1 for i in range(n) if expected[i] == actual[i])
        file_ok = len(expected) == len(actual) and ok == len(expected)
        grand_ok += ok
        grand_total += len(expected)
        failed = failed or not file_ok
        print("  {:<28} {}/{} match   [{}]".format(q, ok, len(expected), "OK" if file_ok else "FAIL"))
        if not file_ok:
            for i in range(max(len(expected), len(actual))):
                e = expected[i] if i < len(expected) else "(none)"
                a = actual[i] if i < len(actual) else "(none)"
                if e != a:
                    print("      exp: {}\n      got: {}".format(e, a))
    if args.update:
        return 0
    print("\n{}/{} RESULT lines match EXPECTPV.".format(grand_ok, grand_total))
    if failed:
        print("CHECK FAILED.")
        return 1
    print("CHECK PASSED.")
    return 0


def _write_expectpv(query, actual):
    path = os.path.join(QUERIES, query)
    text = open(path).read()
    block = "(* EXPECTPV\n" + "\n".join(actual) + "\nEND *)"
    if _EXPECTPV_RE.search(text):
        text = _EXPECTPV_RE.sub(block, text)
    else:
        text = text.rstrip() + "\n\n" + block + "\n"
    with open(path, "w") as f:
        f.write(text)


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    e = sub.add_parser("extract-proverif", help="cargo hax into proverif -> extraction/lib.pvl")
    e.add_argument("--include", help="override the -i target filter")
    e.set_defaults(func=cmd_extract)

    ln = sub.add_parser("extract-lean",
                        help="cargo hax into aeneas-lean -> Lean project under ../aeneas-lean/")
    ln.add_argument("--no-lakefile", action="store_true",
                    help="don't scaffold lakefile.toml / lean-toolchain in ../aeneas-lean/")
    ln.add_argument("--charon-args",
                    help="override the default crypto-core --start-from set (shell-quoted)")
    ln.add_argument("--aeneas-args", help="extra args forwarded to aeneas (shell-quoted)")
    ln.set_defaults(func=cmd_extract_lean)

    r = sub.add_parser("reconstruct-proverif",
                       help="engine-free: verify the committed lib.pvl snapshot digest")
    r.set_defaults(func=cmd_reconstruct)

    v = sub.add_parser("verify-proverif", help="run ProVerif, print RESULT lines")
    v.add_argument("queries", nargs="*", help="query files (default: all queries/*.pv)")
    v.set_defaults(func=cmd_verify)

    c = sub.add_parser("check-proverif", help="run ProVerif, assert EXPECTPV blocks")
    c.add_argument("--update", action="store_true", help="regenerate EXPECTPV blocks")
    c.add_argument("queries", nargs="*", help="query files (default: all queries/*.pv)")
    c.set_defaults(func=cmd_check)

    args = p.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
