#!/usr/bin/env bash
#
# georinex — Python/atheris commit-image build. Air-gapped + idempotent (SPEC §6.2 item 9 / §6.5):
# the FIRST (online) run bakes a pip wheelhouse (atheris + georinex + its full dep closure: numpy,
# xarray, netcdf4, hatanaka, ncompress, python-dateutil, …); every later run — including the offline
# PATCH-tier re-run (`docker run --network none … bash mayhem/build.sh`) — installs from that
# wheelhouse with `pip --no-index`, so it never reaches PyPI.
#
# What it builds:
#   1. atheris + georinex (and its runtime deps) installed from the baked wheelhouse.
#   2. /mayhem/parse-load    — ELF libFuzzer launcher for mayhem/fuzz_load.py (the Mayhem target).
#   3. /mayhem/georinex-test — ELF launcher for the functional KAT (run by mayhem/test.sh).
set -euo pipefail

SRC="${SRC:-/mayhem}"
cd "$SRC"

# An empty SOURCE_DATE_EPOCH (passed through as an ARG) breaks clang — drop it if blank.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${CC:=clang}"

# Debug-info contract (§6.2 item 10): the native ELF launchers must carry DWARF < 4 so Mayhem's
# triage can read them. clang's plain `-g` emits DWARF-5 — pin DWARF-3 explicitly.
DEBUG_FLAGS="${DEBUG_FLAGS:--gdwarf-3}"

# georinex is PURE Python: the fuzzed code runs under atheris coverage instrumentation, not native
# $SANITIZER_FLAGS (which instruments C/C++). Referenced here for the build contract — there are no
# native project objects to sanitize.
: "${SANITIZER_FLAGS:=}"

# ---- air-gapped Python deps: a pip wheelhouse under /opt/toolchains (§6.5) -----------------------
WHEELHOUSE="${PIP_WHEELHOUSE:-/opt/toolchains/pip/wheelhouse}"
ATHERIS_VERSION="${ATHERIS_VERSION:-3.1.0}"
mkdir -p "$WHEELHOUSE"

# Populate the wheelhouse exactly ONCE (first, online build). The offline re-run finds it already
# populated and skips straight to the --no-index install below.
if ! ls "$WHEELHOUSE"/atheris-*.whl >/dev/null 2>&1; then
  echo "build.sh: populating wheelhouse at $WHEELHOUSE (online, first build)"
  pip wheel --wheel-dir "$WHEELHOUSE" "atheris==${ATHERIS_VERSION}"
  # georinex + its full runtime dep closure (numpy, xarray, netcdf4, hatanaka, ncompress, …),
  # built/downloaded from the local source tree.
  pip wheel --wheel-dir "$WHEELHOUSE" "$SRC"
fi

# Install from the wheelhouse ONLY — never reach PyPI. Install georinex BY NAME (not "$SRC") so pip
# picks the prebuilt wheel instead of rebuilding from source offline.
# --break-system-packages: the base python is PEP-668 externally-managed; as non-root this resolves
# to a per-user install.
pip install --no-index --find-links="$WHEELHOUSE" --break-system-packages \
  "atheris==${ATHERIS_VERSION}" georinex

python3 -c 'import atheris, georinex; print("build.sh: deps OK (atheris + georinex importable)")'

# ---- ELF libFuzzer launchers --------------------------------------------------------------------
PYBIN="$(command -v python3)"

# Mayhem fuzz target: launcher -> python3 mayhem/fuzz_load.py, forwarding libFuzzer argv.
$CC $DEBUG_FLAGS \
    -DPYTHON="\"$PYBIN\"" \
    -DSCRIPT="\"$SRC/mayhem/fuzz_load.py\"" \
    -o "$SRC/parse-load" "$SRC/mayhem/pylauncher.c"

# Functional-oracle runner: launcher -> python3 mayhem/test_kat.py. A non-system ELF (so the
# anti-reward-hack sabotage check can neuter it and the oracle is provably behavioral).
$CC $DEBUG_FLAGS \
    -DPYTHON="\"$PYBIN\"" \
    -DSCRIPT="\"$SRC/mayhem/test_kat.py\"" \
    -o "$SRC/georinex-test" "$SRC/mayhem/pylauncher.c"

chmod +x "$SRC/parse-load" "$SRC/georinex-test"
echo "build.sh: done — /mayhem/parse-load, /mayhem/georinex-test"
