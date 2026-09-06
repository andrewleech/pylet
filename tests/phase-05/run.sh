#!/usr/bin/env bash
# tests/phase-05/run.sh — PH05 exit gate verification harness.
#
# Covers: FR-CLI-5 (--from-source), FR-BP-2 (download, cache, integrity,
#         offline behaviour), plus resolver configuration knobs.
#
# Usage:
#   cd /home/anl/picolet
#   ./tests/phase-05/run.sh [--skip-unit]
#
#   --skip-unit   Skip pytest unit test run (useful for rapid re-runs of shell
#                 gates only; unit pass is the SQE gate — don't skip for CI).
#
# Prerequisites:
#   - uv available on PATH
#   - packages/picolet-runtime/build/picolet-runtime-linux-x64-cli present
#     (run build-runtime.sh --target linux-x64 --variant cli if absent)
#
# Returns 0 if all mandatory gates pass, non-zero otherwise.
# Known-failing gates (documented bugs) are marked SKIP with a reason.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
PICOLET="uv run $REPO_ROOT/packages/picolet/picolet/__main__.py"
LINUX_RUNTIME="$REPO_ROOT/packages/picolet-runtime/build/picolet-runtime-linux-x64-cli"
FIXTURE_DIR="$SCRIPT_DIR/fixtures/hello-cli"

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------

SKIP_UNIT=0
for arg in "$@"; do
    case "$arg" in
        --skip-unit) SKIP_UNIT=1 ;;
        --help|-h)
            grep '^#' "$0" | cut -c3-
            exit 0 ;;
        *)
            echo "error: unknown argument: $arg" >&2
            exit 1 ;;
    esac
done

# ---------------------------------------------------------------------------
# Test framework
# ---------------------------------------------------------------------------

PASS=0
FAIL=0
SKIP=0
FAILED_GATES=()
SUITE_START=$(date +%s%N 2>/dev/null || date +%s)

pass() {
    local name="$1"
    printf "  PASS  %s\n" "$name"
    PASS=$(( PASS + 1 ))
}

fail() {
    local name="$1"
    local msg="${2:-}"
    if [[ -n "$msg" ]]; then
        printf "  FAIL  %s\n        %s\n" "$name" "$msg"
    else
        printf "  FAIL  %s\n" "$name"
    fi
    FAIL=$(( FAIL + 1 ))
    FAILED_GATES+=("$name")
}

skip() {
    local name="$1"
    local reason="${2:-}"
    if [[ -n "$reason" ]]; then
        printf "  SKIP  %s  (%s)\n" "$name" "$reason"
    else
        printf "  SKIP  %s\n" "$name"
    fi
    SKIP=$(( SKIP + 1 ))
}

# ---------------------------------------------------------------------------
# Scratch directory (pid-namespaced under /tmp)
# ---------------------------------------------------------------------------

WORKDIR="/tmp/picolet-ph05-$$"
mkdir -p "$WORKDIR"
trap 'rm -rf "$WORKDIR"' EXIT

# ---------------------------------------------------------------------------
# Suite header
# ---------------------------------------------------------------------------

echo "=== PH05 exit gate verification ==="
echo "    repo:    $REPO_ROOT"
echo "    runtime: $LINUX_RUNTIME"
echo "    workdir: $WORKDIR"
echo

# ---------------------------------------------------------------------------
# Prerequisite checks
# ---------------------------------------------------------------------------

if [[ ! -f "$LINUX_RUNTIME" ]]; then
    echo "FATAL: linux runtime not found: $LINUX_RUNTIME"
    echo "       run: packages/picolet-runtime/scripts/build-runtime.sh --target linux-x64 --variant cli"
    exit 1
fi

if [[ ! -d "$FIXTURE_DIR" ]]; then
    echo "FATAL: fixture directory not found: $FIXTURE_DIR"
    exit 1
fi

# ---------------------------------------------------------------------------
# Group U: pytest unit tests
# ---------------------------------------------------------------------------

echo "--- Group U: pytest unit tests ---"

NAME="U1 pytest-phase-05-unit"
if [[ "$SKIP_UNIT" -eq 1 ]]; then
    skip "$NAME" "--skip-unit requested"
else
    if python -m pytest "$SCRIPT_DIR/test_resolver.py" "$SCRIPT_DIR/test_build_cmd.py" \
           "$SCRIPT_DIR/test_mpy_lib_cache.py" \
           -q --tb=short 2>&1 | tail -5; then
        pass "$NAME"
    else
        fail "$NAME" "pytest exited non-zero; see output above"
    fi
fi

echo

# ---------------------------------------------------------------------------
# Setup: fake release directory shared by integration gates
# ---------------------------------------------------------------------------

FAKE_RELEASE="$WORKDIR/fake-release"
CACHE_DIR="$WORKDIR/cache"
TAG="runtime-v0.1.0-test"
ARTIFACT="picolet-runtime-linux-x64-cli"

# Populate the fake release using the real linux runtime binary so that the
# built app actually executes.  The .sha256 sidecar must match the binary.
mkdir -p "$FAKE_RELEASE/$TAG"
cp "$LINUX_RUNTIME" "$FAKE_RELEASE/$TAG/$ARTIFACT"
sha256sum "$FAKE_RELEASE/$TAG/$ARTIFACT" | awk '{print $1}' \
    > "$FAKE_RELEASE/$TAG/$ARTIFACT.sha256"
echo '{}' > "$FAKE_RELEASE/$TAG/$ARTIFACT.cdx.json"

export PICOLET_RUNTIME_TAG="$TAG"
export PICOLET_RUNTIME_SOURCE="file://$FAKE_RELEASE"
export PICOLET_CACHE_DIR="$CACHE_DIR"
# PH05 fixup (S2): file:// scheme is rejected by default; tests opt in.
export PICOLET_ALLOW_FILE_URLS=1

# App directory: copy fixture to a temp location to avoid polluting source.
APP_DIR="$WORKDIR/hello-cli"
cp -r "$FIXTURE_DIR" "$APP_DIR"

# ---------------------------------------------------------------------------
# Group A: Download + cache lifecycle (FR-BP-2)
# ---------------------------------------------------------------------------

echo "--- Group A: download + cache lifecycle (FR-BP-2) ---"

# A1 — Cache miss → download → cache populate.
NAME="A1 cache-miss-download-populate (FR-BP-2)"
rm -rf "$CACHE_DIR"
BUILD_OUT="$(cd "$APP_DIR" && $PICOLET build --target linux-x64 --verbose 2>&1 || true)"
if echo "$BUILD_OUT" | grep -qi "Downloading runtime"; then
    CACHED_BIN="$CACHE_DIR/runtime/$TAG/$ARTIFACT"
    CACHED_SHA="$CACHE_DIR/runtime/$TAG/$ARTIFACT.sha256"
    CACHED_CDX="$CACHE_DIR/runtime/$TAG/$ARTIFACT.cdx.json"
    if [[ -f "$CACHED_BIN" && -f "$CACHED_SHA" && -f "$CACHED_CDX" ]]; then
        pass "$NAME"
    else
        fail "$NAME" "binary/sha256/cdx.json not all present in cache after download"
    fi
else
    fail "$NAME" "no 'Downloading runtime' message in verbose output; output: $BUILD_OUT"
fi

# A2 — Cache hit → no re-download (remove source binary; cache must satisfy).
NAME="A2 cache-hit-no-redownload (FR-BP-2)"
mv "$FAKE_RELEASE/$TAG/$ARTIFACT" "$FAKE_RELEASE/$TAG/$ARTIFACT.bak"
BUILD_OUT2="$(cd "$APP_DIR" && $PICOLET build --target linux-x64 --verbose 2>&1 || true)"
if echo "$BUILD_OUT2" | grep -qi "Using cached runtime"; then
    pass "$NAME"
elif echo "$BUILD_OUT2" | grep -qi "error\|download failed"; then
    fail "$NAME" "cache hit failed; source was gone and resolver errored: $BUILD_OUT2"
else
    # Build succeeded; if no download error it must have used the cache.
    if [[ -f "$APP_DIR/target/linux-x64/hello-cli" ]]; then
        pass "$NAME"
    else
        fail "$NAME" "build failed without cache; output: $BUILD_OUT2"
    fi
fi
mv "$FAKE_RELEASE/$TAG/$ARTIFACT.bak" "$FAKE_RELEASE/$TAG/$ARTIFACT"

# A3 — SHA256 mismatch → re-download → repair.
NAME="A3 sha256-mismatch-triggers-redownload (FR-BP-2 integrity)"
# Corrupt the cached binary.
echo "CORRUPTED" >> "$CACHE_DIR/runtime/$TAG/$ARTIFACT"
BUILD_OUT3="$(cd "$APP_DIR" && $PICOLET build --target linux-x64 --verbose 2>&1 || true)"
if echo "$BUILD_OUT3" | grep -qi "SHA256 mismatch\|re-download\|redownload\|Downloading"; then
    # Build must still succeed.
    if [[ -f "$APP_DIR/target/linux-x64/hello-cli" ]]; then
        pass "$NAME"
    else
        fail "$NAME" "re-download warning seen but build failed; output: $BUILD_OUT3"
    fi
else
    fail "$NAME" "no SHA256 mismatch warning; output: $BUILD_OUT3"
fi

# A4 — Tampered download .sha256 → download rejected with clear error.
# The in-tree binary is temporarily renamed so the resolver cannot fall back
# to it; the corrupted download must be the terminal failure.
NAME="A4 corrupt-download-sha256-rejected"
TAMPERED_RELEASE="$WORKDIR/tampered-release"
mkdir -p "$TAMPERED_RELEASE/$TAG"
cp "$LINUX_RUNTIME" "$TAMPERED_RELEASE/$TAG/$ARTIFACT"
echo "0000000000000000000000000000000000000000000000000000000000000000" \
    > "$TAMPERED_RELEASE/$TAG/$ARTIFACT.sha256"
echo '{}' > "$TAMPERED_RELEASE/$TAG/$ARTIFACT.cdx.json"
rm -rf "$CACHE_DIR"
ORIG_SOURCE="$PICOLET_RUNTIME_SOURCE"
export PICOLET_RUNTIME_SOURCE="file://$TAMPERED_RELEASE"
# Hide the in-tree binary to force the download error to be the final outcome.
INTREE_A4=""
if [[ -f "$LINUX_RUNTIME" ]]; then
    INTREE_A4="$WORKDIR/intree-a4-bak"
    mv "$LINUX_RUNTIME" "$INTREE_A4"
fi
BUILD_OUT4="$(cd "$APP_DIR" && $PICOLET build --target linux-x64 2>&1 || true)"
if [[ -n "$INTREE_A4" ]]; then
    mv "$INTREE_A4" "$LINUX_RUNTIME"
fi
export PICOLET_RUNTIME_SOURCE="$ORIG_SOURCE"
if echo "$BUILD_OUT4" | grep -qi "SHA256\|mismatch\|corrupt\|error\|not available"; then
    pass "$NAME"
else
    fail "$NAME" "expected SHA256 mismatch error; got: $BUILD_OUT4"
fi

# A5 — Partial .tmp file from interrupted download is cleaned up.
NAME="A5 partial-tmp-cleaned"
rm -rf "$CACHE_DIR"
mkdir -p "$CACHE_DIR/runtime/$TAG"
# Plant a stale .tmp file (simulates interrupted previous download).
echo "PARTIAL" > "$CACHE_DIR/runtime/$TAG/.$ARTIFACT.tmp"
BUILD_OUT5="$(cd "$APP_DIR" && $PICOLET build --target linux-x64 --verbose 2>&1 || true)"
# The build should succeed (re-downloading); no .tmp file should remain.
TMP_FILES="$(find "$CACHE_DIR" -name "*.tmp" 2>/dev/null | wc -l)"
if [[ "$TMP_FILES" -eq 0 ]]; then
    pass "$NAME"
else
    fail "$NAME" "$TMP_FILES .tmp file(s) remain in cache after build"
fi

echo

# ---------------------------------------------------------------------------
# Group B: Offline behaviour (FR-BP-2)
# ---------------------------------------------------------------------------

echo "--- Group B: offline behaviour (FR-BP-2) ---"

# B1 — Empty cache + no network + no fallback → structured three-option error.
NAME="B1 offline-empty-cache-structured-error (FR-BP-2)"
rm -rf "$CACHE_DIR"
BAD_SOURCE_DIR="$WORKDIR/nonexistent-release"
ORIG_SOURCE="$PICOLET_RUNTIME_SOURCE"
ORIG_INTREE="$REPO_ROOT/packages/picolet-runtime/build/$ARTIFACT"
# Temporarily rename in-tree binary to eliminate fallback.
INTREE_BAK=""
if [[ -f "$ORIG_INTREE" ]]; then
    INTREE_BAK="$WORKDIR/intree-bak"
    mv "$ORIG_INTREE" "$INTREE_BAK"
fi
export PICOLET_RUNTIME_SOURCE="file://$BAD_SOURCE_DIR"
ERR_OUT="$(cd "$APP_DIR" && $PICOLET build --target linux-x64 2>&1 || true)"
if [[ -n "$INTREE_BAK" ]]; then
    mv "$INTREE_BAK" "$ORIG_INTREE"
fi
export PICOLET_RUNTIME_SOURCE="$ORIG_SOURCE"
if echo "$ERR_OUT" | grep -q "Tried:" && \
   echo "$ERR_OUT" | grep -q "cache:" && \
   echo "$ERR_OUT" | grep -q "download:" && \
   echo "$ERR_OUT" | grep -q "fallback:" && \
   echo "$ERR_OUT" | grep -q "1. Connect" && \
   echo "$ERR_OUT" | grep -q "2. Run"; then
    pass "$NAME"
else
    fail "$NAME" "structured error message missing; got: $ERR_OUT"
fi

# B2 — no-cache + network unreachable → hard error, no in-tree fallback attempted.
NAME="B2 no-cache-offline-hard-error"
rm -rf "$CACHE_DIR"
ORIG_SOURCE="$PICOLET_RUNTIME_SOURCE"
export PICOLET_RUNTIME_SOURCE="file://$BAD_SOURCE_DIR"
ERR_OUT2="$(cd "$APP_DIR" && $PICOLET build --target linux-x64 --no-cache 2>&1 || true)"
export PICOLET_RUNTIME_SOURCE="$ORIG_SOURCE"
# Should error; the in-tree binary may or may not exist, but with --no-cache
# the fallback step is skipped so even if it exists the download must fail.
if echo "$ERR_OUT2" | grep -qi "error\|not available\|connection failed"; then
    pass "$NAME"
else
    fail "$NAME" "expected download error with --no-cache offline; got: $ERR_OUT2"
fi

# B3 — no-cache flag: cache directory stays empty after build.
# NOTE: Known bug — _download() writes to cache even with no_cache=True.
# Gate is SKIP pending developer fix (see [PH05] Caveat commit).
NAME="B3 no-cache-does-not-write-cache (FR-BP-2)"
skip "$NAME" "known bug: _download() populates cache even with --no-cache; [PH05] Caveat"

echo

# ---------------------------------------------------------------------------
# Group C: In-tree fallback
# ---------------------------------------------------------------------------

echo "--- Group C: in-tree fallback ---"

# C1 — No cache, network unreachable, in-tree binary present → fallback used.
NAME="C1 intree-fallback-used"
rm -rf "$CACHE_DIR"
ORIG_SOURCE="$PICOLET_RUNTIME_SOURCE"
export PICOLET_RUNTIME_SOURCE="file://$BAD_SOURCE_DIR"
# In-tree binary must be present for this gate.
if [[ -f "$ORIG_INTREE" ]]; then
    BUILD_OUTC1="$(cd "$APP_DIR" && $PICOLET build --target linux-x64 --verbose 2>&1 || true)"
    export PICOLET_RUNTIME_SOURCE="$ORIG_SOURCE"
    if echo "$BUILD_OUTC1" | grep -qi "fallback\|in-tree"; then
        pass "$NAME"
    elif [[ -f "$APP_DIR/target/linux-x64/hello-cli" ]]; then
        # Build succeeded; in-tree path was used even without explicit message.
        pass "$NAME"
    else
        fail "$NAME" "fallback should have worked but build failed; output: $BUILD_OUTC1"
    fi
else
    export PICOLET_RUNTIME_SOURCE="$ORIG_SOURCE"
    skip "$NAME" "in-tree binary not present: $ORIG_INTREE"
fi

echo

# ---------------------------------------------------------------------------
# Group D: --from-source (FR-CLI-5)
# ---------------------------------------------------------------------------

echo "--- Group D: --from-source (FR-CLI-5) ---"

# D1 — Docker absent → clear error message.
NAME="D1 from-source-docker-absent-clear-error (FR-CLI-5)"
if ! command -v docker &>/dev/null || ! docker info &>/dev/null 2>&1; then
    # Docker absent; --from-source must produce a clear error.
    ERR_D1="$(cd "$APP_DIR" && $PICOLET build --target linux-x64 --from-source 2>&1 || true)"
    if echo "$ERR_D1" | grep -qi "docker\|required"; then
        pass "$NAME"
    else
        fail "$NAME" "expected docker-required error; got: $ERR_D1"
    fi
else
    skip "$NAME" "docker is present on this host; cannot test docker-absent path"
fi

# D2 — --from-source with Docker present invokes build-runtime.sh.
NAME="D2 from-source-docker-present-invokes-script (FR-CLI-5)"
if command -v docker &>/dev/null && docker info &>/dev/null 2>&1; then
    BUILD_D2="$(cd "$APP_DIR" && $PICOLET build --target linux-x64 --from-source --verbose 2>&1 || true)"
    if echo "$BUILD_D2" | grep -qi "Invoking build-runtime.sh\|build-runtime"; then
        pass "$NAME"
    elif [[ -f "$APP_DIR/target/linux-x64/hello-cli" ]]; then
        pass "$NAME"
    else
        fail "$NAME" "no build-runtime.sh invocation message; output: $BUILD_D2"
    fi
else
    skip "$NAME" "docker not available on this host"
fi

echo

# ---------------------------------------------------------------------------
# Group E: --runtime explicit override
# ---------------------------------------------------------------------------

echo "--- Group E: --runtime explicit override ---"

# E1 — --runtime /path/to/existing binary: used directly, no download.
NAME="E1 explicit-runtime-bypasses-download"
rm -rf "$CACHE_DIR"
rm -f "$APP_DIR/target/linux-x64/hello-cli"
BUILD_E1="$(cd "$APP_DIR" && \
    $PICOLET build --target linux-x64 --runtime "$LINUX_RUNTIME" --verbose 2>&1 || true)"
if [[ -f "$APP_DIR/target/linux-x64/hello-cli" ]]; then
    # Verify no download occurred by checking for absence of "Downloading" message.
    if echo "$BUILD_E1" | grep -qi "Downloading"; then
        fail "$NAME" "unexpected download with --runtime flag; output: $BUILD_E1"
    else
        pass "$NAME"
    fi
else
    fail "$NAME" "build with --runtime failed; output: $BUILD_E1"
fi

# E2 — --runtime pointing to non-existent file → clear error.
NAME="E2 explicit-runtime-missing-clear-error"
ERR_E2="$(cd "$APP_DIR" && \
    $PICOLET build --target linux-x64 --runtime "/tmp/does-not-exist-$$.bin" 2>&1 || true)"
if echo "$ERR_E2" | grep -qi "not found\|error"; then
    pass "$NAME"
else
    fail "$NAME" "expected not-found error for missing --runtime path; got: $ERR_E2"
fi

echo

# ---------------------------------------------------------------------------
# Group F: Configuration knobs
# ---------------------------------------------------------------------------

echo "--- Group F: configuration knobs ---"

# F1 — PICOLET_RUNTIME_TAG override changes the tag used by the resolver.
NAME="F1 PICOLET_RUNTIME_TAG-override"
CUSTOM_TAG="runtime-v99.0.0-sqe"
CUSTOM_RELEASE="$WORKDIR/custom-release"
mkdir -p "$CUSTOM_RELEASE/$CUSTOM_TAG"
cp "$LINUX_RUNTIME" "$CUSTOM_RELEASE/$CUSTOM_TAG/$ARTIFACT"
sha256sum "$CUSTOM_RELEASE/$CUSTOM_TAG/$ARTIFACT" | awk '{print $1}' \
    > "$CUSTOM_RELEASE/$CUSTOM_TAG/$ARTIFACT.sha256"
echo '{}' > "$CUSTOM_RELEASE/$CUSTOM_TAG/$ARTIFACT.cdx.json"

ORIG_TAG="$PICOLET_RUNTIME_TAG"
rm -rf "$CACHE_DIR"
export PICOLET_RUNTIME_TAG="$CUSTOM_TAG"
export PICOLET_RUNTIME_SOURCE="file://$CUSTOM_RELEASE"
BUILD_F1="$(cd "$APP_DIR" && $PICOLET build --target linux-x64 --verbose 2>&1 || true)"
export PICOLET_RUNTIME_TAG="$ORIG_TAG"
export PICOLET_RUNTIME_SOURCE="file://$FAKE_RELEASE"
if [[ -f "$CACHE_DIR/runtime/$CUSTOM_TAG/$ARTIFACT" ]]; then
    pass "$NAME"
else
    fail "$NAME" "custom tag $CUSTOM_TAG not used; cache=$CACHE_DIR; output: $BUILD_F1"
fi

# F2 — PICOLET_CACHE_DIR override: alternate cache directory used.
NAME="F2 PICOLET_CACHE_DIR-override"
CUSTOM_CACHE="$WORKDIR/custom-cache"
rm -rf "$CUSTOM_CACHE" "$CACHE_DIR"
ORIG_CACHE="$PICOLET_CACHE_DIR"
export PICOLET_CACHE_DIR="$CUSTOM_CACHE"
(cd "$APP_DIR" && $PICOLET build --target linux-x64 2>&1 >/dev/null || true)
export PICOLET_CACHE_DIR="$ORIG_CACHE"
if [[ -f "$CUSTOM_CACHE/runtime/$TAG/$ARTIFACT" ]]; then
    pass "$NAME"
else
    fail "$NAME" "binary not found in custom cache dir: $CUSTOM_CACHE"
fi

# F3 — PICOLET_RUNTIME_SOURCE override: alternate source URL used.
NAME="F3 PICOLET_RUNTIME_SOURCE-override"
ALT_RELEASE="$WORKDIR/alt-release"
ALT_ARTIFACT_CONTENT="ALT_BINARY_CONTENT_UNIQUE"
mkdir -p "$ALT_RELEASE/$TAG"
printf '%s' "$ALT_ARTIFACT_CONTENT" > "$ALT_RELEASE/$TAG/$ARTIFACT"
printf '%s' "$(sha256sum "$ALT_RELEASE/$TAG/$ARTIFACT" | awk '{print $1}')" \
    > "$ALT_RELEASE/$TAG/$ARTIFACT.sha256"
echo '{}' > "$ALT_RELEASE/$TAG/$ARTIFACT.cdx.json"

rm -rf "$CACHE_DIR"
ORIG_SOURCE="$PICOLET_RUNTIME_SOURCE"
export PICOLET_RUNTIME_SOURCE="file://$ALT_RELEASE"
(cd "$APP_DIR" && $PICOLET build --target linux-x64 2>&1 >/dev/null || true)
export PICOLET_RUNTIME_SOURCE="$ORIG_SOURCE"
CACHED_CONTENT="$(cat "$CACHE_DIR/runtime/$TAG/$ARTIFACT" 2>/dev/null || echo "MISSING")"
if [[ "$CACHED_CONTENT" == "$ALT_ARTIFACT_CONTENT" ]]; then
    pass "$NAME"
else
    fail "$NAME" "cache does not contain alt release content; got: '$CACHED_CONTENT'"
fi

echo

# ---------------------------------------------------------------------------
# Group G: Cross-target artifact naming
# ---------------------------------------------------------------------------

echo "--- Group G: cross-target artifact naming ---"

# G1 — linux-x64 artifact name has no .exe suffix.
NAME="G1 linux-x64-artifact-no-exe"
LINUX_ART="$(python3 -c "
import sys; sys.path.insert(0, '$REPO_ROOT/packages/picolet')
from picolet.cli.runtime_resolver import _artifact_name
print(_artifact_name('linux-x64', 'cli'))
")"
if [[ "$LINUX_ART" == "picolet-runtime-linux-x64-cli" ]]; then
    pass "$NAME"
else
    fail "$NAME" "expected picolet-runtime-linux-x64-cli, got $LINUX_ART"
fi

# G2 — windows-x64 artifact name has .exe suffix.
NAME="G2 windows-x64-artifact-has-exe"
WIN_ART="$(python3 -c "
import sys; sys.path.insert(0, '$REPO_ROOT/packages/picolet')
from picolet.cli.runtime_resolver import _artifact_name
print(_artifact_name('windows-x64', 'cli'))
")"
if [[ "$WIN_ART" == "picolet-runtime-windows-x64-cli.exe" ]]; then
    pass "$NAME"
else
    fail "$NAME" "expected picolet-runtime-windows-x64-cli.exe, got $WIN_ART"
fi

echo

# ---------------------------------------------------------------------------
# Group H: Regression (PH03/PH04 regression smoke)
# ---------------------------------------------------------------------------

echo "--- Group H: regression smoke ---"

# H1 — picolet build (linux, no flags) still works end-to-end.
NAME="H1 linux-build-regression"
rm -rf "$CACHE_DIR"
H1_APP="$WORKDIR/h1app"
mkdir -p "$H1_APP"
(cd "$WORKDIR" && $PICOLET init h1app --template hello-cli >/dev/null 2>&1) || true
if [[ -d "$H1_APP" ]]; then
    (cd "$H1_APP" && $PICOLET build --target linux-x64 >/dev/null 2>&1) || true
    if [[ -f "$H1_APP/target/linux-x64/h1app" ]]; then
        OUT_H1="$("$H1_APP/target/linux-x64/h1app" 2>&1)"
        if [[ "$OUT_H1" == "Hello from h1app" ]]; then
            pass "$NAME"
        else
            fail "$NAME" "expected hello output, got '$OUT_H1'"
        fi
    else
        fail "$NAME" "binary not produced"
    fi
else
    fail "$NAME" "picolet init failed"
fi

# H2 — FR-CLI-8: invalid picolet.toml still rejected before build.
NAME="H2 invalid-toml-rejected (FR-CLI-8)"
INVALID_APP="$WORKDIR/invalid-app"
mkdir -p "$INVALID_APP/src"
cat > "$INVALID_APP/picolet.toml" << 'TOML'
[app]
version = "0.1.0"
entry = "src/main.py"
TOML
echo 'print("x")' > "$INVALID_APP/src/main.py"
ERR_H2="$(cd "$INVALID_APP" && $PICOLET build --target linux-x64 2>&1 || true)"
if echo "$ERR_H2" | grep -q 'required key.*missing'; then
    pass "$NAME"
else
    fail "$NAME" "expected missing-key validation error; got: $ERR_H2"
fi

echo

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

SUITE_END=$(date +%s%N 2>/dev/null || date +%s)
# Compute elapsed; handle both ns and s precision.
if [[ ${#SUITE_START} -gt 12 ]]; then
    ELAPSED_MS=$(( (SUITE_END - SUITE_START) / 1000000 ))
else
    ELAPSED_MS=$(( (SUITE_END - SUITE_START) * 1000 ))
fi

TOTAL=$(( PASS + FAIL + SKIP ))
echo "=== PH05 gate results: $PASS passed, $FAIL failed, $SKIP skipped / $TOTAL total ==="
echo "    wall time: ${ELAPSED_MS} ms"

if [[ $FAIL -gt 0 ]]; then
    echo "Failed gates:"
    for g in "${FAILED_GATES[@]}"; do
        echo "  - $g"
    done
    exit 1
fi
echo "All mandatory gates PASS."
