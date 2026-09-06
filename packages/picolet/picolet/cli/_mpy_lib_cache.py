"""Fetch-and-cache the pinned micropython-lib checkout used by manifest.py.

manifest.py's ``require()`` resolves packages by walking directories under
``MPY_LIB_DIR/{micropython,python-stdlib,python-ecosys}/`` (see
``picolet._vendor.manifestfile.BASE_LIBRARY_NAMES``). A Picolet app doesn't
carry a micropython-lib checkout itself, so this module fetches one on first
use and caches it for subsequent builds.

Two entry points, used together by ``build_cmd._resolve_manifest``:

``mpy_lib_dir_path(config, app_root)``
    Computes the directory MPY_LIB_DIR will point at; zero network access,
    zero filesystem mutation. Always returns a path (an override path, or
    the pinned-commit cache path), whether or not it exists on disk yet.
    This is what gets seeded into ``ManifestFile``'s ``path_vars`` so that
    ``$(MPY_LIB_DIR)``-relative ``add_library()`` calls always resolve to a
    real path, never leaving the literal ``$(MPY_LIB_DIR)`` token unresolved.

``ensure_mpy_lib_dir(config, app_root, verbose=...)``
    Makes that path real: validates an override looks like a micropython-lib
    checkout, or fetches-and-caches the pinned commit. Called lazily, from
    inside a ``require()`` override, only when a require() call actually
    needs to search under MPY_LIB_DIR; see ``build_cmd._LazyManifestFile``.
    Idempotent and network-free to call repeatedly: an already-validated
    override is a plain directory check, and a cache hit re-verifies its
    content against the pinned digest (a local file read, no network).

The pinned commit is fetched as a GitHub codeload tarball
(``https://github.com/<owner>/<repo>/archive/<sha>.tar.gz``) rather than by
``git clone`` + ``git checkout <sha>``: GitHub's smart-HTTP upload-pack
refuses to serve an arbitrary commit SHA to a shallow clone unless it
happens to be a branch tip or tag (``uploadpack.allowReachableSHA1InWant``
is off for public repos), so a shallow clone pinned to an arbitrary SHA
doesn't reliably work. The codeload archive endpoint has no such
restriction, needs no ``git`` binary on the host, and transfers only that
commit's tree rather than a git history bundle.

The extracted tree's content is verified against a pinned sha256 digest
before it is trusted (see ``_tree_digest``/``_PINNED_TREE_SHA256`` below).
GitHub codeload's gzip output is not byte-stable across requests, so the
pin is over the extracted (relpath, content) pairs, not over the tarball
bytes themselves. This is the only integrity gate on third-party code that
gets frozen into the shipped binary; treat a mismatch as fatal, not a
warning.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import sys
import tarfile
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

from picolet._vendor.manifestfile import BASE_LIBRARY_NAMES
from picolet.cli.runtime_resolver import _cache_root

# Tracks packages/picolet-runtime/micropython/lib/micropython-lib's submodule
# pointer at the time manifest.py support was added. This is a stability
# pin, not a moving ref; bump it deliberately (and note why) when picking
# up newer micropython-lib packages, and recompute _PINNED_TREE_SHA256 below
# to match; see that constant's comment for the verification procedure.
_PINNED_SHA = "08cc0acb6515c19ebf2d899c98c41f179fd45202"
_REPO_OWNER = "andrewleech"
_REPO_NAME = "micropython-lib"

# sha256 over the extracted tree's sorted (relpath, content) pairs (see
# _tree_digest) for _PINNED_SHA.
#
# Updating this when _PINNED_SHA changes: derive the digest independently
# from a local `git archive` of the target commit, NOT from the downloaded
# tarball whose integrity you are trying to establish. Hashing the
# tarball you just fetched and pasting the result in only proves the
# download matches itself, not that it matches an independently-known-good
# source. `git archive` is the correct local equivalent because GitHub's
# codeload endpoint runs the same operation server-side:
#
#   SUB=packages/picolet-runtime/micropython/lib/micropython-lib
#   D=$(mktemp -d)
#   git -C $SUB archive --format=tar <NEW_SHA> | tar -x -C "$D"
#   python -c "from picolet.cli._mpy_lib_cache import _tree_digest; \
#              from pathlib import Path; print(_tree_digest(Path('$D')))"
#   rm -rf "$D"
#
# This local-archive/downloaded-tarball equivalence holds only as long as
# micropython-lib has no `.gitattributes` `export-ignore` rules: `git
# archive` and codeload both honour those, so if one is ever added
# upstream the two stop producing identical trees and this whole
# equivalence needs re-checking. There is none as of this pin (verified
# by checking for a .gitattributes file in the submodule).
_PINNED_TREE_SHA256 = "98e0371c66819fc456deeada391c34f60c8ec43e865fa6aad1e36d82ba340e74"

_ENV_OVERRIDE = "PICOLET_MPY_LIB_DIR"
_URLOPEN_TIMEOUT = 60

# The real archive is ~600 KB; this is a generous ceiling against a
# compromised or misbehaving server streaming an unbounded response, not a
# tight fit to the expected size. Checked during download, before the
# archive is ever opened or the integrity digest is computed.
_MAX_TARBALL_BYTES = 64 * 1024 * 1024


class MpyLibFetchError(RuntimeError):
    """Raised when the pinned micropython-lib checkout cannot be resolved."""


def _target_path(config: "dict | None", app_root: Path) -> "tuple[Path, str | None]":
    """Return (path, override_source) with zero network access or fetch.

    override_source is None when falling back to the pinned-commit cache
    path; otherwise it names which override supplied the path, for error
    messages.
    """
    override = os.environ.get(_ENV_OVERRIDE)
    source = "PICOLET_MPY_LIB_DIR" if override else None

    if not override:
        build_section = (config or {}).get("build")
        if isinstance(build_section, dict) and build_section.get("mpy_lib_dir"):
            override = build_section["mpy_lib_dir"]
            source = "[build].mpy_lib_dir"

    if override:
        path = Path(override)
        if not path.is_absolute():
            # Relative to app_root, matching every other path-valued toml key
            # in this codebase (e.g. _copy_includes does app_root / inc).
            path = app_root / path
        return path, source

    return _mpy_lib_cache_dir(), None


def mpy_lib_dir_path(config: "dict | None", app_root: Path) -> Path:
    """The MPY_LIB_DIR path to seed into ManifestFile.path_vars.

    Computed with zero network access and zero filesystem mutation; the
    returned directory may not exist yet. Call ensure_mpy_lib_dir() (or let
    the lazy require() hook do it) before relying on its contents.
    """
    path, _source = _target_path(config, app_root)
    return path


def ensure_mpy_lib_dir(
    config: "dict | None", app_root: Path, *, verbose: bool = False
) -> Path:
    """Make the MPY_LIB_DIR path real: validate an override, or fetch-and-cache.

    Idempotent: an override is re-validated (cheap, no mutation); a cache
    hit is re-verified against the pinned digest (see _fetch_and_cache).
    Safe to call more than once.
    """
    path, source = _target_path(config, app_root)
    if source is not None:
        _validate_override(path, source)
        if verbose:
            print(f"  mpy_lib_dir: {path} (from {source})", file=sys.stderr)
        return path
    return _fetch_and_cache(verbose=verbose)


def _validate_override(path: Path, source: str) -> None:
    """Existence AND shape check for an explicit MPY_LIB_DIR override.

    A user-provided path is trusted as-is content-wise (no fetch, no
    integrity check, that's the point of an override), but pointing it at
    the wrong directory should fail here with a clear message rather than
    several stack frames deep inside ManifestFile.require() as an opaque
    "package not found in any known library".
    """
    if not path.is_dir():
        raise MpyLibFetchError(f"{source} points at a non-existent directory: {path}")
    if not any((path / lib).is_dir() for lib in BASE_LIBRARY_NAMES):
        raise MpyLibFetchError(
            f"{source} ({path}) does not look like a micropython-lib checkout: "
            f"expected at least one of {', '.join(f'{lib}/' for lib in BASE_LIBRARY_NAMES)} "
            f"as a subdirectory"
        )


def _mpy_lib_cache_dir() -> Path:
    return _cache_root() / "micropython-lib" / _PINNED_SHA


def _copy_with_limit(src, dst, limit: int) -> None:
    """Like shutil.copyfileobj, but raises if more than limit bytes are read.

    Bounds the tarball download so a compromised or misbehaving server can't
    stream an unbounded response before the archive is ever opened or the
    integrity digest is computed.
    """
    total = 0
    while True:
        chunk = src.read(65536)
        if not chunk:
            return
        total += len(chunk)
        if total > limit:
            raise MpyLibFetchError(
                f"download exceeded {limit} bytes; aborting (expected ~600 KB "
                f"for micropython-lib@{_PINNED_SHA})"
            )
        dst.write(chunk)


def _tree_digest(root: Path) -> str:
    """sha256 over root's files as sorted (relpath, length, content) triples.

    Hashing the extracted tree's content (not the tarball bytes) is
    deliberate: GitHub codeload's gzip output is not byte-stable across
    requests for the same commit, so a raw-bytes pin would false-positive
    on a legitimate re-fetch. This digest only depends on which files exist
    and what they contain, which is stable for a given commit.
    """
    h = hashlib.sha256()
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        rel = path.relative_to(root).as_posix()
        content = path.read_bytes()
        h.update(rel.encode("utf-8"))
        h.update(b"\0")
        h.update(str(len(content)).encode("ascii"))
        h.update(b"\0")
        h.update(content)
        h.update(b"\0")
    return h.hexdigest()


def _fetch_and_cache(*, verbose: bool = False) -> Path:
    """Download, extract, and integrity-check the pinned commit; cache it.

    A cache hit is re-verified against _PINNED_TREE_SHA256 on every call, not
    just on first fetch (matching runtime_resolver.py's own cached-artifact
    behaviour: a sha256 mismatch there triggers a re-download too, on every
    cache hit, not only the first). Without this, the integrity pin would
    only ever protect the first fetch; a cache tampered with or corrupted
    afterwards would be trusted indefinitely on every subsequent build. No
    network access happens for a verified hit, only local file reads.

    Extraction uses tarfile's ``filter="data"`` unconditionally (no
    pre-3.12-without-backport fallback; see packages/picolet/pyproject.toml's
    requires-python floor of 3.11.4), which rejects path-traversal and
    absolute-path tarball members (CVE-2007-4559) by raising
    tarfile.OutsideDestinationError, a tarfile.TarError subclass already
    handled below.

    Concurrent builds sharing the same cache directory are safe: the
    download + extraction happen under unique temp names (tempfile.mkstemp
    / mkdtemp, not fixed names), and a losing rename() onto an
    already-populated dest is treated as a successful outcome rather than
    an error.
    """
    dest = _mpy_lib_cache_dir()
    if dest.is_dir():
        try:
            cached_digest = _tree_digest(dest)
        except OSError as exc:
            # A read failure (e.g. a file vanishing mid-walk under a
            # concurrent build's rmtree, or a permissions/IO error on an
            # already-corrupt cache) is treated the same as a digest
            # mismatch below: don't let it escape uncaught, don't trust the
            # directory, re-fetch instead.
            cached_digest = None
            print(
                f"warning: could not verify cached micropython-lib@{_PINNED_SHA} "
                f"({exc}); re-fetching",
                file=sys.stderr,
            )
        if cached_digest == _PINNED_TREE_SHA256:
            if verbose:
                print(f"  mpy_lib_dir: using cached {dest}", file=sys.stderr)
            return dest
        if cached_digest is not None:
            print(
                f"warning: integrity check failed for cached micropython-lib@{_PINNED_SHA} "
                f"(expected {_PINNED_TREE_SHA256}, got {cached_digest}); re-fetching",
                file=sys.stderr,
            )
        shutil.rmtree(dest, ignore_errors=True)

    url = f"https://github.com/{_REPO_OWNER}/{_REPO_NAME}/archive/{_PINNED_SHA}.tar.gz"
    if verbose:
        print(f"  mpy_lib_dir: fetching {url}", file=sys.stderr)

    dest.parent.mkdir(parents=True, exist_ok=True)

    tmp_tar_fd, tmp_tar_name = tempfile.mkstemp(
        dir=dest.parent, prefix=f".{dest.name}.", suffix=".tar.gz.tmp"
    )
    tmp_tar = Path(tmp_tar_name)
    tmp_extract = Path(
        tempfile.mkdtemp(dir=dest.parent, prefix=f".{dest.name}.", suffix=".extract.tmp")
    )

    try:
        with os.fdopen(tmp_tar_fd, "wb") as fh:
            with urllib.request.urlopen(url, timeout=_URLOPEN_TIMEOUT) as resp:
                _copy_with_limit(resp, fh, _MAX_TARBALL_BYTES)

        with tarfile.open(tmp_tar) as tar:
            tar.extractall(tmp_extract, filter="data")

        # GitHub codeload tarballs contain exactly one top-level directory
        # (e.g. micropython-lib-08cc0ac.../).
        entries = list(tmp_extract.iterdir())
        if len(entries) != 1 or not entries[0].is_dir():
            raise MpyLibFetchError(
                f"unexpected tarball layout at {url}: expected exactly one "
                f"top-level directory, found {[e.name for e in entries]}"
            )
        extracted_root = entries[0]

        digest = _tree_digest(extracted_root)
        if digest != _PINNED_TREE_SHA256:
            raise MpyLibFetchError(
                f"integrity check failed for micropython-lib@{_PINNED_SHA}: "
                f"expected tree sha256 {_PINNED_TREE_SHA256}, got {digest}. "
                f"Refusing to freeze unverified content into the build. If "
                f"micropython-lib legitimately changed, this pin needs a "
                f"deliberate update in _mpy_lib_cache.py."
            )

        try:
            extracted_root.rename(dest)
        except OSError:
            if not dest.is_dir():
                raise
            # Lost a race with a concurrent build that already populated
            # dest with the same (integrity-verified) content; not a failure.
    except (urllib.error.URLError, OSError, tarfile.TarError) as exc:
        raise MpyLibFetchError(
            f"failed to fetch micropython-lib@{_PINNED_SHA}: {exc}\n"
            f"  Set {_ENV_OVERRIDE} to a local checkout to bypass this fetch, "
            f"or add [build].mpy_lib_dir in picolet.toml."
        ) from exc
    finally:
        tmp_tar.unlink(missing_ok=True)
        shutil.rmtree(tmp_extract, ignore_errors=True)

    if verbose:
        print(f"  mpy_lib_dir: cached at {dest}", file=sys.stderr)
    return dest
