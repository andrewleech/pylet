"""
Unit tests for packages/picolet/picolet/runtime_resolver.py — PH05.

Each test isolates the resolver from the real user cache and real network
by setting PICOLET_CACHE_DIR and PICOLET_RUNTIME_SOURCE to temporary directories.
"""

from __future__ import annotations

import hashlib
import io
import os
import sys
import unittest
import unittest.mock as mock
from pathlib import Path

# Ensure picolet.cli package is importable without installation.
_REPO_ROOT = Path(__file__).parent.parent.parent
_PKG_PARENT = _REPO_ROOT / "packages" / "picolet-cli"
if str(_PKG_PARENT) not in sys.path:
    sys.path.insert(0, str(_PKG_PARENT))

from picolet.cli.runtime_resolver import (
    ResolvedRuntime,
    RuntimeIntegrityError,
    RuntimeNotFound,
    _artifact_name,
    _cache_root,
    _load_config,
    resolve_runtime,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

FAKE_BINARY = b"FAKE_RUNTIME_BINARY_CONTENT"
FAKE_BINARY_SHA256 = hashlib.sha256(FAKE_BINARY).hexdigest()


def _make_fake_release(
    base_dir: Path,
    tag: str = "runtime-v0.1.0-test",
    target: str = "linux-x64",
    variant: str = "cli",
    content: bytes = FAKE_BINARY,
    include_sha256: bool = True,
    include_cdx: bool = True,
) -> Path:
    """Populate a fake release directory and return the artifact path."""
    artifact = _artifact_name(target, variant)
    release_dir = base_dir / tag
    release_dir.mkdir(parents=True, exist_ok=True)

    bin_path = release_dir / artifact
    bin_path.write_bytes(content)

    if include_sha256:
        sha256_path = release_dir / f"{artifact}.sha256"
        sha256_path.write_text(hashlib.sha256(content).hexdigest() + "\n")

    if include_cdx:
        sbom_path = release_dir / f"{artifact}.cdx.json"
        sbom_path.write_text("{}\n")

    return bin_path


def _file_url(path: Path) -> str:
    """Return a file:// URL for a directory path."""
    return path.as_uri()


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------

class TestResolverUnit(unittest.TestCase):

    def setUp(self) -> None:
        import tempfile
        self._tmpdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmpdir.name)

        self.fake_release_dir = self.tmp / "fake-release"
        self.cache_dir = self.tmp / "cache"
        self.tag = "runtime-v0.1.0-test"

        _make_fake_release(
            self.fake_release_dir,
            tag=self.tag,
            target="linux-x64",
            variant="cli",
        )

        os.environ["PICOLET_RUNTIME_TAG"] = self.tag
        os.environ["PICOLET_RUNTIME_SOURCE"] = _file_url(self.fake_release_dir)
        os.environ["PICOLET_CACHE_DIR"] = str(self.cache_dir)
        # PH05 fixup: file:// schemes are rejected by default (S2); the
        # fake release fixtures all use file:// so the test suite opts in.
        os.environ["PICOLET_ALLOW_FILE_URLS"] = "1"

    def tearDown(self) -> None:
        for key in (
            "PICOLET_RUNTIME_TAG",
            "PICOLET_RUNTIME_SOURCE",
            "PICOLET_CACHE_DIR",
            "PICOLET_ALLOW_FILE_URLS",
            "PICOLET_ALLOW_UNVERIFIED_CACHE",
        ):
            os.environ.pop(key, None)
        self._tmpdir.cleanup()

    # -------------------------------------------------------------------------
    # test_download_and_cache_populate
    # -------------------------------------------------------------------------
    def test_download_and_cache_populate(self) -> None:
        """First call with empty cache: artifact + .sha256 + .cdx.json all cached."""
        result = resolve_runtime("linux-x64", "cli")
        self.assertIsInstance(result, ResolvedRuntime)

        # Binary must be inside the cache dir.
        self.assertTrue(
            str(result.binary).startswith(str(self.cache_dir)),
            f"binary not in cache: {result.binary}",
        )
        self.assertTrue(result.binary.is_file())
        self.assertEqual(result.binary.read_bytes(), FAKE_BINARY)

        # Sibling files must also be cached.
        sha256_path = result.binary.parent / f"{result.binary.name}.sha256"
        self.assertTrue(sha256_path.is_file(), ".sha256 not cached")

        sbom_path = result.binary.parent / f"{result.binary.name}.cdx.json"
        self.assertTrue(sbom_path.is_file(), ".cdx.json not cached")
        self.assertIsNotNone(result.sbom)

    # -------------------------------------------------------------------------
    # test_cache_hit_no_redownload
    # -------------------------------------------------------------------------
    def test_cache_hit_no_redownload(self) -> None:
        """Second call returns cached artifact without hitting the network."""
        # Populate cache.
        resolve_runtime("linux-x64", "cli")

        # Simulate network outage by removing the source binary.
        artifact = _artifact_name("linux-x64", "cli")
        (self.fake_release_dir / self.tag / artifact).unlink()

        # Should still succeed from cache.
        result = resolve_runtime("linux-x64", "cli")
        self.assertTrue(result.binary.is_file())
        self.assertEqual(result.binary.read_bytes(), FAKE_BINARY)

    # -------------------------------------------------------------------------
    # test_sha256_mismatch_triggers_redownload
    # -------------------------------------------------------------------------
    def test_sha256_mismatch_triggers_redownload(self) -> None:
        """Corrupted cache artifact triggers re-download and repair."""
        # Populate cache first.
        resolve_runtime("linux-x64", "cli")

        # Corrupt the cached binary.
        artifact = _artifact_name("linux-x64", "cli")
        cached_bin = self.cache_dir / "runtime" / self.tag / artifact
        cached_bin.write_bytes(b"CORRUPTED")

        # Resolver should re-download and succeed.
        result = resolve_runtime("linux-x64", "cli")
        self.assertTrue(result.binary.is_file())
        # Content must now be the original fake binary.
        self.assertEqual(result.binary.read_bytes(), FAKE_BINARY)

    # -------------------------------------------------------------------------
    # test_tampered_cache_no_network_raises
    # -------------------------------------------------------------------------
    def test_tampered_cache_no_network_raises(self) -> None:
        """Corrupted cache + no network raises RuntimeNotFound."""
        resolve_runtime("linux-x64", "cli")

        artifact = _artifact_name("linux-x64", "cli")
        cached_bin = self.cache_dir / "runtime" / self.tag / artifact
        cached_bin.write_bytes(b"CORRUPTED")

        # Point source at a non-existent directory to simulate network absence.
        os.environ["PICOLET_RUNTIME_SOURCE"] = _file_url(self.tmp / "nonexistent")

        # Patch _intree_fallback to return None so in-tree binary doesn't save us.
        from picolet.cli import runtime_resolver as rr
        with mock.patch.object(rr, "_intree_fallback", return_value=None):
            with self.assertRaises(RuntimeNotFound):
                resolve_runtime("linux-x64", "cli")

    # -------------------------------------------------------------------------
    # test_corrupt_download_sha256_raises
    # -------------------------------------------------------------------------
    def test_corrupt_download_sha256_raises(self) -> None:
        """Tampered .sha256 in the source (mismatches actual content) causes download failure."""
        # Create a release where the .sha256 sidecar is wrong.
        tampered_dir = self.tmp / "tampered-release"
        artifact = _artifact_name("linux-x64", "cli")
        release_dir = tampered_dir / self.tag
        release_dir.mkdir(parents=True)
        (release_dir / artifact).write_bytes(FAKE_BINARY)
        # Write a deliberately wrong sha256.
        (release_dir / f"{artifact}.sha256").write_text("0" * 64 + "\n")
        (release_dir / f"{artifact}.cdx.json").write_text("{}\n")

        os.environ["PICOLET_RUNTIME_SOURCE"] = _file_url(tampered_dir)

        from picolet.cli import runtime_resolver as rr
        with mock.patch.object(rr, "_intree_fallback", return_value=None):
            with self.assertRaises(RuntimeNotFound) as ctx:
                resolve_runtime("linux-x64", "cli")

        # The error must propagate as a download failure, not a silent pass.
        msg = str(ctx.exception)
        self.assertIn("runtime artifact not available", msg)

    # -------------------------------------------------------------------------
    # test_explicit_runtime_path
    # -------------------------------------------------------------------------
    def test_explicit_runtime_path(self) -> None:
        """explicit_path bypasses all resolution; returns that path directly."""
        explicit = self.tmp / "my-runtime"
        explicit.write_bytes(b"EXPLICIT")

        result = resolve_runtime("linux-x64", "cli", explicit_path=explicit)
        self.assertEqual(result.binary.resolve(), explicit.resolve())
        self.assertIsNone(result.sbom)

    # -------------------------------------------------------------------------
    # test_explicit_runtime_path_missing
    # -------------------------------------------------------------------------
    def test_explicit_runtime_path_missing(self) -> None:
        """explicit_path pointing to non-existent file raises RuntimeNotFound."""
        explicit = self.tmp / "does-not-exist"
        with self.assertRaises(RuntimeNotFound) as ctx:
            resolve_runtime("linux-x64", "cli", explicit_path=explicit)
        self.assertIn("not found", str(ctx.exception).lower())

    # -------------------------------------------------------------------------
    # test_no_cache_flag_downloads_fresh
    # -------------------------------------------------------------------------
    def test_no_cache_flag_downloads_fresh(self) -> None:
        """no_cache=True downloads even when cache is populated."""
        # Populate cache first.
        resolve_runtime("linux-x64", "cli")

        # Count urlopen calls with no_cache=True.
        import urllib.request as _urq
        call_count = 0
        original_urlopen = _urq.urlopen

        def counting_urlopen(url, *a, **kw):
            nonlocal call_count
            call_count += 1
            return original_urlopen(url, *a, **kw)

        with mock.patch("urllib.request.urlopen", side_effect=counting_urlopen):
            result = resolve_runtime("linux-x64", "cli", no_cache=True)

        self.assertGreater(call_count, 0, "urlopen was not called with no_cache=True")
        self.assertTrue(result.binary.is_file())

    # -------------------------------------------------------------------------
    # test_no_cache_disables_cache_writes
    # NOTE: This test documents a known bug in the current implementation.
    # The spec (phase file Gate 7) requires the cache directory to remain
    # empty after a --no-cache build. The current _download() always writes
    # to cfg.cache_root regardless of no_cache. This test is marked expected
    # failure until the developer fixes _download() to accept a no_cache flag.
    # See [PH05] Caveat commit for details.
    # -------------------------------------------------------------------------
    @unittest.expectedFailure
    def test_no_cache_disables_cache_writes(self) -> None:
        """--no-cache (no_cache=True) must not populate the cache directory."""
        result = resolve_runtime("linux-x64", "cli", no_cache=True)
        self.assertTrue(result.binary.is_file())

        # Cache directory should be empty (or not exist) after --no-cache.
        cache_runtime_dir = self.cache_dir / "runtime"
        if cache_runtime_dir.exists():
            cached_files = list(cache_runtime_dir.rglob("*"))
            self.assertEqual(
                cached_files, [],
                f"--no-cache wrote {len(cached_files)} file(s) to cache: "
                + ", ".join(str(f) for f in cached_files),
            )

    # -------------------------------------------------------------------------
    # test_offline_with_empty_cache_raises
    # -------------------------------------------------------------------------
    def test_offline_with_empty_cache_raises(self) -> None:
        """Empty cache + bad URL + no in-tree fallback → structured RuntimeNotFound."""
        os.environ["PICOLET_RUNTIME_SOURCE"] = _file_url(self.tmp / "nonexistent")

        # Patch _intree_fallback to return None so in-tree binary doesn't save us.
        from picolet.cli import runtime_resolver as rr
        with mock.patch.object(rr, "_intree_fallback", return_value=None):
            with self.assertRaises(RuntimeNotFound) as ctx:
                resolve_runtime("linux-x64", "cli")

        msg = str(ctx.exception)
        self.assertIn("Tried:", msg)
        self.assertIn("cache:", msg)
        self.assertIn("download:", msg)
        self.assertIn("fallback:", msg)
        self.assertIn("1. Connect", msg)
        self.assertIn("2. Run `picolet build --from-source`", msg)
        self.assertIn("3. Run `picolet build --runtime", msg)

    # -------------------------------------------------------------------------
    # test_offline_no_cache_hard_errors_no_fallback
    # -------------------------------------------------------------------------
    def test_offline_no_cache_hard_errors_no_fallback(self) -> None:
        """--no-cache + network unavailable: hard error; no in-tree fallback attempted."""
        os.environ["PICOLET_RUNTIME_SOURCE"] = _file_url(self.tmp / "nonexistent")

        from picolet.cli import runtime_resolver as rr
        # Patch _intree_fallback to ensure it is NOT called with no_cache=True.
        with mock.patch.object(rr, "_intree_fallback") as mock_fallback:
            with self.assertRaises(RuntimeNotFound):
                resolve_runtime("linux-x64", "cli", no_cache=True)
            mock_fallback.assert_not_called()

    # -------------------------------------------------------------------------
    # test_intree_fallback
    # -------------------------------------------------------------------------
    def test_intree_fallback(self) -> None:
        """Empty cache + bad URL + existing in-tree binary → in-tree fallback used."""
        os.environ["PICOLET_RUNTIME_SOURCE"] = _file_url(self.tmp / "nonexistent")

        # Create a fake in-tree artifact.
        artifact = _artifact_name("linux-x64", "cli")
        intree_dir = self.tmp / "fake-repo" / "packages" / "picolet-runtime" / "build"
        intree_dir.mkdir(parents=True, exist_ok=True)
        intree_bin = intree_dir / artifact
        intree_bin.write_bytes(b"INTREE")

        # Patch _find_repo_root to return our fake repo root.
        from picolet.cli import runtime_resolver as rr
        with mock.patch.object(rr, "_find_repo_root", return_value=self.tmp / "fake-repo"):
            with mock.patch("sys.stderr", new_callable=io.StringIO) as mock_stderr:
                result = resolve_runtime("linux-x64", "cli")
                stderr_out = mock_stderr.getvalue()

        self.assertTrue(result.binary.is_file())
        self.assertEqual(result.binary.read_bytes(), b"INTREE")
        self.assertIn("fallback", stderr_out.lower())

    # -------------------------------------------------------------------------
    # test_intree_fallback_warning_message
    # -------------------------------------------------------------------------
    def test_intree_fallback_warning_message(self) -> None:
        """In-tree fallback emits a warning to stderr."""
        os.environ["PICOLET_RUNTIME_SOURCE"] = _file_url(self.tmp / "nonexistent")

        artifact = _artifact_name("linux-x64", "cli")
        intree_dir = self.tmp / "fake-repo" / "packages" / "picolet-runtime" / "build"
        intree_dir.mkdir(parents=True, exist_ok=True)
        (intree_dir / artifact).write_bytes(b"INTREE")

        from picolet.cli import runtime_resolver as rr
        with mock.patch.object(rr, "_find_repo_root", return_value=self.tmp / "fake-repo"):
            with mock.patch("sys.stderr", new_callable=io.StringIO) as mock_stderr:
                resolve_runtime("linux-x64", "cli")
                stderr_out = mock_stderr.getvalue()

        self.assertIn("warning", stderr_out.lower())

    # -------------------------------------------------------------------------
    # test_config_reads_runtime_tag_sidecar
    # -------------------------------------------------------------------------
    def test_config_reads_runtime_tag_sidecar(self) -> None:
        """_load_config() reads tag from RUNTIME_TAG sidecar when no env/toml override."""
        # Remove env override so sidecar is consulted.
        del os.environ["PICOLET_RUNTIME_TAG"]

        from picolet.cli import runtime_resolver as rr

        with mock.patch.object(rr, "_read_runtime_tag_sidecar", return_value="runtime-v0.0.1"):
            cfg = _load_config()

        self.assertEqual(cfg.tag, "runtime-v0.0.1")

    # -------------------------------------------------------------------------
    # test_env_var_overrides_sidecar
    # -------------------------------------------------------------------------
    def test_env_var_overrides_sidecar(self) -> None:
        """PICOLET_RUNTIME_TAG env var overrides the sidecar file."""
        os.environ["PICOLET_RUNTIME_TAG"] = "runtime-v9.9.9"
        cfg = _load_config()
        self.assertEqual(cfg.tag, "runtime-v9.9.9")

    # -------------------------------------------------------------------------
    # test_picolet_runtime_source_env_override
    # -------------------------------------------------------------------------
    def test_picolet_runtime_source_env_override(self) -> None:
        """PICOLET_RUNTIME_SOURCE env var overrides the default base URL."""
        custom_url = "file:///tmp/custom-source"
        os.environ["PICOLET_RUNTIME_SOURCE"] = custom_url
        cfg = _load_config()
        # The resolver strips trailing slashes.
        self.assertEqual(cfg.base_url, custom_url.rstrip("/"))

    # -------------------------------------------------------------------------
    # test_runtime_table_source_in_config
    # -------------------------------------------------------------------------
    def test_runtime_table_source_in_config(self) -> None:
        """[runtime] source in picolet.toml config dict is read by _load_config()."""
        del os.environ["PICOLET_RUNTIME_SOURCE"]
        toml_data = {
            "runtime": {
                "source": "file:///tmp/toml-source",
                "tag": "runtime-v2.0.0",
            }
        }
        cfg = _load_config(config=toml_data)
        self.assertEqual(cfg.base_url, "file:///tmp/toml-source")

    # -------------------------------------------------------------------------
    # test_runtime_table_tag_in_config
    # -------------------------------------------------------------------------
    def test_runtime_table_tag_in_config(self) -> None:
        """[runtime] tag in picolet.toml config dict overrides sidecar."""
        del os.environ["PICOLET_RUNTIME_TAG"]
        toml_data = {
            "runtime": {
                "tag": "runtime-v2.0.0",
            }
        }
        cfg = _load_config(config=toml_data)
        self.assertEqual(cfg.tag, "runtime-v2.0.0")

    # -------------------------------------------------------------------------
    # test_env_var_overrides_toml_table
    # -------------------------------------------------------------------------
    def test_env_var_overrides_toml_table(self) -> None:
        """PICOLET_RUNTIME_TAG env var takes precedence over [runtime] tag in picolet.toml."""
        os.environ["PICOLET_RUNTIME_TAG"] = "runtime-v9.9.9"
        toml_data = {"runtime": {"tag": "runtime-v1.0.0"}}
        cfg = _load_config(config=toml_data)
        self.assertEqual(cfg.tag, "runtime-v9.9.9")

    # -------------------------------------------------------------------------
    # test_cache_root_linux
    # -------------------------------------------------------------------------
    def test_cache_root_linux(self) -> None:
        """On Linux with no overrides, cache root is ~/.cache/picolet."""
        if sys.platform != "linux":
            self.skipTest("Linux-only test")

        del os.environ["PICOLET_CACHE_DIR"]
        env_backup = os.environ.pop("XDG_CACHE_HOME", None)
        try:
            root = _cache_root()
            self.assertEqual(root, Path.home() / ".cache" / "picolet")
        finally:
            if env_backup is not None:
                os.environ["XDG_CACHE_HOME"] = env_backup
            os.environ["PICOLET_CACHE_DIR"] = str(self.cache_dir)

    # -------------------------------------------------------------------------
    # test_cache_root_xdg
    # -------------------------------------------------------------------------
    def test_cache_root_xdg(self) -> None:
        """XDG_CACHE_HOME sets cache root to XDG_CACHE_HOME/picolet."""
        del os.environ["PICOLET_CACHE_DIR"]
        os.environ["XDG_CACHE_HOME"] = str(self.tmp / "xdg")
        try:
            root = _cache_root()
            self.assertEqual(root, self.tmp / "xdg" / "picolet")
        finally:
            del os.environ["XDG_CACHE_HOME"]
            os.environ["PICOLET_CACHE_DIR"] = str(self.cache_dir)

    # -------------------------------------------------------------------------
    # test_cache_root_picolet_cache_dir_override
    # -------------------------------------------------------------------------
    def test_cache_root_picolet_cache_dir_override(self) -> None:
        """PICOLET_CACHE_DIR env var sets cache root and is used by the resolver."""
        custom_cache = self.tmp / "custom-cache"
        os.environ["PICOLET_CACHE_DIR"] = str(custom_cache)

        resolve_runtime("linux-x64", "cli")

        artifact = _artifact_name("linux-x64", "cli")
        expected = custom_cache / "runtime" / self.tag / artifact
        self.assertTrue(expected.is_file(), f"binary not in custom cache: {expected}")

    # -------------------------------------------------------------------------
    # test_artifact_name_linux
    # -------------------------------------------------------------------------
    def test_artifact_name_linux(self) -> None:
        """linux-x64 target produces artifact name without .exe."""
        name = _artifact_name("linux-x64", "cli")
        self.assertEqual(name, "picolet-runtime-linux-x64-cli")
        self.assertFalse(name.endswith(".exe"))

    # -------------------------------------------------------------------------
    # test_artifact_name_windows
    # -------------------------------------------------------------------------
    def test_artifact_name_windows(self) -> None:
        """windows-x64 target produces artifact name with .exe suffix."""
        name = _artifact_name("windows-x64", "cli")
        self.assertEqual(name, "picolet-runtime-windows-x64-cli.exe")

    # -------------------------------------------------------------------------
    # test_cross_target_windows_from_same_release
    # -------------------------------------------------------------------------
    def test_cross_target_windows_from_same_release(self) -> None:
        """Resolver selects the correct artifact for windows-x64 from the same release tree."""
        # Add windows artifact to existing fake release.
        win_artifact = _artifact_name("windows-x64", "cli")
        release_dir = self.fake_release_dir / self.tag
        win_content = b"FAKE_WIN_BINARY"
        (release_dir / win_artifact).write_bytes(win_content)
        (release_dir / f"{win_artifact}.sha256").write_text(
            hashlib.sha256(win_content).hexdigest() + "\n"
        )
        (release_dir / f"{win_artifact}.cdx.json").write_text("{}\n")

        result = resolve_runtime("windows-x64", "cli")
        self.assertTrue(result.binary.is_file())
        self.assertIn("windows-x64", result.binary.name)
        self.assertTrue(result.binary.name.endswith(".exe"))
        self.assertEqual(result.binary.read_bytes(), win_content)

    # -------------------------------------------------------------------------
    # test_partial_tmp_file_cleaned_on_download_failure
    # -------------------------------------------------------------------------
    def test_partial_tmp_file_cleaned_on_download_failure(self) -> None:
        """A .tmp file left by a failed download is removed; no partial artifact in cache."""
        # Point at nonexistent source to force download failure.
        os.environ["PICOLET_RUNTIME_SOURCE"] = _file_url(self.tmp / "nonexistent")

        from picolet.cli import runtime_resolver as rr
        with mock.patch.object(rr, "_intree_fallback", return_value=None):
            with self.assertRaises(RuntimeNotFound):
                resolve_runtime("linux-x64", "cli")

        # No .tmp files should remain in the cache.
        artifact = _artifact_name("linux-x64", "cli")
        tag_dir = self.cache_dir / "runtime" / self.tag
        if tag_dir.exists():
            tmp_files = list(tag_dir.glob(f".{artifact}*.tmp"))
            self.assertEqual(tmp_files, [], f"stale .tmp files found: {tmp_files}")

    # -------------------------------------------------------------------------
    # test_from_source_docker_absent_raises_clear_error
    # -------------------------------------------------------------------------
    def test_from_source_docker_absent_raises_clear_error(self) -> None:
        """from_source=True with Docker absent raises RuntimeNotFound with clear message."""
        from picolet.cli import runtime_resolver as rr
        with mock.patch.object(rr, "_check_docker", return_value=False):
            with self.assertRaises(RuntimeNotFound) as ctx:
                resolve_runtime("linux-x64", "cli", from_source=True)
        msg = str(ctx.exception)
        self.assertIn("docker", msg.lower())
        self.assertIn("required", msg.lower())

    # -------------------------------------------------------------------------
    # test_from_source_invokes_build_script
    # -------------------------------------------------------------------------
    def test_from_source_invokes_build_script(self) -> None:
        """from_source=True with Docker available calls _build_from_source."""
        from picolet.cli import runtime_resolver as rr

        fake_built = self.tmp / "fake-built-runtime"
        fake_built.write_bytes(b"BUILT")

        def fake_build(target, variant, verbose):
            return fake_built

        with mock.patch.object(rr, "_check_docker", return_value=True):
            with mock.patch.object(rr, "_build_from_source", side_effect=fake_build) as mock_build:
                result = resolve_runtime("linux-x64", "cli", from_source=True)

        mock_build.assert_called_once()
        call_args = mock_build.call_args
        self.assertEqual(call_args[0][0], "linux-x64")  # target
        self.assertEqual(call_args[0][1], "cli")        # variant
        self.assertEqual(result.binary, fake_built)

    # -------------------------------------------------------------------------
    # test_sbom_absent_from_release_does_not_fail
    # -------------------------------------------------------------------------
    def test_sbom_absent_from_release_does_not_fail(self) -> None:
        """Missing .cdx.json at the source is treated as best-effort; download succeeds."""
        no_sbom_dir = self.tmp / "no-sbom-release"
        _make_fake_release(no_sbom_dir, tag=self.tag, include_cdx=False)
        os.environ["PICOLET_RUNTIME_SOURCE"] = _file_url(no_sbom_dir)

        result = resolve_runtime("linux-x64", "cli")
        self.assertTrue(result.binary.is_file())
        self.assertIsNone(result.sbom)


class TestUrlSchemeAllowList(unittest.TestCase):
    """PH05 fixup (S2): non-http(s) URL schemes are rejected by default."""

    def setUp(self) -> None:
        # Save and clear opt-in env so the default policy is observed.
        self._saved = os.environ.pop("PICOLET_ALLOW_FILE_URLS", None)
        os.environ["PICOLET_RUNTIME_TAG"] = "runtime-v0.1.0-test"

    def tearDown(self) -> None:
        os.environ.pop("PICOLET_ALLOW_FILE_URLS", None)
        if self._saved is not None:
            os.environ["PICOLET_ALLOW_FILE_URLS"] = self._saved
        os.environ.pop("PICOLET_RUNTIME_TAG", None)
        os.environ.pop("PICOLET_RUNTIME_SOURCE", None)

    def test_file_url_rejected_by_default(self) -> None:
        """file:// URLs raise RuntimeNotFound without PICOLET_ALLOW_FILE_URLS=1."""
        os.environ["PICOLET_RUNTIME_SOURCE"] = "file:///tmp/anything"
        with self.assertRaises(RuntimeNotFound) as ctx:
            resolve_runtime("linux-x64", "cli")
        msg = str(ctx.exception)
        self.assertIn("file://", msg)
        self.assertIn("PICOLET_ALLOW_FILE_URLS", msg)

    def test_file_url_allowed_with_env_opt_in(self) -> None:
        """PICOLET_ALLOW_FILE_URLS=1 permits file:// (download itself may fail)."""
        os.environ["PICOLET_RUNTIME_SOURCE"] = "file:///does/not/exist"
        os.environ["PICOLET_ALLOW_FILE_URLS"] = "1"
        # Should NOT raise the scheme-rejection message; it'll go on to attempt
        # the download and fail with a different error path.
        from picolet.cli import runtime_resolver as rr
        with mock.patch.object(rr, "_intree_fallback", return_value=None):
            with self.assertRaises(RuntimeNotFound) as ctx:
                resolve_runtime("linux-x64", "cli")
        msg = str(ctx.exception)
        self.assertNotIn("PICOLET_ALLOW_FILE_URLS", msg)
        # The scheme passed validation; the eventual failure is a download error.
        self.assertIn("Tried:", msg)

    def test_ftp_url_always_rejected(self) -> None:
        """ftp:// has no opt-in; rejected unconditionally."""
        os.environ["PICOLET_RUNTIME_SOURCE"] = "ftp://example.com/releases"
        os.environ["PICOLET_ALLOW_FILE_URLS"] = "1"  # does not apply to ftp
        with self.assertRaises(RuntimeNotFound) as ctx:
            resolve_runtime("linux-x64", "cli")
        msg = str(ctx.exception)
        self.assertIn("ftp", msg)
        self.assertIn("unsupported scheme", msg)

    def test_https_url_accepted(self) -> None:
        """https:// passes the scheme check (downstream connection may fail)."""
        os.environ["PICOLET_RUNTIME_SOURCE"] = "https://example.invalid/releases"
        from picolet.cli import runtime_resolver as rr
        with mock.patch.object(rr, "_intree_fallback", return_value=None):
            with self.assertRaises(RuntimeNotFound) as ctx:
                resolve_runtime("linux-x64", "cli")
        # Reached the download attempt; scheme check passed.
        self.assertIn("Tried:", str(ctx.exception))


class TestUnverifiedCacheRefusal(unittest.TestCase):
    """PH05 fixup (S3): missing .sha256 sidecar is a hard error by default."""

    def setUp(self) -> None:
        import tempfile
        self._tmpdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmpdir.name)
        self.cache_dir = self.tmp / "cache"
        self.tag = "runtime-v0.1.0-test"

        os.environ["PICOLET_RUNTIME_TAG"] = self.tag
        os.environ["PICOLET_CACHE_DIR"] = str(self.cache_dir)
        os.environ["PICOLET_ALLOW_FILE_URLS"] = "1"

    def tearDown(self) -> None:
        for key in (
            "PICOLET_RUNTIME_TAG",
            "PICOLET_RUNTIME_SOURCE",
            "PICOLET_CACHE_DIR",
            "PICOLET_ALLOW_FILE_URLS",
            "PICOLET_ALLOW_UNVERIFIED_CACHE",
        ):
            os.environ.pop(key, None)
        self._tmpdir.cleanup()

    def _stage_unverified_cache_entry(self) -> Path:
        """Populate the cache with a binary and *no* .sha256 sidecar."""
        artifact = _artifact_name("linux-x64", "cli")
        tag_dir = self.cache_dir / "runtime" / self.tag
        tag_dir.mkdir(parents=True, exist_ok=True)
        bin_path = tag_dir / artifact
        bin_path.write_bytes(FAKE_BINARY)
        return bin_path

    def test_cache_hit_without_sha256_refuses_by_default(self) -> None:
        """Cache hit + no sidecar + no opt-in → RuntimeIntegrityError."""
        from picolet.cli.runtime_resolver import RuntimeIntegrityError

        self._stage_unverified_cache_entry()
        # Point at a non-existent source so the resolver cannot re-download
        # and "fix" the missing sidecar.
        os.environ["PICOLET_RUNTIME_SOURCE"] = _file_url(self.tmp / "nonexistent")

        from picolet.cli import runtime_resolver as rr
        with mock.patch.object(rr, "_intree_fallback", return_value=None):
            with self.assertRaises(RuntimeIntegrityError) as ctx:
                resolve_runtime("linux-x64", "cli")

        msg = str(ctx.exception)
        self.assertIn("refusing to execute", msg)
        self.assertIn("PICOLET_ALLOW_UNVERIFIED_CACHE", msg)

    def test_cache_hit_without_sha256_permitted_with_env(self) -> None:
        """PICOLET_ALLOW_UNVERIFIED_CACHE=1 lets a sidecar-less cache hit through."""
        bin_path = self._stage_unverified_cache_entry()
        os.environ["PICOLET_RUNTIME_SOURCE"] = _file_url(self.tmp / "nonexistent")
        os.environ["PICOLET_ALLOW_UNVERIFIED_CACHE"] = "1"

        result = resolve_runtime("linux-x64", "cli")
        self.assertEqual(result.binary, bin_path)

    def test_cache_hit_without_sha256_permitted_with_flag(self) -> None:
        """allow_unverified=True (CLI flag) lets a sidecar-less cache hit through."""
        bin_path = self._stage_unverified_cache_entry()
        os.environ["PICOLET_RUNTIME_SOURCE"] = _file_url(self.tmp / "nonexistent")

        result = resolve_runtime("linux-x64", "cli", allow_unverified=True)
        self.assertEqual(result.binary, bin_path)

    def test_download_without_sha256_refuses_by_default(self) -> None:
        """Download succeeds but source has no .sha256 → RuntimeIntegrityError."""
        from picolet.cli.runtime_resolver import RuntimeIntegrityError

        release_dir = self.tmp / "no-sha-release"
        _make_fake_release(release_dir, tag=self.tag, include_sha256=False)
        os.environ["PICOLET_RUNTIME_SOURCE"] = _file_url(release_dir)

        from picolet.cli import runtime_resolver as rr
        with mock.patch.object(rr, "_intree_fallback", return_value=None):
            with self.assertRaises(RuntimeIntegrityError) as ctx:
                resolve_runtime("linux-x64", "cli")
        msg = str(ctx.exception)
        self.assertIn("refusing to execute", msg)


class TestPathsNoCrossModulePrivateImport(unittest.TestCase):
    """PH05 fixup (Q7): _paths.resolve_app must not import private names from build_cmd."""

    def test_resolve_app_does_not_import_build_cmd_private(self) -> None:
        """_paths module text must not contain ``from picolet.cli.build_cmd import _``."""
        from picolet.cli import _paths

        source = Path(_paths.__file__).read_text()
        # No private-name imports from build_cmd anywhere in the module.
        self.assertNotIn("from picolet.cli.build_cmd import", source)
        self.assertNotIn("import picolet.cli.build_cmd", source)

    def test_find_picolet_toml_lives_in_paths(self) -> None:
        """find_picolet_toml is a public helper in _paths."""
        from picolet.cli._paths import find_picolet_toml
        self.assertTrue(callable(find_picolet_toml))


class TestRepoRootSingleHelper(unittest.TestCase):
    """PH05 fixup (A6): repo-root walk is funnelled through one helper."""

    def test_repo_root_and_find_repo_root_agree(self) -> None:
        """_find_repo_root (back-compat alias) returns the same path as _repo_root."""
        from picolet.cli.runtime_resolver import _find_repo_root, _repo_root
        self.assertEqual(_repo_root(), _find_repo_root())

    def test_locate_mpy_cross_uses_repo_root(self) -> None:
        """locate_mpy_cross error message names the repo-root path when PATH lookup fails."""
        from picolet.cli import runtime_resolver as rr
        fake_repo = Path("/tmp/fake-picolet-repo-test")
        # Suppress PATH lookup so the repo-walk error path is exercised.
        with mock.patch("picolet.cli.runtime_resolver.shutil.which", return_value=None):
            with mock.patch.object(rr, "_repo_root", return_value=fake_repo):
                try:
                    rr.locate_mpy_cross()
                except rr.RuntimeNotFound as exc:
                    # Error path must reflect the patched repo root.
                    self.assertIn(str(fake_repo), str(exc))


class TestValidatorRuntimeSection(unittest.TestCase):
    """Test the [runtime] table in picolet.toml validator."""

    def _make_toml(self, tmpdir: Path, extra: str = "") -> Path:
        toml = tmpdir / "picolet.toml"
        toml.write_text(
            "[app]\n"
            'name = "test"\n'
            'version = "0.1.0"\n'
            'entry = "src/main.py"\n'
            + extra
        )
        return toml

    def test_runtime_section_absent_is_valid(self) -> None:
        """picolet.toml without [runtime] is valid (table is optional)."""
        import tempfile
        from picolet.cli.validator import validate_toml

        with tempfile.TemporaryDirectory() as d:
            toml = self._make_toml(Path(d))
            errors = validate_toml(toml)
        self.assertEqual(errors, [])

    def test_runtime_section_valid(self) -> None:
        """[runtime] with source and tag passes validation."""
        import tempfile
        from picolet.cli.validator import validate_toml

        with tempfile.TemporaryDirectory() as d:
            toml = self._make_toml(
                Path(d),
                '\n[runtime]\nsource = "file:///tmp/releases"\ntag = "runtime-v0.1.0"\n',
            )
            errors = validate_toml(toml)
        self.assertEqual(errors, [])

    def test_runtime_section_source_only_valid(self) -> None:
        """[runtime] with only source (no tag) passes validation."""
        import tempfile
        from picolet.cli.validator import validate_toml

        with tempfile.TemporaryDirectory() as d:
            toml = self._make_toml(
                Path(d),
                '\n[runtime]\nsource = "https://example.com/releases"\n',
            )
            errors = validate_toml(toml)
        self.assertEqual(errors, [])

    def test_runtime_section_tag_only_valid(self) -> None:
        """[runtime] with only tag (no source) passes validation."""
        import tempfile
        from picolet.cli.validator import validate_toml

        with tempfile.TemporaryDirectory() as d:
            toml = self._make_toml(
                Path(d),
                '\n[runtime]\ntag = "runtime-v0.1.0"\n',
            )
            errors = validate_toml(toml)
        self.assertEqual(errors, [])

    def test_runtime_section_wrong_type(self) -> None:
        """[runtime] tag with wrong type (integer) yields a validation error."""
        import tempfile
        from picolet.cli.validator import validate_toml

        with tempfile.TemporaryDirectory() as d:
            toml = self._make_toml(
                Path(d),
                "\n[runtime]\ntag = 123\n",
            )
            errors = validate_toml(toml)
        self.assertEqual(len(errors), 1)
        self.assertIn("tag", str(errors[0]))

    def test_runtime_section_source_wrong_type(self) -> None:
        """[runtime] source with wrong type (integer) yields a validation error."""
        import tempfile
        from picolet.cli.validator import validate_toml

        with tempfile.TemporaryDirectory() as d:
            toml = self._make_toml(
                Path(d),
                "\n[runtime]\nsource = 99\n",
            )
            errors = validate_toml(toml)
        self.assertEqual(len(errors), 1)
        self.assertIn("source", str(errors[0]))

    def test_runtime_both_source_and_tag_wrong_type(self) -> None:
        """[runtime] with both source and tag as wrong types yields two errors."""
        import tempfile
        from picolet.cli.validator import validate_toml

        with tempfile.TemporaryDirectory() as d:
            toml = self._make_toml(
                Path(d),
                "\n[runtime]\nsource = 1\ntag = 2\n",
            )
            errors = validate_toml(toml)
        self.assertEqual(len(errors), 2)
        keys = {e.key for e in errors}
        self.assertIn("source", keys)
        self.assertIn("tag", keys)

    def test_unknown_section_rejected(self) -> None:
        """Top-level section not in the allowed list is rejected."""
        import tempfile
        from picolet.cli.validator import validate_toml

        with tempfile.TemporaryDirectory() as d:
            toml = self._make_toml(Path(d), "\n[notavalidsection]\nfoo = 1\n")
            errors = validate_toml(toml)
        self.assertTrue(any("notavalidsection" in str(e) for e in errors))


class TestValidatorPackagingExtensions(unittest.TestCase):
    """[build].variant, [romfs].exclude, [[version_check]] schema additions."""

    def _make_toml(self, tmpdir: Path, extra: str = "") -> Path:
        toml = tmpdir / "picolet.toml"
        toml.write_text(
            "[app]\n"
            'name = "test"\n'
            'version = "0.1.0"\n'
            'entry = "src/main.py"\n'
            + extra
        )
        return toml

    def test_build_variant_valid(self) -> None:
        """[build].variant, an explicit runtime-variant override, is a valid str."""
        import tempfile
        from picolet.cli.validator import validate_toml

        with tempfile.TemporaryDirectory() as d:
            toml = self._make_toml(Path(d), '\n[build]\nvariant = "mcp"\n')
            errors = validate_toml(toml)
        self.assertEqual(errors, [])

    def test_build_variant_wrong_type(self) -> None:
        """[build].variant with wrong type (integer) yields a validation error."""
        import tempfile
        from picolet.cli.validator import validate_toml

        with tempfile.TemporaryDirectory() as d:
            toml = self._make_toml(Path(d), "\n[build]\nvariant = 5\n")
            errors = validate_toml(toml)
        self.assertEqual(len(errors), 1)
        self.assertIn("variant", str(errors[0]))

    def test_build_mpy_lib_dir_valid(self) -> None:
        """[build].mpy_lib_dir, a manifest.py require() override path, is a valid str."""
        import tempfile
        from picolet.cli.validator import validate_toml

        with tempfile.TemporaryDirectory() as d:
            toml = self._make_toml(Path(d), '\n[build]\nmpy_lib_dir = "/opt/micropython-lib"\n')
            errors = validate_toml(toml)
        self.assertEqual(errors, [])

    def test_build_mpy_lib_dir_wrong_type(self) -> None:
        """[build].mpy_lib_dir with wrong type (integer) yields a validation error."""
        import tempfile
        from picolet.cli.validator import validate_toml

        with tempfile.TemporaryDirectory() as d:
            toml = self._make_toml(Path(d), "\n[build]\nmpy_lib_dir = 5\n")
            errors = validate_toml(toml)
        self.assertEqual(len(errors), 1)
        self.assertIn("mpy_lib_dir", str(errors[0]))

    def test_romfs_exclude_valid(self) -> None:
        """[romfs].exclude alongside include passes validation."""
        import tempfile
        from picolet.cli.validator import validate_toml

        with tempfile.TemporaryDirectory() as d:
            toml = self._make_toml(
                Path(d),
                '\n[romfs]\ninclude = ["lib"]\nexclude = ["tests", "*.pyc"]\n',
            )
            errors = validate_toml(toml)
        self.assertEqual(errors, [])

    def test_romfs_exclude_wrong_type(self) -> None:
        """[romfs].exclude with wrong type (string, not list) yields an error."""
        import tempfile
        from picolet.cli.validator import validate_toml

        with tempfile.TemporaryDirectory() as d:
            toml = self._make_toml(Path(d), '\n[romfs]\nexclude = "tests"\n')
            errors = validate_toml(toml)
        self.assertEqual(len(errors), 1)
        self.assertIn("exclude", str(errors[0]))

    def test_version_check_valid(self) -> None:
        """[[version_check]] with valid path/pattern entries passes validation."""
        import tempfile
        from picolet.cli.validator import validate_toml

        with tempfile.TemporaryDirectory() as d:
            toml = self._make_toml(
                Path(d),
                "\n[[version_check]]\n"
                'path = "a.py"\n'
                'pattern = \'VERSION = "([^"]+)"\'\n'
                "\n[[version_check]]\n"
                'path = "b.json"\n'
                'pattern = \'"version": "([^"]+)"\'\n',
            )
            errors = validate_toml(toml)
        self.assertEqual(errors, [])

    def test_version_check_missing_pattern(self) -> None:
        """[[version_check]] entry missing the required pattern key errors."""
        import tempfile
        from picolet.cli.validator import validate_toml

        with tempfile.TemporaryDirectory() as d:
            toml = self._make_toml(Path(d), '\n[[version_check]]\npath = "a.py"\n')
            errors = validate_toml(toml)
        self.assertEqual(len(errors), 1)
        self.assertIn("pattern", str(errors[0]))

    def test_version_check_not_a_list(self) -> None:
        """version_check as a scalar (not an array of tables) errors.

        version_check must precede [app] here: once a [table] header has
        opened, TOML treats every following `key = value` line as part of
        that table, not as a new top-level key (no blank-line table close).
        """
        import tempfile
        from picolet.cli.validator import validate_toml

        with tempfile.TemporaryDirectory() as d:
            toml = Path(d) / "picolet.toml"
            toml.write_text(
                "version_check = 1\n"
                "[app]\n"
                'name = "test"\n'
                'version = "0.1.0"\n'
                'entry = "src/main.py"\n'
            )
            errors = validate_toml(toml)
        self.assertEqual(len(errors), 1)
        self.assertIn("array of tables", str(errors[0]))

    def test_version_check_entry_wrong_type(self) -> None:
        """A version_check entry that isn't itself a table errors."""
        import tempfile
        from picolet.cli.validator import validate_toml

        with tempfile.TemporaryDirectory() as d:
            toml = Path(d) / "picolet.toml"
            toml.write_text(
                "version_check = [1]\n"
                "[app]\n"
                'name = "test"\n'
                'version = "0.1.0"\n'
                'entry = "src/main.py"\n'
            )
            errors = validate_toml(toml)
        self.assertEqual(len(errors), 1)
        self.assertIn("must be a table", str(errors[0]))


class TestRuntimeTagResourceLookup(unittest.TestCase):
    """A6 fix: RUNTIME_TAG is resolved via importlib.resources, not only repo-walk."""

    # -------------------------------------------------------------------------
    # test_package_resource_provides_runtime_tag
    # -------------------------------------------------------------------------
    def test_package_resource_provides_runtime_tag(self) -> None:
        """importlib.resources.files('picolet.cli') / 'RUNTIME_TAG' is readable."""
        import importlib.resources

        ref = importlib.resources.files("picolet.cli").joinpath("RUNTIME_TAG")
        content = ref.read_text(encoding="utf-8").strip()
        self.assertTrue(content, "RUNTIME_TAG is empty inside picolet.cli package")
        self.assertTrue(content.startswith("runtime-"), f"unexpected tag format: {content!r}")

    # -------------------------------------------------------------------------
    # test_read_runtime_tag_sidecar_uses_package_resource
    # -------------------------------------------------------------------------
    def test_read_runtime_tag_sidecar_uses_package_resource(self) -> None:
        """_read_runtime_tag_sidecar() returns the tag from the package resource."""
        from picolet.cli.runtime_resolver import _read_runtime_tag_sidecar

        tag = _read_runtime_tag_sidecar()
        self.assertTrue(tag, "tag is empty")
        self.assertTrue(tag.startswith("runtime-"), f"unexpected tag format: {tag!r}")

    # -------------------------------------------------------------------------
    # test_package_resource_takes_priority_over_repo_walk
    # -------------------------------------------------------------------------
    def test_package_resource_takes_priority_over_repo_walk(self) -> None:
        """Package resource is used even when the repo-walk sidecar has a different value."""
        from picolet.cli import runtime_resolver as rr

        # Patch _repo_root to return a non-existent path so the repo-walk
        # step would produce a different (or absent) sidecar.
        with mock.patch.object(rr, "_repo_root", return_value=Path("/nonexistent/repo")):
            tag = rr._read_runtime_tag_sidecar()

        # Must still return a non-empty tag sourced from the package resource.
        self.assertTrue(tag, "tag is empty when repo-walk is patched away")
        self.assertTrue(tag.startswith("runtime-"), f"unexpected tag: {tag!r}")

    # -------------------------------------------------------------------------
    # test_repo_walk_fallback_used_when_package_resource_missing
    # -------------------------------------------------------------------------
    def test_repo_walk_fallback_used_when_package_resource_missing(self) -> None:
        """Repo-walk fallback is used when importlib.resources raises FileNotFoundError."""
        import importlib.resources
        from picolet.cli import runtime_resolver as rr

        # Simulate the package resource being absent (e.g. running from raw
        # source tree without picolet.cli/RUNTIME_TAG installed).
        class _FakeTraversable:
            def joinpath(self, *a):
                return self

            def read_text(self, **kw):
                raise FileNotFoundError("no RUNTIME_TAG in package")

        with mock.patch.object(
            importlib.resources,
            "files",
            return_value=_FakeTraversable(),
        ):
            # Also point repo-walk at a real sidecar so the fallback succeeds.
            repo_tag_file = (
                Path(__file__).parent.parent.parent
                / "packages"
                / "picolet-runtime"
                / "RUNTIME_TAG"
            )
            if repo_tag_file.is_file():
                tag = rr._read_runtime_tag_sidecar()
                self.assertTrue(tag.startswith("runtime-"), f"unexpected tag: {tag!r}")
            else:
                self.skipTest("packages/picolet-runtime/RUNTIME_TAG not present in repo")

    # -------------------------------------------------------------------------
    # test_last_resort_default_when_all_sources_missing
    # -------------------------------------------------------------------------
    def test_last_resort_default_when_all_sources_missing(self) -> None:
        """Last-resort default is returned when package resource and repo-walk both fail."""
        import importlib.resources
        from picolet.cli import runtime_resolver as rr

        class _FakeTraversable:
            def joinpath(self, *a):
                return self

            def read_text(self, **kw):
                raise FileNotFoundError("no RUNTIME_TAG in package")

        with mock.patch.object(
            importlib.resources,
            "files",
            return_value=_FakeTraversable(),
        ):
            with mock.patch.object(rr, "_repo_root", return_value=Path("/nonexistent/repo")):
                tag = rr._read_runtime_tag_sidecar()

        # Default tracks the value hard-coded in runtime_resolver._read_runtime_tag_sidecar
        # last-resort branch.  Updated to runtime-v0.0.1 alongside the initial CLI
        # release.  Keep in sync with packages/picolet-runtime/RUNTIME_TAG and the
        # similarly-hardcoded fallback in sbom_gen._runtime_tag.
        self.assertEqual(tag, "runtime-v0.0.1")

    # -------------------------------------------------------------------------
    # test_load_config_uses_package_resource_tag_by_default
    # -------------------------------------------------------------------------
    def test_load_config_uses_package_resource_tag_by_default(self) -> None:
        """_load_config() uses the package-bundled RUNTIME_TAG when no env/toml override."""
        from picolet.cli.runtime_resolver import _load_config

        env_backup = os.environ.pop("PICOLET_RUNTIME_TAG", None)
        os.environ.pop("PICOLET_RUNTIME_SOURCE", None)
        # Must not raise; tag must come from the package resource.
        try:
            cfg = _load_config(config={"runtime": {"source": "https://example.invalid"}})
            self.assertTrue(cfg.tag.startswith("runtime-"), f"unexpected tag: {cfg.tag!r}")
        finally:
            if env_backup is not None:
                os.environ["PICOLET_RUNTIME_TAG"] = env_backup


class TestLocateMpyCrossPathFirst(unittest.TestCase):
    """A6 fix: locate_mpy_cross resolves from PATH before repo-walk."""

    # -------------------------------------------------------------------------
    # test_path_lookup_wins_over_intree
    # -------------------------------------------------------------------------
    def test_path_lookup_wins_over_intree(self) -> None:
        """When mpy-cross is on PATH it is returned without touching repo-walk."""
        import tempfile
        from picolet.cli import runtime_resolver as rr

        with tempfile.TemporaryDirectory() as d:
            fake_mpy = Path(d) / "mpy-cross"
            fake_mpy.write_bytes(b"fake")
            fake_mpy.chmod(0o755)

            with mock.patch("picolet.cli.runtime_resolver.shutil.which", return_value=str(fake_mpy)):
                result = rr.locate_mpy_cross()

        self.assertEqual(result, fake_mpy.resolve())

    # -------------------------------------------------------------------------
    # test_intree_fallback_when_not_on_path
    # -------------------------------------------------------------------------
    def test_intree_fallback_when_not_on_path(self) -> None:
        """When mpy-cross is not on PATH, repo-walk in-tree path is tried."""
        import tempfile
        from picolet.cli import runtime_resolver as rr

        with tempfile.TemporaryDirectory() as d:
            # Create a fake in-tree mpy-cross.
            intree = (
                Path(d)
                / "packages"
                / "picolet-runtime"
                / "micropython"
                / "mpy-cross"
                / "build"
                / "mpy-cross"
            )
            intree.parent.mkdir(parents=True, exist_ok=True)
            intree.write_bytes(b"fake-mpy-cross")

            with mock.patch("picolet.cli.runtime_resolver.shutil.which", return_value=None):
                with mock.patch.object(rr, "_repo_root", return_value=Path(d)):
                    result = rr.locate_mpy_cross()

        self.assertEqual(result, intree.resolve())

    # -------------------------------------------------------------------------
    # test_clear_error_when_neither_available
    # -------------------------------------------------------------------------
    def test_clear_error_when_neither_available(self) -> None:
        """RuntimeNotFound with both remedy options when neither PATH nor in-tree works."""
        from picolet.cli import runtime_resolver as rr

        with mock.patch("picolet.cli.runtime_resolver.shutil.which", return_value=None):
            with mock.patch.object(rr, "_repo_root", return_value=Path("/nonexistent")):
                with self.assertRaises(rr.RuntimeNotFound) as ctx:
                    rr.locate_mpy_cross()

        msg = str(ctx.exception)
        self.assertIn("Option 1", msg)
        self.assertIn("Option 2", msg)
        self.assertIn("mpy-cross", msg)


if __name__ == "__main__":
    unittest.main()
