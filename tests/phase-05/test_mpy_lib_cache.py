"""
Unit tests for packages/picolet/picolet/cli/_mpy_lib_cache.py.

No test in this file performs a real network fetch of micropython-lib.
Cache-hit paths are exercised via a pre-populated directory; the fetch
tests stub urllib.request.urlopen with in-memory tarballs built by the
tests themselves (including malicious ones, for the path-traversal gate).
"""

from __future__ import annotations

import io
import os
import sys
import tarfile
import unittest
import unittest.mock as mock
from pathlib import Path

_REPO_ROOT = Path(__file__).parent.parent.parent
_PKG_PARENT = _REPO_ROOT / "packages" / "picolet"
if str(_PKG_PARENT) not in sys.path:
    sys.path.insert(0, str(_PKG_PARENT))

from picolet.cli import _mpy_lib_cache as mlc


class _FakeResponse:
    """Minimal urlopen()-context-manager stand-in yielding fixed bytes."""

    def __init__(self, content: bytes) -> None:
        self._content = content

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self, *_a, **_kw):
        chunk, self._content = self._content, b""
        return chunk


def _make_tarball(members: dict) -> bytes:
    """Build an in-memory .tar.gz from {tar_member_name: content_bytes}."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, content in members.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(content)
            tar.addfile(info, io.BytesIO(content))
    return buf.getvalue()


def _shaped_tarball() -> bytes:
    """A well-formed tarball shaped like a real GitHub codeload archive:
    exactly one top-level directory."""
    top = "micropython-lib-08cc0ac"
    return _make_tarball({
        f"{top}/python-stdlib/collections/manifest.py": b'metadata(version="0.2.0")\n',
        f"{top}/python-stdlib/collections/collections/__init__.py": b"# stub\n",
    })


class TestTargetPathAndMpyLibDirPath(unittest.TestCase):
    """_target_path / mpy_lib_dir_path: zero-network path computation."""

    def setUp(self) -> None:
        import tempfile
        self._tmpdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmpdir.name)
        self.app_root = self.tmp / "app"
        self.app_root.mkdir()
        self._saved_env = os.environ.pop("PICOLET_MPY_LIB_DIR", None)

    def tearDown(self) -> None:
        os.environ.pop("PICOLET_MPY_LIB_DIR", None)
        if self._saved_env is not None:
            os.environ["PICOLET_MPY_LIB_DIR"] = self._saved_env
        self._tmpdir.cleanup()

    def test_no_override_targets_pinned_cache_dir(self) -> None:
        """With no override, the target path is the pinned-commit cache dir."""
        path = mlc.mpy_lib_dir_path(None, self.app_root)
        self.assertEqual(path, mlc._mpy_lib_cache_dir())

    def test_env_override_absolute_used_as_is(self) -> None:
        """An absolute PICOLET_MPY_LIB_DIR is used verbatim."""
        os.environ["PICOLET_MPY_LIB_DIR"] = str(self.tmp / "custom-mpy-lib")
        path = mlc.mpy_lib_dir_path(None, self.app_root)
        self.assertEqual(path, self.tmp / "custom-mpy-lib")

    def test_toml_override_relative_resolves_against_app_root(self) -> None:
        """A relative [build].mpy_lib_dir resolves against app_root, not cwd.

        Every other path-valued toml key in this codebase (e.g.
        _copy_includes's app_root / inc) resolves relative to app_root;
        mpy_lib_dir must match, not the process's current working directory.
        """
        config = {"build": {"mpy_lib_dir": "vendor/mpy-lib"}}
        path = mlc.mpy_lib_dir_path(config, self.app_root)
        self.assertEqual(path, self.app_root / "vendor" / "mpy-lib")

    def test_env_override_takes_precedence_over_toml(self) -> None:
        """PICOLET_MPY_LIB_DIR wins over [build].mpy_lib_dir when both are set."""
        os.environ["PICOLET_MPY_LIB_DIR"] = str(self.tmp / "env-mpy-lib")
        config = {"build": {"mpy_lib_dir": str(self.tmp / "toml-mpy-lib")}}
        path = mlc.mpy_lib_dir_path(config, self.app_root)
        self.assertEqual(path, self.tmp / "env-mpy-lib")

    def test_computing_path_touches_no_filesystem(self) -> None:
        """mpy_lib_dir_path never creates or fetches anything."""
        os.environ["PICOLET_MPY_LIB_DIR"] = str(self.tmp / "does-not-exist-yet")
        path = mlc.mpy_lib_dir_path(None, self.app_root)
        self.assertFalse(path.exists())


class TestEnsureMpyLibDir(unittest.TestCase):
    """ensure_mpy_lib_dir: override validation (#5/#6) + fetch delegation."""

    def setUp(self) -> None:
        import tempfile
        self._tmpdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmpdir.name)
        self.app_root = self.tmp / "app"
        self.app_root.mkdir()
        self._saved_env = os.environ.pop("PICOLET_MPY_LIB_DIR", None)

    def tearDown(self) -> None:
        os.environ.pop("PICOLET_MPY_LIB_DIR", None)
        if self._saved_env is not None:
            os.environ["PICOLET_MPY_LIB_DIR"] = self._saved_env
        self._tmpdir.cleanup()

    def _make_valid_checkout(self, root: Path) -> None:
        (root / "python-stdlib").mkdir(parents=True)

    def test_env_override_valid_checkout_returned(self) -> None:
        override_dir = self.tmp / "custom-mpy-lib"
        self._make_valid_checkout(override_dir)
        os.environ["PICOLET_MPY_LIB_DIR"] = str(override_dir)

        with mock.patch.object(mlc, "_fetch_and_cache") as m_fetch:
            result = mlc.ensure_mpy_lib_dir(None, self.app_root)

        self.assertEqual(result, override_dir)
        m_fetch.assert_not_called()

    def test_env_override_missing_dir_raises(self) -> None:
        """PICOLET_MPY_LIB_DIR pointing at a non-existent path raises MpyLibFetchError."""
        os.environ["PICOLET_MPY_LIB_DIR"] = str(self.tmp / "does-not-exist")

        with self.assertRaises(mlc.MpyLibFetchError) as ctx:
            mlc.ensure_mpy_lib_dir(None, self.app_root)
        self.assertIn("PICOLET_MPY_LIB_DIR", str(ctx.exception))

    def test_env_override_wrong_shape_raises(self) -> None:
        """An override dir that exists but has none of BASE_LIBRARY_NAMES raises,
        with the expected layout named in the error (#6)."""
        override_dir = self.tmp / "not-a-mpy-lib-checkout"
        override_dir.mkdir()
        (override_dir / "random_file.txt").write_text("nope\n")
        os.environ["PICOLET_MPY_LIB_DIR"] = str(override_dir)

        with self.assertRaises(mlc.MpyLibFetchError) as ctx:
            mlc.ensure_mpy_lib_dir(None, self.app_root)
        msg = str(ctx.exception)
        self.assertIn(str(override_dir), msg)
        self.assertIn("python-stdlib", msg)

    def test_toml_override_valid_checkout_returned(self) -> None:
        override_dir = self.app_root / "vendor" / "mpy-lib"
        self._make_valid_checkout(override_dir)
        config = {"build": {"mpy_lib_dir": "vendor/mpy-lib"}}

        with mock.patch.object(mlc, "_fetch_and_cache") as m_fetch:
            result = mlc.ensure_mpy_lib_dir(config, self.app_root)

        self.assertEqual(result, override_dir)
        m_fetch.assert_not_called()

    def test_toml_override_missing_dir_raises(self) -> None:
        config = {"build": {"mpy_lib_dir": "does-not-exist"}}

        with self.assertRaises(mlc.MpyLibFetchError) as ctx:
            mlc.ensure_mpy_lib_dir(config, self.app_root)
        self.assertIn("[build].mpy_lib_dir", str(ctx.exception))

    def test_no_override_delegates_to_fetch_and_cache(self) -> None:
        with mock.patch.object(
            mlc, "_fetch_and_cache", return_value=Path("/fake/cached")
        ) as m_fetch:
            result = mlc.ensure_mpy_lib_dir(None, self.app_root)

        m_fetch.assert_called_once()
        self.assertEqual(result, Path("/fake/cached"))


class TestFetchAndCache(unittest.TestCase):
    """_fetch_and_cache: cache hit, integrity gate, malicious/corrupt tarballs."""

    def setUp(self) -> None:
        import tempfile
        self._tmpdir = tempfile.TemporaryDirectory()
        self.cache_root = Path(self._tmpdir.name) / "cache"
        self._saved_cache_dir = os.environ.get("PICOLET_CACHE_DIR")
        os.environ["PICOLET_CACHE_DIR"] = str(self.cache_root)

    def tearDown(self) -> None:
        if self._saved_cache_dir is not None:
            os.environ["PICOLET_CACHE_DIR"] = self._saved_cache_dir
        else:
            os.environ.pop("PICOLET_CACHE_DIR", None)
        self._tmpdir.cleanup()

    def test_cache_hit_skips_network(self) -> None:
        """An already-cached, integrity-verified checkout skips the network.

        The digest is re-verified on every call (not just first fetch), so
        this fake cache content is patched to match its own digest; the
        real _PINNED_TREE_SHA256 is for the real package, not this marker file.
        """
        cached_dir = mlc._mpy_lib_cache_dir()
        cached_dir.mkdir(parents=True)
        (cached_dir / "marker.txt").write_text("cached\n")
        fake_digest = mlc._tree_digest(cached_dir)

        with mock.patch.object(mlc, "_PINNED_TREE_SHA256", fake_digest):
            with mock.patch("urllib.request.urlopen") as m_urlopen:
                result = mlc._fetch_and_cache()

        m_urlopen.assert_not_called()
        self.assertEqual(result, cached_dir)
        self.assertTrue((result / "marker.txt").is_file())

    def test_tampered_cache_hit_triggers_refetch_not_blind_trust(self) -> None:
        """A cache hit whose content no longer matches the pinned digest
        (tampered or corrupted since it was written) is not trusted blindly:
        it is discarded and re-fetched, the same as a cold cache; the pin
        must protect every use of the cache, not just the first fetch.
        """
        cached_dir = mlc._mpy_lib_cache_dir()
        cached_dir.mkdir(parents=True)
        (cached_dir / "tampered.txt").write_text("not the real content\n")

        good_tarball = _shaped_tarball()
        good_digest = self._digest_of_tarball(good_tarball)

        with mock.patch.object(mlc, "_PINNED_TREE_SHA256", good_digest):
            with mock.patch(
                "urllib.request.urlopen", return_value=_FakeResponse(good_tarball)
            ) as m_urlopen:
                result = mlc._fetch_and_cache()

        m_urlopen.assert_called_once()
        self.assertEqual(result, cached_dir)
        # The tampered file is gone; the re-fetched, verified content replaced it.
        self.assertFalse((result / "tampered.txt").exists())
        self.assertTrue(
            (result / "python-stdlib" / "collections" / "manifest.py").is_file()
        )

    def test_cache_hit_unreadable_treated_like_mismatch_not_uncaught(self) -> None:
        """A cache-hit digest computation that raises OSError (e.g. a file
        vanishing mid-walk under a concurrent build's rmtree, or a
        permissions/IO error on an already-corrupt cache) is treated the
        same as a digest mismatch: warn, discard, re-fetch; it must not
        propagate uncaught out of _fetch_and_cache.
        """
        cached_dir = mlc._mpy_lib_cache_dir()
        cached_dir.mkdir(parents=True)
        (cached_dir / "unreadable.txt").write_text("won't actually be read\n")

        good_tarball = _shaped_tarball()
        good_digest = self._digest_of_tarball(good_tarball)

        real_tree_digest = mlc._tree_digest
        call_count = 0

        def flaky_tree_digest(root):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise OSError("simulated read failure during cache-hit check")
            return real_tree_digest(root)

        with mock.patch.object(mlc, "_PINNED_TREE_SHA256", good_digest):
            with mock.patch.object(mlc, "_tree_digest", side_effect=flaky_tree_digest):
                with mock.patch(
                    "urllib.request.urlopen", return_value=_FakeResponse(good_tarball)
                ) as m_urlopen:
                    result = mlc._fetch_and_cache()

        m_urlopen.assert_called_once()
        self.assertEqual(result, cached_dir)
        self.assertFalse((result / "unreadable.txt").exists())
        self.assertTrue(
            (result / "python-stdlib" / "collections" / "manifest.py").is_file()
        )

    def test_fetch_extracts_and_caches_when_integrity_matches(self) -> None:
        """A stubbed tarball whose content matches the pinned digest is cached.

        The real _PINNED_TREE_SHA256 is for the real pinned commit; this
        test patches it to the fake tarball's own digest so the integrity
        gate is exercised for real without needing network access to the
        genuine package.
        """
        tarball_bytes = _shaped_tarball()
        fake_digest = self._digest_of_tarball(tarball_bytes)

        with mock.patch.object(mlc, "_PINNED_TREE_SHA256", fake_digest):
            with mock.patch(
                "urllib.request.urlopen", return_value=_FakeResponse(tarball_bytes)
            ) as m_urlopen:
                result = mlc._fetch_and_cache()

        m_urlopen.assert_called_once()
        self.assertEqual(result, mlc._mpy_lib_cache_dir())
        self.assertTrue(
            (result / "python-stdlib" / "collections" / "manifest.py").is_file()
        )
        self.assertTrue(
            (result / "python-stdlib" / "collections" / "collections" / "__init__.py").is_file()
        )
        # No leftover temp files.
        leftovers = list(result.parent.glob(".*"))
        self.assertEqual(leftovers, [], f"stale temp entries left behind: {leftovers}")

    def _digest_of_tarball(self, tarball_bytes: bytes) -> str:
        """Extract a tarball to a scratch dir and compute its _tree_digest."""
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            with tarfile.open(fileobj=io.BytesIO(tarball_bytes)) as tar:
                tar.extractall(d, filter="data")
            top = next(Path(d).iterdir())
            return mlc._tree_digest(top)

    def test_integrity_mismatch_raises_and_does_not_cache(self) -> None:
        """A tarball whose content doesn't match the pinned digest is rejected.

        _PINNED_TREE_SHA256 is left at its real (production) value here, so
        this fake, arbitrary tarball's digest is guaranteed not to match.
        """
        tarball_bytes = _shaped_tarball()

        with mock.patch(
            "urllib.request.urlopen", return_value=_FakeResponse(tarball_bytes)
        ):
            with self.assertRaises(mlc.MpyLibFetchError) as ctx:
                mlc._fetch_and_cache()

        self.assertIn("integrity check failed", str(ctx.exception))
        self.assertFalse(mlc._mpy_lib_cache_dir().exists())

    def test_malicious_tarball_path_traversal_rejected(self) -> None:
        """A tarball member escaping the extraction dir via '..' is rejected,
        not extracted outside the destination (CVE-2007-4559 regression gate).

        This is the confirmed-exploitable case from the security review:
        one benign top-level directory (so the "exactly one top-level entry"
        shape check passes) plus a second member that climbs out of it.
        """
        top = "micropython-lib-08cc0ac"
        tarball_bytes = _make_tarball({
            f"{top}/manifest.py": b'metadata(version="0.1.0")\n',
            f"{top}/../../../../tmp/PICOLET_PWNED_MARKER": b"pwned\n",
        })

        with mock.patch(
            "urllib.request.urlopen", return_value=_FakeResponse(tarball_bytes)
        ):
            with self.assertRaises(mlc.MpyLibFetchError):
                mlc._fetch_and_cache()

        # The traversal target must not have been written anywhere under
        # this test's own tmpdir (scoped to it, not a full /tmp walk: the
        # cache lives entirely under self._tmpdir.name, and the traversal
        # depth in this payload climbs back to exactly that root).
        escaped = list(Path(self._tmpdir.name).rglob("PICOLET_PWNED_MARKER"))
        self.assertEqual(escaped, [], f"path traversal wrote outside the extraction dir: {escaped}")
        self.assertFalse(mlc._mpy_lib_cache_dir().exists())

    def test_malicious_tarball_absolute_path_rejected(self) -> None:
        """A tarball member with an absolute path is rejected outright."""
        top = "micropython-lib-08cc0ac"
        # Built directly with tarfile (rather than via _make_tarball) since
        # an absolute TarInfo.name needs constructing explicitly.
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            info = tarfile.TarInfo(name=f"{top}/manifest.py")
            content = b'metadata(version="0.1.0")\n'
            info.size = len(content)
            tar.addfile(info, io.BytesIO(content))
            evil_content = b"pwned\n"
            evil = tarfile.TarInfo(name="/tmp/PICOLET_PWNED_ABS_MARKER")
            evil.size = len(evil_content)
            tar.addfile(evil, io.BytesIO(evil_content))
        tarball_bytes = buf.getvalue()

        with mock.patch(
            "urllib.request.urlopen", return_value=_FakeResponse(tarball_bytes)
        ):
            with self.assertRaises(mlc.MpyLibFetchError):
                mlc._fetch_and_cache()

        self.assertFalse(Path("/tmp/PICOLET_PWNED_ABS_MARKER").exists())
        self.assertFalse(mlc._mpy_lib_cache_dir().exists())

    def test_corrupt_tarball_raises_mpy_lib_fetch_error(self) -> None:
        """Garbage bytes (not a valid tar/gzip stream) raise MpyLibFetchError,
        not an uncaught tarfile.TarError."""
        with mock.patch(
            "urllib.request.urlopen",
            return_value=_FakeResponse(b"this is not a tarball, just garbage bytes"),
        ):
            with self.assertRaises(mlc.MpyLibFetchError) as ctx:
                mlc._fetch_and_cache()

        self.assertIn("failed to fetch", str(ctx.exception))

    def test_oversized_download_aborted_before_extraction(self) -> None:
        """A response exceeding the size cap is aborted mid-download rather
        than being fully buffered, opened as a tarball, and hashed.

        _MAX_TARBALL_BYTES is patched down to a tiny value so this test
        doesn't need to actually transfer megabytes of data.
        """
        with mock.patch.object(mlc, "_MAX_TARBALL_BYTES", 10):
            with mock.patch(
                "urllib.request.urlopen",
                return_value=_FakeResponse(b"x" * 1000),
            ):
                with self.assertRaises(mlc.MpyLibFetchError) as ctx:
                    mlc._fetch_and_cache()

        self.assertIn("exceeded", str(ctx.exception))
        # No leftover temp files from the aborted download.
        cache_dir = mlc._mpy_lib_cache_dir()
        leftovers = list(cache_dir.parent.glob(".*")) if cache_dir.parent.is_dir() else []
        self.assertEqual(leftovers, [], f"stale temp entries left behind: {leftovers}")

    def test_zero_top_level_entries_rejected(self) -> None:
        """An empty tarball (no top-level directory at all) is rejected clearly."""
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz"):
            pass  # empty archive

        with mock.patch(
            "urllib.request.urlopen", return_value=_FakeResponse(buf.getvalue())
        ):
            with self.assertRaises(mlc.MpyLibFetchError) as ctx:
                mlc._fetch_and_cache()
        self.assertIn("expected exactly one top-level directory", str(ctx.exception))

    def test_multiple_top_level_entries_rejected(self) -> None:
        """A tarball with two top-level directories is rejected clearly."""
        tarball_bytes = _make_tarball({
            "dir-one/manifest.py": b'metadata(version="0.1.0")\n',
            "dir-two/manifest.py": b'metadata(version="0.1.0")\n',
        })

        with mock.patch(
            "urllib.request.urlopen", return_value=_FakeResponse(tarball_bytes)
        ):
            with self.assertRaises(mlc.MpyLibFetchError) as ctx:
                mlc._fetch_and_cache()
        self.assertIn("expected exactly one top-level directory", str(ctx.exception))

    def test_fetch_failure_raises_mpy_lib_fetch_error(self) -> None:
        """A network failure during fetch raises MpyLibFetchError with remediation hints."""
        import urllib.error

        with mock.patch(
            "urllib.request.urlopen", side_effect=urllib.error.URLError("no route")
        ):
            with self.assertRaises(mlc.MpyLibFetchError) as ctx:
                mlc._fetch_and_cache()

        msg = str(ctx.exception)
        self.assertIn("PICOLET_MPY_LIB_DIR", msg)
        self.assertIn("mpy_lib_dir", msg)


if __name__ == "__main__":
    unittest.main()
