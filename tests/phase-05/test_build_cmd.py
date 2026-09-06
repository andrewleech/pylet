"""
build_cmd integration tests — PH05.

NOTE: The full build pipeline requires mpremote (from the project .venv) to
be on sys.executable's path. When pytest runs under the system Python
(/usr/bin/python) rather than the project .venv, mpremote is unavailable
and the subprocess-based integration tests fail at the romfs build step.

The integration gate tests (cache hit, full build, --from-source, --runtime,
--no-cache) are therefore in tests/phase-05/run.sh which uses 'uv run' to
invoke picolet with the correct Python and dependencies.

This file contains only the tests that can run correctly under pytest without
the full build pipeline:
  - Argument parsing: --from-source, --no-cache, --runtime parsed correctly.
  - resolve_runtime integration: build_cmd passes the right args to the resolver.
"""

from __future__ import annotations

import hashlib
import os
import sys
import unittest
import unittest.mock as mock
from pathlib import Path

_REPO_ROOT = Path(__file__).parent.parent.parent
_PKG_PARENT = _REPO_ROOT / "packages" / "picolet"
if str(_PKG_PARENT) not in sys.path:
    sys.path.insert(0, str(_PKG_PARENT))

from picolet.cli import build_cmd
from picolet.cli import _mpy_lib_cache as mlc
from picolet.cli.runtime_resolver import ResolvedRuntime

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "hello-cli"
LINUX_RUNTIME = _REPO_ROOT / "packages" / "picolet-runtime" / "build" / "picolet-runtime-linux-x64-cli"

FAKE_BINARY = b"FAKE_RUNTIME_BINARY_CONTENT"


def _file_url(path: Path) -> str:
    return path.as_uri()


def _make_fake_release(base_dir: Path, tag: str, content: bytes = FAKE_BINARY) -> None:
    artifact = "picolet-runtime-linux-x64-cli"
    release_dir = base_dir / tag
    release_dir.mkdir(parents=True, exist_ok=True)
    (release_dir / artifact).write_bytes(content)
    sha256 = hashlib.sha256(content).hexdigest()
    (release_dir / f"{artifact}.sha256").write_text(sha256 + "\n")
    (release_dir / f"{artifact}.cdx.json").write_text("{}\n")


class TestBuildCmdArgParsing(unittest.TestCase):
    """Verify the --from-source, --no-cache, and --runtime flags are wired correctly."""

    def _make_parser(self):
        import argparse
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        build_cmd.add_parser(subparsers)
        return parser

    def test_from_source_flag_parsed(self) -> None:
        """--from-source sets args.from_source = True."""
        parser = self._make_parser()
        args = parser.parse_args(["build", "--from-source"])
        self.assertTrue(args.from_source)

    def test_no_cache_flag_parsed(self) -> None:
        """--no-cache sets args.no_cache = True."""
        parser = self._make_parser()
        args = parser.parse_args(["build", "--no-cache"])
        self.assertTrue(args.no_cache)

    def test_runtime_flag_parsed(self) -> None:
        """--runtime /path sets args.runtime = '/path'."""
        parser = self._make_parser()
        args = parser.parse_args(["build", "--runtime", "/some/path"])
        self.assertEqual(args.runtime, "/some/path")

    def test_defaults_are_false(self) -> None:
        """Without flags, from_source and no_cache default to False."""
        parser = self._make_parser()
        args = parser.parse_args(["build"])
        self.assertFalse(args.from_source)
        self.assertFalse(args.no_cache)
        self.assertIsNone(args.runtime)


class TestBuildCmdResolverIntegration(unittest.TestCase):
    """Verify build_cmd.run() passes the correct arguments to resolve_runtime.

    These tests patch resolve_runtime to raise immediately after capturing args,
    avoiding the need to mock the entire downstream build pipeline.
    """

    @classmethod
    def setUpClass(cls) -> None:
        if not FIXTURE_DIR.is_dir():
            raise unittest.SkipTest(f"fixture not found: {FIXTURE_DIR}")

    def setUp(self) -> None:
        import tempfile
        self._tmpdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmpdir.name)

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def _make_args(self, **kwargs):
        """Build a minimal args namespace for build_cmd.run()."""
        class Args:
            target = "linux-x64"
            verbose = False
            keep_staging = False
            runtime = None
            from_source = False
            no_cache = False
            allow_unverified_runtime = False
            no_sbom = True
        for k, v in kwargs.items():
            setattr(Args, k, v)
        return Args()

    def _capture_resolve_args(self, args):
        """Run build_cmd.run() with a resolve_runtime that captures its call args.

        resolve_runtime raises RuntimeNotFound after capturing, which causes
        build_cmd.run() to call sys.exit(1). We catch SystemExit.
        Returns the captured keyword arguments dict.
        """
        from picolet.cli import runtime_resolver as rr

        captured = {}

        class _Captured(Exception):
            pass

        def fake_resolve(target, variant, **kwargs):
            captured.update({
                "target": target,
                "variant": variant,
                **kwargs,
            })
            raise rr.RuntimeNotFound("captured")

        orig_cwd = os.getcwd()
        try:
            os.chdir(str(FIXTURE_DIR))
            # build_cmd imports resolve_runtime directly; patch it in build_cmd's namespace.
            with mock.patch.object(build_cmd, "resolve_runtime", side_effect=fake_resolve):
                try:
                    build_cmd.run(args)
                except SystemExit:
                    pass  # expected: resolve_runtime raised RuntimeNotFound → sys.exit(1)
        finally:
            os.chdir(orig_cwd)

        return captured

    def test_resolve_runtime_called_with_explicit_path(self) -> None:
        """--runtime arg is forwarded to resolve_runtime as explicit_path."""
        fake_runtime = self.tmp / "my-runtime"
        fake_runtime.write_bytes(b"FAKE")

        args = self._make_args(runtime=str(fake_runtime))
        captured = self._capture_resolve_args(args)

        self.assertIn("explicit_path", captured)
        self.assertEqual(captured["explicit_path"], fake_runtime)

    def test_resolve_runtime_called_with_from_source(self) -> None:
        """--from-source arg is forwarded to resolve_runtime as from_source=True."""
        args = self._make_args(from_source=True)
        captured = self._capture_resolve_args(args)

        self.assertTrue(captured.get("from_source"), "from_source not forwarded to resolve_runtime")

    def test_resolve_runtime_called_with_no_cache(self) -> None:
        """--no-cache arg is forwarded to resolve_runtime as no_cache=True."""
        args = self._make_args(no_cache=True)
        captured = self._capture_resolve_args(args)

        self.assertTrue(captured.get("no_cache"), "no_cache not forwarded to resolve_runtime")

    def test_resolve_runtime_no_flags_default_args(self) -> None:
        """Without flags, resolve_runtime is called with from_source=False, no_cache=False, explicit_path=None."""
        args = self._make_args()
        captured = self._capture_resolve_args(args)

        self.assertFalse(captured.get("from_source"))
        self.assertFalse(captured.get("no_cache"))
        self.assertIsNone(captured.get("explicit_path"))


class TestBuildCmdVariantOverride(unittest.TestCase):
    """[build].variant explicit override wins over [ui].renderer-derived variant."""

    def setUp(self) -> None:
        import tempfile
        self._tmpdir = tempfile.TemporaryDirectory()
        self.app_root = Path(self._tmpdir.name)
        (self.app_root / "src").mkdir()
        (self.app_root / "src" / "main.py").write_text("print('hi')\n")

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def _write_toml(self, extra: str) -> None:
        (self.app_root / "picolet.toml").write_text(
            "[app]\n"
            'name = "test"\n'
            'version = "0.1.0"\n'
            'entry = "src/main.py"\n'
            + extra
        )

    def _make_args(self):
        class Args:
            target = "linux-x64"
            verbose = False
            keep_staging = False
            runtime = None
            from_source = False
            no_cache = False
            allow_unverified_runtime = False
            no_sbom = True
        return Args()

    def _capture_variant(self, args) -> str | None:
        """Run build_cmd.run() with resolve_runtime patched to capture `variant`.

        Same technique as TestBuildCmdResolverIntegration._capture_resolve_args,
        against a per-test app_root rather than the shared hello-cli fixture.
        """
        from picolet.cli import runtime_resolver as rr

        captured: dict = {}

        def fake_resolve(target, variant, **kwargs):
            captured["variant"] = variant
            raise rr.RuntimeNotFound("captured")

        orig_cwd = os.getcwd()
        try:
            os.chdir(str(self.app_root))
            with mock.patch.object(build_cmd, "resolve_runtime", side_effect=fake_resolve):
                try:
                    build_cmd.run(args)
                except SystemExit:
                    pass
        finally:
            os.chdir(orig_cwd)
        return captured.get("variant")

    def test_explicit_variant_wins(self) -> None:
        """[build].variant = "mcp" is used when [ui] is absent."""
        self._write_toml('\n[build]\nvariant = "mcp"\n')
        self.assertEqual(self._capture_variant(self._make_args()), "mcp")

    def test_no_override_falls_back_to_renderer(self) -> None:
        """Without [build].variant, absent [ui] still resolves to "cli"."""
        self._write_toml("")
        self.assertEqual(self._capture_variant(self._make_args()), "cli")

    def test_explicit_variant_wins_over_explicit_renderer(self) -> None:
        """[build].variant wins even when [ui].renderer is also set."""
        self._write_toml('\n[ui]\nrenderer = "tui"\n\n[build]\nvariant = "mcp"\n')
        self.assertEqual(self._capture_variant(self._make_args()), "mcp")


class TestCopyIncludesExcludeAndCompile(unittest.TestCase):
    """[romfs].exclude pruning, .py -> .mpy compilation, and the collision guard."""

    @classmethod
    def setUpClass(cls) -> None:
        from picolet.cli.runtime_resolver import locate_mpy_cross, RuntimeNotFound
        try:
            cls.mpy_cross = locate_mpy_cross()
        except RuntimeNotFound:
            raise unittest.SkipTest("mpy-cross not available on PATH or in-tree")

    def setUp(self) -> None:
        import tempfile
        self._tmpdir = tempfile.TemporaryDirectory()
        tmp = Path(self._tmpdir.name)
        self.app_root = tmp / "app"
        self.app_root.mkdir()
        self.romfs_root = tmp / "romfs"

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def test_py_file_compiled_to_mpy(self) -> None:
        """A .py file under an include dir is compiled to .mpy, not copied verbatim."""
        lib = self.app_root / "lib"
        lib.mkdir()
        (lib / "mod.py").write_text("x = 1\n")

        build_cmd._copy_includes(
            self.app_root, ["lib"], [], self.romfs_root, self.mpy_cross, False
        )

        self.assertFalse((self.romfs_root / "lib" / "mod.py").exists())
        self.assertTrue((self.romfs_root / "lib" / "mod.mpy").exists())

    def test_non_py_file_copied_verbatim(self) -> None:
        """A non-.py asset file is copied unchanged, byte for byte."""
        assets = self.app_root / "assets"
        assets.mkdir()
        (assets / "cert.der").write_bytes(b"\x01\x02\x03")

        build_cmd._copy_includes(
            self.app_root, ["assets"], [], self.romfs_root, self.mpy_cross, False
        )

        copied = self.romfs_root / "assets" / "cert.der"
        self.assertTrue(copied.exists())
        self.assertEqual(copied.read_bytes(), b"\x01\x02\x03")

    def test_exclude_prunes_matching_directory(self) -> None:
        """A directory name matching an exclude pattern is pruned, with its contents."""
        lib = self.app_root / "lib"
        (lib / "tests").mkdir(parents=True)
        (lib / "tests" / "test_mod.py").write_text("assert True\n")
        (lib / "mod.py").write_text("x = 1\n")

        build_cmd._copy_includes(
            self.app_root, ["lib"], ["tests"], self.romfs_root, self.mpy_cross, False
        )

        self.assertFalse((self.romfs_root / "lib" / "tests").exists())
        self.assertTrue((self.romfs_root / "lib" / "mod.mpy").exists())

    def test_exclude_prunes_matching_basename(self) -> None:
        """A file basename matching an exclude pattern is skipped."""
        lib = self.app_root / "lib"
        lib.mkdir()
        (lib / "README.md").write_text("docs\n")
        (lib / "mod.py").write_text("x = 1\n")

        build_cmd._copy_includes(
            self.app_root, ["lib"], ["README.md"], self.romfs_root, self.mpy_cross, False
        )

        self.assertFalse((self.romfs_root / "lib" / "README.md").exists())
        self.assertTrue((self.romfs_root / "lib" / "mod.mpy").exists())

    def test_py_and_mpy_collision_raises(self) -> None:
        """A .py and a pre-existing .mpy resolving to the same romfs path fails loudly."""
        lib = self.app_root / "lib"
        lib.mkdir()
        (lib / "mod.py").write_text("x = 1\n")
        (lib / "mod.mpy").write_bytes(b"STALE_PREBUILT_MPY")

        with self.assertRaises(build_cmd.BuildFailed):
            build_cmd._copy_includes(
                self.app_root, ["lib"], [], self.romfs_root, self.mpy_cross, False
            )

    def test_own_staging_output_never_included(self) -> None:
        """include=["."] doesn't walk back into app_root/target (this
        build's own staging/output tree), which would otherwise be live on
        disk by the time _copy_includes runs after _compile_mpy."""
        (self.app_root / "asset.der").write_bytes(b"\x01")
        stale_staging = self.app_root / "target" / "linux-x64" / ".picolet-build" / "romfs"
        stale_staging.mkdir(parents=True)
        (stale_staging / "main.mpy").write_bytes(b"SHOULD_NOT_BE_RECOPIED")

        build_cmd._copy_includes(
            self.app_root, ["."], [], self.romfs_root, self.mpy_cross, False
        )

        self.assertTrue((self.romfs_root / "asset.der").exists())
        self.assertFalse((self.romfs_root / "target").exists())

    def test_pycache_and_pyc_still_skipped(self) -> None:
        """Pre-existing __pycache__/.pyc skip behaviour is unchanged."""
        lib = self.app_root / "lib"
        cache = lib / "__pycache__"
        cache.mkdir(parents=True)
        (cache / "mod.cpython-312.pyc").write_bytes(b"\x00")
        (lib / "mod.py").write_text("x = 1\n")

        build_cmd._copy_includes(
            self.app_root, ["lib"], [], self.romfs_root, self.mpy_cross, False
        )

        self.assertFalse((self.romfs_root / "lib" / "__pycache__").exists())
        self.assertTrue((self.romfs_root / "lib" / "mod.mpy").exists())


class TestCompileMpyExclude(unittest.TestCase):
    """_compile_mpy's [romfs].exclude support (entry tree, not just includes)."""

    @classmethod
    def setUpClass(cls) -> None:
        from picolet.cli.runtime_resolver import locate_mpy_cross, RuntimeNotFound
        try:
            cls.mpy_cross = locate_mpy_cross()
        except RuntimeNotFound:
            raise unittest.SkipTest("mpy-cross not available on PATH or in-tree")

    def setUp(self) -> None:
        import tempfile
        self._tmpdir = tempfile.TemporaryDirectory()
        tmp = Path(self._tmpdir.name)
        self.app_root = tmp / "app"
        self.app_root.mkdir()
        self.romfs_root = tmp / "romfs"

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def test_excluded_sibling_not_compiled(self) -> None:
        """A test file alongside the entry, matching an exclude, is skipped."""
        (self.app_root / "plugin.py").write_text("print('hi')\n")
        tests_dir = self.app_root / "tests"
        tests_dir.mkdir()
        (tests_dir / "test_plugin.py").write_text("assert True\n")

        build_cmd._compile_mpy(
            self.app_root, "plugin.py", self.romfs_root, self.mpy_cross,
            ["tests"], False,
        )

        self.assertFalse((self.romfs_root / "tests").exists())
        self.assertTrue((self.romfs_root / "main.mpy").exists())

    def test_entry_itself_never_excluded(self) -> None:
        """The entry point still compiles to main.mpy even if it would
        otherwise match an (overly broad) exclude pattern."""
        (self.app_root / "plugin.py").write_text("print('hi')\n")

        build_cmd._compile_mpy(
            self.app_root, "plugin.py", self.romfs_root, self.mpy_cross,
            ["*.py"], False,
        )

        self.assertTrue((self.romfs_root / "main.mpy").exists())


class TestRunVersionChecks(unittest.TestCase):
    """[[version_check]] enforcement."""

    def setUp(self) -> None:
        import tempfile
        self._tmpdir = tempfile.TemporaryDirectory()
        self.app_root = Path(self._tmpdir.name)

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def test_no_entries_is_noop(self) -> None:
        """Absent [[version_check]] does nothing."""
        build_cmd._run_version_checks({}, self.app_root)

    def test_matching_sources_pass(self) -> None:
        """All sources extracting the same string passes silently."""
        (self.app_root / "a.py").write_text('VERSION = "1.2.3"\n')
        (self.app_root / "b.json").write_text('{"version": "1.2.3"}\n')
        data = {
            "version_check": [
                {"path": "a.py", "pattern": r'VERSION = "([^"]+)"'},
                {"path": "b.json", "pattern": r'"version": "([^"]+)"'},
            ]
        }
        build_cmd._run_version_checks(data, self.app_root)

    def test_mismatched_sources_raise(self) -> None:
        """Sources extracting different strings raises BuildFailed."""
        (self.app_root / "a.py").write_text('VERSION = "1.2.3"\n')
        (self.app_root / "b.json").write_text('{"version": "9.9.9"}\n')
        data = {
            "version_check": [
                {"path": "a.py", "pattern": r'VERSION = "([^"]+)"'},
                {"path": "b.json", "pattern": r'"version": "([^"]+)"'},
            ]
        }
        with self.assertRaises(build_cmd.BuildFailed):
            build_cmd._run_version_checks(data, self.app_root)

    def test_pattern_no_match_raises(self) -> None:
        """A pattern that doesn't match its file raises BuildFailed."""
        (self.app_root / "a.py").write_text("no version here\n")
        data = {"version_check": [{"path": "a.py", "pattern": r'VERSION = "([^"]+)"'}]}
        with self.assertRaises(build_cmd.BuildFailed):
            build_cmd._run_version_checks(data, self.app_root)

    def test_pattern_wrong_group_count_raises(self) -> None:
        """A pattern with zero capture groups raises BuildFailed."""
        (self.app_root / "a.py").write_text('VERSION = "1.2.3"\n')
        data = {"version_check": [{"path": "a.py", "pattern": r'VERSION = ".+"'}]}
        with self.assertRaises(build_cmd.BuildFailed):
            build_cmd._run_version_checks(data, self.app_root)

    def test_missing_file_raises(self) -> None:
        """A path that doesn't exist raises BuildFailed."""
        data = {"version_check": [{"path": "does-not-exist.py", "pattern": r"(.+)"}]}
        with self.assertRaises(build_cmd.BuildFailed):
            build_cmd._run_version_checks(data, self.app_root)


class TestResolveManifest(unittest.TestCase):
    """_resolve_manifest: manifest.py execution in MODE_COMPILE via require()/module()."""

    def setUp(self) -> None:
        import tempfile
        self._tmpdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmpdir.name)
        self.app_root = self.tmp / "app"
        self.app_root.mkdir()
        self.mpy_lib_dir = self.tmp / "mpylib"
        # An override is used throughout this class (never the real
        # fetch-and-cache path), so no test here touches the network.
        self.config = {"build": {"mpy_lib_dir": str(self.mpy_lib_dir)}}

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def _write_something_package(self, *, license: "str | None" = "MIT") -> None:
        """A toy micropython-lib-shaped package: <mpy_lib_dir>/micropython/something/."""
        pkg_dir = self.mpy_lib_dir / "micropython" / "something"
        pkg_dir.mkdir(parents=True)
        meta_kwargs = 'version="0.1.0"' + (f', license="{license}"' if license else "")
        (pkg_dir / "manifest.py").write_text(f"metadata({meta_kwargs})\nmodule('foo.py')\n")
        (pkg_dir / "foo.py").write_text("FOO = 1\n")

    def test_require_and_module_resolve_expected_pairs(self) -> None:
        """require("something") + module("x.py") resolve to the expected (src, dest) pairs."""
        self._write_something_package()
        (self.app_root / "x.py").write_text("VALUE = 1\n")
        (self.app_root / "manifest.py").write_text(
            'metadata(version="0.1.0")\n'
            'require("something")\n'
            'module("x.py")\n'
        )

        resolved = build_cmd._resolve_manifest(
            self.app_root, self.app_root / "manifest.py", self.config, False
        )

        pairs = {(src, target) for src, target in resolved.files}
        self.assertIn(
            (self.mpy_lib_dir / "micropython" / "something" / "foo.py", "foo.py"),
            pairs,
        )
        self.assertIn((self.app_root / "x.py", "x.py"), pairs)
        self.assertEqual(len(resolved.files), 2)

    def test_required_packages_captures_name_and_metadata(self) -> None:
        """required_packages records (name, metadata) with the require()'d
        package's own version/license, closing the SBOM/license gate."""
        self._write_something_package(license="MIT")
        (self.app_root / "manifest.py").write_text(
            'metadata(version="0.1.0")\nrequire("something")\n'
        )

        resolved = build_cmd._resolve_manifest(
            self.app_root, self.app_root / "manifest.py", self.config, False
        )

        self.assertEqual(len(resolved.required_packages), 1)
        name, meta = resolved.required_packages[0]
        self.assertEqual(name, "something")
        self.assertEqual(meta.version, "0.1.0")
        self.assertEqual(meta.license, "MIT")

    def test_required_packages_empty_when_no_license_declared(self) -> None:
        """A require()'d package with no license kwarg still records metadata
        (version present, license None); the SBOM layer treats that as
        LicenseRef-Unknown, not as an absent record."""
        self._write_something_package(license=None)
        (self.app_root / "manifest.py").write_text(
            'metadata(version="0.1.0")\nrequire("something")\n'
        )

        resolved = build_cmd._resolve_manifest(
            self.app_root, self.app_root / "manifest.py", self.config, False
        )

        self.assertEqual(len(resolved.required_packages), 1)
        name, meta = resolved.required_packages[0]
        self.assertEqual(name, "something")
        self.assertIsNone(meta.license)

    def test_add_library_local_path_resolves_without_network(self) -> None:
        """add_library() + require(library=...) against a purely local path
        never calls ensure_mpy_lib_dir (no network access, no override needed)."""
        vendor_dir = self.app_root / "vendor" / "widget"
        vendor_dir.mkdir(parents=True)
        (vendor_dir / "manifest.py").write_text('metadata(version="0.1.0")\nmodule("widget.py")\n')
        (vendor_dir / "widget.py").write_text("X = 1\n")
        (self.app_root / "manifest.py").write_text(
            'metadata(version="0.1.0")\n'
            'add_library("vendor", "./vendor")\n'
            'require("widget", library="vendor")\n'
        )

        with mock.patch.object(build_cmd, "ensure_mpy_lib_dir") as m_ensure:
            resolved = build_cmd._resolve_manifest(
                self.app_root, self.app_root / "manifest.py", {}, False
            )

        m_ensure.assert_not_called()
        self.assertEqual(resolved.files, [(vendor_dir / "widget.py", "widget.py")])
        self.assertEqual(resolved.required_packages, [("widget", mock.ANY)])

    def test_manifest_error_raises_build_failed(self) -> None:
        """A require() for a package that can't be found raises BuildFailed."""
        (self.app_root / "manifest.py").write_text(
            'metadata(version="0.1.0")\nrequire("does-not-exist")\n'
        )
        with self.assertRaises(build_cmd.BuildFailed):
            build_cmd._resolve_manifest(
                self.app_root, self.app_root / "manifest.py", self.config, False
            )


class TestLazyManifestFileMpyLibTrigger(unittest.TestCase):
    """_LazyManifestFile: lazy MPY_LIB_DIR fetch trigger, including the
    add_library("x", "$(MPY_LIB_DIR)/x") + require(name, library="x") idiom
    (confirmed false negative of the earlier AST-prescan approach)."""

    def setUp(self) -> None:
        import tempfile
        self._tmpdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmpdir.name)
        self.app_root = self.tmp / "app"
        self.app_root.mkdir()
        self.mpy_lib_dir = self.tmp / "mpylib"

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def _package(self, root: Path, name: str, module_file: str = "foo.py") -> None:
        pkg_dir = root / name
        pkg_dir.mkdir(parents=True)
        (pkg_dir / "manifest.py").write_text(
            f'metadata(version="0.1.0")\nmodule({module_file!r})\n'
        )
        (pkg_dir / module_file).write_text("X = 1\n")

    def _run(self, manifest_text: str, *, fetcher) -> "build_cmd.ResolvedManifest":
        manifest_path = self.app_root / "manifest.py"
        manifest_path.write_text(manifest_text)
        mf = build_cmd._LazyManifestFile(
            build_cmd.MODE_COMPILE,
            path_vars={"MPY_LIB_DIR": str(self.mpy_lib_dir)},
            mpy_lib_dir=self.mpy_lib_dir,
            mpy_lib_fetcher=fetcher,
        )
        mf.execute(str(manifest_path))
        return build_cmd.ResolvedManifest(
            files=[(Path(f.full_path), f.target_path) for f in mf.files()],
            required_packages=mf.required_packages,
        )

    def test_bare_require_triggers_fetcher(self) -> None:
        calls = []
        def fetcher():
            calls.append(1)
            self._package(self.mpy_lib_dir / "micropython", "something")

        self._run(
            'metadata(version="0.1.0")\nrequire("something")\n',
            fetcher=fetcher,
        )
        self.assertEqual(len(calls), 1)

    def test_require_library_local_path_does_not_trigger_fetcher(self) -> None:
        """require(library="vendor") against a plain local add_library() path
        never triggers the fetcher."""
        vendor_dir = self.app_root / "vendor"
        self._package(vendor_dir, "widget")
        calls = []

        self._run(
            'metadata(version="0.1.0")\n'
            f'add_library("vendor", {str(vendor_dir)!r})\n'
            'require("widget", library="vendor")\n',
            fetcher=lambda: calls.append(1),
        )
        self.assertEqual(calls, [])

    def test_require_library_derived_from_mpy_lib_dir_triggers_fetcher(self) -> None:
        """The canonical add_library("x", "$(MPY_LIB_DIR)/x") +
        require(name, library="x") idiom triggers the fetcher, even though
        library= is explicitly given; this is the confirmed false negative
        the earlier AST-prescan approach missed."""
        calls = []
        def fetcher():
            calls.append(1)
            self._package(self.mpy_lib_dir / "unix-ffi", "ffilib")

        self._run(
            'metadata(version="0.1.0")\n'
            'add_library("unix-ffi", "$(MPY_LIB_DIR)/unix-ffi", prepend=True)\n'
            'require("ffilib", library="unix-ffi")\n',
            fetcher=fetcher,
        )
        self.assertEqual(len(calls), 1)

    def test_fetcher_called_at_most_once_across_multiple_requires(self) -> None:
        calls = []
        def fetcher():
            calls.append(1)
            self._package(self.mpy_lib_dir / "micropython", "something")
            self._package(self.mpy_lib_dir / "micropython", "other")

        self._run(
            'metadata(version="0.1.0")\n'
            'require("something")\n'
            'require("other")\n',
            fetcher=fetcher,
        )
        self.assertEqual(len(calls), 1)

    def test_nested_include_require_triggers_fetcher(self) -> None:
        """A require() reached only through include() is still caught --
        require() is intercepted regardless of which manifest.py is running."""
        nested = self.app_root / "nested.py"
        nested.write_text('require("something")\n')
        calls = []
        def fetcher():
            calls.append(1)
            self._package(self.mpy_lib_dir / "micropython", "something")

        self._run(
            'metadata(version="0.1.0")\ninclude("nested.py")\n',
            fetcher=fetcher,
        )
        self.assertEqual(len(calls), 1)

    def test_c_module_rejected(self) -> None:
        """c_module() in an app manifest.py raises, rather than silently
        dropping the module (MODE_COMPILE's base c_module() is a no-op that
        records nothing, so it can't be detected after the fact)."""
        manifest_path = self.app_root / "manifest.py"
        manifest_path.write_text(
            'metadata(version="0.1.0")\nc_module("$(MPY_DIR)/somewhere")\n'
        )
        with self.assertRaises(build_cmd.BuildFailed):
            build_cmd._resolve_manifest(self.app_root, manifest_path, {}, False)


class TestCompileManifestFiles(unittest.TestCase):
    """_compile_manifest_files: mpy-cross compile + shared collision guard."""

    @classmethod
    def setUpClass(cls) -> None:
        from picolet.cli.runtime_resolver import locate_mpy_cross, RuntimeNotFound
        try:
            cls.mpy_cross = locate_mpy_cross()
        except RuntimeNotFound:
            raise unittest.SkipTest("mpy-cross not available on PATH or in-tree")

    def setUp(self) -> None:
        import tempfile
        self._tmpdir = tempfile.TemporaryDirectory()
        tmp = Path(self._tmpdir.name)
        self.src_dir = tmp / "src"
        self.src_dir.mkdir()
        self.romfs_root = tmp / "romfs"

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def test_resolved_files_compiled_to_mpy(self) -> None:
        """Each resolved (src, target_path) pair is compiled to romfs_root/target.mpy."""
        src = self.src_dir / "foo.py"
        src.write_text("X = 1\n")

        build_cmd._compile_manifest_files(
            [(src, "foo.py")], self.romfs_root, self.mpy_cross, False
        )

        self.assertTrue((self.romfs_root / "foo.mpy").exists())
        self.assertFalse((self.romfs_root / "foo.py").exists())

    def test_manifest_dest_colliding_with_app_source_raises(self) -> None:
        """A manifest-resolved dest colliding with an entry-tree file raises BuildFailed."""
        app_src = self.src_dir / "app_main.py"
        app_src.write_text("X = 1\n")
        manifest_src = self.src_dir / "manifest_provided.py"
        manifest_src.write_text("X = 2\n")

        mpy_sources: dict[Path, Path] = {}
        # Simulate the entry tree having already claimed romfs/foo.mpy.
        build_cmd._claim_mpy_dest(
            mpy_sources, self.romfs_root / "foo.mpy", app_src, self.romfs_root
        )

        with self.assertRaises(build_cmd.BuildFailed):
            build_cmd._compile_manifest_files(
                [(manifest_src, "foo.py")], self.romfs_root, self.mpy_cross, False,
                mpy_sources=mpy_sources,
            )

    def test_manifest_dest_colliding_with_romfs_include_raises(self) -> None:
        """A manifest-resolved dest colliding with a [romfs] include file raises BuildFailed."""
        include_src = self.src_dir / "included.py"
        include_src.write_text("X = 1\n")
        manifest_src = self.src_dir / "manifest_provided.py"
        manifest_src.write_text("X = 2\n")

        mpy_sources: dict[Path, Path] = {}
        app_root = self.src_dir  # stand-in app_root for _copy_includes below
        include_dir = app_root / "lib"
        include_dir.mkdir()
        (include_dir / "included.py").write_text("X = 1\n")

        build_cmd._copy_includes(
            app_root, ["lib"], [], self.romfs_root, self.mpy_cross, False,
            mpy_sources=mpy_sources,
        )
        self.assertTrue((self.romfs_root / "lib" / "included.mpy").exists())

        with self.assertRaises(build_cmd.BuildFailed):
            build_cmd._compile_manifest_files(
                [(manifest_src, "lib/included.py")], self.romfs_root, self.mpy_cross, False,
                mpy_sources=mpy_sources,
            )

    def test_manifest_dest_escaping_romfs_root_raises_build_failed(self) -> None:
        """A manifest-resolved target_path escaping romfs_root (e.g. via
        module("../evil.py")) raises BuildFailed, not a raw ValueError, and
        writes nothing outside romfs_root."""
        evil_src = self.src_dir.parent / "evil.py"
        evil_src.write_text("PWNED = 1\n")

        with self.assertRaises(build_cmd.BuildFailed):
            build_cmd._compile_manifest_files(
                [(evil_src, "../evil.py")], self.romfs_root, self.mpy_cross, False,
            )

        self.assertFalse((self.romfs_root.parent / "evil.mpy").exists())


class TestEntryTreeAndRomfsIncludeSameSourceNoCollision(unittest.TestCase):
    """A shared mpy_sources dict must not false-positive when _compile_mpy's
    entry tree and _copy_includes's [romfs] include legitimately resolve the
    exact same source file to the exact same romfs destination (e.g.
    entry = "src/main.py" with [romfs] include = ["src"])."""

    @classmethod
    def setUpClass(cls) -> None:
        from picolet.cli.runtime_resolver import locate_mpy_cross, RuntimeNotFound
        try:
            cls.mpy_cross = locate_mpy_cross()
        except RuntimeNotFound:
            raise unittest.SkipTest("mpy-cross not available on PATH or in-tree")

    def setUp(self) -> None:
        import tempfile
        self._tmpdir = tempfile.TemporaryDirectory()
        tmp = Path(self._tmpdir.name)
        self.app_root = tmp / "app"
        self.app_root.mkdir()
        self.romfs_root = tmp / "romfs"

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def test_same_source_via_entry_and_include_is_not_a_collision(self) -> None:
        src_dir = self.app_root / "src"
        src_dir.mkdir()
        (src_dir / "main.py").write_text("print('hi')\n")
        (src_dir / "helper.py").write_text("X = 1\n")

        mpy_sources: dict[Path, Path] = {}
        build_cmd._compile_mpy(
            self.app_root, "src/main.py", self.romfs_root, self.mpy_cross, [], False,
            mpy_sources=mpy_sources,
        )
        # Both src/main.py and src/helper.py already claimed romfs/src/*.mpy;
        # [romfs] include = ["src"] resolves the exact same source files to
        # the exact same destinations; must not raise.
        build_cmd._copy_includes(
            self.app_root, ["src"], [], self.romfs_root, self.mpy_cross, False,
            mpy_sources=mpy_sources,
        )

        self.assertTrue((self.romfs_root / "src" / "main.mpy").exists())
        self.assertTrue((self.romfs_root / "src" / "helper.mpy").exists())
        self.assertTrue((self.romfs_root / "main.mpy").exists())


class TestResolveAppManifest(unittest.TestCase):
    """_resolve_app_manifest: auto-detection, no-op regression guard, SBOM
    metadata pass-through."""

    def setUp(self) -> None:
        import tempfile
        self._tmpdir = tempfile.TemporaryDirectory()
        self.app_root = Path(self._tmpdir.name)

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def test_no_manifest_py_is_noop(self) -> None:
        """No manifest.py at the app root: returns None, no resolution attempted.

        Regression guard: an app without manifest.py must build identically
        to before this feature existed: _resolve_manifest and
        ensure_mpy_lib_dir must not be invoked at all.
        """
        with mock.patch.object(build_cmd, "_resolve_manifest") as m_resolve, \
             mock.patch.object(build_cmd, "ensure_mpy_lib_dir") as m_ensure:
            result = build_cmd._resolve_app_manifest(self.app_root, {}, False)

        self.assertIsNone(result)
        m_resolve.assert_not_called()
        m_ensure.assert_not_called()

    def test_manifest_without_require_skips_mpy_lib_dir_entirely(self) -> None:
        """A manifest.py using only module() never calls ensure_mpy_lib_dir."""
        (self.app_root / "manifest.py").write_text(
            'metadata(version="0.1.0")\nmodule("x.py")\n'
        )
        (self.app_root / "x.py").write_text("X = 1\n")

        with mock.patch.object(build_cmd, "ensure_mpy_lib_dir") as m_ensure:
            result = build_cmd._resolve_app_manifest(self.app_root, {}, False)

        m_ensure.assert_not_called()
        self.assertEqual(result.files, [(self.app_root / "x.py", "x.py")])
        self.assertEqual(result.required_packages, [])

    def test_result_carries_required_packages_for_sbom(self) -> None:
        """The ResolvedManifest returned carries required_packages, ready for
        _manifest_sbom_records / emit_app_sbom's policy gate."""
        pkg_dir = self.app_root / "vendor" / "widget"
        pkg_dir.mkdir(parents=True)
        (pkg_dir / "manifest.py").write_text(
            'metadata(version="2.0.0", license="Apache-2.0")\nmodule("widget.py")\n'
        )
        (pkg_dir / "widget.py").write_text("X = 1\n")
        (self.app_root / "manifest.py").write_text(
            'metadata(version="0.1.0")\n'
            'add_library("vendor", "./vendor")\n'
            'require("widget", library="vendor")\n'
        )

        result = build_cmd._resolve_app_manifest(self.app_root, {}, False)

        self.assertEqual(len(result.required_packages), 1)
        name, meta = result.required_packages[0]
        self.assertEqual(name, "widget")
        self.assertEqual(meta.version, "2.0.0")
        self.assertEqual(meta.license, "Apache-2.0")

    def test_mpy_lib_fetch_error_raises_build_failed(self) -> None:
        """MpyLibFetchError from ensure_mpy_lib_dir surfaces as BuildFailed,
        not an uncaught exception or a silently-wrong-but-successful build."""
        (self.app_root / "manifest.py").write_text(
            'metadata(version="0.1.0")\nrequire("something")\n'
        )

        with mock.patch.object(
            build_cmd, "ensure_mpy_lib_dir",
            side_effect=mlc.MpyLibFetchError("network unavailable"),
        ):
            with self.assertRaises(build_cmd.BuildFailed):
                build_cmd._resolve_app_manifest(self.app_root, {}, False)


class TestManifestSbomRecords(unittest.TestCase):
    """_manifest_sbom_records: (name, ManifestPackageMetadata) -> plain dicts."""

    def test_converts_metadata_fields(self) -> None:
        class _FakeMeta:
            version = "1.2.3"
            license = "MIT"
            description = "a widget"
            author = "Jane Doe"

        records = build_cmd._manifest_sbom_records([("widget", _FakeMeta())])

        self.assertEqual(records, [{
            "name": "widget",
            "version": "1.2.3",
            "license": "MIT",
            "description": "a widget",
            "author": "Jane Doe",
        }])

    def test_missing_fields_default_sensibly(self) -> None:
        class _EmptyMeta:
            version = None
            license = None
            description = None
            author = None

        records = build_cmd._manifest_sbom_records([("widget", _EmptyMeta())])

        self.assertEqual(records[0]["version"], "unknown")
        self.assertIsNone(records[0]["license"])
        self.assertEqual(records[0]["description"], "")
        self.assertEqual(records[0]["author"], "")

    def test_empty_input_returns_empty_list(self) -> None:
        self.assertEqual(build_cmd._manifest_sbom_records([]), [])


if __name__ == "__main__":
    unittest.main()
