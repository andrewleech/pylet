"""
picolet build — compile a picolet app into a single self-contained binary.

Usage:
    picolet build [--target {linux-x64,windows-x64}] [--verbose]
                [--keep-staging] [--runtime PATH]

Pipeline (FR-BP-1 through FR-BP-6):

  1. Read + validate picolet.toml (FR-CLI-8 pre-flight).
  2. Enforce [[version_check]], if present — fail fast on a version mismatch
     across the app's own source files, before any runtime work.
  3. Resolve runtime variant: explicit [build].variant, else from [ui]
     (absent → cli) (FR-BP-1).
  4. Resolve target from --target or host auto-detection (FR-BP-1).
  5. Locate runtime artifact + mpy-cross, verify version match.
  6. Resolve manifest.py, if present at the app root: require()/add_library()/
     module()/package() are processed via the vendored MicroPython manifest
     processor (picolet._vendor.manifestfile), in MODE_COMPILE.
  7. Compile user .py sources → .mpy via mpy-cross, applying [romfs].exclude
     to skip test/example files living alongside the entry (FR-BP-3).
  8. Compile manifest.py-resolved files → .mpy, sharing the same romfs-path
     collision guard as steps 7 and 9.
  9. Copy [romfs] include dirs into staging, applying [romfs].exclude and
     compiling any .py found there to .mpy too — an appended romfs never
     ships raw .py, regardless of which step put a file there (FR-BP-4).
 10. Zero mtimes for reproducibility (FR-BP-6).
 11. Build romfs image with mpremote (FR-BP-4).
 12. Append romfs + 24-byte trailer to runtime binary (FR-BP-5).
 13. Emit SBOM sibling .cdx.json (FR-SBOM-1, FR-SBOM-2, FR-SBOM-3).
"""

from __future__ import annotations

import argparse
import fnmatch
import importlib.resources
import os
import platform
import re
import shlex
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import NamedTuple

from picolet._vendor.manifestfile import (
    ManifestFile,
    ManifestFileError,
    MODE_COMPILE,
)
from picolet.cli._mpy_lib_cache import ensure_mpy_lib_dir, mpy_lib_dir_path
from picolet.cli._paths import find_picolet_toml as _find_picolet_toml
from picolet.cli._targets import (
    SUPPORTED_RENDERERS,
    SUPPORTED_TARGETS,
    TARGET_WINDOWS_X64,
    VARIANT_CLI,
    VARIANT_LVGL,
    VARIANT_WEBVIEW,
    host_target,
    target_exe_suffix,
    variant_for_renderer,
)
from picolet.cli._trailer import pack_trailer
from picolet.git_version import resolve_git_version
from picolet.pe_icon import _read_ico, apply_icon
from picolet.pe_resources import load_resource_tree, save_resource_tree
from picolet.pe_subsystem import set_subsystem_gui
from picolet.pe_version import apply_version_info
from picolet.cli.runtime_resolver import (
    locate_mpy_cross,
    resolve_runtime,
    ResolvedRuntime,
    RuntimeIntegrityError,
    RuntimeNotFound,
)
from picolet.cli.sbom_gen import emit_app_sbom, SbomViolation
from picolet.cli.validator import validate_toml


class BuildFailed(Exception):
    """Raised by build helpers to abort the build with a structured error.

    The error message (if any) is expected to have been printed to stderr
    before raising. ``run()`` catches this and converts it into an exit
    code; callers (``dev_cmd``, ``run_cmd``) can also catch it to keep a
    long-lived process alive across a failed build.
    """


def build_args_namespace(target, verbose, **overrides) -> argparse.Namespace:
    """Return a :class:`argparse.Namespace` suitable for :func:`run`.

    Provides the minimal set of attributes that :func:`run` / ``_do_build``
    read.  ``target`` and ``verbose`` are the two most commonly varied
    fields; all others default to False/None but may be overridden via
    keyword arguments.

    Used by ``run_cmd`` and ``dev_cmd`` to synthesise build arguments from
    their own parsed args without duplicating the field list in each caller.
    """
    defaults = dict(
        target=target,
        verbose=verbose,
        keep_staging=False,
        runtime=None,
        from_source=False,
        no_cache=False,
        no_sbom=False,
        allow_unverified_runtime=False,
    )
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


_BUILD_EPILOG = """\
Examples:
  picolet build
  picolet build --target windows-x64
  picolet build --target linux-x64 --verbose
  picolet build --from-source        # build runtime locally (requires Docker)
"""


def add_parser(subparsers) -> None:
    """Register the build subcommand with the given subparsers object."""
    p = subparsers.add_parser(
        "build",
        help="build a picolet app into a single executable",
        description=(
            "Compile the current app's Python sources, build a romfs image, "
            "and append it to the pre-built runtime to produce a single binary.\n\n"
            "Run from the app directory (the one containing picolet.toml). "
            "The output binary is written to target/<target>/<app-name>[.exe]."
        ),
        epilog=_BUILD_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--target",
        default=None,
        metavar="TARGET",
        help=(
            "build target (default: host; "
            "supported: linux-x64, windows-x64)"
        ),
    )
    p.add_argument(
        "--verbose", "-v",
        action="store_true",
        default=False,
        help="print build steps to stderr",
    )
    p.add_argument(
        "--keep-staging",
        action="store_true",
        default=False,
        help="keep the staging directory after a successful build (for debugging)",
    )
    # Undocumented escape hatch — used by SQE to test alternate runtimes.
    p.add_argument(
        "--runtime",
        default=None,
        help=argparse.SUPPRESS,
    )
    p.add_argument(
        "--from-source",
        action="store_true",
        default=False,
        dest="from_source",
        help="build the runtime locally using build-runtime.sh (requires Docker)",
    )
    p.add_argument(
        "--no-cache",
        action="store_true",
        default=False,
        dest="no_cache",
        help="skip the runtime artifact cache; always download fresh",
    )
    p.add_argument(
        "--allow-unverified-runtime",
        action="store_true",
        default=False,
        dest="allow_unverified_runtime",
        help=(
            "run with a runtime binary that has no .sha256 sidecar "
            "(escape hatch for air-gapped mirrors; equivalent to "
            "PICOLET_ALLOW_UNVERIFIED_CACHE=1)"
        ),
    )
    p.add_argument(
        "--no-sbom",
        action="store_true",
        default=False,
        dest="no_sbom",
        help="skip SBOM emission (for tests that do not need the .cdx.json side-effect)",
    )
    p.set_defaults(func=run)


def run(args) -> int:
    """Entry point for `picolet build`. Returns the exit code (0 on success)."""
    try:
        return _do_build(args)
    except BuildFailed as exc:
        if str(exc):
            print(f"error: {exc}", file=sys.stderr)
        return 1


def _do_build(args) -> int:
    # -------------------------------------------------------------------------
    # Step 1 – Find and validate picolet.toml.
    # -------------------------------------------------------------------------
    toml_path = _find_picolet_toml(Path.cwd())
    if toml_path is None:
        print(
            "error: picolet.toml not found in current directory or any ancestor",
            file=sys.stderr,
        )
        return 1

    _all_validation = validate_toml(toml_path)
    _hard_errors = [e for e in _all_validation if e.level != "warn"]
    for e in _all_validation:
        if e.level == "warn":
            print(str(e), file=sys.stderr)
    if _hard_errors:
        for e in _hard_errors:
            print(str(e), file=sys.stderr)
        return 1

    with open(toml_path, "rb") as fh:
        data = tomllib.load(fh)

    app_name: str = data["app"]["name"]
    entry: str = data["app"]["entry"]            # e.g. "src/main.py"
    romfs_includes: list[str] = data.get("romfs", {}).get("include", [])
    romfs_excludes: list[str] = data.get("romfs", {}).get("exclude", [])
    app_root: Path = toml_path.parent

    _run_version_checks(data, app_root)

    # -------------------------------------------------------------------------
    # Step 1a – Resolve [app] version = "git" to a concrete version string
    # (FR-GITVER-1). Mutates `data` in place so every downstream consumer
    # (VERSION_INFO patch below, SBOM emission) sees the resolved value.
    # -------------------------------------------------------------------------
    if data["app"]["version"] == "git":
        try:
            data["app"]["version"] = resolve_git_version(app_root)
        except RuntimeError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1

    # -------------------------------------------------------------------------
    # Step 2 – Resolve runtime variant (FR-BP-1).
    #
    # [build].variant is an explicit override for variants with no UI at all
    # (e.g. "mcp" — a stdio-only variant that doesn't fit the renderer
    # concept), and always wins when present. Absent it, variant is derived
    # from [ui].renderer as before.
    # -------------------------------------------------------------------------
    explicit_variant = data.get("build", {}).get("variant")
    if explicit_variant:
        variant = explicit_variant
    else:
        renderer = data.get("ui", {}).get("renderer") if "ui" in data else None
        try:
            variant = variant_for_renderer(renderer)
        except ValueError:
            # Validator already rejected invalid renderer values; this is a
            # belt-and-suspenders guard.
            sys.exit(
                f"error: unknown ui.renderer {renderer!r}; "
                f"valid values are: {', '.join(sorted(SUPPORTED_RENDERERS))}"
            )

    # -------------------------------------------------------------------------
    # Step 3 – Resolve target (FR-BP-1).
    # -------------------------------------------------------------------------
    target = args.target if args.target else host_target()

    if target not in SUPPORTED_TARGETS:
        sys.exit(
            f"error: unsupported --target {target!r}; "
            f"choose from: {', '.join(sorted(SUPPORTED_TARGETS))}"
        )

    if args.verbose:
        print(f"runtime variant: {variant}", file=sys.stderr)
        print(f"target: {target}", file=sys.stderr)

    # -------------------------------------------------------------------------
    # Step 4 – Locate runtime artifact and mpy-cross; verify version match.
    # -------------------------------------------------------------------------
    try:
        resolved: ResolvedRuntime = resolve_runtime(
            target,
            variant,
            explicit_path=Path(args.runtime) if args.runtime else None,
            from_source=args.from_source,
            no_cache=args.no_cache,
            allow_unverified=getattr(args, "allow_unverified_runtime", False),
            config=data,
            verbose=args.verbose,
        )
    except (RuntimeNotFound, RuntimeIntegrityError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    runtime_path = resolved.binary
    # resolved.sbom is preserved for PH13's SBOM emitter; unused here.

    # -------------------------------------------------------------------------
    # Step 4a – Windows icon embedding (FR-ICON-1): validate early, patch just
    # before the romfs append (Step 9) once a staging dir exists to hold the
    # patched copy — runtime_path itself is the resolver's cache and must not
    # be mutated in place.
    # -------------------------------------------------------------------------
    icon = data["app"].get("icon")
    icon_path: Path | None = None
    if icon == "":
        print("error: [app] icon is set but empty", file=sys.stderr)
        return 1
    if icon:
        if target != TARGET_WINDOWS_X64:
            print(
                f"error: [app] icon is only supported for --target {TARGET_WINDOWS_X64}",
                file=sys.stderr,
            )
            return 1
        icon_path = app_root / icon
        if not icon_path.is_file():
            print(f"error: [app] icon file not found: {icon_path}", file=sys.stderr)
            return 1
        if icon_path.suffix.lower() != ".ico":
            print(f"error: [app] icon must be a .ico file, got: {icon_path}", file=sys.stderr)
            return 1
        try:
            _read_ico(icon_path)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1

    # -------------------------------------------------------------------------
    # Step 4b – Windows console suppression (FR-CONSOLE-1): [app] console =
    # false flips the staged runtime copy's PE subsystem from CUI to GUI so
    # no console window flashes on launch. Same staging/timing rules as the
    # icon patch above.
    # -------------------------------------------------------------------------
    console = data["app"].get("console", True)
    if console is False and target != TARGET_WINDOWS_X64:
        print(
            f"error: [app] console = false is only supported for --target {TARGET_WINDOWS_X64}",
            file=sys.stderr,
        )
        return 1

    try:
        mpy_cross = locate_mpy_cross()
    except RuntimeNotFound as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    _verify_mpy_cross_version(runtime_path, mpy_cross, args.verbose)

    # -------------------------------------------------------------------------
    # Step 4b – Resolve manifest.py, if present at the app root (FR-CLI-8
    # style pre-flight; no toml key required for the common case).
    # -------------------------------------------------------------------------
    resolved_manifest = _resolve_app_manifest(app_root, data, args.verbose)

    # -------------------------------------------------------------------------
    # Step 4c – Frontend build (FR-VUE-4, FR-VUE-5): run npm install + build
    # command when [ui.frontend].framework is non-vanilla.  No-op for vanilla.
    # -------------------------------------------------------------------------
    _run_frontend_build(data, app_root, args.verbose)

    # -------------------------------------------------------------------------
    # Steps 5–9 in a temp staging area.
    # -------------------------------------------------------------------------
    staging = app_root / "target" / target / ".picolet-build"
    staging.mkdir(parents=True, exist_ok=True)

    if args.verbose:
        print(f"staging: {staging}", file=sys.stderr)

    try:
        # Step 5 – Compile .py → .mpy (FR-BP-3).
        romfs_root = staging / "romfs"
        # Shared across steps 5-6a so a manifest.py require()'d module, an
        # app source file, and a [romfs] include can't silently collide at
        # the same romfs path; see _claim_mpy_dest.
        mpy_sources: dict[Path, Path] = {}
        _compile_mpy(
            app_root, entry, romfs_root, mpy_cross, romfs_excludes, args.verbose,
            mpy_sources=mpy_sources,
        )

        # Step 5a – Compile manifest.py-resolved files (require()/module()/
        # package()), if a manifest.py was found in step 4b.
        if resolved_manifest is not None:
            _compile_manifest_files(
                resolved_manifest.files, romfs_root, mpy_cross, args.verbose,
                mpy_sources=mpy_sources,
            )

        # Step 6 – Copy [romfs] include dirs, compiling .py -> .mpy (FR-BP-4).
        _copy_includes(
            app_root, romfs_includes, romfs_excludes, romfs_root, mpy_cross, args.verbose,
            mpy_sources=mpy_sources,
        )

        # Step 6a – For non-vanilla frontend frameworks, copy the built
        # dist/ into romfs at the [ui] root.  Vanilla apps include their
        # static files via [romfs] include = ["ui"] — Vue apps omit that
        # entry and rely on this step instead (FR-VUE-4).
        _copy_dist_to_ui_root(data, app_root, romfs_root, args.verbose)

        # Step 6b – UI variants: drop a sanitised picolet.toml at the
        # romfs root so the runtime can read [window] and [ui] at
        # startup (FR-WV-3 webview, FR-LV-2 lvgl).  The user does not
        # need to add picolet.toml to [romfs] include manually.
        if variant in (VARIANT_WEBVIEW, VARIANT_LVGL):
            _emit_webview_toml(data, romfs_root, args.verbose)
        if variant == VARIANT_WEBVIEW:
            # Step 6c – Copy the picolet-bridge-js bundle into the romfs
            # at picolet/picolet-bridge.js (FR-BP-4, FR-WV-4).  The runtime
            # reads it from /rom/picolet/picolet-bridge.js and injects it
            # at DOCUMENT_START so window.picolet is available to user JS.
            _copy_bridge_js(romfs_root, args.verbose)
            # Step 6d – Windows-x64: copy WebView2Loader.dll into the
            # romfs at picolet/WebView2Loader.dll (PH10).  The runtime
            # extracts it to %LOCALAPPDATA%\picolet\<pid>\ at first use
            # and LoadLibraryW's it from there (the loader DLL is not
            # in System32, so the search-path-based default load is
            # unreliable).
            if target == TARGET_WINDOWS_X64:
                _copy_webview2_loader(romfs_root, args.verbose)

        # Step 7 – Zero mtimes for reproducibility (FR-BP-6).
        _zero_mtimes(romfs_root)

        # Step 8 – Build romfs image with mpremote.
        romfs_img = staging / f"{app_name}.romfs"
        _build_romfs(romfs_root, romfs_img, args.verbose)

        # Step 8a – Patch PE resources on a staged copy of the runtime binary
        # (FR-ICON-1, FR-VERINFO-1): the app icon (if any) and VERSION_INFO
        # both go through one load_resource_tree/save_resource_tree round
        # trip so a build using both appends a single new section rather
        # than two (each pass's serialized tree carries every resource, so
        # doing this as two separate inject_* calls would duplicate the
        # icon's bytes into two orphaned-plus-live sections). Never mutate
        # runtime_path itself: it's the resolver's cache and may be shared
        # by other builds/targets.
        if target == TARGET_WINDOWS_X64:
            if args.verbose:
                print(
                    "  patching PE resources (version-info"
                    + (f", icon: {icon_path}" if icon_path is not None else "")
                    + ")",
                    file=sys.stderr,
                )
            app_version = data["app"]["version"]
            version_fields = {
                "CompanyName": data["app"].get("company_name", ""),
                "FileDescription": data["app"].get("file_description") or app_name,
                "ProductName": data["app"].get("product_name") or app_name,
            }
            try:
                original_bytes = runtime_path.read_bytes()
                pe, tree, old_resource_section = load_resource_tree(original_bytes)
                if icon_path is not None:
                    apply_icon(tree, icon_path)
                apply_version_info(tree, version_fields, app_version, app_version)
                patched_bytes = save_resource_tree(pe, original_bytes, tree, old_resource_section)
            except ValueError as exc:
                print(f"error: {exc}", file=sys.stderr)
                return 1
            patched_runtime = staging / runtime_path.name
            patched_runtime.write_bytes(patched_bytes)
            runtime_path = patched_runtime

        # Step 8b – Flip the staged runtime copy to GUI subsystem (FR-CONSOLE-1).
        if console is False:
            if args.verbose:
                print("  console: disabling (GUI subsystem)", file=sys.stderr)
            patched_bytes = set_subsystem_gui(runtime_path.read_bytes())
            patched_runtime = staging / runtime_path.name
            patched_runtime.write_bytes(patched_bytes)
            runtime_path = patched_runtime

        # Step 9 – Append + trailer → final binary.
        output_dir = app_root / "target" / target
        output_path = output_dir / (app_name + target_exe_suffix(target))
        _append_with_trailer(runtime_path, romfs_img, output_path, args.verbose)
        output_path.chmod(0o755)

    finally:
        if not args.keep_staging and staging.exists():
            shutil.rmtree(staging)

    # Step 10 – Emit SBOM (FR-SBOM-1, FR-SBOM-2, FR-SBOM-3).
    if not args.no_sbom:
        sbom_path = output_path.parent / f"{output_path.name}.cdx.json"
        if args.verbose:
            print(f"  sbom: emitting {sbom_path}", file=sys.stderr)
        manifest_dependencies = (
            _manifest_sbom_records(resolved_manifest.required_packages)
            if resolved_manifest is not None
            else []
        )
        violations = emit_app_sbom(
            output_path=sbom_path,
            runtime_sbom_path=resolved.sbom,
            app_data=data,
            target=target,
            variant=variant,
            repo_root=_find_repo_root(),
            artifact_path=output_path,
            manifest_dependencies=manifest_dependencies,
        )
        _handle_sbom_violations(violations, data, args.verbose)
        if args.verbose:
            print(f"  sbom: written {sbom_path}", file=sys.stderr)

    # flush=True so callers consuming stdout in real time (notably
    # `picolet dev`, which now invokes build in-process) see this without
    # waiting for the process to exit.
    print(f"Built {output_path}", flush=True)
    return 0


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _find_repo_root() -> Path:
    """Return the repository root (four levels up from this file).

    This file lives at packages/picolet/picolet/cli/build_cmd.py.
    """
    here = Path(__file__).parent            # packages/picolet/picolet/cli/
    return here.parent.parent.parent.parent  # repo root


def _manifest_sbom_records(required_packages: list[tuple[str, object]]) -> list[dict]:
    """Convert (name, ManifestPackageMetadata) pairs to plain SBOM record dicts.

    Feeds sbom_gen.manifest_dep_components(), which is what actually runs
    manifest.py require()'d packages through the [sbom] allow_licences /
    fail_unknown policy gate; without this, third-party code frozen into
    the binary via require() would carry no license review at all.
    """
    records = []
    for name, meta in required_packages:
        records.append({
            "name": name,
            "version": getattr(meta, "version", None) or "unknown",
            "license": getattr(meta, "license", None),
            "description": getattr(meta, "description", None) or "",
            "author": getattr(meta, "author", None) or "",
        })
    return records


def _handle_sbom_violations(
    violations: list[SbomViolation],
    app_data: dict,
    verbose: bool,
) -> None:
    """Print warnings and exit 1 on policy failures.

    The SBOM file is always written before this is called, so downstream
    tooling can inspect the document even when the build fails.
    """
    if not violations:
        return

    has_fail = any(v.severity == "fail" for v in violations)

    for v in violations:
        if v.severity == "fail":
            print(
                f"error: sbom policy violation in {v.component!r}: {v.reason}",
                file=sys.stderr,
            )
        else:
            print(
                f"warn: sbom policy: {v.component!r}: {v.reason}",
                file=sys.stderr,
            )

    if has_fail:
        print(
            "error: sbom policy — build failed due to licence policy violations; "
            "see [sbom] allow_licences / allow_dynamic / fail_unknown in picolet.toml",
            file=sys.stderr,
        )
        raise BuildFailed()


def _verify_mpy_cross_version(
    runtime_path: Path, mpy_cross: Path, verbose: bool
) -> None:
    """Compare the .version sidecar against mpy-cross --version output.

    Exits with an error if they differ.  The sidecar is written by
    build-runtime.sh step [7b] and encodes the mpy bytecode format version
    (e.g. 'mpy v6.3').  Using a mismatched mpy-cross silently produces
    bytecode the runtime cannot load.
    """
    version_file = runtime_path.parent / f"{runtime_path.name}.version"
    if not version_file.is_file():
        # Sidecar absent (pre-PH03 runtime or --runtime override).
        # Warn and continue rather than hard-fail — the runtime may still work.
        if verbose:
            print(
                f"warning: no .version sidecar at {version_file}; "
                "skipping version check",
                file=sys.stderr,
            )
        return

    runtime_ver = version_file.read_text().strip()

    try:
        ver_output = subprocess.check_output(
            [str(mpy_cross), "--version"], text=True, stderr=subprocess.STDOUT
        ).strip()
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        print(
            f"error: could not run mpy-cross at {mpy_cross}: {exc}",
            file=sys.stderr,
        )
        raise BuildFailed()

    # mpy-cross --version outputs something like:
    #   "MicroPython v1.24.0 on 2025-01-01; mpy-cross emitting mpy v6.3"
    # Extract the "mpy v6.3" token to compare against the sidecar.
    m = re.search(r"mpy v[\d.]+", ver_output)
    mpy_ver = m.group(0) if m else ver_output

    if mpy_ver != runtime_ver:
        print(
            f"error: mpy-cross version mismatch\n"
            f"  mpy-cross reports: {mpy_ver}\n"
            f"  runtime expects:   {runtime_ver}\n"
            f"  Use the mpy-cross built alongside this runtime, or rebuild\n"
            f"  the runtime with build-runtime.sh --target {_guess_target(runtime_path)} "
            f"--variant {_guess_variant(runtime_path)}.",
            file=sys.stderr,
        )
        raise BuildFailed()

    if verbose:
        print(f"mpy-cross version: {mpy_ver} (matches runtime)", file=sys.stderr)


def _guess_target(runtime_path: Path) -> str:
    """Extract target from runtime artifact name."""
    name = runtime_path.stem  # e.g. picolet-runtime-linux-x64-cli
    parts = name.split("-")
    # picolet-runtime-linux-x64-cli → linux-x64
    if len(parts) >= 5:
        return f"{parts[2]}-{parts[3]}"
    return "linux-x64"


def _guess_variant(runtime_path: Path) -> str:
    """Extract variant from runtime artifact name."""
    name = runtime_path.stem
    parts = name.split("-")
    if len(parts) >= 5:
        return parts[4]
    return "cli"


def _run_frontend_build(data: dict, app_root: Path, verbose: bool) -> None:
    """Run npm install + the configured build command for non-vanilla frontends.

    Called after runtime resolution (step 4) and before mpy-cross compilation
    (step 5) so the dist/ output is available when _copy_dist_to_ui_root runs.

    No-op when [ui.frontend].framework is absent or "vanilla".

    Raises BuildFailed when:
      - npm is not on PATH (Node ≥ 18 LTS required for Vue projects).
      - npm install exits non-zero.
      - The build command exits non-zero.
    """
    frontend = data.get("ui", {}).get("frontend", {})
    framework = frontend.get("framework", "vanilla")
    if framework == "vanilla":
        return

    if shutil.which("npm") is None:
        print(
            "error: npm not found on PATH; Node ≥ 18 LTS is required for Vue projects "
            "(see docs/architecture.md §Frontend toolchains)",
            file=sys.stderr,
        )
        raise BuildFailed()

    if verbose:
        print(f"  frontend: framework={framework!r}; running npm install …", file=sys.stderr)

    # npm install --prefer-offline: respects package-lock.json when present;
    # fast when node_modules/ already exists (D2).
    subprocess.run(
        ["npm", "install", "--prefer-offline", "--no-fund", "--no-audit"],
        cwd=str(app_root),
        check=True,
        capture_output=not verbose,
    )

    build_cmd_str = frontend.get("build_cmd", "npm run build")
    if verbose:
        print(f"  frontend: running {build_cmd_str!r} in {app_root}", file=sys.stderr)

    try:
        subprocess.run(
            shlex.split(build_cmd_str),
            cwd=str(app_root),
            check=True,
            capture_output=not verbose,
        )
    except subprocess.CalledProcessError as exc:
        print(
            f"error: frontend build command {build_cmd_str!r} failed (rc={exc.returncode})",
            file=sys.stderr,
        )
        raise BuildFailed()


def _copy_dist_to_ui_root(
    data: dict, app_root: Path, romfs_root: Path, verbose: bool
) -> None:
    """Copy the frontend build dist/ into romfs at [ui] root.

    No-op when [ui.frontend].framework is absent or "vanilla".

    The dist/ contents are merged into romfs_root/<ui_root>/ using
    shutil.copytree with dirs_exist_ok=True so any existing files from a
    prior step are not clobbered.

    Raises BuildFailed when dist_dir does not exist (frontend build must
    have run first via _run_frontend_build).
    """
    frontend = data.get("ui", {}).get("frontend", {})
    framework = frontend.get("framework", "vanilla")
    if framework == "vanilla":
        return

    dist_dir = frontend.get("dist_dir", "dist")
    ui_root = data.get("ui", {}).get("root", "ui")

    src = app_root / dist_dir
    if not src.is_dir():
        print(
            f"error: frontend dist directory not found: {src}; "
            f"the build command did not produce expected output",
            file=sys.stderr,
        )
        raise BuildFailed()

    dst = romfs_root / ui_root
    dst.mkdir(parents=True, exist_ok=True)
    shutil.copytree(src, dst, dirs_exist_ok=True)
    if verbose:
        count = sum(1 for _ in dst.rglob("*") if _.is_file())
        print(
            f"  dist: copied {count} files from {src} → romfs/{ui_root}/",
            file=sys.stderr,
        )


def _copy_bridge_js(romfs_root: Path, verbose: bool) -> None:
    """Copy picolet-bridge.js into the romfs at picolet/picolet-bridge.js.

    The bundle is located relative to this module's package root so no
    Python package installation is needed for development (AD4).  The
    canonical source is packages/picolet-bridge-js/dist/picolet-bridge.js.

    Inside the frozen runtime the file is accessible at
    /rom/picolet/picolet-bridge.js.  _webview.py reads it at Webview
    construction time and injects it via webkit_user_script_new at
    DOCUMENT_START.
    """
    # Resolution order:
    #   1. importlib.resources — bundled inside the installed picolet wheel
    #      at picolet/_bridge/picolet-bridge.js (force-included by hatch).
    #   2. Source-tree fallback at packages/picolet-bridge-js/dist/ when
    #      running directly from a checkout without `pip install`.
    bridge_src: Path | None = None
    try:
        bridge_resource = importlib.resources.files("picolet._bridge").joinpath(
            "picolet-bridge.js"
        )
        if bridge_resource.is_file():
            bridge_src = Path(str(bridge_resource))
    except (ModuleNotFoundError, FileNotFoundError):
        pass

    if bridge_src is None or not bridge_src.is_file():
        here = Path(__file__).parent            # packages/picolet/picolet/cli/
        candidate = (
            here.parent.parent.parent           # packages/
            / "picolet-bridge-js"
            / "dist"
            / "picolet-bridge.js"
        )
        if candidate.is_file():
            bridge_src = candidate

    if bridge_src is None or not bridge_src.is_file():
        print(
            "error: picolet-bridge.js not found in installed wheel or "
            "source tree; run: cd packages/picolet-bridge-js && node build.mjs "
            "and reinstall picolet",
            file=sys.stderr,
        )
        raise BuildFailed()
    dest = romfs_root / "picolet" / "picolet-bridge.js"
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(bridge_src, dest)
    if verbose:
        print(
            f"  bridge: {bridge_src.name} → romfs/picolet/picolet-bridge.js "
            f"({bridge_src.stat().st_size} bytes)",
            file=sys.stderr,
        )


def _copy_webview2_loader(romfs_root: Path, verbose: bool) -> None:
    """Copy WebView2Loader.dll into the romfs at picolet/WebView2Loader.dll.

    PH10.  The runtime needs the loader DLL to LoadLibraryW it at
    startup; bundling inside the romfs (not the runtime's empty-default
    romfs) is AD1's load-deterministic distribution.

    Resolution order:
      1. Environment variable PICOLET_WEBVIEW2_LOADER_DLL (escape hatch
         for CI / hosts with a system-installed loader).
      2. packages/picolet-runtime/overlay/ports/windows/modules/picolet_webview2/
         redist/WebView2Loader.x64.dll  (vendored, dev path).

    Errors with a clear message + fetch instructions when neither
    source is present.
    """
    import os

    dest = romfs_root / "picolet" / "WebView2Loader.dll"
    dest.parent.mkdir(parents=True, exist_ok=True)

    env_path = os.environ.get("PICOLET_WEBVIEW2_LOADER_DLL")
    sources = []
    if env_path:
        sources.append(Path(env_path))

    # Repo-relative dev path: ../picolet-runtime/overlay/ports/windows/
    # variants/picolet-webview/redist/WebView2Loader.x64.dll
    here = Path(__file__).parent
    repo_dev = (
        here.parent.parent
        / "picolet-runtime" / "overlay" / "ports" / "windows"
        / "variants" / "picolet-webview" / "redist"
        / "WebView2Loader.x64.dll"
    )
    sources.append(repo_dev)

    for src in sources:
        if src.is_file():
            shutil.copy2(src, dest)
            if verbose:
                print(
                    f"  loader: {src.name} -> romfs/picolet/WebView2Loader.dll "
                    f"({src.stat().st_size} bytes)",
                    file=sys.stderr,
                )
            return

    print(
        "error: WebView2Loader.dll not found in any of:\n"
        + "\n".join(f"  {s}" for s in sources)
        + "\n\n"
        "Obtain the loader DLL from the Microsoft Edge WebView2 SDK:\n"
        "  nuget install Microsoft.Web.WebView2 -Version 1.0.2210.55\n"
        "and place build/native/x64/WebView2Loader.dll at:\n"
        f"  {repo_dev}\n"
        "Or point PICOLET_WEBVIEW2_LOADER_DLL at a copy on disk.",
        file=sys.stderr,
    )
    raise BuildFailed()


def _emit_webview_toml(
    data: dict, romfs_root: Path, verbose: bool
) -> None:
    """Write a sanitised picolet.toml into the romfs root for the runtime.

    The webview runtime reads /rom/picolet.toml at startup to apply
    [window] (title, size, resizable) and [ui] (root, index) — FR-WV-3
    and FR-WV-2.  Users do not need to add picolet.toml to [romfs] include
    themselves; we emit a minimal subset automatically.

    Only [window] and [ui] are emitted — host-only sections like [app],
    [build], [runtime] are deliberately dropped.  The runtime's
    picolet_ui._toml is a small subset reader; it tolerates extra keys
    but the surface area is minimal by design.
    """
    out_path = romfs_root / "picolet.toml"
    lines = []
    window = data.get("window") or {}
    if window:
        lines.append("[window]")
        if "title" in window:
            lines.append('title = "{}"'.format(_escape_toml_string(window["title"])))
        if "size" in window and isinstance(window["size"], list):
            sz = window["size"]
            if len(sz) == 2:
                lines.append("size = [{}, {}]".format(int(sz[0]), int(sz[1])))
        if "resizable" in window:
            lines.append("resizable = {}".format("true" if window["resizable"] else "false"))
        lines.append("")
    ui = data.get("ui") or {}
    if ui:
        lines.append("[ui]")
        if "renderer" in ui:
            lines.append('renderer = "{}"'.format(_escape_toml_string(ui["renderer"])))
        if "root" in ui:
            lines.append('root = "{}"'.format(_escape_toml_string(ui["root"])))
        if "index" in ui:
            lines.append('index = "{}"'.format(_escape_toml_string(ui["index"])))
        lines.append("")
    romfs_root.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(lines))
    if verbose:
        print(
            f"  emitted webview picolet.toml at {out_path}",
            file=sys.stderr,
        )


def _escape_toml_string(s: str) -> str:
    """Minimal TOML string escape: backslash and double-quote."""
    return s.replace("\\", "\\\\").replace('"', '\\"')


def _run_version_checks(data: dict, app_root: Path) -> None:
    """Enforce [[version_check]]: every entry's regex extraction must agree.

    Each entry is {path, pattern}; pattern must have exactly one capture
    group. Runs before any runtime resolution work, so a version mismatch
    across an app's own source files is reported immediately rather than
    after a slow build. Absent or empty [[version_check]] is a no-op.
    """
    checks = data.get("version_check", [])
    if not checks:
        return

    extracted: list[tuple[str, str]] = []
    for entry in checks:
        rel_path = entry["path"]
        pattern = entry["pattern"]
        try:
            compiled = re.compile(pattern)
        except re.error as exc:
            print(
                f"error: [[version_check]] invalid pattern {pattern!r}: {exc}",
                file=sys.stderr,
            )
            raise BuildFailed()
        if compiled.groups != 1:
            print(
                f"error: [[version_check]] pattern {pattern!r} must have "
                f"exactly one capture group, has {compiled.groups}",
                file=sys.stderr,
            )
            raise BuildFailed()

        full_path = app_root / rel_path
        try:
            text = full_path.read_text(encoding="utf-8")
        except OSError as exc:
            print(
                f"error: [[version_check]] could not read {rel_path}: {exc}",
                file=sys.stderr,
            )
            raise BuildFailed()

        match = compiled.search(text)
        if match is None:
            print(
                f"error: [[version_check]] pattern {pattern!r} did not match "
                f"in {rel_path}",
                file=sys.stderr,
            )
            raise BuildFailed()
        extracted.append((rel_path, match.group(1)))

    values = {value for _, value in extracted}
    if len(values) > 1:
        print("error: [[version_check]] sources disagree:", file=sys.stderr)
        for rel_path, value in extracted:
            print(f"  {rel_path}: {value!r}", file=sys.stderr)
        raise BuildFailed()


class ResolvedManifest(NamedTuple):
    """Result of processing an app's manifest.py.

    files: (abs_source_path, romfs_target_path) pairs to compile (see
        _compile_manifest_files).
    required_packages: (name, ManifestPackageMetadata) pairs, one per
        require() call the manifest made (including transitively, through
        nested include()s), fed to the SBOM/license policy gate so
        third-party code pulled in this way doesn't bypass it.
    """
    files: list[tuple[Path, str]]
    required_packages: list[tuple[str, object]]


def _resolve_app_manifest(
    app_root: Path, data: dict, verbose: bool
) -> "ResolvedManifest | None":
    """Resolve app_root/manifest.py, if present; else a no-op.

    Returns None when no manifest.py exists at the app root; callers must
    treat that identically to "manifest.py support does not exist", so an
    app without one builds exactly as before this feature was added.
    """
    manifest_path = app_root / "manifest.py"
    if not manifest_path.is_file():
        return None

    resolved = _resolve_manifest(app_root, manifest_path, data, verbose)
    if verbose:
        print(
            f"  manifest: {len(resolved.files)} file(s), "
            f"{len(resolved.required_packages)} require()'d package(s) "
            f"resolved from manifest.py",
            file=sys.stderr,
        )
    return resolved


def _is_excluded(rel_parts: tuple[str, ...], excludes: list[str]) -> bool:
    """True if any path component (any depth) matches an fnmatch exclude pattern.

    A directory-name match therefore excludes its whole subtree, since every
    file under it has that name among its rel_parts. Shared by _compile_mpy
    and _copy_includes so [romfs].exclude applies uniformly to everything
    picolet build walks, not just explicitly-included directories.
    """
    return any(
        fnmatch.fnmatch(part, pat) for part in rel_parts for pat in excludes
    )


def _claim_mpy_dest(
    mpy_sources: dict[Path, Path], dst: Path, src: Path, romfs_root: Path
) -> None:
    """Record dst → src in a shared romfs-path collision-guard dict.

    Raises BuildFailed naming both source paths when dst is already claimed
    by a different source. Shared across _compile_mpy, _compile_manifest_files,
    and _copy_includes so an entry-tree file, a manifest.py require()'d
    module, and a [romfs] include can't silently collide at the same romfs
    path (ambiguous which one would ship).

    Also raises BuildFailed if dst resolves outside romfs_root entirely --
    reachable from a manifest.py module()/package() call with a ".."-laden
    path (e.g. module("../evil.py", base_path="sub")), where target_path is
    used verbatim as the romfs destination with no bounds checking of its
    own. .resolve() is used (not a lexical prefix check) because dst may
    contain unresolved ".." components that a plain string/parts comparison
    would not catch.
    """
    resolved_dst = dst.resolve()
    resolved_root = romfs_root.resolve()
    if resolved_root not in resolved_dst.parents:
        print(
            f"error: {src} resolves to a romfs destination outside the "
            f"romfs root: {dst} (romfs root: {romfs_root})",
            file=sys.stderr,
        )
        raise BuildFailed()

    if dst in mpy_sources and mpy_sources[dst] != src:
        print(
            f"error: {mpy_sources[dst]} and {src} both resolve to "
            f"romfs/{dst.relative_to(romfs_root)}; ship only one",
            file=sys.stderr,
        )
        raise BuildFailed()
    mpy_sources[dst] = src


def _mpy_cross_compile(
    mpy_cross: Path, src: Path, dst: Path, verbose: bool, *, label: "str | None" = None
) -> None:
    """Compile src → dst via mpy-cross, creating dst's parent dir as needed.

    label overrides the verbose progress line (default: full src/dst paths);
    callers with a shorter, romfs-relative description pass one for
    readability.
    """
    dst.parent.mkdir(parents=True, exist_ok=True)
    if verbose:
        print(f"  mpy-cross: {label if label is not None else f'{src} → {dst}'}", file=sys.stderr)
    subprocess.run(
        [str(mpy_cross), "-o", str(dst), str(src)],
        check=True,
        capture_output=not verbose,
    )


class _LazyManifestFile(ManifestFile):
    """ManifestFile that fetches MPY_LIB_DIR lazily and records require()'d
    package metadata for the SBOM/license policy gate.

    ManifestFile.__init__ resolves path_vars["MPY_LIB_DIR"] into concrete
    add_library() search-root paths eagerly, before any manifest.py content
    runs; but the directory those paths point at doesn't need to exist yet:
    _require_from_path's os.walk() on a missing directory just yields
    nothing. So MPY_LIB_DIR is always seeded with its real, deterministic
    target path (mpy_lib_cache.mpy_lib_dir_path, zero network access), and
    the actual fetch-and-cache (network access, only on a cold cache) is
    deferred to here, inside require(), only when a require() call would
    actually need to search under it. No static prescan of the manifest
    source is needed, and this handles a require() reached through a nested
    include() the same as a top-level one, since require() is intercepted
    regardless of which manifest.py is currently executing.

    A require() call needs MPY_LIB_DIR populated when either:
      - library= is not given (falls back to the BASE_LIBRARY_NAMES search
        roots registered from MPY_LIB_DIR at construction time), or
      - library= names a library whose add_library()-registered path itself
        lives under the MPY_LIB_DIR target: the canonical upstream idiom
        add_library("unix-ffi", "$(MPY_LIB_DIR)/unix-ffi", prepend=True) +
        require("ffilib", library="unix-ffi").

    required_packages collects (name, ManifestPackageMetadata) for every
    require() call. Attribution is correct even through nested/transitive
    require() chains: metadata() is only intercepted while
    _pending_require_names shows a require() call is in flight, and its top
    entry always names whichever manifest.py is currently executing.
    """

    def __init__(
        self,
        *args,
        mpy_lib_dir: "Path | None" = None,
        mpy_lib_fetcher=None,
        **kwargs,
    ) -> None:
        super().__init__(*args, **kwargs)
        # self._libraries (base class) maps library name -> abspath'd
        # directory string, populated by add_library(); comparing against it
        # is how a require(library=...) call is recognised as needing
        # MPY_LIB_DIR too. This is a deliberate coupling to ManifestFile's
        # internals; see picolet/_vendor/README.md for how to re-verify it
        # on a re-vendor.
        self._mpy_lib_dir_target = str(mpy_lib_dir) if mpy_lib_dir else None
        self._mpy_lib_fetcher = mpy_lib_fetcher
        self._mpy_lib_ensured = False
        self._pending_require_names: list[str] = []
        self._recorded_metadata_ids: set[int] = set()
        self.required_packages: list[tuple[str, object]] = []

    def _library_needs_mpy_lib_dir(self, library: "str | None") -> bool:
        if library is None:
            return True
        if self._mpy_lib_dir_target is None:
            return False
        lib_path = self._libraries.get(library)
        if lib_path is None:
            return False
        target = self._mpy_lib_dir_target
        return lib_path == target or lib_path.startswith(target + os.sep)

    def require(self, name, version=None, pypi=None, library=None, **kwargs):
        if (
            not self._mpy_lib_ensured
            and self._mpy_lib_fetcher is not None
            and self._library_needs_mpy_lib_dir(library)
        ):
            self._mpy_lib_ensured = True
            self._mpy_lib_fetcher()
        self._pending_require_names.append(name)
        try:
            super().require(name, version=version, pypi=pypi, library=library, **kwargs)
        finally:
            self._pending_require_names.pop()

    def metadata(self, **kwargs):
        result = super().metadata(**kwargs)
        if kwargs and self._pending_require_names:
            frame = self._metadata[-1]
            if id(frame) not in self._recorded_metadata_ids:
                self._recorded_metadata_ids.add(id(frame))
                self.required_packages.append((self._pending_require_names[-1], frame))
        return result

    def c_module(self, module_path):
        """Reject c_module() explicitly rather than silently dropping it.

        The base class's c_module() is a no-op outside MODE_FREEZE /
        MODE_LIST_C_MODULES (it returns before recording anything), so a
        manifest.py using it under MODE_COMPILE would otherwise "succeed"
        with the module simply absent from the build; there is no way to
        detect that after the fact via mf.c_modules().
        """
        raise ManifestFileError(
            f"c_module({module_path!r}) is not supported in an app's "
            f"manifest.py: picolet build only processes manifest.py in "
            f"MODE_COMPILE, which freezes Python sources, not C modules. "
            f"Remove this call."
        )


def _resolve_manifest(
    app_root: Path, manifest_path: Path, config: dict, verbose: bool
) -> ResolvedManifest:
    """Run manifest.py in MODE_COMPILE; return its resolved files + packages.

    MPY_LIB_DIR is always seeded with its real target path (see
    _LazyManifestFile), computed with zero network access; the fetch (or
    override validation) itself is deferred to the first require() call
    that actually needs it.
    """
    mpy_lib_dir = mpy_lib_dir_path(config, app_root)

    def fetcher() -> None:
        # Deliberately lets MpyLibFetchError propagate uncaught: it's raised
        # from inside a require() call, itself inside manifestfile.py's own
        # exec() of the currently-processing manifest.py, which wraps any
        # exception into ManifestFileError; that's the single error path
        # this function's caller (_resolve_manifest) already handles below.
        ensure_mpy_lib_dir(config, app_root, verbose=verbose)

    mf = _LazyManifestFile(
        MODE_COMPILE,
        path_vars={"MPY_LIB_DIR": str(mpy_lib_dir)},
        mpy_lib_dir=mpy_lib_dir,
        mpy_lib_fetcher=fetcher,
    )
    try:
        mf.execute(str(manifest_path))
    except ManifestFileError as exc:
        print(f"error: manifest.py: {exc}", file=sys.stderr)
        raise BuildFailed()
    files = [(Path(f.full_path), f.target_path) for f in mf.files()]
    return ResolvedManifest(files=files, required_packages=mf.required_packages)


def _compile_manifest_files(
    resolved: list[tuple[Path, str]],
    romfs_root: Path,
    mpy_cross: Path,
    verbose: bool,
    *,
    mpy_sources: "dict[Path, Path] | None" = None,
) -> None:
    """Compile manifest.py-resolved (src, target_path) pairs into romfs_root.

    Every ManifestOutput produced in MODE_COMPILE is a .py file
    (picolet._vendor.manifestfile._add_file() enforces this), so each entry
    is cross-compiled to .mpy, same as _compile_mpy/_copy_includes; an
    appended romfs never ships raw .py regardless of which pipeline step
    produced it.
    """
    if mpy_sources is None:
        mpy_sources = {}
    for src, target_path in resolved:
        romfs_target = Path(target_path).with_suffix(".mpy")
        dst = romfs_root / romfs_target
        _claim_mpy_dest(mpy_sources, dst, src, romfs_root)
        _mpy_cross_compile(
            mpy_cross, src, dst, verbose,
            label=f"{target_path} (manifest) → romfs/{romfs_target}",
        )


def _compile_mpy(
    app_root: Path,
    entry_str: str,
    romfs_root: Path,
    mpy_cross: Path,
    excludes: list[str],
    verbose: bool,
    *,
    mpy_sources: "dict[Path, Path] | None" = None,
) -> None:
    """Compile all .py files under dirname(entry) → .mpy in romfs_root.

    Files are processed in sorted order for reproducibility (FR-BP-6).
    Output paths mirror the input tree relative to app_root. excludes (see
    _is_excluded) skips files the entry tree shouldn't ship, e.g. tests or
    examples living alongside the app's real source — the entry point
    itself is never excludable (see below).

    The entry point file is additionally compiled to romfs_root/main.mpy so
    the runtime's auto-run path (/rom/main.mpy) executes the app entry.

    e.g. entry = "src/main.py"  →  src_dir = app_root / "src"
         src/main.py            →  romfs_root/src/main.mpy
         src/main.py (entry)    →  romfs_root/main.mpy   (auto-run by runtime)
    """
    if mpy_sources is None:
        mpy_sources = {}

    entry = Path(entry_str)
    entry_abs = app_root / entry
    src_dir = app_root / entry.parent  # e.g. app_root/"src"

    if not src_dir.is_dir():
        print(
            f"error: entry directory not found: {src_dir}",
            file=sys.stderr,
        )
        raise BuildFailed()

    py_files = sorted(src_dir.rglob("*.py"))
    if not py_files:
        print(
            f"warning: no .py files found under {src_dir}",
            file=sys.stderr,
        )

    for py in py_files:
        rel_in_src = py.relative_to(src_dir).parts
        if py != entry_abs and _is_excluded(rel_in_src, excludes):
            continue
        rel = py.relative_to(app_root)          # e.g. src/main.py
        out_mpy = romfs_root / rel.with_suffix(".mpy")
        _claim_mpy_dest(mpy_sources, out_mpy, py, romfs_root)
        _mpy_cross_compile(
            mpy_cross, py, out_mpy, verbose,
            label=f"{rel} → romfs/{rel.with_suffix('.mpy')}",
        )

    # Compile the entry point to /rom/main.mpy (the runtime's auto-run location).
    # The runtime auto-runs /rom/main.mpy on startup.  If the entry lives under
    # a subdirectory (e.g. src/main.py), its siblings land at /rom/src/*.mpy but
    # the runtime's sys.path does NOT include /rom/src — only /rom and /rom/lib.
    # We therefore prepend a sys.path fixup to the entry source before compiling
    # the /rom/main.mpy copy, so siblings are importable at runtime.
    romfs_root.mkdir(parents=True, exist_ok=True)
    entry_main_mpy = romfs_root / "main.mpy"
    _claim_mpy_dest(mpy_sources, entry_main_mpy, entry_abs, romfs_root)

    # Derive the romfs dirname from the entry path.  If entry == "src/main.py"
    # then entry_dir_in_romfs == "src", and the path to prepend is "/rom/src".
    # If the entry is at the root (e.g. "main.py") no fixup is needed.
    entry_romfs_dir = entry.parent  # PurePosixPath; "" for root-level entries
    needs_syspath_fixup = entry_romfs_dir != Path(".")  # true when dirname is non-trivial

    if needs_syspath_fixup:
        rom_dir = "/rom/" + entry_romfs_dir.as_posix()
        original_source = entry_abs.read_text(encoding="utf-8")
        wrapper = (
            "# Auto-generated by picolet build: prepend entry dirname to sys.path\n"
            "# so frozen siblings under {rom_dir}/ are importable.\n"
            "import sys\n"
            "if {rom_dir!r} not in sys.path:\n"
            "    sys.path.insert(0, {rom_dir!r})\n"
            "del sys\n"
            "# --- original {entry} content below ---\n"
            "{original_source}"
        ).format(
            rom_dir=rom_dir,
            entry=entry.as_posix(),
            original_source=original_source,
        )
        # Write the wrapper to a fixed, deterministic path in the staging
        # directory rather than a random tempfile.  The source filename is
        # embedded in the compiled .mpy bytecode; a random suffix would make
        # each build byte-distinct even for identical inputs (FR-BP-6).
        tmp_path = romfs_root.parent / "picolet_entry_wrapper.py"
        tmp_path.write_text(wrapper, encoding="utf-8")
        try:
            if verbose:
                print(
                    f"  mpy-cross: {entry} → romfs/main.mpy (entry + sys.path fixup for {rom_dir})",
                    file=sys.stderr,
                )
            subprocess.run(
                [str(mpy_cross), "-o", str(entry_main_mpy), str(tmp_path)],
                check=True,
                capture_output=not verbose,
            )
        finally:
            tmp_path.unlink(missing_ok=True)
    else:
        if verbose:
            print(f"  mpy-cross: {entry} → romfs/main.mpy (entry point)", file=sys.stderr)
        subprocess.run(
            [str(mpy_cross), "-o", str(entry_main_mpy), str(entry_abs)],
            check=True,
            capture_output=not verbose,
        )


def _copy_includes(
    app_root: Path,
    includes: list[str],
    excludes: list[str],
    romfs_root: Path,
    mpy_cross: Path,
    verbose: bool,
    *,
    mpy_sources: "dict[Path, Path] | None" = None,
) -> None:
    """Copy [romfs] include directories into romfs_root (FR-BP-4).

    Files are copied preserving their relative path within each include dir.
    Destination paths mirror the source tree rooted at romfs_root.

    `.py` files are cross-compiled to `.mpy` via mpy_cross rather than copied
    verbatim, so an appended romfs never ships raw `.py` regardless of which
    pipeline step put a file there. MicroPython's import resolution prefers
    `.py` over `.mpy` when both exist at the same path, so a raw `.py` here
    would silently win and recompile on every process start — the failure
    mode docs/proposals/app-romfs-mpy-packaging.md describes.

    excludes are fnmatch glob patterns matched against each path component
    (any depth) relative to its include dir — e.g. "tests" excludes a
    directory of that name and everything under it; "*.der" excludes files
    by extension anywhere in the tree. Matches claude-net-mpy's
    package-plugin.py _EXCLUDE_PATTERNS semantics.

    mpy_sources: romfs .mpy destination -> its source file, to catch a .py
    and a pre-existing .mpy (here, or from the entry tree, or from a
    manifest.py require()) both resolving to the same romfs path (ambiguous
    which one ships; see _claim_mpy_dest). Callers that don't pass one get a
    dict scoped to this call only (this function's own historical behaviour).
    """
    if mpy_sources is None:
        mpy_sources = {}

    for inc in includes:
        src = app_root / inc
        if not src.is_dir():
            print(
                f"error: [romfs] include directory not found: {src}",
                file=sys.stderr,
            )
            raise BuildFailed()
        for f in sorted(src.rglob("*")):
            if f.is_dir():
                continue
            # Skip CPython cache artefacts that have no meaning in the romfs.
            if "__pycache__" in f.parts or f.suffix == ".pyc":
                continue
            # Skip this build's own staging/output tree unconditionally: it
            # lives under app_root/target, so an include of "." (or any
            # ancestor of it) would otherwise walk back into the very romfs
            # this function is populating, mid-build.
            if f.relative_to(app_root).parts[0] == "target":
                continue
            rel_in_src = f.relative_to(src).parts
            if _is_excluded(rel_in_src, excludes):
                continue

            rel = f.relative_to(app_root)
            dst = romfs_root / (rel.with_suffix(".mpy") if f.suffix == ".py" else rel)

            if dst.suffix == ".mpy":
                _claim_mpy_dest(mpy_sources, dst, f, romfs_root)

            if f.suffix == ".py":
                _mpy_cross_compile(
                    mpy_cross, f, dst, verbose,
                    label=f"{rel} → romfs/{rel.with_suffix('.mpy')}",
                )
            else:
                dst.parent.mkdir(parents=True, exist_ok=True)
                if verbose:
                    print(f"  include: {rel} → romfs/{rel}", file=sys.stderr)
                shutil.copy2(f, dst)


def _zero_mtimes(root: Path) -> None:
    """Recursively set all file mtimes to epoch 0 for reproducibility (FR-BP-6).

    mpremote romfs build embeds file mtimes in the romfs directory entries.
    Setting all mtimes to 0 ensures byte-identical romfs images for identical
    inputs regardless of when the build is run.
    """
    for item in root.rglob("*"):
        if item.is_file() or item.is_dir():
            os.utime(item, (0, 0))


def _build_romfs(romfs_root: Path, output: Path, verbose: bool) -> None:
    """Invoke mpremote to build a romfs image from romfs_root.

    mpremote romfs --output <output> build <dir>
    """
    if verbose:
        print(f"  mpremote romfs build → {output}", file=sys.stderr)
    subprocess.run(
        [
            sys.executable,
            "-m", "mpremote",
            "romfs",
            "--output", str(output),
            "build", str(romfs_root),
        ],
        check=True,
        capture_output=not verbose,
    )


def _append_with_trailer(
    runtime_path: Path,
    romfs_path: Path,
    out_path: Path,
    verbose: bool,
) -> None:
    """Concatenate runtime + romfs payload + 24-byte trailer → out_path.

    Writes to a temporary path first, then renames atomically (or falls back
    to shutil.move on cross-filesystem writes) to avoid partial outputs.

    Layout (FR-BP-5):
        [ELF runtime bytes][romfs payload N bytes][trailer 24 bytes]
    """
    runtime = runtime_path.read_bytes()
    payload = romfs_path.read_bytes()
    trailer = pack_trailer(payload)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = out_path.parent / f".{out_path.name}.tmp"

    with open(tmp_path, "wb") as f:
        f.write(runtime)
        f.write(payload)
        f.write(trailer)

    # Atomic rename; falls back to copy+unlink on cross-filesystem writes.
    try:
        tmp_path.rename(out_path)
    except OSError:
        shutil.move(str(tmp_path), out_path)

    if verbose:
        total = len(runtime) + len(payload) + len(trailer)
        print(
            f"  binary: {out_path}  "
            f"({len(runtime)} + {len(payload)} + {len(trailer)} = {total} bytes)",
            file=sys.stderr,
        )


