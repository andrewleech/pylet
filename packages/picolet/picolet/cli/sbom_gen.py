"""
picolet SBOM generator — CycloneDX 1.5 JSON emitter.

Public API
----------
emit_runtime_sbom(output_path, target, variant, repo_root) -> None
    Assemble and write a CycloneDX 1.5 SBOM for a runtime artifact.

emit_app_sbom(output_path, runtime_sbom_path, app_data, target, variant,
              repo_root) -> list[SbomViolation]
    Merge runtime SBOM + app [dependencies], enforce policy, write output.
    Returns a (possibly empty) list of SbomViolation records.

SbomViolation
    Dataclass: component (str), reason (str), severity ("warn"|"fail").

CLI shim (FR-SBOM-1, build-runtime.sh post-build)
----------
    python -m picolet.cli.sbom_gen emit-runtime \\
        --output <path> --target <t> --variant <v> --repo-root <r>

Design notes
------------
AD1: runtime.toml is the authoritative source for native components.
AD2: This file lives in picolet-cli so the whole pipeline shares one package.
AD3: No external CycloneDX library — the format is well-bounded for this
     use-case; a dependency on cyclonedx-python-lib adds a transitive dep
     chain for marginal benefit at this scale.
AD4: Enforcement defaults match docs/sbom.md allowlist table.
AD5: build-runtime.sh calls the CLI shim on the host shell after the
     Docker container exits (Risk 1 mitigation).

[PH13] Caveat: [dependencies] declarations are not auto-discovered from an
app's own manifest.py; users still declare micropython-lib modules pulled
in that way under [dependencies] / [dependency_meta] if they want them
represented that way. This is a separate, narrower mechanism from
manifest_dep_components() below, which does derive real CycloneDX
components directly from an app's manifest.py require() calls (see
build_cmd._resolve_app_manifest); that path closes the SBOM/license gate
for manifest.py-resolved packages; this caveat is about the older
[dependencies]-table-driven auto-discovery only.
"""

from __future__ import annotations

import argparse
import ast
import datetime
import hashlib
import importlib.resources
import json
import sys
import tomllib
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Public constants
# ---------------------------------------------------------------------------

CDX_SPEC_VERSION = "1.5"
CDX_BOM_FORMAT = "CycloneDX"

try:
    from importlib.metadata import version as _v
    _PICOLET_CLI_VERSION = _v("picolet-cli")
except Exception:
    _PICOLET_CLI_VERSION = "0.0.0-dev"

# ---------------------------------------------------------------------------
# Default allowlists (FR-SBOM-3, docs/sbom.md)
# ---------------------------------------------------------------------------

_DEFAULT_ALLOW_LICENCES: list[str] = [
    "MIT",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "Apache-2.0",
    "Zlib",
    "0BSD",
    "ISC",
    "Python-2.0",
    # SIL Open Font Licence — used by JetBrains Mono and IBM Plex Sans (PH19).
    # OFL-1.1 is the canonical SPDX identifier; SIL-OFL-1.1 is not a registered
    # SPDX identifier and is therefore not included.
    "OFL-1.1",
]
_DEFAULT_ALLOW_DYNAMIC: list[str] = [
    "LGPL-2.1-or-later",
    "LicenseRef-MS-WebView2-Fixed",
]


# ---------------------------------------------------------------------------
# SbomViolation dataclass
# ---------------------------------------------------------------------------

@dataclass
class SbomViolation:
    """A single policy violation detected during SBOM emission.

    severity is "warn" when warn_unknown=true and fail_unknown=false;
    "fail" when fail_unknown=true (fail always implies warn too).
    """
    component: str
    reason: str
    severity: str   # "warn" | "fail"


# ---------------------------------------------------------------------------
# runtime.toml loader
# ---------------------------------------------------------------------------

def _runtime_toml_path(repo_root: Path) -> Path:
    """Source-tree path to runtime.toml.

    Used as a fallback when the package-resource lookup misses (e.g. running
    directly from a checkout without `pip install`).
    """
    return repo_root / "packages" / "picolet-runtime" / "sbom" / "runtime.toml"


def _load_packaged_toml(resource_name: str) -> "dict | None":
    """Read a bundled runtime data file via importlib.resources.

    Returns the parsed TOML dict, or None if the resource isn't present
    (which means we're running from a source checkout that didn't
    pip-install picolet — fall back to the source-tree path).
    """
    try:
        ref = importlib.resources.files("picolet._runtime_data").joinpath(
            resource_name
        )
        if ref.is_file():
            return tomllib.loads(ref.read_text(encoding="utf-8"))
    except (ModuleNotFoundError, FileNotFoundError, AttributeError):
        pass
    return None


def load_runtime_toml(repo_root: Path) -> list[dict]:
    """Parse runtime.toml; return the raw list of component dicts.

    Resolution order:
      1. Bundled at picolet/_runtime_data/sbom/runtime.toml (wheel install).
      2. Source-tree at packages/picolet-runtime/sbom/runtime.toml (dev).
    """
    data = _load_packaged_toml("sbom/runtime.toml")
    if data is None:
        path = _runtime_toml_path(repo_root)
        with open(path, "rb") as fh:
            data = tomllib.load(fh)
    return data.get("component", [])


def filter_components(
    components: list[dict],
    target: str,
    variant: str,
) -> list[dict]:
    """Apply variants/targets inclusion filters to the component list."""
    result = []
    for c in components:
        variants_filter = c.get("variants")
        if variants_filter is not None and variant not in variants_filter:
            continue
        targets_filter = c.get("targets")
        if targets_filter is not None and target not in targets_filter:
            continue
        result.append(c)
    return result


# ---------------------------------------------------------------------------
# mbm.toml PR list loader
# ---------------------------------------------------------------------------

def _mbm_toml_path(repo_root: Path) -> Path:
    return repo_root / "packages" / "picolet-runtime" / "mbm.toml"


def load_mbm_prs(repo_root: Path) -> list[str]:
    """Read mbm.toml and return a list of PR title strings.

    These are used to populate the MicroPython component's notes field
    in the runtime SBOM.  Returns an empty list if mbm.toml is absent.

    Resolution order: package-resource first, source-tree fallback.
    """
    data = _load_packaged_toml("mbm.toml")
    if data is None:
        path = _mbm_toml_path(repo_root)
        if not path.is_file():
            return []
        with open(path, "rb") as fh:
            data = tomllib.load(fh)
    titles = []
    for sub in data.get("submodules", []):
        for branch in sub.get("branches", []):
            name = branch.get("name", "")
            title = branch.get("title", "")
            if name or title:
                titles.append(f"{name}: {title}" if name and title else name or title)
    return titles


# ---------------------------------------------------------------------------
# CycloneDX component converter
# ---------------------------------------------------------------------------

def _to_cdx_component(entry: dict, bom_ref: str) -> dict:
    """Convert a runtime.toml entry dict to a CycloneDX 1.5 component object.

    component type:
      - MicroPython → "framework" (it is an interpreter/runtime framework)
      - all others  → "library"
    """
    name = entry["name"]
    comp_type = "framework" if name == "MicroPython" else "library"

    cdx: dict[str, Any] = {
        "type": comp_type,
        "bom-ref": bom_ref,
        "name": name,
        "version": entry["version"],
    }

    # Licence
    licence_id = entry["licence"]
    if licence_id.startswith("LicenseRef-"):
        cdx["licenses"] = [{"license": {"name": licence_id}}]
    else:
        cdx["licenses"] = [{"license": {"id": licence_id}}]

    # External reference
    source_url = entry.get("source_url", "")
    if source_url:
        cdx["externalReferences"] = [{"type": "website", "url": source_url}]

    # purl
    purl = entry.get("purl")
    if purl:
        cdx["purl"] = purl

    # Properties: picolet-specific metadata
    properties = []
    link_type = entry.get("link_type", "")
    if link_type:
        properties.append({"name": "picolet:link_type", "value": link_type})

    variants = entry.get("variants")
    if variants:
        properties.append({"name": "picolet:variants", "value": ",".join(variants)})

    targets = entry.get("targets")
    if targets:
        properties.append({"name": "picolet:targets", "value": ",".join(targets)})

    if properties:
        cdx["properties"] = properties

    # Notes as description
    notes = entry.get("notes", "").strip()
    if notes:
        cdx["description"] = notes

    return cdx


def _inject_mbm_prs(cdx_components: list[dict], pr_titles: list[str]) -> None:
    """Append PR title list to the MicroPython component's description.

    Operates in-place on the list of CycloneDX component dicts.
    """
    if not pr_titles:
        return
    for comp in cdx_components:
        if comp.get("name") == "MicroPython":
            existing = comp.get("description", "")
            pr_block = "\n".join(pr_titles)
            if existing:
                comp["description"] = existing + "\n" + pr_block
            else:
                comp["description"] = pr_block
            break


# ---------------------------------------------------------------------------
# Document assembly helpers
# ---------------------------------------------------------------------------

def _now_utc() -> str:
    """Return the current UTC time as an ISO 8601 string with Z suffix."""
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def _hash_file(path: Path) -> dict:
    """Return a CycloneDX 1.5 hash entry for the file at *path*.

    Returns ``{"alg": "SHA-256", "content": "<hex>"}`` using SHA-256.
    """
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return {"alg": "SHA-256", "content": digest}


def _make_document(
    artifact_name: str,
    artifact_version: str,
    artifact_type: str,   # "application" | "library"
    cdx_components: list[dict],
    artifact_path: "Path | None" = None,
) -> dict:
    """Assemble a minimal valid CycloneDX 1.5 JSON document.

    When *artifact_path* is provided and the file exists, a SHA-256 hash is
    attached to ``metadata.component.hashes`` so the SBOM is verifiable.
    """
    metadata_component: dict[str, Any] = {
        "type": artifact_type,
        "name": artifact_name,
        "version": artifact_version,
    }
    if artifact_path is not None and artifact_path.is_file():
        metadata_component["hashes"] = [_hash_file(artifact_path)]

    return {
        "bomFormat": CDX_BOM_FORMAT,
        "specVersion": CDX_SPEC_VERSION,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": _now_utc(),
            "tools": [
                {
                    "vendor": "picolet",
                    "name": "picolet-sbom-gen",
                    "version": _PICOLET_CLI_VERSION,
                }
            ],
            "component": metadata_component,
        },
        "components": cdx_components,
    }


def _write_document(doc: dict, output_path: Path) -> None:
    """Write a CycloneDX document as pretty-printed JSON."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2, ensure_ascii=False)
        fh.write("\n")


# ---------------------------------------------------------------------------
# Runtime tag helper
# ---------------------------------------------------------------------------

def _runtime_tag(repo_root: Path) -> str:
    """Read RUNTIME_TAG sidecar or return a fallback."""
    tag_file = repo_root / "packages" / "picolet-runtime" / "RUNTIME_TAG"
    if tag_file.is_file():
        return tag_file.read_text().strip()
    return "runtime-v0.0.1"


# ---------------------------------------------------------------------------
# micropython-lib manifest auto-discovery (A8)
# ---------------------------------------------------------------------------

# Search paths within micropython-lib for a named module's manifest.py.
# Tried in order; first hit wins.
_UPYLIB_SEARCH_DIRS = (
    "python-stdlib",
    "micropython",
    "unix-ffi",
)

# Canonical licence for all micropython-lib modules (MIT per the repo LICENSE).
_UPYLIB_LICENCE = "MIT"

# micropython-lib source URL prefix.
_UPYLIB_SOURCE_URL = "https://github.com/micropython/micropython-lib"


def _upylib_root(repo_root: Path) -> Path:
    """Return the path to the vendored micropython-lib directory."""
    return (
        repo_root
        / "packages"
        / "picolet-runtime"
        / "micropython"
        / "lib"
        / "micropython-lib"
    )


def parse_upylib_manifest(manifest_path: Path) -> dict:
    """Parse a micropython-lib manifest.py and return its metadata.

    Uses ast to evaluate only the ``metadata(...)`` call safely.
    Returns a dict with keys "version" and "description" (may be empty
    strings if absent from the manifest).

    Raises ValueError if the manifest cannot be parsed.
    """
    try:
        source = manifest_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"cannot read {manifest_path}: {exc}") from exc

    try:
        tree = ast.parse(source, filename=str(manifest_path))
    except SyntaxError as exc:
        raise ValueError(f"syntax error in {manifest_path}: {exc}") from exc

    version = ""
    description = ""

    for node in ast.walk(tree):
        if not isinstance(node, ast.Expr):
            continue
        call = node.value
        if not isinstance(call, ast.Call):
            continue
        func = call.func
        if not (isinstance(func, ast.Name) and func.id == "metadata"):
            continue
        # Extract keyword arguments.
        for kw in call.keywords:
            if kw.arg == "version" and isinstance(kw.value, ast.Constant):
                version = str(kw.value.value)
            elif kw.arg == "description" and isinstance(kw.value, ast.Constant):
                description = str(kw.value.value)
        # Also accept positional first arg as version (rare but exists).
        if not version and call.args and isinstance(call.args[0], ast.Constant):
            version = str(call.args[0].value)
        break  # only first metadata() call matters

    return {"version": version, "description": description}


def find_upylib_manifest(module_name: str, repo_root: Path) -> "Path | None":
    """Locate the manifest.py for a named micropython-lib module.

    Searches _UPYLIB_SEARCH_DIRS in order; returns the first manifest.py
    found, or None if the module is not in the vendored micropython-lib.
    """
    root = _upylib_root(repo_root)
    for subdir in _UPYLIB_SEARCH_DIRS:
        candidate = root / subdir / module_name / "manifest.py"
        if candidate.is_file():
            return candidate
    return None


def upylib_components(
    module_names: list[str],
    repo_root: Path,
    offset: int,
) -> list[dict]:
    """Build CycloneDX components for a list of micropython-lib module names.

    For each name, attempts to locate and parse the vendored manifest.py.
    On success: emits a component with the manifest version and MIT licence.
    On failure (module not found): emits a component with version "unknown"
    and LicenseRef-Unknown so downstream policy enforcement handles it.
    """
    components = []
    for i, name in enumerate(module_names):
        manifest_path = find_upylib_manifest(name, repo_root)
        if manifest_path is not None:
            try:
                meta = parse_upylib_manifest(manifest_path)
                version = meta["version"] or "unknown"
                description = meta.get("description", "")
                licence = _UPYLIB_LICENCE
            except ValueError:
                version = "unknown"
                description = ""
                licence = "LicenseRef-Unknown"
        else:
            version = "unknown"
            description = ""
            licence = "LicenseRef-Unknown"
            sys.stderr.write(
                f"warning: SBOM auto-discovery could not find manifest for"
                f" micropython-lib module '{name}' under {repo_root};"
                f" emitting as LicenseRef-Unknown\n"
            )

        bom_ref = f"upylib-{name.lower().replace('-', '_')}-{offset + i}"
        cdx: dict[str, Any] = {
            "type": "library",
            "bom-ref": bom_ref,
            "name": name,
            "version": version,
        }
        if licence.startswith("LicenseRef-"):
            cdx["licenses"] = [{"license": {"name": licence}}]
        else:
            cdx["licenses"] = [{"license": {"id": licence}}]
        cdx["externalReferences"] = [{"type": "website", "url": _UPYLIB_SOURCE_URL}]
        cdx["properties"] = [
            {"name": "picolet:link_type", "value": "static"},
            {"name": "picolet:source", "value": "micropython-lib"},
        ]
        if description:
            cdx["description"] = description
        components.append(cdx)
    return components


def manifest_dep_components(records: list[dict], offset: int) -> list[dict]:
    """Build CycloneDX components for manifest.py require()'d packages.

    records is a list of plain dicts (name, version, license, description,
    author) built by build_cmd from the (name, ManifestPackageMetadata)
    pairs a manifest.py's require() calls produced; see
    build_cmd._resolve_app_manifest / _LazyManifestFile.required_packages.

    link_type is always "static": everything manifest.py resolves is
    compiled and frozen into the romfs the same way as every other source
    picolet build packages, so it is checked against allow_licences (not
    allow_dynamic) by _enforce_policy, and a missing metadata(license=...)
    call yields LicenseRef-Unknown, subject to warn_unknown/fail_unknown
    like any other unknown-licence component. This is what actually closes
    the SBOM/license policy gate for third-party code pulled in via
    require(); without this, that code would be frozen into the shipped
    binary with no license review at all.
    """
    components: list[dict] = []
    for i, rec in enumerate(records):
        name = rec["name"]
        version = str(rec.get("version") or "unknown")
        licence = rec.get("license") or "LicenseRef-Unknown"
        description = rec.get("description") or ""
        author = rec.get("author") or ""

        bom_ref = f"manifest-{name.lower().replace('-', '_').replace('.', '_')}-{offset + i}"
        cdx: dict[str, Any] = {
            "type": "library",
            "bom-ref": bom_ref,
            "name": name,
            "version": version,
        }
        if licence.startswith("LicenseRef-"):
            cdx["licenses"] = [{"license": {"name": licence}}]
        else:
            cdx["licenses"] = [{"license": {"id": licence}}]
        properties = [
            {"name": "picolet:link_type", "value": "static"},
            {"name": "picolet:source", "value": "manifest.py require()"},
        ]
        if author:
            properties.append({"name": "picolet:author", "value": author})
        cdx["properties"] = properties
        if description:
            cdx["description"] = description
        components.append(cdx)
    return components


# ---------------------------------------------------------------------------
# Public: emit_runtime_sbom
# ---------------------------------------------------------------------------

def emit_runtime_sbom(
    output_path: Path,
    target: str,
    variant: str,
    repo_root: Path,
    artifact_path: "Path | None" = None,
) -> None:
    """Assemble and write a CycloneDX 1.5 SBOM for a runtime artifact.

    Reads runtime.toml, filters by (target, variant), injects mbm.toml PR
    list into the MicroPython component notes, and writes the document.

    When *artifact_path* is provided and the file exists, a SHA-256 hash is
    attached to ``metadata.component.hashes``.
    """
    all_components = load_runtime_toml(repo_root)
    filtered = filter_components(all_components, target, variant)

    pr_titles = load_mbm_prs(repo_root)

    cdx_components = []
    for i, entry in enumerate(filtered):
        bom_ref = f"runtime-{entry['name'].lower().replace(' ', '-').replace('.','-')}-{i}"
        cdx_components.append(_to_cdx_component(entry, bom_ref))

    _inject_mbm_prs(cdx_components, pr_titles)

    artifact_name = f"picolet-runtime-{target}-{variant}"
    tag = _runtime_tag(repo_root)

    doc = _make_document(
        artifact_name=artifact_name,
        artifact_version=tag,
        artifact_type="library",
        cdx_components=cdx_components,
        artifact_path=artifact_path,
    )
    _write_document(doc, output_path)


# ---------------------------------------------------------------------------
# Public: emit_app_sbom
# ---------------------------------------------------------------------------

def emit_app_sbom(
    output_path: Path,
    runtime_sbom_path: "Path | None",
    app_data: dict,
    target: str,
    variant: str,
    repo_root: Path,
    artifact_path: "Path | None" = None,
    manifest_dependencies: "list[dict] | None" = None,
) -> list[SbomViolation]:
    """Merge runtime + app deps; enforce policy; write CycloneDX 1.5 SBOM.

    Parameters
    ----------
    output_path:
        Destination path for the .cdx.json file (always written, even on
        policy violations, so downstream tooling can inspect the SBOM).
    runtime_sbom_path:
        Path to the runtime's pre-built .cdx.json sidecar, or None when
        building from source (the resolver could not provide one).  When
        None, falls back to reading runtime.toml + mbm.toml directly.
    app_data:
        Parsed picolet.toml dict.
    target, variant:
        Build target and runtime variant strings.
    repo_root:
        Absolute path to the repository root.
    artifact_path:
        Path to the built application binary.  When provided and the file
        exists, a SHA-256 hash is attached to ``metadata.component.hashes``.
    manifest_dependencies:
        Plain-dict records (name/version/license/description/author) for
        packages an app's manifest.py pulled in via require(); see
        manifest_dep_components(). None or empty when the app has no
        manifest.py, or its manifest.py used no require().

    Returns
    -------
    list[SbomViolation]
        Empty when the build is policy-clean.  Caller must print warnings
        for severity="warn" and exit 1 for any severity="fail" entry.
    """
    # Step 1 — Build the runtime component list.
    if runtime_sbom_path is not None and runtime_sbom_path.is_file():
        # Merge from pre-built runtime SBOM.
        with open(runtime_sbom_path, encoding="utf-8") as fh:
            runtime_doc = json.load(fh)
        runtime_cdx_components = list(runtime_doc.get("components", []))
    else:
        # Fall back to reading runtime.toml directly.
        all_rt = load_runtime_toml(repo_root)
        filtered_rt = filter_components(all_rt, target, variant)
        pr_titles = load_mbm_prs(repo_root)
        runtime_cdx_components = []
        for i, entry in enumerate(filtered_rt):
            bom_ref = f"runtime-{entry['name'].lower().replace(' ', '-').replace('.','-')}-{i}"
            runtime_cdx_components.append(_to_cdx_component(entry, bom_ref))
        _inject_mbm_prs(runtime_cdx_components, pr_titles)

    # Step 2 — Build the app dependency component list ([dependencies] table
    # plus manifest.py require() calls; both go through the same collision
    # + policy pipeline below).
    app_cdx_components = _app_dep_components(
        app_data, offset=len(runtime_cdx_components), repo_root=repo_root
    )
    manifest_cdx_components = manifest_dep_components(
        manifest_dependencies or [],
        offset=len(runtime_cdx_components) + len(app_cdx_components),
    )
    declared_app_components = app_cdx_components + manifest_cdx_components

    # Step 3 — Merge; detect name collisions and keep both with warning.
    runtime_by_name: dict[str, dict] = {c["name"]: c for c in runtime_cdx_components}
    collision_violations: list[SbomViolation] = []
    merged = list(runtime_cdx_components)
    seen_names: set[str] = set(runtime_by_name.keys())
    for comp in declared_app_components:
        name = comp["name"]
        if name in runtime_by_name:
            # Collision: preserve both entries.  Rewrite bom-ref to avoid
            # duplicates — app entry gets "app-<name>-..." prefix.
            rt_comp = runtime_by_name[name]
            rt_version = rt_comp.get("version", "?")
            rt_licence = _get_component_licence(rt_comp)
            app_version = comp.get("version", "?")
            app_licence = _get_component_licence(comp)
            # Ensure the app component's bom-ref is distinguishable from the
            # runtime one by prepending "app-" if not already present.
            old_ref = comp.get("bom-ref", "")
            if not old_ref.startswith("app-"):
                comp = dict(comp)
                comp["bom-ref"] = "app-" + old_ref
            collision_violations.append(SbomViolation(
                severity="warn",
                component=name,
                reason=(
                    f"app-declared component (from [dependencies] or manifest.py "
                    f"require()) collides with runtime component "
                    f"(runtime: {rt_version}/{rt_licence}; app: {app_version}/{app_licence})"
                ),
            ))
            merged.append(comp)
        else:
            merged.append(comp)
            seen_names.add(name)

    # Step 4 — Policy enforcement (FR-SBOM-3).
    sbom_config = app_data.get("sbom") or {}
    violations = collision_violations + _enforce_policy(merged, sbom_config)

    # Step 5 — Write SBOM (always, even on violations).
    app_name = app_data.get("app", {}).get("name", "unknown-app")
    app_version = app_data.get("app", {}).get("version", "0.0.0")
    doc = _make_document(
        artifact_name=app_name,
        artifact_version=app_version,
        artifact_type="application",
        cdx_components=merged,
        artifact_path=artifact_path,
    )
    _write_document(doc, output_path)

    return violations


# ---------------------------------------------------------------------------
# App dependency components
# ---------------------------------------------------------------------------

def _app_dep_components(
    app_data: dict,
    offset: int,
    repo_root: "Path | None" = None,
) -> list[dict]:
    """Convert app [dependencies] + [dependency_meta] to CDX components.

    [dependencies] is a flat table: name = "version".

    Special key: ``micropython-lib`` may map to a list of module names
    (e.g. ``micropython-lib = ["asyncio", "json"]``).  When detected,
    each name is resolved against the vendored micropython-lib manifests
    (requires *repo_root*) to extract version and licence automatically.

    [dependency_meta.<name>] may carry a 'licence' key for other deps.
    Without it the generator emits LicenseRef-Unknown.
    """
    deps: dict = app_data.get("dependencies") or {}
    meta_root: dict = app_data.get("dependency_meta") or {}

    if not deps or not isinstance(deps, dict):
        return []

    components: list[dict] = []
    i = 0

    # Guard: micropython-lib manifest resolution requires a repo_root.
    # Detect the problematic combination early so the user gets a clear
    # error rather than a silently incomplete SBOM.
    if repo_root is None and any(
        k == "micropython-lib" and isinstance(v, list) for k, v in deps.items()
    ):
        raise ValueError(
            "SBOM auto-discovery for micropython-lib modules requires repo_root; got None"
        )

    for name, version in deps.items():
        # Special case: micropython-lib = ["asyncio", "json", ...]
        if name == "micropython-lib" and isinstance(version, list):
            module_names = [str(m) for m in version]
            upy_comps = upylib_components(module_names, repo_root, offset + i)
            components.extend(upy_comps)
            i += len(module_names)
            continue

        meta = meta_root.get(name) or {}
        licence = meta.get("licence") or meta.get("license") or "LicenseRef-Unknown"
        source_url = meta.get("source_url") or meta.get("url") or ""
        link_type = meta.get("link_type") or "dynamic"
        purl = meta.get("purl") or ""

        bom_ref = f"app-dep-{name.lower().replace(' ', '-')}-{offset + i}"

        cdx: dict[str, Any] = {
            "type": "library",
            "bom-ref": bom_ref,
            "name": name,
            "version": str(version),
        }
        if licence.startswith("LicenseRef-"):
            cdx["licenses"] = [{"license": {"name": licence}}]
        else:
            cdx["licenses"] = [{"license": {"id": licence}}]
        if source_url:
            cdx["externalReferences"] = [{"type": "website", "url": source_url}]
        if purl:
            cdx["purl"] = purl
        cdx["properties"] = [{"name": "picolet:link_type", "value": link_type}]

        components.append(cdx)
        i += 1

    return components


# ---------------------------------------------------------------------------
# Policy enforcement
# ---------------------------------------------------------------------------

def _get_component_licence(comp: dict) -> str:
    """Extract the SPDX id or LicenseRef-* name from a CDX component."""
    for lic_entry in comp.get("licenses") or []:
        lic = lic_entry.get("license") or {}
        return lic.get("id") or lic.get("name") or "LicenseRef-Unknown"
    return "LicenseRef-Unknown"


def _get_component_link_type(comp: dict) -> str:
    """Extract picolet:link_type from a CDX component's properties."""
    for prop in comp.get("properties") or []:
        if prop.get("name") == "picolet:link_type":
            return prop.get("value", "static")
    return "static"


def _enforce_policy(
    components: list[dict],
    sbom_config: dict,
) -> list[SbomViolation]:
    """Check each component against the [sbom] allow-lists.

    FR-SBOM-3 enforcement logic:
      - static link: licence must be in allow_licences.
      - dynamic link: licence must be in allow_licences OR allow_dynamic.
      - build-time-only: skipped (not shipped in artifact).
      - LicenseRef-Unknown: apply warn_unknown / fail_unknown policy.
    """
    allow_licences = sbom_config.get("allow_licences") or _DEFAULT_ALLOW_LICENCES
    allow_dynamic  = sbom_config.get("allow_dynamic")  or _DEFAULT_ALLOW_DYNAMIC
    warn_unknown   = sbom_config.get("warn_unknown", True)
    fail_unknown   = sbom_config.get("fail_unknown", False)

    # fail_unknown implies warn_unknown.
    if fail_unknown:
        warn_unknown = True

    violations: list[SbomViolation] = []

    for comp in components:
        name = comp.get("name", "<unknown>")
        licence = _get_component_licence(comp)
        link_type = _get_component_link_type(comp)

        # build-time-only components are not in the shipped artifact.
        if link_type == "build-time-only":
            continue

        if licence == "LicenseRef-Unknown":
            severity = "fail" if fail_unknown else ("warn" if warn_unknown else None)
            if severity:
                violations.append(SbomViolation(
                    component=name,
                    reason=f"licence is LicenseRef-Unknown (link_type={link_type})",
                    severity=severity,
                ))
            continue

        if link_type == "static":
            allowed = set(allow_licences)
        else:
            # dynamic
            allowed = set(allow_licences) | set(allow_dynamic)

        if licence not in allowed:
            violations.append(SbomViolation(
                component=name,
                reason=(
                    f"licence {licence!r} not in allow_licences"
                    + (" or allow_dynamic" if link_type == "dynamic" else "")
                    + f" (link_type={link_type})"
                ),
                severity="fail",
            ))

    return violations


# ---------------------------------------------------------------------------
# CLI shim
# ---------------------------------------------------------------------------

def _cli_emit_runtime(args: argparse.Namespace) -> None:
    """Implement 'emit-runtime' subcommand."""
    output = Path(args.output)
    repo_root = Path(args.repo_root)
    artifact_path = Path(args.artifact) if args.artifact else None
    emit_runtime_sbom(
        output_path=output,
        target=args.target,
        variant=args.variant,
        repo_root=repo_root,
        artifact_path=artifact_path,
    )
    print(f"SBOM written: {output}", file=sys.stderr)


def main() -> None:
    """Entry point for 'python -m picolet.cli.sbom_gen'."""
    parser = argparse.ArgumentParser(
        prog="python -m picolet.cli.sbom_gen",
        description="Picolet CycloneDX 1.5 SBOM generator",
    )
    sub = parser.add_subparsers(dest="subcommand", required=True)

    p_rt = sub.add_parser("emit-runtime", help="emit a runtime artifact SBOM")
    p_rt.add_argument("--output", required=True, help="output .cdx.json path")
    p_rt.add_argument("--target", required=True, help="e.g. linux-x64")
    p_rt.add_argument("--variant", required=True, help="e.g. cli")
    p_rt.add_argument("--repo-root", required=True, dest="repo_root",
                      help="absolute path to repo root")
    p_rt.add_argument("--artifact", default=None,
                      help="path to the built runtime binary (used to compute SHA-256 hash)")
    p_rt.set_defaults(func=_cli_emit_runtime)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
