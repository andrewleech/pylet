"""
PH13 SBOM generator unit tests.

Covers:
  - CycloneDX 1.5 document structure (gates 3, 9).
  - Component names, licences, and link types (gate 5, 11).
  - variant+target filtering: cli does not include LVGL or SDL2 (gate 11).
  - MicroPython PR list from mbm.toml in MicroPython component notes (gate 10).
  - Allowlist enforcement: warn path (gate 6), fail path (gate 7).
  - emit_app_sbom: app SBOM is a superset of runtime SBOM components (gate 5).
  - serialNumber is a valid urn:uuid:<uuid4> (gate 9).
  - metadata.component.hashes carries SHA-256 when artifact_path is supplied.
"""
from __future__ import annotations

import json
import re
import sys
import tempfile
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(_REPO_ROOT / "packages" / "picolet"))

from picolet.cli.sbom_gen import (
    SbomViolation,
    emit_app_sbom,
    emit_runtime_sbom,
    filter_components,
    load_mbm_prs,
    load_runtime_toml,
    manifest_dep_components,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _tmp_path() -> Path:
    d = tempfile.mkdtemp()
    return Path(d)


# ---------------------------------------------------------------------------
# runtime.toml loading + filtering (gates 11, 1)
# ---------------------------------------------------------------------------

class TestRuntimeToml:
    def test_loads_components(self):
        components = load_runtime_toml(_REPO_ROOT)
        assert len(components) >= 8, f"Expected at least 8 components, got {len(components)}"

    def test_cli_variant_excludes_lvgl_sdl2(self):
        all_c = load_runtime_toml(_REPO_ROOT)
        cli_c = filter_components(all_c, "linux-x64", "cli")
        names = [c["name"] for c in cli_c]
        assert "LVGL" not in names, f"LVGL should not appear in cli SBOM: {names}"
        assert "SDL2" not in names, f"SDL2 should not appear in cli SBOM: {names}"

    def test_cli_variant_includes_micropython_libffi(self):
        all_c = load_runtime_toml(_REPO_ROOT)
        cli_c = filter_components(all_c, "linux-x64", "cli")
        names = [c["name"] for c in cli_c]
        assert "MicroPython" in names
        assert "libffi" in names

    def test_lvgl_linux_includes_sdl2_dynamic(self):
        all_c = load_runtime_toml(_REPO_ROOT)
        lvgl_c = filter_components(all_c, "linux-x64", "lvgl")
        names = [c["name"] for c in lvgl_c]
        assert "LVGL" in names
        sdl2_entries = [c for c in lvgl_c if c["name"] == "SDL2"]
        assert sdl2_entries, "SDL2 must appear in lvgl/linux-x64"
        assert sdl2_entries[0]["link_type"] == "dynamic"

    def test_lvgl_windows_includes_sdl2_static(self):
        all_c = load_runtime_toml(_REPO_ROOT)
        lvgl_c = filter_components(all_c, "windows-x64", "lvgl")
        sdl2_entries = [c for c in lvgl_c if c["name"] == "SDL2"]
        assert sdl2_entries, "SDL2 must appear in lvgl/windows-x64"
        assert sdl2_entries[0]["link_type"] == "static"

    def test_webview_linux_includes_webkitgtk(self):
        all_c = load_runtime_toml(_REPO_ROOT)
        wv_c = filter_components(all_c, "linux-x64", "webview")
        names = [c["name"] for c in wv_c]
        assert "WebKitGTK" in names

    def test_webview_windows_includes_webview2(self):
        all_c = load_runtime_toml(_REPO_ROOT)
        wv_c = filter_components(all_c, "windows-x64", "webview")
        names = [c["name"] for c in wv_c]
        assert "Microsoft.Web.WebView2" in names
        assert "WebView2Loader.dll" in names

    def test_required_keys_present(self):
        components = load_runtime_toml(_REPO_ROOT)
        required = {"name", "version", "licence", "source_url", "link_type"}
        for c in components:
            missing = required - c.keys()
            assert not missing, f"Component {c.get('name')} missing keys: {missing}"


# ---------------------------------------------------------------------------
# mbm.toml PR loading (gate 10)
# ---------------------------------------------------------------------------

class TestMbmPrs:
    def test_loads_pr_titles(self):
        prs = load_mbm_prs(_REPO_ROOT)
        assert len(prs) >= 7, f"Expected at least 7 PRs from mbm.toml, got {len(prs)}"

    def test_pr_titles_contain_pr_prefix(self):
        prs = load_mbm_prs(_REPO_ROOT)
        assert any("pr/" in t for t in prs), f"Expected pr/ prefix in PR titles: {prs}"


# ---------------------------------------------------------------------------
# emit_runtime_sbom — document structure (gates 3, 9, 10, 11)
# ---------------------------------------------------------------------------

class TestEmitRuntimeSbom:
    def _emit(self, target: str, variant: str) -> dict:
        out = Path(tempfile.mktemp(suffix=".cdx.json"))
        emit_runtime_sbom(out, target, variant, _REPO_ROOT)
        return json.loads(out.read_text())

    def test_cdx_format_and_version(self):
        doc = self._emit("linux-x64", "cli")
        assert doc["bomFormat"] == "CycloneDX"
        assert doc["specVersion"] == "1.5"

    def test_serial_number_is_urn_uuid(self):
        doc = self._emit("linux-x64", "cli")
        assert re.match(r"urn:uuid:[0-9a-f\-]{36}$", doc["serialNumber"]), \
            f"serialNumber invalid: {doc['serialNumber']}"

    def test_metadata_fields(self):
        doc = self._emit("linux-x64", "cli")
        meta = doc["metadata"]
        assert "timestamp" in meta
        assert meta["tools"][0]["vendor"] == "picolet"
        assert meta["component"]["type"] == "library"
        assert "picolet-runtime-linux-x64-cli" in meta["component"]["name"]

    def test_has_components(self):
        doc = self._emit("linux-x64", "cli")
        assert len(doc["components"]) >= 1

    def test_cli_no_lvgl_sdl2(self):
        doc = self._emit("linux-x64", "cli")
        names = [c["name"] for c in doc["components"]]
        assert "LVGL" not in names
        assert "SDL2" not in names

    def test_micropython_type_is_framework(self):
        doc = self._emit("linux-x64", "cli")
        mp = next(c for c in doc["components"] if c["name"] == "MicroPython")
        assert mp["type"] == "framework"

    def test_micropython_has_pr_in_description(self):
        """Gate 10: MicroPython component carries mbm.toml PR list."""
        doc = self._emit("linux-x64", "cli")
        mp = next(c for c in doc["components"] if c["name"] == "MicroPython")
        desc = mp.get("description", "")
        props = mp.get("properties", [])
        has_pr = "pr/" in desc or any("pr/" in str(p) for p in props)
        assert has_pr, f"MicroPython component missing PR list. description={desc!r}"

    def test_licenseref_uses_name_field(self):
        """LicenseRef-* identifiers must use 'name' not 'id' in CDX."""
        doc = self._emit("windows-x64", "webview")
        for comp in doc["components"]:
            for lic_entry in comp.get("licenses", []):
                lic = lic_entry.get("license", {})
                raw = lic.get("id") or lic.get("name") or ""
                if raw.startswith("LicenseRef-"):
                    assert "name" in lic, \
                        f"LicenseRef- in {comp['name']} must use 'name' field, got {lic}"
                    assert "id" not in lic, \
                        f"LicenseRef- in {comp['name']} must not use 'id' field, got {lic}"

    def test_bom_refs_unique(self):
        doc = self._emit("linux-x64", "lvgl")
        refs = [c.get("bom-ref") for c in doc["components"]]
        assert len(refs) == len(set(refs)), f"Duplicate bom-refs: {refs}"

    def test_lvgl_linux_sdl2_link_type_in_properties(self):
        doc = self._emit("linux-x64", "lvgl")
        sdl2 = next(c for c in doc["components"] if c["name"] == "SDL2")
        props = {p["name"]: p["value"] for p in sdl2.get("properties", [])}
        assert props.get("picolet:link_type") == "dynamic"


# ---------------------------------------------------------------------------
# emit_app_sbom — superset check (gate 5), policy enforcement (gates 6, 7)
# ---------------------------------------------------------------------------

class TestEmitAppSbom:
    def _emit_runtime(self, target: str, variant: str) -> Path:
        out = Path(tempfile.mktemp(suffix=".cdx.json"))
        emit_runtime_sbom(out, target, variant, _REPO_ROOT)
        return out

    def _emit_app(
        self,
        app_data: dict,
        target: str = "linux-x64",
        variant: str = "cli",
        runtime_sbom_path: "Path | None" = None,
    ) -> tuple[dict, list[SbomViolation]]:
        out = Path(tempfile.mktemp(suffix=".cdx.json"))
        violations = emit_app_sbom(
            output_path=out,
            runtime_sbom_path=runtime_sbom_path,
            app_data=app_data,
            target=target,
            variant=variant,
            repo_root=_REPO_ROOT,
        )
        return json.loads(out.read_text()), violations

    # ------ superset check (gate 5) ----------------------------------------

    def test_app_sbom_is_superset_of_runtime(self):
        rt_path = self._emit_runtime("linux-x64", "cli")
        rt_doc = json.loads(rt_path.read_text())
        rt_names = {c["name"] for c in rt_doc["components"]}

        app_data = {"app": {"name": "myapp", "version": "1.0.0"}}
        app_doc, _ = self._emit_app(app_data, runtime_sbom_path=rt_path)
        app_names = {c["name"] for c in app_doc["components"]}

        missing = rt_names - app_names
        assert not missing, f"App SBOM missing runtime components: {missing}"

    def test_app_metadata_type_is_application(self):
        app_data = {"app": {"name": "myapp", "version": "0.1.0"}}
        doc, _ = self._emit_app(app_data)
        assert doc["metadata"]["component"]["type"] == "application"

    def test_app_sbom_serial_is_urn_uuid(self):
        app_data = {"app": {"name": "myapp", "version": "0.1.0"}}
        doc, _ = self._emit_app(app_data)
        assert re.match(r"urn:uuid:[0-9a-f\-]{36}$", doc["serialNumber"])

    # ------ two separate emit calls produce different serialNumbers ---------

    def test_serial_number_unique_per_emission(self):
        app_data = {"app": {"name": "myapp", "version": "0.1.0"}}
        doc1, _ = self._emit_app(app_data)
        doc2, _ = self._emit_app(app_data)
        assert doc1["serialNumber"] != doc2["serialNumber"], \
            "Serial numbers must be unique per emission"

    # ------ fallback to runtime.toml when runtime_sbom_path is None --------

    def test_fallback_reads_runtime_toml_when_sbom_absent(self):
        app_data = {"app": {"name": "myapp", "version": "0.1.0"}}
        doc, _ = self._emit_app(app_data, runtime_sbom_path=None)
        names = [c["name"] for c in doc["components"]]
        assert "MicroPython" in names

    # ------ app [dependencies] appear in merged SBOM -----------------------

    def test_app_dep_appears_in_sbom(self):
        app_data = {
            "app": {"name": "myapp", "version": "0.1.0"},
            "dependencies": {"my-python-lib": "1.2.3"},
            "dependency_meta": {
                "my-python-lib": {"licence": "MIT"}
            },
        }
        doc, _ = self._emit_app(app_data)
        names = [c["name"] for c in doc["components"]]
        assert "my-python-lib" in names

    def test_unknown_licence_dep_uses_licenseref_unknown(self):
        app_data = {
            "app": {"name": "myapp", "version": "0.1.0"},
            "dependencies": {"no-meta-dep": "0.1"},
        }
        doc, _ = self._emit_app(app_data)
        dep = next(c for c in doc["components"] if c["name"] == "no-meta-dep")
        lic_val = (
            dep["licenses"][0]["license"].get("name")
            or dep["licenses"][0]["license"].get("id")
        )
        assert lic_val == "LicenseRef-Unknown"

    # ------ policy enforcement: warn path (gate 6) -------------------------

    def test_warn_path_unknown_licence(self):
        """LicenseRef-Unknown dep with warn_unknown=true, fail_unknown=false
        produces a warn-severity violation and no fail violation."""
        app_data = {
            "app": {"name": "myapp", "version": "0.1.0"},
            "dependencies": {"bad-dep": "0.1"},
            "sbom": {"warn_unknown": True, "fail_unknown": False},
        }
        _, violations = self._emit_app(app_data)
        warn_v = [v for v in violations if v.severity == "warn"]
        fail_v = [v for v in violations if v.severity == "fail"]
        assert warn_v, "Expected at least one warn violation"
        assert not fail_v, "Expected no fail violations"

    def test_warn_path_disallowed_licence(self):
        """A known licence not in allow_licences (not LicenseRef-Unknown)
        produces a fail violation regardless of warn_unknown."""
        app_data = {
            "app": {"name": "myapp", "version": "0.1.0"},
            "dependencies": {"gpl-dep": "1.0"},
            "dependency_meta": {
                "gpl-dep": {"licence": "GPL-3.0-only", "link_type": "static"}
            },
            "sbom": {"allow_licences": ["MIT"]},
        }
        _, violations = self._emit_app(app_data)
        fail_v = [v for v in violations if v.severity == "fail"]
        assert fail_v, "Expected fail violation for GPL-3.0-only not in allow_licences"

    # ------ policy enforcement: fail path (gate 7) -------------------------

    def test_fail_path_unknown_licence(self):
        """LicenseRef-Unknown dep with fail_unknown=true produces
        a fail-severity violation."""
        app_data = {
            "app": {"name": "myapp", "version": "0.1.0"},
            "dependencies": {"bad-dep": "0.1"},
            "sbom": {"fail_unknown": True},
        }
        _, violations = self._emit_app(app_data)
        fail_v = [v for v in violations if v.severity == "fail"]
        assert fail_v, "Expected fail violation for LicenseRef-Unknown with fail_unknown=true"

    # ------ build-time-only components are exempt from policy --------------

    def test_build_time_only_exempt_from_policy(self):
        """build-time-only components must not trigger policy violations
        even when their licence is not in allow_licences."""
        app_data = {
            "app": {"name": "myapp", "version": "0.1.0"},
            "sbom": {"allow_licences": ["MIT"]},
        }
        # windows-x64/webview includes WebView2_min.h (build-time-only, MIT).
        # Even with allow_licences=["MIT"] only, the LicenseRef-MS-WebView2-Fixed
        # components exist but the build-time-only component should not produce
        # a fail violation (it is exempt).  The dynamic webview components
        # (MS-WebView2-Fixed) would produce violations unless allow_dynamic
        # includes them — which this test does not, so we only check that
        # the build-time-only component itself is not the source.
        doc, violations = self._emit_app(
            app_data, target="windows-x64", variant="webview"
        )
        bto_names = {
            comp["name"]
            for comp in doc["components"]
            if any(
                p.get("name") == "picolet:link_type" and p.get("value") == "build-time-only"
                for p in comp.get("properties", [])
            )
        }
        fail_v_components = {v.component for v in violations if v.severity == "fail"}
        intersection = bto_names & fail_v_components
        assert not intersection, \
            f"build-time-only components must not trigger fail violations: {intersection}"

    # ------ default allowlist includes LGPL dynamic (webview linux) --------

    def test_default_allowlist_permits_webkitgtk(self):
        """WebKitGTK (LGPL-2.1-or-later, dynamic) must be clean under
        default allowlist."""
        app_data = {"app": {"name": "myapp", "version": "0.1.0"}}
        _, violations = self._emit_app(
            app_data, target="linux-x64", variant="webview"
        )
        fail_v = [v for v in violations if v.severity == "fail"]
        assert not fail_v, \
            f"Default allowlist should permit WebKitGTK (LGPL-2.1-or-later): {fail_v}"

    # ------ SBOM is always written even on violation -----------------------

    def test_sbom_written_on_violation(self):
        """The .cdx.json file must be written even when fail violations occur."""
        out = Path(tempfile.mktemp(suffix=".cdx.json"))
        app_data = {
            "app": {"name": "myapp", "version": "0.1.0"},
            "dependencies": {"bad-dep": "0.1"},
            "sbom": {"fail_unknown": True},
        }
        violations = emit_app_sbom(
            output_path=out,
            runtime_sbom_path=None,
            app_data=app_data,
            target="linux-x64",
            variant="cli",
            repo_root=_REPO_ROOT,
        )
        assert out.is_file(), "SBOM file must be written even on violation"
        assert violations, "Expected at least one violation"

    # ------ name collision: both entries present, warning emitted (C4) ------

    def test_app_dep_collision_with_runtime_produces_both_entries_and_warning(self):
        """When an app [dependencies] name collides with a runtime component:
        - Both entries appear in the emitted SBOM (different bom-refs).
        - A warn-severity SbomViolation is returned.
        """
        # MicroPython is always in the cli runtime SBOM.
        app_data = {
            "app": {"name": "myapp", "version": "0.1.0"},
            "dependencies": {"MicroPython": "1.25.0"},
            "dependency_meta": {
                "MicroPython": {"licence": "MIT", "link_type": "dynamic"},
            },
        }
        out = Path(tempfile.mktemp(suffix=".cdx.json"))
        violations = emit_app_sbom(
            output_path=out,
            runtime_sbom_path=None,
            app_data=app_data,
            target="linux-x64",
            variant="cli",
            repo_root=_REPO_ROOT,
        )
        doc = json.loads(out.read_text())
        components = doc["components"]

        # Both the runtime and app MicroPython entries must be present.
        mp_components = [c for c in components if c["name"] == "MicroPython"]
        assert len(mp_components) == 2, \
            f"Expected 2 MicroPython entries (runtime + app), got {len(mp_components)}: " \
            f"{[c['bom-ref'] for c in mp_components]}"

        # Their bom-refs must be distinct.
        refs = [c["bom-ref"] for c in mp_components]
        assert refs[0] != refs[1], f"bom-refs must differ: {refs}"

        # One bom-ref must identify as the app entry.
        assert any(r.startswith("app-") for r in refs), \
            f"Expected at least one 'app-' prefixed bom-ref: {refs}"

        # A warn-severity violation must be returned.
        warn_v = [v for v in violations if v.severity == "warn" and v.component == "MicroPython"]
        assert warn_v, \
            f"Expected warn SbomViolation for MicroPython collision. Got: {violations}"
        assert "runtime" in warn_v[0].reason.lower() or "collide" in warn_v[0].reason.lower(), \
            f"Violation reason should mention collision context: {warn_v[0].reason}"


# ---------------------------------------------------------------------------
# manifest_dep_components: manifest.py require()'d packages -> CDX components
# ---------------------------------------------------------------------------

class TestManifestDepComponents:
    """manifest_dep_components(): the code path that closes the SBOM/license
    gate for build_cmd._resolve_app_manifest's required_packages."""

    def test_known_spdx_license_uses_id_field(self):
        records = [{
            "name": "something", "version": "0.1.0", "license": "MIT",
            "description": "", "author": "",
        }]
        components = manifest_dep_components(records, offset=0)
        assert len(components) == 1
        lic = components[0]["licenses"][0]["license"]
        assert lic.get("id") == "MIT"
        assert "name" not in lic

    def test_missing_license_uses_licenseref_unknown_name_field(self):
        records = [{
            "name": "something", "version": "0.1.0", "license": None,
            "description": "", "author": "",
        }]
        components = manifest_dep_components(records, offset=0)
        lic = components[0]["licenses"][0]["license"]
        assert lic.get("name") == "LicenseRef-Unknown"
        assert "id" not in lic

    def test_explicit_licenseref_prefixed_value_uses_name_field(self):
        records = [{
            "name": "something", "version": "0.1.0", "license": "LicenseRef-Proprietary",
            "description": "", "author": "",
        }]
        components = manifest_dep_components(records, offset=0)
        lic = components[0]["licenses"][0]["license"]
        assert lic.get("name") == "LicenseRef-Proprietary"

    def test_link_type_is_always_static(self):
        records = [{"name": "something", "version": "0.1.0", "license": "MIT",
                    "description": "", "author": ""}]
        components = manifest_dep_components(records, offset=0)
        link_props = [p for p in components[0]["properties"] if p["name"] == "picolet:link_type"]
        assert link_props == [{"name": "picolet:link_type", "value": "static"}]

    def test_bom_refs_offset_and_unique(self):
        records = [
            {"name": "foo", "version": "1.0", "license": "MIT", "description": "", "author": ""},
            {"name": "bar", "version": "2.0", "license": "MIT", "description": "", "author": ""},
        ]
        components = manifest_dep_components(records, offset=5)
        refs = [c["bom-ref"] for c in components]
        assert refs == ["manifest-foo-5", "manifest-bar-6"]

    def test_empty_records_returns_empty_list(self):
        assert manifest_dep_components([], offset=0) == []


# ---------------------------------------------------------------------------
# emit_app_sbom(manifest_dependencies=...): integration with the full
# collision + policy pipeline
# ---------------------------------------------------------------------------

class TestEmitAppSbomManifestDependencies:
    def _emit_app(
        self,
        app_data: dict,
        manifest_dependencies: "list[dict] | None" = None,
        target: str = "linux-x64",
        variant: str = "cli",
    ) -> tuple[dict, list[SbomViolation]]:
        out = Path(tempfile.mktemp(suffix=".cdx.json"))
        violations = emit_app_sbom(
            output_path=out,
            runtime_sbom_path=None,
            app_data=app_data,
            target=target,
            variant=variant,
            repo_root=_REPO_ROOT,
            manifest_dependencies=manifest_dependencies,
        )
        return json.loads(out.read_text()), violations

    def test_manifest_dependency_appears_in_sbom(self):
        app_data = {"app": {"name": "myapp", "version": "0.1.0"}}
        doc, violations = self._emit_app(
            app_data,
            manifest_dependencies=[{
                "name": "something", "version": "0.1.0", "license": "MIT",
                "description": "", "author": "",
            }],
        )
        names = [c["name"] for c in doc["components"]]
        assert "something" in names
        assert violations == []

    def test_no_manifest_dependencies_is_backward_compatible(self):
        """Omitting manifest_dependencies (existing callers) changes nothing."""
        app_data = {"app": {"name": "myapp", "version": "0.1.0"}}
        doc, violations = self._emit_app(app_data, manifest_dependencies=None)
        names = [c["name"] for c in doc["components"]]
        assert "MicroPython" in names
        assert violations == []

    def test_unknown_license_manifest_dependency_fails_with_fail_unknown(self):
        """A require()'d package with no metadata(license=...) call, combined
        with [sbom] fail_unknown=true, must fail the build; this is the
        actual enforcement path that closes the SBOM/license policy gate for
        manifest.py-resolved packages (must-fix #4)."""
        app_data = {
            "app": {"name": "myapp", "version": "0.1.0"},
            "sbom": {"fail_unknown": True},
        }
        doc, violations = self._emit_app(
            app_data,
            manifest_dependencies=[{
                "name": "something", "version": "0.1.0", "license": None,
                "description": "", "author": "",
            }],
        )
        fail_v = [v for v in violations if v.severity == "fail" and v.component == "something"]
        assert fail_v, f"Expected a fail violation for unlicensed 'something'. Got: {violations}"
        comp = next(c for c in doc["components"] if c["name"] == "something")
        assert comp["licenses"][0]["license"]["name"] == "LicenseRef-Unknown"

    def test_unknown_license_manifest_dependency_warns_by_default(self):
        """Default policy (warn_unknown=True, fail_unknown=False): a warning,
        not a build failure."""
        app_data = {"app": {"name": "myapp", "version": "0.1.0"}}
        _, violations = self._emit_app(
            app_data,
            manifest_dependencies=[{
                "name": "something", "version": "0.1.0", "license": None,
                "description": "", "author": "",
            }],
        )
        warn_v = [v for v in violations if v.severity == "warn" and v.component == "something"]
        fail_v = [v for v in violations if v.severity == "fail"]
        assert warn_v, f"Expected a warn violation. Got: {violations}"
        assert not fail_v

    def test_disallowed_known_license_fails_regardless_of_fail_unknown(self):
        """A manifest dependency with a real but disallowed SPDX id fails,
        same as any other component, not just the LicenseRef-Unknown case."""
        app_data = {
            "app": {"name": "myapp", "version": "0.1.0"},
            "sbom": {"allow_licences": ["MIT"]},
        }
        _, violations = self._emit_app(
            app_data,
            manifest_dependencies=[{
                "name": "something", "version": "0.1.0", "license": "GPL-3.0-only",
                "description": "", "author": "",
            }],
        )
        fail_v = [v for v in violations if v.severity == "fail" and v.component == "something"]
        assert fail_v, f"Expected fail violation for disallowed GPL-3.0-only. Got: {violations}"

    def test_manifest_dependency_name_collision_with_runtime_component(self):
        """A require()'d package that happens to share a name with a runtime
        SBOM component (e.g. MicroPython) produces both entries plus a warn
        violation, the same as an app [dependencies] collision; this is
        new code (declared_app_components merge), not just a re-run of the
        existing [dependencies] collision path."""
        app_data = {"app": {"name": "myapp", "version": "0.1.0"}}
        doc, violations = self._emit_app(
            app_data,
            manifest_dependencies=[{
                "name": "MicroPython", "version": "9.9.9", "license": "MIT",
                "description": "", "author": "",
            }],
        )
        mp_components = [c for c in doc["components"] if c["name"] == "MicroPython"]
        assert len(mp_components) == 2, \
            f"Expected 2 MicroPython entries (runtime + manifest), got {len(mp_components)}"
        refs = [c["bom-ref"] for c in mp_components]
        assert refs[0] != refs[1]
        assert any(r.startswith("app-") for r in refs)

        warn_v = [v for v in violations if v.severity == "warn" and v.component == "MicroPython"]
        assert warn_v, f"Expected warn SbomViolation for MicroPython collision. Got: {violations}"

    def test_manifest_dependency_and_declared_dependency_both_present(self):
        """[dependencies] and manifest.py require() results are independent
        sources merged into the same SBOM, not mutually exclusive."""
        app_data = {
            "app": {"name": "myapp", "version": "0.1.0"},
            "dependencies": {"declared-dep": "1.0"},
            "dependency_meta": {"declared-dep": {"licence": "MIT"}},
        }
        doc, violations = self._emit_app(
            app_data,
            manifest_dependencies=[{
                "name": "manifest-dep", "version": "2.0", "license": "MIT",
                "description": "", "author": "",
            }],
        )
        names = {c["name"] for c in doc["components"]}
        assert "declared-dep" in names
        assert "manifest-dep" in names
        assert violations == []


# ---------------------------------------------------------------------------
# metadata.component hashes (CycloneDX 1.5 verifiability)
# ---------------------------------------------------------------------------

class TestMetadataComponentHashes:
    """metadata.component.hashes must carry a SHA-256 entry when a binary is
    passed; must be absent (or empty) when no artifact is supplied."""

    def _write_fake_binary(self, path: Path, content: bytes = b"fake-binary-content") -> Path:
        path.write_bytes(content)
        return path

    def test_runtime_sbom_has_sha256_when_artifact_provided(self):
        import hashlib
        tmp = Path(tempfile.mkdtemp())
        artifact = self._write_fake_binary(tmp / "picolet-runtime-linux-x64-cli")
        sbom_out = tmp / "out.cdx.json"
        emit_runtime_sbom(sbom_out, "linux-x64", "cli", _REPO_ROOT, artifact_path=artifact)
        doc = json.loads(sbom_out.read_text())
        hashes = doc["metadata"]["component"].get("hashes", [])
        assert len(hashes) == 1, f"Expected 1 hash entry, got: {hashes}"
        assert hashes[0]["alg"] == "SHA-256"
        content = hashes[0]["content"]
        assert len(content) == 64, f"SHA-256 hex digest must be 64 chars, got {len(content)}"
        assert re.fullmatch(r"[0-9a-f]{64}", content), f"Not valid hex: {content}"
        expected = hashlib.sha256(artifact.read_bytes()).hexdigest()
        assert content == expected, "Hash content does not match artifact SHA-256"

    def test_runtime_sbom_no_hashes_when_no_artifact(self):
        tmp = Path(tempfile.mkdtemp())
        sbom_out = tmp / "out.cdx.json"
        emit_runtime_sbom(sbom_out, "linux-x64", "cli", _REPO_ROOT)
        doc = json.loads(sbom_out.read_text())
        assert "hashes" not in doc["metadata"]["component"], \
            "metadata.component must not have hashes when no artifact path is given"

    def test_app_sbom_has_sha256_when_artifact_provided(self):
        import hashlib
        tmp = Path(tempfile.mkdtemp())
        artifact = self._write_fake_binary(tmp / "myapp")
        sbom_out = tmp / "out.cdx.json"
        app_data = {"app": {"name": "myapp", "version": "1.0.0"}}
        emit_app_sbom(
            output_path=sbom_out,
            runtime_sbom_path=None,
            app_data=app_data,
            target="linux-x64",
            variant="cli",
            repo_root=_REPO_ROOT,
            artifact_path=artifact,
        )
        doc = json.loads(sbom_out.read_text())
        hashes = doc["metadata"]["component"].get("hashes", [])
        assert len(hashes) == 1, f"Expected 1 hash entry, got: {hashes}"
        assert hashes[0]["alg"] == "SHA-256"
        content = hashes[0]["content"]
        assert len(content) == 64
        assert content == hashlib.sha256(artifact.read_bytes()).hexdigest()
