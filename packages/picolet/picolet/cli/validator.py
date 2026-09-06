"""
Validator for app-level picolet.toml files.

Schema source: docs/architecture.md §App-level picolet.toml schema.

Usage:
    from picolet.cli.validator import validate_toml, PicoletTomlError
    errors = validate_toml(Path("picolet.toml"))
    if errors:
        for e in errors:
            if e.level == "warn":
                print(e, file=sys.stderr)
            else:
                print(e)
"""
from __future__ import annotations

import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Top-level sections the schema allows.
# "dependencies" is a passthrough section (v1.1 feature, not yet type-checked;
# see [PH13] Caveat commit — deferred to avoid manifest-parsing complexity).
_ALLOWED_SECTIONS: frozenset[str] = frozenset(
    {"app", "ui", "window", "build", "romfs", "sbom", "runtime", "dependencies",
     "dependency_meta", "version_check"}
)

# Keys allowed in each section, with their expected Python types.
# None means "any scalar" (used for keys we don't type-check beyond being present).
_APP_SCHEMA: dict[str, type | tuple[type, ...]] = {
    "name": str,
    "version": str,
    "entry": str,
    # Windows only; embeds this .ico as the built exe's icon (build_cmd.py
    # checks the file exists / build-time support, not this shape check).
    "icon": str,
    # Windows only; false flips the exe's PE subsystem to GUI so no console
    # window flashes on launch (build_cmd.py enforces the target, not this
    # shape check).
    "console": bool,
    # Windows only; replace the runtime's generic VERSION_INFO resource
    # (build_cmd.py enforces the target; "version" is required already and
    # doubles as FileVersion/ProductVersion, or "git" to derive it from the
    # nearest git tag -- see git_version.py).
    "company_name": str,
    "file_description": str,
    "product_name": str,
}
_APP_REQUIRED: frozenset[str] = frozenset({"name", "version", "entry"})

_UI_SCHEMA: dict[str, type | tuple[type, ...]] = {
    "renderer": str,
    "root": str,
    "index": str,
    # [ui.frontend] is a sub-table; its Python type is dict.
    # Registering it here prevents the _check_section "unknown key" warn.
    "frontend": dict,
}
_UI_RENDERER_VALUES: frozenset[str] = frozenset({"webview", "lvgl", "tui"})

# [ui.frontend] sub-table schema (FR-VUE-5).
_UI_FRONTEND_SCHEMA: dict[str, type | tuple[type, ...]] = {
    "framework": str,
    "build_cmd": str,
    "dist_dir":  str,
    "dev_url":   str,
}
# Valid framework values (spec §FR-VUE-5; "react" accepted forward-compat,
# not yet implemented in the build pipeline — see architecture.md §O4).
_UI_FRONTEND_FRAMEWORK_VALUES: frozenset[str] = frozenset(
    {"vanilla", "vue", "react"}
)

_WINDOW_SCHEMA: dict[str, type | tuple[type, ...]] = {
    "title": str,
    "size": list,
    "resizable": bool,
}

_BUILD_SCHEMA: dict[str, type | tuple[type, ...]] = {
    "targets": list,
    "variant": str,   # explicit runtime-variant override; wins over [ui].renderer
    "mpy_lib_dir": str,   # override for manifest.py require() resolution;
                          # same precedence tier as PICOLET_MPY_LIB_DIR (env wins)
}

_ROMFS_SCHEMA: dict[str, type | tuple[type, ...]] = {
    "include": list,
    "exclude": list,   # fnmatch glob patterns, matched against basenames
}

_SBOM_SCHEMA: dict[str, type | tuple[type, ...]] = {
    "allow_licences": list,   # list of SPDX ids allowed for static and dynamic
    "allow_dynamic":  list,   # additional SPDX ids allowed for dynamic links only
    "warn_unknown":   bool,
    "fail_unknown":   bool,
}

_RUNTIME_SCHEMA: dict[str, type | tuple[type, ...]] = {
    "source": str,
    "tag": str,
}

# [dependency_meta.<name>] allowed string keys.
_DEPENDENCY_META_ENTRY_SCHEMA: dict[str, type | tuple[type, ...]] = {
    "licence":    str,
    "license":    str,   # alias accepted by sbom_gen
    "source_url": str,
    "url":        str,   # alias accepted by sbom_gen
    "link_type":  str,
    "purl":       str,
}

_SECTION_SCHEMAS: dict[str, dict[str, type | tuple[type, ...]]] = {
    "app": _APP_SCHEMA,
    "ui": _UI_SCHEMA,
    "window": _WINDOW_SCHEMA,
    "build": _BUILD_SCHEMA,
    "romfs": _ROMFS_SCHEMA,
    "sbom": _SBOM_SCHEMA,
    "runtime": _RUNTIME_SCHEMA,
}


@dataclass
class PicoletTomlError:
    """A structured validation error or warning from a picolet.toml file.

    level is "error" for hard validation failures; "warn" for soft issues
    that are reported to stderr but do not prevent the build from proceeding.
    """

    file: str
    section: str
    key: str
    reason: str
    level: str = field(default="error")   # "error" | "warn"

    def __str__(self) -> str:
        prefix = "warn" if self.level == "warn" else "error"
        return f"{prefix}: {self.file}: [{self.section}] {self.key}: {self.reason}"


def validate_toml(path: Path) -> list[PicoletTomlError]:
    """Parse and validate a picolet.toml file.

    Returns a list of PicoletTomlError instances. An empty list means valid.
    Raises SystemExit on TOML syntax errors (unrecoverable).
    """
    file_str = str(path)
    errors: list[PicoletTomlError] = []

    # Pass 1: parse.
    try:
        with open(path, "rb") as fh:
            data: dict[str, Any] = tomllib.load(fh)
    except tomllib.TOMLDecodeError as exc:
        # Syntax errors are unrecoverable; report and return immediately.
        errors.append(
            PicoletTomlError(
                file=file_str,
                section="(syntax)",
                key="(parse)",
                reason=str(exc),
            )
        )
        return errors
    except OSError as exc:
        errors.append(
            PicoletTomlError(
                file=file_str,
                section="(io)",
                key="(open)",
                reason=str(exc),
            )
        )
        return errors

    # Pass 2: schema check.

    # Unknown top-level sections.
    for section in data:
        if section not in _ALLOWED_SECTIONS:
            errors.append(
                PicoletTomlError(
                    file=file_str,
                    section=section,
                    key="(section)",
                    reason=f'unknown section "{section}"; allowed sections are: '
                    + ", ".join(sorted(_ALLOWED_SECTIONS)),
                )
            )

    # [app] — required.
    if "app" not in data:
        errors.append(
            PicoletTomlError(
                file=file_str,
                section="app",
                key="(section)",
                reason='required section "[app]" is missing',
            )
        )
    else:
        app = data["app"]
        if not isinstance(app, dict):
            errors.append(
                PicoletTomlError(
                    file=file_str,
                    section="app",
                    key="(section)",
                    reason='"[app]" must be a table',
                )
            )
        else:
            errors.extend(_check_section(file_str, "app", app, _APP_SCHEMA))
            for key in _APP_REQUIRED:
                if key not in app:
                    errors.append(
                        PicoletTomlError(
                            file=file_str,
                            section="app",
                            key=key,
                            reason=f'required key "{key}" is missing',
                        )
                    )

    # [ui] — optional; if present, validate.
    if "ui" in data:
        ui = data["ui"]
        if not isinstance(ui, dict):
            errors.append(
                PicoletTomlError(
                    file=file_str,
                    section="ui",
                    key="(section)",
                    reason='"[ui]" must be a table',
                )
            )
        else:
            errors.extend(_check_section(file_str, "ui", ui, _UI_SCHEMA))
            renderer = ui.get("renderer")
            if renderer is not None and isinstance(renderer, str):
                if renderer not in _UI_RENDERER_VALUES:
                    errors.append(
                        PicoletTomlError(
                            file=file_str,
                            section="ui",
                            key="renderer",
                            reason=(
                                f'unknown value "{renderer}"; '
                                f'expected "webview" or "lvgl"'
                            ),
                        )
                    )
            # [ui.frontend] — optional sub-table (FR-VUE-5).
            if "frontend" in ui:
                fe = ui["frontend"]
                if not isinstance(fe, dict):
                    errors.append(
                        PicoletTomlError(
                            file=file_str,
                            section="ui.frontend",
                            key="(section)",
                            reason='"[ui.frontend]" must be a table',
                        )
                    )
                else:
                    errors.extend(
                        _check_section(file_str, "ui.frontend", fe, _UI_FRONTEND_SCHEMA)
                    )
                    fw = fe.get("framework")
                    if fw is not None and isinstance(fw, str):
                        if fw not in _UI_FRONTEND_FRAMEWORK_VALUES:
                            errors.append(
                                PicoletTomlError(
                                    file=file_str,
                                    section="ui.frontend",
                                    key="framework",
                                    reason=(
                                        f'unknown framework "{fw}"; '
                                        f'expected one of: '
                                        + ", ".join(
                                            f'"{v}"'
                                            for v in sorted(_UI_FRONTEND_FRAMEWORK_VALUES)
                                        )
                                    ),
                                )
                            )

    # [window] — optional; if present, validate.
    if "window" in data:
        window = data["window"]
        if not isinstance(window, dict):
            errors.append(
                PicoletTomlError(
                    file=file_str,
                    section="window",
                    key="(section)",
                    reason='"[window]" must be a table',
                )
            )
        else:
            errors.extend(_check_section(file_str, "window", window, _WINDOW_SCHEMA))

    # [build] — optional.
    if "build" in data:
        build = data["build"]
        if not isinstance(build, dict):
            errors.append(
                PicoletTomlError(
                    file=file_str,
                    section="build",
                    key="(section)",
                    reason='"[build]" must be a table',
                )
            )
        else:
            errors.extend(_check_section(file_str, "build", build, _BUILD_SCHEMA))

    # [romfs] — optional.
    if "romfs" in data:
        romfs = data["romfs"]
        if not isinstance(romfs, dict):
            errors.append(
                PicoletTomlError(
                    file=file_str,
                    section="romfs",
                    key="(section)",
                    reason='"[romfs]" must be a table',
                )
            )
        else:
            errors.extend(_check_section(file_str, "romfs", romfs, _ROMFS_SCHEMA))

    # [sbom] — optional; validate typed keys when present.
    if "sbom" in data:
        sbom = data["sbom"]
        if not isinstance(sbom, dict):
            errors.append(
                PicoletTomlError(
                    file=file_str,
                    section="sbom",
                    key="(section)",
                    reason='"[sbom]" must be a table',
                )
            )
        else:
            errors.extend(_check_section(file_str, "sbom", sbom, _SBOM_SCHEMA))

    # [runtime] — optional; source (str URL) and tag (str).
    if "runtime" in data:
        runtime = data["runtime"]
        if not isinstance(runtime, dict):
            errors.append(
                PicoletTomlError(
                    file=file_str,
                    section="runtime",
                    key="(section)",
                    reason='"[runtime]" must be a table',
                )
            )
        else:
            errors.extend(_check_section(file_str, "runtime", runtime, _RUNTIME_SCHEMA))

    # [dependencies] — optional; flat {name: version_str} table.
    if "dependencies" in data:
        deps = data["dependencies"]
        if not isinstance(deps, dict):
            errors.append(
                PicoletTomlError(
                    file=file_str,
                    section="dependencies",
                    key="(section)",
                    reason='"[dependencies]" must be a table',
                )
            )
        else:
            for dep_name, dep_value in deps.items():
                if not isinstance(dep_value, str):
                    errors.append(
                        PicoletTomlError(
                            file=file_str,
                            section="dependencies",
                            key=dep_name,
                            reason=(
                                f"version must be a string, "
                                f"got {type(dep_value).__name__} ({dep_value!r})"
                            ),
                        )
                    )

    # [dependency_meta] — optional; nested {name: {key: str, ...}} tables.
    if "dependency_meta" in data:
        meta_root = data["dependency_meta"]
        if not isinstance(meta_root, dict):
            errors.append(
                PicoletTomlError(
                    file=file_str,
                    section="dependency_meta",
                    key="(section)",
                    reason='"[dependency_meta]" must be a table',
                )
            )
        else:
            for dep_name, meta in meta_root.items():
                if not isinstance(meta, dict):
                    errors.append(
                        PicoletTomlError(
                            file=file_str,
                            section="dependency_meta",
                            key=dep_name,
                            reason=(
                                f'[dependency_meta.{dep_name}] must be a table, '
                                f'got {type(meta).__name__}'
                            ),
                        )
                    )
                    continue
                errors.extend(
                    _check_section(
                        file_str,
                        f"dependency_meta.{dep_name}",
                        meta,
                        _DEPENDENCY_META_ENTRY_SCHEMA,
                    )
                )

    # [[version_check]] — optional array of tables; each entry regex-extracts
    # a string from `path` (relative to app_root), and the build fails if any
    # two entries extract different strings.
    if "version_check" in data:
        checks = data["version_check"]
        if not isinstance(checks, list):
            errors.append(
                PicoletTomlError(
                    file=file_str,
                    section="version_check",
                    key="(section)",
                    reason='"[[version_check]]" must be an array of tables',
                )
            )
        else:
            for i, entry in enumerate(checks):
                if not isinstance(entry, dict):
                    errors.append(
                        PicoletTomlError(
                            file=file_str,
                            section="version_check",
                            key=f"[{i}]",
                            reason=(
                                f"entry must be a table, "
                                f"got {type(entry).__name__} ({entry!r})"
                            ),
                        )
                    )
                    continue
                for key in ("path", "pattern"):
                    if key not in entry:
                        errors.append(
                            PicoletTomlError(
                                file=file_str,
                                section="version_check",
                                key=f"[{i}].{key}",
                                reason=f'required key "{key}" is missing',
                            )
                        )
                    elif not isinstance(entry[key], str):
                        errors.append(
                            PicoletTomlError(
                                file=file_str,
                                section="version_check",
                                key=f"[{i}].{key}",
                                reason=(
                                    f"expected str, got "
                                    f"{type(entry[key]).__name__} ({entry[key]!r})"
                                ),
                            )
                        )

    return errors


def _check_section(
    file_str: str,
    section: str,
    table: dict[str, Any],
    schema: dict[str, type | tuple[type, ...]],
) -> list[PicoletTomlError]:
    """Type-check known keys and soft-warn on unknown keys in a section table.

    Unknown keys are reported as level="warn" entries for forward-compatibility
    — a future schema version may add them; rejecting hard would break existing
    configs.  Type mismatches on known keys are level="error".
    """
    results: list[PicoletTomlError] = []

    # Check types of schema-known keys present in the table.
    for key, expected_type in schema.items():
        if key not in table:
            continue
        value = table[key]
        if not isinstance(value, expected_type):
            type_name = (
                expected_type.__name__
                if isinstance(expected_type, type)
                else " or ".join(t.__name__ for t in expected_type)
            )
            results.append(
                PicoletTomlError(
                    file=file_str,
                    section=section,
                    key=key,
                    reason=(
                        f"expected {type_name}, "
                        f"got {type(value).__name__} ({value!r})"
                    ),
                    level="error",
                )
            )

    # Warn on user-declared keys that are not in the schema.
    for key in table:
        if key not in schema:
            results.append(
                PicoletTomlError(
                    file=file_str,
                    section=section,
                    key=key,
                    reason=f'unknown key "{key}" in [{section}]; ignored',
                    level="warn",
                )
            )

    return results
