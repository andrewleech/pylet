# manifest.py

`manifest.py`, placed next to `picolet.toml` at the app root, declares extra Python sources for `picolet build` to freeze into the romfs: packages pulled from `micropython-lib` via `require()`, local packages registered via `add_library()`, and individual files via `module()`/`package()`. It is auto-detected: if `manifest.py` exists at the app root, `picolet build` processes it. No `picolet.toml` key or CLI flag is needed to opt in.

The manifest is executed by the same manifest-processing module MicroPython itself uses for board manifests (vendored at `packages/picolet/picolet/_vendor/manifestfile.py`; see the README there for provenance), running in `MODE_COMPILE`. That mode supports `metadata()`, `include()`, `require()`, `add_library()`, `package()`, and `module()`. `freeze()` and its variants (`freeze_as_str`, `freeze_as_mpy`, `freeze_mpy`) are not available in this mode; they belong to MicroPython's own firmware-build freezing pipeline, which Picolet does not use. Picolet apps declare frozen sources with `module()`/`package()`/`require()` instead.

## When do you need one

For a single-file app with no third-party dependencies, you don't need one: `[app] entry = "src/main.py"` plus `[romfs] include` already covers first-party sources and static assets.

A manifest.py is for the case where a module needs to come from `micropython-lib` (a stdlib polyfill, an ecosystem package) or from another local package that isn't already under the entry tree or a `[romfs] include` directory.

## Getting started

```python
# manifest.py, next to picolet.toml
metadata(version="0.1.0")

require("argparse")              # micropython-lib stdlib polyfill
module("extra.py")               # a first-party module outside the entry tree
```

`metadata()` must be the first call in the manifest; `require()`/`module()`/`package()` all check that it already ran, and raise `manifestfile.ManifestFileError` if it hasn't.

```bash
picolet build
```

No flag or `picolet.toml` key is needed; `app_root/manifest.py` is picked up automatically.

## Function reference

### `metadata(version=None, description=None, license=None, author=None)`

Must be called first. Establishes the top-level manifest's metadata record.

```python
metadata(version="0.2.1", description="My DFU flasher", license="MIT", author="Andrew Leech")
```

### `require(name, library=None)`

Pull a package by name.

```python
require("argparse")
require("dataclasses")
require("widget", library="vendor")   # from a library registered with add_library()
```

Without `library=`, `require()` searches `micropython/`, `python-stdlib/`, and `python-ecosys/` under a micropython-lib checkout for a directory named `name` containing its own `manifest.py`. That checkout is resolved by `picolet build` as described in [MPY_LIB_DIR resolution](#mpy_lib_dir-resolution) below, which is the only thing in a manifest.py that can trigger a network fetch.

With `library="name"`, resolution is scoped to a directory previously registered with `add_library()`. MPY_LIB_DIR is only involved if that directory's own path was itself derived from `$(MPY_LIB_DIR)` (see below); a purely local `add_library()` path never touches it.

### `add_library(library, library_path, prepend=False)`

Register a local directory that `require(..., library=library)` can search. `library_path` is resolved relative to the manifest.py that calls it.

```python
add_library("vendor", "./vendor")
require("colorlog", library="vendor")
```

The registered package still needs its own `manifest.py` at `<library_path>/<name>/manifest.py`.

### `module(module_path, base_path=".", opt=None)`

Freeze a single `.py` file as a top-level romfs entry.

```python
module("extra.py")                      # ./extra.py, relative to this manifest.py
module("helpers.py", base_path="lib")   # ./lib/helpers.py
```

### `package(package_path, files=None, base_path=".", opt=None)`

Freeze a directory of `.py` files, preserving its internal structure.

```python
package("mypkg")                        # everything under ./mypkg/
package("mypkg", files=["a.py"])        # just ./mypkg/a.py
```

### `include(manifest_path)`

Compose manifests: execute another manifest.py file (or directory containing one) as part of this one.

```python
include("../common/base-manifest.py")
```

## MPY_LIB_DIR resolution

A bare `require("name")` (no `library=`) needs a local `micropython-lib` checkout to search; so does `require(name, library="x")` when `"x"` was itself registered via `add_library("x", "$(MPY_LIB_DIR)/...")`. `picolet build` resolves one automatically, lazily, only the first time a `require()` call in the manifest actually needs it:

1. `PICOLET_MPY_LIB_DIR` environment variable, if set, used as-is: checked for existence and for looking like a real micropython-lib checkout (at least one of `micropython/`, `python-stdlib/`, `python-ecosys/` present as a subdirectory), but not otherwise validated.
2. `[build].mpy_lib_dir` in `picolet.toml`, if set, at the same trust level as (1). A relative path resolves against the app root (the directory containing `picolet.toml`), not the current working directory.
3. Otherwise, `picolet build` fetches and caches a pinned `micropython-lib` commit into `<cache_root>/micropython-lib/<sha>/`, using the same cache root `picolet build` already uses for runtime artifacts (`PICOLET_CACHE_DIR`, or `$XDG_CACHE_HOME/picolet`/`~/.cache/picolet` on Linux, `%LOCALAPPDATA%\picolet\cache` on Windows). The fetched content is verified against a pinned digest before it is trusted; a mismatch fails the build rather than freezing unverified code into it. The fetch happens once; subsequent builds reuse the cached checkout with no network access.

A manifest using only `module()`/`package()` and `add_library()`-registered local paths never triggers this at all, no matter how the manifest is structured (including through `include()`); the trigger is tied to the actual `require()` call, not to any static analysis of the manifest source.

```toml
# picolet.toml: pin a specific local checkout instead of the default fetch
[build]
mpy_lib_dir = "/opt/micropython-lib"
```

## Collisions with app sources and `[romfs]` includes

Every `.py` file a manifest.py resolves is compiled to `.mpy` and placed in the romfs at the path `manifestfile.py` assigns it (e.g. `module("foo.py")` lands at `/foo.mpy`; `package("mypkg")` preserves `mypkg/`'s internal layout). If that destination path collides with a file compiled from the app's entry tree or from a `[romfs] include` directory, `picolet build` fails with an error naming both source paths; it does not pick one silently. A resolved destination is also rejected if it would land outside the romfs root entirely (e.g. a `module("../evil.py")`-style path) rather than silently writing there.

## License review (SBOM)

Every package pulled in via `require()` is represented in the build's CycloneDX SBOM (`<binary>.cdx.json`), using the `version`/`license`/`description`/`author` from that package's own `metadata()` call, and goes through the same `[sbom]` policy gate (`allow_licences`, `warn_unknown`, `fail_unknown`) as everything else `picolet build` links in. A package whose manifest never calls `metadata(license=...)` is treated as `LicenseRef-Unknown`, same as any other unlicensed dependency; see `docs/sbom.md`. `require(..., library=...)` against a local `add_library()` path is included the same way; there is no way for a `require()`'d package to be frozen into the binary without going through this gate.

## C modules

`c_module()` is not supported in an app's `manifest.py`: `picolet build` processes manifest.py in `MODE_COMPILE`, which only handles Python sources, and calling `c_module()` there raises a build error rather than silently dropping the C module from the build.

## Community packages

Packages that aren't in `micropython-lib`, whether vendored from elsewhere or pulled down ahead of time with `mpremote mip install` into a local directory, are used the same way as any other local package: register the directory with `add_library()` and `require()` it, or freeze it directly with `package()`/`module()` if it's simple enough not to need its own manifest.py.

```python
add_library("vendor", "./vendor")       # populated by: mpremote mip install --target ./vendor widget-toolkit
require("widget-toolkit", library="vendor")
```

The [License review (SBOM)](#license-review-sbom) section above applies here too: if the vendored package's own `manifest.py` doesn't set `license=` in its `metadata()` call, it shows up as `LicenseRef-Unknown` in the SBOM. Add a `license=` kwarg to that `metadata()` call (it's your vendored copy, so you can edit it) rather than trying to declare it separately; `[dependency_meta]` in `picolet.toml` is for the unrelated `[dependencies]` flat-table mechanism (see `docs/sbom.md`), not for `manifest.py`-resolved packages.

## Limits and gotchas

- Everything a manifest.py resolves is fixed at build time. There is no runtime `mip.install` story for a Picolet binary; restart after a code change (`picolet dev` automates this for the entry tree, not for manifest.py-resolved packages, which only change when you edit the manifest or re-run build).
- Not all CPython libraries port cleanly to MicroPython. Check `docs/caveats.md` before committing to a `require()`.

## See also

- [docs/architecture.md](architecture.md): `[build]` schema, including `mpy_lib_dir`.
- [docs/caveats.md](caveats.md): MicroPython vs CPython compatibility.
- [packages/picolet/picolet/_vendor/README.md](../packages/picolet/picolet/_vendor/README.md): provenance of the vendored manifest processor.
