# Vendored `manifestfile.py`

`manifestfile.py` in this directory is a verbatim copy of MicroPython's
manifest-processing module. `picolet build` imports it directly
(`picolet._vendor.manifestfile`) to drive `manifest.py` resolution
(`require()`, `add_library()`, `module()`, `package()`, `include()`) in
`MODE_COMPILE`, the same processing upstream `mpy-cross`/`mpremote` builds
use for board manifests. Picolet does not invoke mpy-cross internally from
this module; `picolet.cli.build_cmd` drives that separately, exactly as it
already does for the entry tree and `[romfs]` includes.

## Provenance

- Upstream source: `tools/manifestfile.py` in the `micropython/micropython`
  project (MIT licensed; see the header in the file itself).
- Vendored from this repo's `packages/picolet-runtime/micropython` submodule
  (tracking `andrewleech/micropython`'s `integration` branch per
  `packages/picolet-runtime/mbm.toml`), content-identical to the revision
  introduced at commit `f6c7803d49a6dddb11bc91f7f6c47c4a3e6219fd`, the
  commit that added `c_module()` support (upstream PR
  [micropython#18229](https://github.com/micropython/micropython/pull/18229),
  composed into the integration branch via `mbm`). This is a superset of
  the pristine `micropython/micropython` upstream version.
- Blob hash (the actual content-identity check; `git hash-object
  tools/manifestfile.py` in the submodule): `2e2ade6783cfaabbc2189098123da4ad57b7430f`.
  The submodule's `integration` branch is rebuilt periodically by `mbm`
  (see `scripts/rebuild-integration.sh`), which changes commit history
  without necessarily changing this file's content; `git log -1 --format=%H
  -- tools/manifestfile.py` can therefore point at a different commit than
  `f6c7803d...` after a rebuild even when nothing about this file actually
  changed. The commit SHA above records *when the feature landed*; the blob
  hash is what actually needs to match to confirm "this is still the same
  file".
- Copied byte-for-byte, no modifications. It imports only the Python
  standard library (`os`, `re`, `sys`, `glob`, `tempfile`, `contextlib`,
  `collections.namedtuple`) and has no dependency on the rest of the
  MicroPython source tree, so it runs standalone inside `picolet-cli`.

## Re-vendoring

Needed only if a newer feature (e.g. a future manifest function) is added
upstream and Picolet wants to pick it up. To refresh:

```bash
git -C packages/picolet-runtime/micropython hash-object tools/manifestfile.py
cp packages/picolet-runtime/micropython/tools/manifestfile.py \
   packages/picolet/picolet/_vendor/manifestfile.py
```

If the blob hash differs from the one recorded above, update both the blob
hash and the commit SHA (use `git log --format=%H -- tools/manifestfile.py`
and pick the commit that actually introduces the new content, not
necessarily the first one listed (see the caveat above), and diff the old
and new copies to confirm nothing in `picolet.cli.build_cmd`'s usage
(`ManifestFile`, `MODE_COMPILE`, `ManifestFileError`, `.execute()`,
`.files()`, `ManifestOutput.full_path`/`.target_path`,
`ManifestPackageMetadata.version`/`.license`/`.description`/`.author`,
`BASE_LIBRARY_NAMES`) changed shape.
