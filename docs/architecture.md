# Architecture

This document captures the load-bearing design decisions made for Picolet v1.

## Frame

Picolet generalizes the pattern proven by
[pydfu-win](https://github.com/andrewleech/pydfu-win): a frozen-Python
MicroPython binary with embedded romfs and a minimal variant config
produces a single ~750 KB executable.

Picolet packages that pattern into a framework that ships:

- A pre-built MicroPython runtime per (platform, renderer) tuple.
- A CLI tool that glues a user's frozen `.mpy` + romfs assets onto a
  runtime to produce the final binary.
- Renderer modules (webview / LVGL) that expose a native GUI to the app's
  Python code, mediated by an IPC bridge.

## Decisions

### D1 — Both renderers (webview + LVGL) functional in v1

Webview is the Tauri analogue: HTML/CSS/JS frontend, system webview.
LVGL gives a true zero-system-dependency single binary. Both pull their
weight, and a renderer abstraction in the runtime is cheap once the second
implementation exists.

**Consequence**: CI release matrix is at least 6 runtime binaries
(3 platforms × 2 renderers) plus the headless CLI variant.

### D2 — Pre-built runtimes by default, `--from-source` opt-in

`picolet build` downloads a pre-compiled
`picolet-runtime-{platform}-{renderer}` artifact, then embeds the user's
`.mpy` + romfs into it.

Users who need to add a native C module, change `mpconfigvariant`, or vet
the runtime build use `picolet build --from-source`, which invokes dockcross
locally.

**Consequence**: Picolet's own CI runs the dockcross build matrix and
publishes runtime artifacts per release. End users only need Docker if
they opt into source builds.

### D3 — Sync-RPC IPC

JavaScript calls Python with `await picolet.invoke('cmd', args)` and
receives a return value. Python handlers are registered with
`@picolet.command async def`.

Push-from-Python uses a secondary event channel: `picolet.emit('topic', data)`
on the Python side, `picolet.on('topic', handler)` on the JS side.

**Consequence**: MicroPython's `asyncio` is a hard runtime dependency.
The JS bridge can generate TypeScript types from a registered command
table.

### D4 — No headless renderer; `[ui]` is optional

CLI tools omit the `[ui]` section entirely. This selects the
`picolet-runtime-{platform}-cli` variant: no webview module, no LVGL, no
window module. Smallest binary.

**Consequence**: Three runtime variants per platform (webview, lvgl, cli),
not two.

### D5a — Resource resolution strategy (A6, wheel distribution)

`picolet-cli` ships as an installable wheel. Package data that is needed at
runtime is accessed via `importlib.resources.files("picolet.cli")`, not by
walking up from `__file__` to a repo root.

**RUNTIME_TAG** — the default runtime version tag — is shipped as
`picolet.cli/RUNTIME_TAG` inside the wheel. `_read_runtime_tag_sidecar()` reads
it via `importlib.resources.files` first, with a repo-walk fallback for
bare-source-tree execution (no `pip install -e`).

**mpy-cross** — not bundled in the wheel (option c, audit finding A6). The
binary is platform-specific and its version must match the runtime's bytecode
format exactly. `locate_mpy_cross()` resolves it in this order:

1. `mpy-cross` on PATH — the standard mechanism for wheel installs
   (`pip install mpy-cross`, system package, or manual placement).
2. In-tree build output under `packages/picolet-runtime/micropython/mpy-cross/
   build/mpy-cross` — development convenience after running `build-runtime.sh`.

**build-runtime.sh and in-tree build/** — repo-local operations only. The
`--from-source` flag requires a source checkout and Docker; it is not
meaningful from a wheel install and uses `_repo_root()` (the file-walk helper)
directly. This is intentional and documented.

**Consequence**: `pip install picolet-cli` followed by `picolet build` works
without a source checkout, provided `mpy-cross` is on PATH and a runtime
artifact is available (via cache or network download).

### D5 — Raw binary in v1, packaging on roadmap

`picolet build` produces a single executable in `target/<target>/`. Native
installer formats (`.msi`, `.dmg`, `.AppImage`) deferred to a
`picolet bundle` subcommand on the roadmap, post-v0.4.

## Roadmap

### windows-x64/lvgl: recover < 2 MiB NFR-3 target via custom SDL2 build

The current windows-x64/lvgl build uses the official SDL2 upstream MinGW
binary release (SDL2-devel-2.30.10-mingw.tar.gz, dynamic linkage via
SDL2.dll).  This simplifies the build considerably but the resulting
executable is ~2.05 MiB, exceeding the original NFR-3 target of 2 MiB.
The NFR-3 ceiling for windows-x64/lvgl is temporarily raised to 3 MiB to
accommodate this.

A future pass should:
1. Build SDL2 from source inside the dockcross container with
   `-ffunction-sections -fdata-sections -Os` and link with `--gc-sections`
   to strip unused SDL2 backends (DirectX audio, haptics, sensors, etc.).
2. This was previously implemented at SDL2 2.26.2 (see the removed
   `[2b/8]` block in `build-runtime.sh` git history) but reverted because
   the resulting binary was still marginally over 2 MiB (~2.05 MB).
3. A tighter subsystem exclusion list or further LTO/size tuning should
   close the remaining gap and restore static linkage (eliminating the
   SDL2.dll redistribution requirement).

## Runtime artifact matrix

```
picolet-runtime-{windows-x64,linux-x64} × {webview,lvgl,cli}
= 6 release artifacts
```

macOS is out of scope for v1 (see CLAUDE.md).

## App-level `picolet.toml` schema

```toml
[app]
name = "my-app"
version = "0.1.0"
entry = "src/main.py"
icon = "assets/app.ico"     # windows-x64 only; embeds this .ico as the exe's icon
console = false             # windows-x64 only; no console window flash (no stdio either)

# windows-x64 only; replace the runtime's generic VERSION_INFO (Explorer's
# Properties > Details tab). name/version above always feed FileDescription/
# ProductName/FileVersion/ProductVersion unless overridden here.
company_name = "My Company"
file_description = "My App"    # defaults to [app] name
product_name = "My App"        # defaults to [app] name

# version = "git" derives the version from `git describe` instead of a
# static string -- see git_version.py for the scheme (setuptools-scm-like,
# not byte-identical).

# Omit [ui] for a CLI tool — picks the *-cli runtime variant.
[ui]
renderer = "webview"        # "webview" | "lvgl"
root = "ui"

[window]                    # ignored when [ui] absent
title = "My App"
size = [900, 600]
resizable = true

[build]
targets = ["windows-x64", "linux-x64"]
variant = "mcp"             # explicit runtime-variant override; wins over
                             # [ui].renderer. For a variant with no UI at all
                             # (e.g. a stdio-only MCP server) — forcing it
                             # into the renderer concept would be wrong, so
                             # this is a separate, independent selector.
mpy_lib_dir = "/opt/micropython-lib"
                             # optional; overrides where manifest.py's require()
                             # calls resolve micropython-lib packages from.
                             # A relative path resolves against the app root.
                             # Absent this key (and PICOLET_MPY_LIB_DIR),
                             # picolet build fetches and caches a pinned
                             # micropython-lib commit on first use, lazily,
                             # only if a require() call actually needs it.
                             # See docs/manifest.md.

[romfs]
include = ["ui", "assets"]
exclude = ["tests", "*.pyc", "README.md"]
                             # fnmatch glob patterns, matched against each
                             # path component (any depth) relative to the
                             # entry directory and each include dir; a
                             # directory-name match prunes its whole subtree.
                             # Applies to BOTH the app entry tree and [romfs]
                             # include dirs — e.g. test/example files living
                             # alongside the entry point are excluded the
                             # same way. `.py` files that survive are
                             # cross-compiled to `.mpy`; an appended romfs
                             # never ships raw `.py`, which recompiles on
                             # every process start (see
                             # docs/proposals/app-romfs-mpy-packaging.md).

# Optional: fail the build if these sources disagree on a version string.
# Each pattern must have exactly one capture group; useful when an app's
# version is duplicated across a source constant, package.json, etc.
[[version_check]]
path = "src/_version.py"
pattern = 'VERSION = "([^"]+)"'

[[version_check]]
path = "../package.json"
pattern = '"version": "([^"]+)"'
```

## Source layout for `picolet-runtime`

Inherits the pydfu-win submodule + overlay pattern:

- `micropython/` — git submodule pointed at `andrewleech/micropython`.
- `mbm.toml` — list of feature branches that compose the integration
  branch via [`mbm`](https://gitlab.com/alelec/micropython-branch-manager).
- `overlay/` — downstream-only files re-applied on top of the integration
  branch after each rebase.
- `manifests/` — frozen-module manifests per renderer.
- `scripts/rebuild-integration.sh` — rebases via `mbm` and re-applies the
  overlay.

## IPC wire format

JSON messages over a `postMessage` shim (webview) or an in-process queue
(LVGL — `InProcessTransport` as mandated by FR-LV-4).

Request:
```json
{ "id": 17, "cmd": "greet", "args": { "name": "World" } }
```

Reply:
```json
{ "id": 17, "ok": true, "result": "Hello, World" }
```

Error:
```json
{ "id": 17, "ok": false, "error": { "type": "ValueError", "message": "..." } }
```

Event (push, no reply expected):
```json
{ "event": "progress", "data": { "pct": 42 } }
```

## Test surface (PH17)

### PICOLET_TEST_MODE

Set `PICOLET_TEST_MODE=1` in the environment before launching a picolet
binary to enable the debug/inspect port.  The environment variable is
read at runtime; it is never compiled into release builds (NFR-TEST-2).

### Port announcement contract

When `PICOLET_TEST_MODE=1` the runtime writes exactly one line to stderr
immediately after the debug port is bound:

```
picolet:test-port=<N>
```

where `<N>` is the decimal port number (1024–65535).  The port is bound
to 127.0.0.1 only (NFR-TEST-2 loopback restriction).

- **Linux/WebKit**: `WEBKIT_INSPECTOR_SERVER=127.0.0.1:<N>` is set via
  `setenv()` before `webkit_web_view_new()`.  The port is chosen with a
  bind/getsockname/close probe so the kernel picks an ephemeral port.
- **Windows/WebView2**: `--remote-debugging-port=<N>
  --remote-debugging-address=127.0.0.1` is passed as
  `AdditionalBrowserArguments` to `CreateCoreWebView2EnvironmentWithOptions`
  via a stack-allocated `ICoreWebView2EnvironmentOptions` vtable shim.
- **macOS/WKWebView**: `NSUserDefaults` keys `WebInspectorServerEnabled=YES`
  and `WebInspectorPort=<N>` are set before the WKWebView is created.
  The port is chosen via `picolet_wkwv_pick_test_port` (bind/getsockname/close
  on 127.0.0.1:0).  These defaults activate the WKRP TCP listener that
  Safari Web Inspector uses; the same WKRP WebSocket protocol is spoken by
  AppHarness's webkit path, which already handles macOS transparently.

### AppHarness

`picolet.testing.AppHarness` (in `packages/picolet/`) is the
host-side helper for writing automated tests against a running picolet app.

```python
async with AppHarness(binary, env={"PICOLET_TEST_MODE": "1"}) as h:
    page = await h.page()          # Playwright Page (webview) or facade
    await page.evaluate("...")     # run JS
    png_bytes = await h.snapshot() # LVGL screenshot
```

`AppHarness` reads the `picolet:test-port=<N>` announcement from stderr,
then connects to the debug port using the appropriate protocol:

- Chromium / WebView2: Playwright `connect_over_cdp("http://127.0.0.1:<N>")`
- WebKit: custom `WebKitPage` facade using the WebKit Inspector Protocol
  (WebSocket JSON-RPC at `ws://127.0.0.1:<N>`)
- LVGL: no debug port; `snapshot()` is driven via `picolet._test` stdio
  channel; `page()` is not available

### picolet._test API (LVGL)

Available only when `PICOLET_TEST_MODE=1`.  Import raises `ImportError`
otherwise.

```python
import picolet._test as t
t.tap(x, y)          # inject pointer press+release at (x, y)
t.press(key)         # inject keypad press+release
png = t.snapshot()   # capture PNG bytes of the current screen
```

---

## Perf-check CI (C4 + C5)

`.github/workflows/perf-check.yml` enforces two startup NFRs that are too
noisy to measure reliably in WSL2.  It runs on `ubuntu-latest` (GitHub-hosted
VM) for more consistent timing.

### NFR bounds

| ID | Metric | Median cap |
|----|--------|------------|
| NFR-EX-2 | spawn → window visible + first paint | 1500 ms |
| NFR-TEST-1 | spawn → `picolet:test-port=<N>` announcement | 3000 ms |

### Methodology

`scripts/perf-check.py` (PEP 723; `uv run --no-project scripts/perf-check.py`)
drives both measurements using `AppHarness` for timing and process management:

**NFR-TEST-1** — port-announcement latency:
1. Call `AppHarness.start()` with `_xvfb_display` set; this spawns the binary
   with `PICOLET_TEST_MODE=1`, drains stderr via a daemon thread, and sets
   `spawn_ms` immediately after `Popen()` returns.
2. On the webkit/xvfb path, `start()` returns as soon as `picolet:test-port=<N>`
   is seen (no inspector attach), setting `ready_ms` at that point.
3. Elapsed time is `ready_ms - spawn_ms`.

**NFR-EX-2** — window-visible latency:
1. Same `AppHarness.start()` call as NFR-TEST-1; `spawn_ms` marks the spawn
   instant.
2. After `start()` returns (port seen, child running), call
   `xdotool search --sync --pid <child-pid>` to confirm the app's own window
   is visible in the Xvfb framebuffer.
3. Elapsed time is `time.time()*1000 - spawn_ms` (covers spawn to xdotool
   return, inclusive of the port-announcement delay).

Each NFR is measured in 5 runs per example app; the **median** is compared
against the bound.  The **max** is recorded in the JSON artifact but does not
drive the gate.

### Noise tolerance

If a single run exceeds 2× the NFR bound while the median stays within it, the
script emits a soft warning in the log and the gate passes.  This handles
transient runner noise (shared CPU, page-cache cold misses).  The script does
not auto-disable the gate regardless of noise level; persistent breaches
(3+ consecutive CI runs failing) are the signal to escalate.

### `AppHarness` timing attributes

`AppHarness` exposes two float attributes (milliseconds since epoch) after
`start()` completes:

- `spawn_ms` — set immediately after `Popen()` returns inside `_spawn()`.
  `None` when the harness is constructed with a pre-spawned `_running_proc`
  (we did not spawn the process, so the spawn instant is unknown).
- `ready_ms` — set at the end of `start()` once the debug driver is attached
  (or the port line is seen if no inspector is available).

These are used by `scripts/perf-check.py` and are also available to any test
that wants to assert on startup latency without reinventing the measurement.

### Trigger conditions

The workflow runs:
- On `workflow_dispatch` (manual).
- On a weekly schedule (Sunday 03:00 UTC).
- On `push` to `dev` touching `packages/picolet-runtime/**` or `examples/**`.

Results are uploaded as a `perf-results` workflow artifact (JSON, retained 90
days) for trend analysis across runs.

---

## Frontend toolchains (PH18, FR-VUE-1..5)

Picolet supports multi-framework frontends through the `[ui.frontend]` table
in `picolet.toml`. The default (absent `[ui.frontend]` or `framework =
"vanilla"`) uses the v1 static-file model unchanged. Vue 3 + Vite + TypeScript
is the v1.1 framework of record.

### `[ui.frontend]` table schema

```toml
[ui.frontend]
framework = "vue"          # "vanilla" | "vue" | "react" (see O4)
build_cmd = "npm run build"  # optional override; default is npm run build
dist_dir  = "dist"           # optional; Vite default output directory
dev_url   = "http://localhost:5173/"  # optional; default for picolet dev
```

**`framework`** controls whether the frontend build hook fires during
`picolet build`. When `"vanilla"`, `picolet build` uses the static `[romfs]
include` path unchanged. For any other value, the npm-based pipeline runs.

**`react`** is accepted by the validator for forward compatibility (O4 —
React is out of scope for v1.1 but the pipeline is framework-agnostic once
npm is involved; a user who provides a correct `build_cmd` and `dist_dir`
for a React project will get the same pipeline treatment as Vue).

### Host requirements

Node ≥ 18 LTS (currently Node 20 or 22 LTS) must be on PATH for any project
with a non-vanilla `[ui.frontend]`. Node is a **host build-time dependency
only** — it is not shipped in the app binary. Vue/TS toolchain output is
compiled and packed into the romfs at build time; the runtime is pure C + MicroPython.

`picolet build` checks `shutil.which("npm")` before any npm invocation and
emits a clear error with a pointer to this section when npm is absent.

### Build pipeline integration

When `framework != "vanilla"`, `picolet build` inserts two steps:

1. **Step 4b**: `npm install --prefer-offline --no-fund --no-audit` in `app_root`.
   This is idempotent: fast on a warm `node_modules/` tree, respects
   `package-lock.json` when present (D2).

2. **Step 6a**: `_copy_dist_to_ui_root` copies `<dist_dir>/` (default: `dist/`)
   into the romfs staging area at `<ui_root>/` (default: `ui/`). Vue apps
   must **not** add `"ui"` to `[romfs] include` — the build pipeline copies
   `dist/` there automatically (R2 footgun: double-copy if both are present).

The `[ui.frontend]` table is **not emitted** into the romfs `picolet.toml`
(F8). The frozen runtime does not parse it; only `[ui].root` and `[ui].index`
are emitted, pointing the runtime at the packed assets.

### `base: './'` requirement (F10, R4)

Vite projects targeting picolet must set `base: './'` in `vite.config.ts`.
The picolet:// custom URI scheme (WebKitGTK) and WebView2 resolve sub-assets
differently from a standard HTTP origin. Absolute-path assets (`/assets/main.js`)
work on Linux but break on Windows via WebView2 (scheme resolution differs).
Relative paths (`./assets/main.js`) work on both.

Asset filename hashing (e.g. `assets/main-Cn3VHXS6.js`) is intentional
and correct — the full `dist/` is packed including hashed filenames.

### `PICOLET_DEV_URL` environment variable (D1, FR-VUE-2)

`picolet dev` uses environment variables (not romfs patching) to redirect the
runtime's initial URL to the Vite dev server. When `[ui.frontend].framework
!= "vanilla"`, `picolet dev`:

1. Spawns `npm run dev` in a new process group (`start_new_session=True`)
   before the first binary build.
2. Sets `PICOLET_DEV_URL=<dev_url>` (default: `http://localhost:5173/`) in the
   launched binary's environment.

The runtime (`picolet_ui._app.Application.__init__`) reads `PICOLET_DEV_URL` at
startup. If set, it skips the romfs `picolet://` load and calls
`webkit_web_view_load_uri(view, dev_url)` directly (Linux). On Windows it
calls `picolet_wv2_navigate(controller, url)` which invokes
`ICoreWebView2->Navigate` directly (R3 resolved — meta-refresh redirect
removed).

`PICOLET_DEV_URL` is **never set in production builds**. The released binary
launched directly or via `picolet run` has no such environment variable and
loads from romfs normally.

### Process group teardown (D3)

Vite spawns child processes (ESBuild, Rollup workers). A SIGTERM to the
`npm run dev` process does not propagate to grandchildren on Linux. `picolet dev`
creates the Vite process in a new session via `start_new_session=True` and
tears it down with `os.killpg(pgid, SIGTERM)`, ensuring the full process group
is terminated on exit (CTRL-C, rebuild, or `picolet dev` normal exit).

On Windows (`sys.platform == "win32"`), `vite_proc.terminate()` is used as
a best-effort fallback. Full process-group teardown on Windows requires
`CREATE_NEW_PROCESS_GROUP + GenerateConsoleCtrlEvent` and is deferred (R3).

### `picolet.d.ts` type declaration (FR-VUE-3)

`picolet-bridge-js` builds as an IIFE and exports nothing, so `tsc --declaration`
produces nothing useful. The type declaration for `window.picolet` is
**hand-authored** at `packages/picolet-bridge-js/src/picolet.d.ts`. It augments
the global `Window` interface via ambient module augmentation.

In a monorepo / workspace setup, Vue projects reference it via:

```typescript
// ui/src/env.d.ts
/// <reference path="../../../../packages/picolet-bridge-js/src/picolet.d.ts" />
```

In a standalone project scaffolded from `hello-vue`, a local copy of
`picolet.d.ts` is bundled in `ui/src/picolet.d.ts` and referenced the same way.

### npm lockfile convention (O3)

- `examples/with-vue/` commits `package-lock.json` for reproducible,
  offline-capable builds (`npm install --prefer-offline` respects it).
- `packages/picolet/picolet/templates/hello-vue/` does NOT commit a
  lockfile. Users get the latest compatible versions at `picolet init` time.
  PH23's mirror script must not copy `package-lock.json` from examples into
  templates.

**Escape hatch for air-gapped CI**: if `npm install --prefer-offline` fails
on a cold cache, override by setting `PICOLET_NPM_ARGS` (future knob, not yet
implemented in PH18).

### R2 footgun: double-copy of ui/

If a Vue app's `picolet.toml` includes `"ui"` in `[romfs] include` AND has an
active frontend build hook, the vanilla static files would be copied alongside
(or overwriting) the Vite `dist/` output. The `with-vue` template omits
`[romfs] include` entirely to avoid this. The validator does not yet detect
this combination (deferred; documented here as a footgun).

---

## macOS WKWebView backend (PH25)

### ObjC runtime via libffi — no `.m` files

All Objective-C calls on macOS go through the public `objc_msgSend` ABI
exported by `libobjc.A.dylib`.  The C glue in `picolet_webview_mac.c` casts
`objc_msgSend` to the concrete prototype required at each call site (the
approach used by PyObjC, GNUstep, and Apple's own ObjC bridge tests).
There is no static ObjC++ linkage and no `.m` source file.

**Why**: `.m` files require clang's ObjC front-end and generate code that
transitively links ObjC runtime init stubs.  The pure-C approach compiles
with any C99 compiler that has the macOS SDK headers available, stays in
the same `picolet_webview2.c` lineage as the Windows overlay, and keeps the
link-time symbol footprint explicit.

### Per-platform FFI module split

Each platform has its own `_*_ffi.py` binding module:

| Platform | Module | Entry point |
|---|---|---|
| Linux | `_gtk_ffi.py` | `ffi.open("libwebkit2gtk-4.1.so.0")` |
| Windows | `_win_ffi.py` | `ffi.open(None)` → main `.exe` |
| macOS | `_mac_ffi.py` | `ffi.open(None)` → main Mach-O binary |

The split keeps each module minimal: only the symbols relevant to one
platform are bound, so a wrong-platform import fails fast at `ffi.open`.
The `_webview.py` module selects the right class via `sys.platform` at
import time; the frozen manifest includes all three modules but only the
correct one's symbols are present in the binary.

### CGRect / struct-return ABI

On x86_64 macOS, structs larger than 16 bytes are returned via a hidden
first pointer argument (`objc_msgSend_stret`).  `CGRect` is 32 bytes on
x86_64.  On arm64 all structs up to 128 bytes are returned in registers
and `objc_msgSend` is used directly.

`picolet_webview_mac.c` wraps all `CGRect`-returning calls inside a
C-level helper (`picolet_make_rect`) that builds the rect on the stack.
Python never calls `objc_msgSend_stret` directly.

### Cocoa run loop integration

`[NSApplication run]` blocks; it cannot be called from inside the asyncio
event loop.  Instead, `picolet_wkwv_pump_messages(seconds)` calls
`CFRunLoopRunInMode(kCFRunLoopDefaultMode, seconds, false)` — the macOS
equivalent of `gtk_main_iteration_do`.  It is driven by `_loop._mac_pump`
on the same asyncio thread, mirroring the Linux GTK pump pattern exactly.
