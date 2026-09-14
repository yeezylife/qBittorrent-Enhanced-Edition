# AGENTS.md

qBittorrent is a fork of **c0re100/qBittorrent-Enhanced-Edition** built on upstream qBittorrent. C++/Qt6 + libtorrent, built with CMake + Ninja.

## Build

Configure generates `src/base/version.h` from `src/base/version.h.in` (gitignored, do not hand-edit the generated file; bump versions in the `.in` file).

Feature options (top of `CMakeLists.txt`): `GUI`, `WEBUI`, `STACKTRACE`, `TESTING` (default OFF), `VERBOSE_CONFIGURE`. Platform-only: `DBUS` (Linux/FreeBSD), `SYSTEMD` (Linux), `MSVC_RUNTIME_DYNAMIC` (MSVC, default ON). Min versions: Qt 6.6.0, Boost 1.76, OpenSSL 3.0.2, libtorrent 1.2.19 / 2.0.10, zlib 1.2.11.

Example configure + build:
```
cmake -B build -G Ninja -DTESTING=ON -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build --target qbt_update_translations   # required before full build; runs lupdate on sources
cmake --build build
cmake --build build --target check                    # runs ctest --output-on-failure
```

Always build `qbt_update_translations` before the main build (the CI does this first); it runs `lupdate` to refresh `src/lang/*.ts`.

## Tests

- 16 standalone test executables in `test/`, each a separate `add_test`; they only run when configured with `-DTESTING=ON`.
- Test files are registered in `test/CMakeLists.txt` (manually added to `testFiles` — new tests must be added there).
- No public headers needed beyond `src/`; each test links `Qt::Test qbt_base`.
- To run a single test, invoke its binary from the `build/` dir (e.g. `build/testpath.exe`).

## Code style & checks

- `.clang-tidy` (tidy config) and `uncrustify.cfg` are present; there is **no** `.clang-format` and no bundled formatter — do not assume clang-format exists.
- `pre-commit` hooks (`.pre-commit-config.yaml`): local scripts check `.ui` grid item order and `<translation>` newlines; plus codespell, typos, JSON/YAML validity, UTF-8-no-BOM, LF endings, trailing whitespace. Match these manually — generated/vendored dirs (`src/base/3rdparty/`, `src/webui/www/private/scripts/lib/`, `src/lang/*.ts`) are excluded.
- Review `CODING_GUIDELINES.md` before PRs; commit messages must be `Closes #NNNN.` style when fixing an issue.

## Enhanced Edition specifics

This fork's unique value is anti-leech automation (Auto-Ban Xunlei/QQ/Baidu/offline downloaders, unknown-China-peer and BitTorrent-media bans) and peer whitelist/blacklist. These are implemented as scattered additions across upstream files, not a separate module — the main touch points are:
- `src/base/preferences.cpp` — feature toggles/defaults
- `src/base/bittorrent/sessionimpl.cpp` and `torrentimpl.cpp` — peer banning logic
- `src/gui/advancedsettings.cpp` — UI for the toggles

When editing, keep these enhancements and their WebUI/option plumbing intact; the upstream remote history (`yeezylife`) is the source of the anti-leech diff.

## Search feature

The search tab requires a working Python install at runtime (per CONTRIBUTING.md) — note this when diagnosing search issues; search code lives in `src/base/search/` and `src/searchengine/`.