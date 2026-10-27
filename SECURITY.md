# Security and reviewed build requirements

These controls are inherited from NoSelection/Losshound. The installation and first-launch checklist in [AGENTS.md](AGENTS.md) also applies. Passing advisory checks or matching hashes does not certify software as malware-free.

## Current status and interpreters

- Pillow 12.3.0 and setuptools 83.0.0 remain blocked. Pillow 13.0.0 and setuptools 84.1.0 are future candidates, not adopted pins or installed packages. Updates require fresh advisories, compatibility review, separate approval and a passing gate; elapsed observation time alone grants no installation permission.
- Minimum Python is >=3.11. Native Windows bounded diagnostic console/file/pipe output requires >=3.12; prefer the separately approved Windows 3.12 environment for real acceptance. Windows 3.11 fails closed for those output sinks.
- Windows packaging remains Python 3.13.15 x64 on windows-2022. Ubuntu 24.04 Python 3.11.18/3.12.16 jobs cover syntax, metadata and inert stdlib contracts only, not Linux product support or Windows/GUI/EXE acceptance. Interpreter and bundled native-library review remain separate from PyPI/OSV checks.

## Dependency provenance and installation gate

- Keep exact stable pins in requirements-ci.txt, official package identities/publishers and source links, reviewed dependencies/privileges, and official GitHub Actions pinned to full commit hashes. No lookalike replacements or automatic upgrades.
- Run the existing stdlib checker with `-I -S -B` before installation or first application launch. OSV and official PyPI checks must complete. Incomplete responses, API failures, vulnerabilities, unpinned/prerelease inputs, unexpected wheel hosts, yanked/missing wheels or any wheel younger than **14 days** block the affected installation/launch. Native Qt vendor checks supplement database coverage.
- Accept only HTTPS files.pythonhosted.org wheels with reviewed official SHA-256 metadata. No source builds, remote install scripts or automatic dependencies. Only a passing current gate produces the hash-bound lock used for installation; an older lock cannot bypass a failure.
- Use an isolated environment with system-site packages disabled. Verify interpreter provenance, wheel identity/compatibility, hashes, archive paths, active dependencies and startup hooks. CI uses `--only-binary=:all: --require-hashes --no-deps`, then requires `pip check`; verified local-wheel installation also uses `--no-index`.
- Keep workflow repository permissions read-only, `persist-credentials: false`, and no pull_request_target or release publishing. A source-only green job does not clear a failing Windows dependency gate.

## Exact Qt XML applicability exception

The recorded vendor CVE-2026-15037 concerns untrusted QDom comment/CDATA/processing-instruction data serialized with AcceptInvalidChars. The vendor rated it LOW (2.9), without Qt code execution or denial of service. Qt 6.12 changes the default; older applications can select ReturnNullNode with checks or DropInvalidChars. This project instead excludes the unused XML component.

- The **sole exception** covers only the explicit vendor XML check for **exactly Qt 6.11.2** and only with `--losshound-qt-xml-exclusion`. Without the flag, or for a different affected version, XML still blocks.
- The gate validates Losshound.spec's explicit `PySide6.QtXml` exclusion and all application/test Python sources for QtXml/QDom references. These conservative static checks do not prove arbitrary dynamic-code behavior.
- Losshound.spec fails on QtXml/Qt6Xml names in binaries, data or Python modules. It must not silently remove a DLL another component requires.
- Before any EXE launch or artifact upload, CI independently inspects the actual EXE archive with PyInstaller's reader and rejects XML entries without extracting or executing the application.
- SVG CVE-2026-6210, codec CVE-2026-9499 and **all OSV/PyPI vulnerability records remain blocking**. A new database record requires review even if it concerns this same XML issue; no automatic suppression.
- Full PySide6 still contains XML. This exception covers this application's enforced bundle exclusion, not unrelated programs. New QDom use requires stopping and reviewing a vendor fix or explicit invalid-data-policy mitigation. Refresh vendor advisories when pins change; native checks are not exhaustive.

## Native build and packaged verification

- Keep Windows analysis PATH restricted to the selected Python/base interpreter and Windows directories. Reviewed wheel hooks may locate their own DLLs; ambient developer-tool DLLs must not participate.
- Reject resolved native binary sources outside the selected Python environment, base interpreter or Windows System32. Apply locally and in CI without changing system/global PATH or Windows DLLs.
- After a separately authorized passing gate, require the full retained tests, PyInstaller build, XML absence check and packaged `--gui-smoke-test` and `--help`, each successful within **60 seconds**. Inspect EXE/checksum, dependency lock and test report together; upload only after all checks succeed.
- Qt smoke imports GUI modules, initializes the platform plugin and renders a small widget/icon. It starts no monitoring, database, firewall setup or application workers, and does not replace full GUI/network or offline EXE acceptance.
- Keep stdlib gate/spec regressions for missing exclusions, new XML source references, other Qt versions, retained database blocks, injected XML DLL/modules, ambient PATH and untrusted native sources.

## Retained runtime boundaries

- Windows commands resolve an allowlisted executable to an absolute path beneath GetSystemDirectoryW's protected system directory. Unknown/missing commands fail without CWD, PATH, WINDIR or SystemRoot fallback. netsh runs directly without cmd/chcp; nslookup and wevtutil use the same policy. Preserve hostile-search-path and process-cleanup regressions.
- Retained LAN title/SSDP helpers use direct device IPs without proxy lookup. Initial/redirected URLs must be HTTP(S), credential-free and stay on the responding private/link-local device IP. Reject DNS names, loopback/public addresses and cross-device redirects. Keep three redirects maximum, 256 KiB and the shared timeout/deadline/watchdog. Self-signed HTTPS is permitted only in this unauthenticated local discovery helper; hostname/cloud/proxy/compressed/oversized responses can fall back to other discovered labels.
- Retained webhook failures log only channel/status/error category, never URL or raw exception/traceback. Preserve synthetic redaction regressions. Existing logs are not rewritten; rotate credentials if an older shared log exposed them. Local webhook credential storage remains a separate hardening opportunity.
- Ordinary startup/diagnostics stay read-only. Legacy modification paths remain denied, GUI repair stays simulation-only, and real DNS-cache clearing requires separate explicit authorization. Preserve confirmation, finite budgets, Epoch isolation, cancellation and cleanup in README/AGENTS.

## Historical audit basis and sources

The inherited 2026-09-05 environment, package, smoke-test and artifact records are historical. Their counts, locks, payload comparisons and EXE hashes do not clear the current checkout or authorize a new launch/release. The complete prior record remains at reviewed [commit 59cd599c](https://github.com/runyiy/NetworkDoctorTool/commit/59cd599c5a895a397df1547a97eb91280244177a); the [initial upstream CI run](https://github.com/NoSelection/Losshound/actions/runs/33953468731) belongs to its own commit. Raw reports, installed-wheel evidence, logs and artifacts remain outside the public tree.

- [Qt XML advisory](https://www.qt.io/blog/security-advisory-cve-2026-15037-xml-injection), [Qt SVG advisory](https://www.qt.io/blog/security-advisory-type-confusion-and-heap-buffer-overflow-vulnerability-in-qt-svg-marker-handling), [Qt vendor list](https://wiki.qt.io/List_of_known_vulnerabilities_in_Qt_products), [recorded pip advisory](https://github.com/advisories/GHSA-qwm4-qh6w-59xr).
- [OSV API](https://google.github.io/osv.dev/api/), [PyPI JSON API](https://docs.pypi.org/api/json/), [GetSystemDirectoryW](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemdirectoryw), [subprocess lookup](https://docs.python.org/3.13/library/subprocess.html), [HTTP handling](https://docs.python.org/3.13/library/http.client.html).
- [Python 3.13.15](https://www.python.org/downloads/release/python-31315/), [recorded 3.12 security/binary transition](https://www.python.org/downloads/release/python-31211/), [Actions Python versions](https://github.com/actions/python-versions/blob/main/versions-manifest.json), [checkout](https://github.com/actions/checkout), [setup-python](https://github.com/actions/setup-python), [upload-artifact](https://github.com/actions/upload-artifact).
