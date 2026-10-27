# Windows CI dependency review

## Current Python support adjustment: 2026-10-26

The project minimum is now Python >=3.11 by explicit user approval. The Windows
package job retains Python 3.13.15 and every existing dependency/Qt security gate.
The added Python 3.11/3.12 compatibility matrix runs only syntax, metadata and
inert stdlib tests on Linux; it does not establish Windows native/GUI acceptance
or Linux product support. Current local Windows acceptance prioritizes the
user-approved existing Python 3.12 environment; this batch installs nothing.
Bounded OS CLI output still needs Windows Python >=3.12. Dependencies and the
fourteen-day observation rule are unchanged. The September environment/runtime
records below remain historical, not clearance of the current checkout.


Reviewed 2026-09-05. **CI requires Python 3.13.15, reviewed wheels, passing
tests, and packaged component/startup checks.** See the
[Windows CI runs](https://github.com/NoSelection/Losshound/actions/workflows/windows-ci.yml)
for each commit's result. Local and initial hosted-run evidence is recorded below.
A green advisory scan or a checksum is not proof that a package cannot contain malware.

## Local environment findings

Read-only inspection of the local environment found:

- pip 26.1.2: CVE-2026-13346, fixed in 26.2. The exploit requires a malicious
  package index. CI proposes pip 26.2.1 from official PyPI instead.
- PySide6 and its bundled Qt DLLs were 6.11.0. Qt SVG CVE-2026-6210 and codec
  CVE-2026-9499 are fixed in 6.11.1. CI proposes stable 6.11.2 wheels.
- Qt XML CVE-2026-15037 still applies to the Qt version in those wheels.
  Losshound does not use the affected component and excludes it from the EXE.
  The scoped decision and enforcement are recorded below; this does not
  declare the installed wheels themselves free of that advisory.

The OSV batch query covered 39 installed third-party distributions and returned
two advisory records for the single pip CVE above. Qt issues were found in
vendor advisories, despite empty OSV results for PySide6. All 39 exact package
versions existed on official PyPI, had no yanked distributions in that metadata,
and were older than 14 days. Package names and project links were consistent
with the expected dependencies. The observed Python startup hooks belonged to
the local editable checkout, coverage, and setuptools; their contents did not
show an unexpected download or remote execution hook.

The old environment contained git-filter-repo, which is not needed by the
app or CI, and stale editable Losshound 0.1.0 metadata despite source version
0.1.3. Neither is included as a CI dependency. Its base Python 3.10 interpreter
was missing, so it could not launch. That obsolete environment has since been
removed. During the initial read-only review, only the new stdlib checker was run with
an existing interpreter using -I -S -B, which disables installed-package startup
hooks. Installed files were not compared byte-for-byte with publisher
wheels; this was not a forensic malware scan or a full native-library/OS audit.

## Proposed CI inputs and controls

- requirements-ci.txt pins the inspected package set, excludes unrelated
  git-filter-repo and the stale editable installation, and proposes only the
  pip/Qt patch updates above. pip 26.2.1 was published 2026-08-04; PySide6 6.11.2
  was published 2026-08-18. Qt companion packages use the same exact version.
- Package identities, project source links, publication dates, and yank status
  were checked through official PyPI JSON metadata. Main publishers include
  Qt, PyPA, PyInstaller, pytest, Matplotlib, NumPy, Pillow, ReportLab, and PyCA;
  no similarly named substitute package is introduced.
- Official GitHub Actions are pinned to full commit hashes resolved from their
  release tags: checkout v7.0.1 (2026-07-20), setup-python v7.0.0 (2026-07-20),
  and upload-artifact v7.0.1 (2026-04-10). Their action definitions use Node 24.
  The workflow uses read-only repository permissions and does not retain Git
  credentials, use pull_request_target, or publish releases.
- Before installation, a standard-library-only checker queries OSV and PyPI,
  rejects unpinned/prerelease inputs, unexpected wheel hosts, yanked or very new
  wheels, and known vulnerabilities. API failures stop the job. Explicit Qt
  checks cover the vendor advisories missed by the Python database.
- Only a passing check produces a hash-bound installation file. pip installs
  wheels from official PyPI with --require-hashes --no-deps; undeclared
  dependencies fail pip check rather than being installed automatically.
- CI pins 64-bit Python 3.13.15 on a GitHub Windows 2022 runner, matching the
  verified local interpreter version. Dependencies are not automatically upgraded.

## Scoped Qt XML applicability decision

Qt's advisory concerns applications placing untrusted text into QDom comments,
CDATA or processing instructions and serializing the result with the default
AcceptInvalidChars policy. This can inject markup into the output. Qt rates it
LOW (2.9) and states there is no code execution or denial of service within Qt.
Qt 6.12 changes the default policy; earlier versions can explicitly select
ReturnNullNode and check returned nodes, or use DropInvalidChars.

For the reviewed Qt 6.11.2 CI pins, Losshound instead excludes the unused
component. This avoids adding a dependency on Qt XML just to configure its
policy. Evidence and controls:

- A targeted check of application and test Python sources found no QtXml or
  QDom references. Application Qt imports use QtCore, QtGui and QtWidgets.
- Read-only inspection of the existing dist/Losshound.exe archive directory
  found 433 entries with neither QtXml.pyd nor Qt6Xml.dll. The bundle contains
  QtCore, QtGui, QtNetwork and QtWidgets extension modules.
  Its SHA-256 is
  c79372192a9804fd1cfcd3fcfe78b8885c0efc3f78d9adc13aec1c5c55bedcf4.
  This is evidence about an old artifact, not a rebuild of the current source
  or clearance of that artifact's other dependency versions.
- Losshound.spec explicitly excludes PySide6.QtXml. After Analysis it rejects
  Qt XML names in binaries, data and Python modules. It fails the build rather
  than removing a DLL needed by some other component.
- The dependency gate requires an explicit --losshound-qt-xml-exclusion flag.
  It first checks that the spec declares the exclusion and that application
  and test sources contain no QtXml/QDom references. These are conservative
  regression checks, not proof of arbitrary dynamic-code behavior.
- The exception covers only this vendor XML check at exactly Qt 6.11.2.
  Without the flag the advisory still blocks. Different affected Qt versions,
  the SVG/codec advisories and all OSV/PyPI vulnerability reports still block.
  A newly reported database advisory requires review rather than automatic
  suppression, even if it describes the same XML issue.
- After building, CI independently reads the actual EXE archive directory with
  PyInstaller's reader and rejects Qt XML entries before any EXE launch or
  artifact upload. It does not extract or execute the application to do so.
- All 14 stdlib security tests passed locally, including missing exclusions,
  new XML source references, unreviewed Qt versions, retained database blocks,
  and injected XML DLL/module entries in the actual spec with inert builders.

The live scoped dependency gate also passed for all 38 proposed CI pins on
2026-09-05 and wrote build/requirements-ci.lock. During that Qt-only step, no
packages were installed and neither the application nor PyInstaller was run.

The full PySide6 installation still contains Qt XML. This decision covers this
application and its enforced bundle exclusion, not unrelated programs sharing
an environment. If Losshound needs QDom in future, stop and review a vendor fix
or the explicit invalid-data-policy mitigation before restoring the module.
Refresh vendor advisories when changing pins; the native checks are not an
exhaustive advisory feed.

After the gate passes: run the full tests, build the executable, check packaged
--help and --gui-smoke-test each exit successfully within 60 seconds, and inspect
the uploaded artifact. The Qt smoke test imports the GUI modules, initializes the
platform plugin, and renders a small widget with the app icon. It starts no
monitoring, database, firewall setup, or application workers. It does not replace
a walkthrough of the full GUI/network feature set.

## Native library discovery during packaging

The 2026-09-05 GUI walkthrough exposed a local packaging failure: ambient PATH
entries let PyInstaller collect Poppler's ICU DLL from Codex's document tools.
Its versioned exports did not match the unversioned ICU functions required by Qt.
The previous packaged --help check passed because it did not import QtWidgets.

Losshound.spec now limits Windows PATH during analysis to the selected Python
installation and Windows directories. Package hooks can still locate the reviewed
wheels' own DLLs. A post-analysis check rejects native binaries whose resolved
sources are outside the selected Python environment, its base interpreter, or
Windows System32. These controls apply to local and CI builds; no system-wide
PATH or Windows DLLs are changed. CI additionally runs the packaged Qt smoke test
before uploading an artifact. The stdlib tests exercise both ambient PATH
exclusion and rejection of an unexpected native-library source.

## Fresh local environment: 2026-09-05

Created .venv inside the project using the existing 64-bit Python 3.13.15.
Its executable has a valid Python Software Foundation Authenticode signature.
The system installation remains unchanged. The obsolete venv directory has
been removed; .venv is now the project environment. The source launcher and
README use .venv, and the launcher stops if that environment is missing.
include-system-site-packages is false in the new environment.

Before installing the application dependencies:

- Refreshed OSV/PyPI checks for all 38 pins and the Qt vendor advisory review,
  retaining only the documented Qt XML applicability exception.
- Verified Python's bundled pip 26.2.1 wheel against the official PyPI SHA-256
  before bootstrapping the environment.
- Selected compatible Windows wheels from the reviewed metadata. Downloaded
  only their exact files.pythonhosted.org URLs with required hashes and no
  package-index lookup, automatic dependencies, or source builds.
- Verified all 38 downloaded wheel hashes, package identities, Python version
  requirements, active dependency requirements and archive paths.
- Inspected the two startup hooks: coverage's environment-controlled startup
  hook and setuptools' distutils compatibility hook. Neither contained an
  unexpected download or remote execution step.

Installed only those verified local wheels with --no-index --no-deps
--only-binary=:all: --require-hashes. The resulting environment contains exactly
the 38 reviewed versions, including the already bootstrapped pip.

Validation passed:

- pip check: No broken requirements found.
- 9,369 installed payload files match the verified publisher wheel records.
  Two additional script bodies match, with only the expected interpreter-line
  rewrite. Generated console launchers, installer RECORD files and bytecode
  are not covered by this publisher-payload comparison.
- The installed startup-hook set matches the two inspected wheel hooks.
- Qt6Core.dll, Qt6Svg.dll and Qt6Xml.dll report file version 6.11.2.0.

Local evidence is retained under the ignored build/environment-setup directory:
reviewed-pypi-metadata.json, requirements.lock, downloads.lock,
wheel-manifest.json, reviewed-startup-hooks.json, install-report.json and
installed-verification.json. The downloaded wheels are retained there too.

Use the new environment explicitly, from the project directory:

    .\.venv\Scripts\python.exe -m pip check

The project was not installed as an editable package. Tests use the src path
configured in pyproject.toml. The source launcher sets PYTHONPATH to src;
manual source launches need that path too, as in CI.
Neither the application, its test suite nor PyInstaller was run during this
environment setup. Local Python is 3.13.15; the subsequent CI runtime review
and pin are recorded below.

Matching publisher files and passing advisory checks do not certify a package
as malware-free. The full Qt XML component remains present in the environment;
the previously documented application/bundle exclusion still applies.

## Local tests and packaged validation: 2026-09-05

- Refreshed the dependency gate for all 38 pins; it passed with the existing,
  scoped Qt XML exception. All 14 stdlib gate tests passed.
- All 252 application tests passed using local Python 3.13.15 and offscreen
  Qt. Five dashboard UI tests now opt into a shared interface-worker mock,
  keeping those tests independent of Windows network discovery.
- A local Python audit hook rejected subprocess launches, os.system, and
  selected registry mutation APIs during the suite. The final run recorded
  zero attempts at those operations. This is a targeted guard, not a general
  sandbox or proof that every possible native side effect is intercepted.
- PyInstaller 6.20.0 built a fresh 64-bit Losshound 0.1.3 executable.
  Its 480 archive entries contain the required configuration/image assets
  and no QtXml/Qt6Xml entries. All 13 bundled Qt DLL payloads match the
  corresponding verified environment files.
- Packaged --help exited with code 0 in 5.178 seconds. The EXE is 94,022,347
  bytes; dist/Losshound.exe.sha256 records its SHA-256:
  8e47dc6afaaf2ba65363f252f3b3ef9e72f6fd12aae0b328970fac602b10b135.
- Test reports and bundle/smoke evidence are under build/windows-validation.
  Build caches and the smoke check's temporary/app-data paths were kept
  inside the project.

This validates local tests, packaging and process startup/exit. The full GUI
and live monitoring/tuning were not launched. CI pins Python 3.13.15 on
windows-2022; its logs and artifacts provide the separate runner result.

## Hosted CI and Python runtime review: 2026-09-05

The [initial Windows run](https://github.com/NoSelection/Losshound/actions/runs/33953468731)
at commit d3626a432521e0a535f03ff2d6226455547b71d4 passed all 14 gate tests,
the live dependency gate, all 252 application tests, packaging, the Qt XML
absence check, the packaged help smoke check, and artifact upload.

The logs also revealed that the floating 3.12 setting selected Python 3.12.10.
That was the last 3.12 release with Windows binary installers; later source-only
releases contain security fixes, including tarfile extraction-filter bypasses.
Passing package checks did not establish that this older interpreter was current.
The initial artifact is superseded as the intended development build.

CI now pins Python 3.13.15 x64, matching the verified local environment. Its
official release and the x64 entry in actions/python-versions were checked
before adopting the pin. Use a successful run whose setup log confirms this
version; its test report, dependency lock, EXE and checksum are uploaded together.
Interpreter and bundled native-library reviews remain necessary when updating
this pin; the PyPI/OSV gate is not an exhaustive interpreter or OS advisory scan.

## Runtime security fixes: 2026-09-05

The focused review identified three issues, now addressed in the local source:

- **SEC-01: Windows command lookup.** Every subprocess launch resolves an
  allowlisted tool to an absolute path beneath the system directory returned by
  `GetSystemDirectoryW`. Unknown or missing tools fail without falling back to
  CWD, PATH, WINDIR, or SystemRoot. Wi-Fi diagnostics invoke netsh directly,
  without cmd/chcp. Tests cover hostile search paths, process cleanup, and a
  source guard against bypassing resolution. This assumes the Windows system
  directory itself has its normal protected permissions.
  The Drop Analyzer follow-up adds its previously omitted `nslookup` and
  `wevtutil` commands to the same System32 resolution policy, with regression
  tests for both call paths.
- **SEC-02: LAN discovery downloads.** HTTP titles and SSDP descriptions share
  a direct-IP fetcher with no HTTP proxy lookup. Initial URLs and every redirect
  must use HTTP(S), contain no credentials, and remain on the responding private
  or link-local device IP. Loopback, public IPs, DNS names, and redirects to other
  devices are rejected. Downloads allow at most three redirects and 256 KiB;
  socket timeouts plus a shared deadline/watchdog interrupt slow response headers,
  bodies, and chunk framing. Tests use real HTTP parsing over in-memory streams,
  without contacting real devices. HTTPS may use a self-signed certificate only
  inside this unauthenticated local discovery helper. Devices that require a
  hostname/cloud redirect, proxy, compressed response, or larger description may
  fall back to their other discovered name or vendor label.
- **SEC-03: Webhook logs.** Failure logs contain channel/status/error category,
  never the webhook URL or raw exception/traceback. Synthetic credentials test
  HTTP errors, network errors, unexpected errors, unsuccessful responses, and
  malformed URLs. This prevents future log leakage; existing logs are not
  rewritten. Rotate a webhook credential if an older log containing it was shared.
  Webhook credentials in the local configuration remain a separate storage
  hardening opportunity.

These controls address the three findings, not all possible vulnerabilities.
They use the standard library and do not add or upgrade dependencies. The Qt XML
exception and packaged startup checks above remain required. Local validation
is separate from a hosted CI run; use the linked Windows CI runs to verify the
result for a published commit.

Local validation passed: 297 application tests (37 additional security regression
cases), all 16 dependency/packaging guard tests, and the rebuilt executable's
offscreen Qt startup check (exit 0). All 110 bundled native payloads match their
approved sources, Qt XML remains absent, and the two new security modules are
included. The tested executable is copied to `dist/Losshound.exe` with a matching
SHA-256 file:

`b2dfb018b883a9dede1f944152568287231405d84553149dfc691852e2070006`

The ignored `build/gui-walkthrough` directory retains `security-test-results.xml`,
`security-package-verification.json`, and `security-startup-verification.json`.
This verifies startup and automated regressions, not a new full visual walkthrough.

## Latest local checkpoint: 2026-09-05

Following the Drop Analyzer and UI updates, all 335 application tests and all
16 dependency/packaging guard tests passed. The rebuilt executable passed its
offscreen Qt startup check (exit 0); all 110 native payloads matched their approved
sources and Qt XML remained absent. Actual Qt widget renders and controlled
interaction checks covered grouped navigation, contextual links, and the
Optimizer approval/cancellation flow without applying real network changes.

The tested executable's SHA-256 is
`2ff22edfb1eed12dddc885479742ec522c8f7240745ffe0427427e7876323fc3`.
Local profiles, logs, databases, review renders, and executables remain excluded
from Git. These checks do not constitute a complete security audit.

## Sources

- [Windows GetSystemDirectoryW](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemdirectoryw)
- [Python subprocess executable lookup](https://docs.python.org/3.13/library/subprocess.html)
- [Python HTTP client response handling](https://docs.python.org/3.13/library/http.client.html)
- [Python 3.12.11 security release and binary-support transition](https://www.python.org/downloads/release/python-31211/)
- [Python 3.13.15 release](https://www.python.org/downloads/release/python-31315/)
- [Official Actions Python versions](https://github.com/actions/python-versions/blob/main/versions-manifest.json)
- [pip advisory](https://github.com/advisories/GHSA-qwm4-qh6w-59xr)
- [Qt SVG advisory](https://www.qt.io/blog/security-advisory-type-confusion-and-heap-buffer-overflow-vulnerability-in-qt-svg-marker-handling)
- [Qt XML advisory](https://www.qt.io/blog/security-advisory-cve-2026-15037-xml-injection)
- [Qt vendor vulnerability list](https://wiki.qt.io/List_of_known_vulnerabilities_in_Qt_products)
- [OSV API](https://google.github.io/osv.dev/api/)
- [PyPI JSON API](https://docs.pypi.org/api/json/)
- [Official checkout](https://github.com/actions/checkout)
- [Official setup-python](https://github.com/actions/setup-python)
- [Official upload-artifact](https://github.com/actions/upload-artifact)
