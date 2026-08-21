# NetworkDoctor MVP Design

## Purpose

NetworkDoctor is a small, self-contained Windows desktop application for personal network diagnosis. It runs locally, remains usable without Internet access, and explains the most likely cause of a disconnected or unstable network in plain Simplified Chinese.

The MVP is diagnostic only. It does not request administrator privileges and does not change DNS, IP addresses, adapters, routes, or other system settings.

## Supported environment

- Windows 10 and Windows 11
- Simplified Chinese user interface
- Distributed as a single `NetworkDoctor.exe`
- No Python installation required on the target computer
- No online service, database, installer, or updater
- No third-party runtime dependency in application code

## Technical approach

The application uses Python and Tkinter. Windows networking data comes from built-in facilities:

- PowerShell commands returning JSON for adapters, IPv4 addresses, DHCP state, gateways, and DNS servers
- `netsh` for Wi-Fi state and signal strength
- `ping.exe` for latency samples and packet-loss observations
- Python `socket` calls for DNS resolution and short TCP connectivity fallbacks

PowerShell JSON is preferred over localized text parsing. Ping parsing extracts language-independent numeric patterns and is tested against representative English and Chinese output.

## Project structure

- `network_doctor/app.py`: Tkinter window, controls, progress updates, and report presentation
- `network_doctor/windows_probes.py`: Windows commands, timeouts, parsing, DNS queries, and TCP connectivity checks
- `network_doctor/diagnostics.py`: ordered execution of probes and construction of a diagnostic snapshot
- `network_doctor/analysis.py`: deterministic rules that turn a snapshot into findings, a primary conclusion, and recommendations
- `network_doctor/models.py`: small data classes and enums shared by the other modules
- `tests/`: parsing, calculation, rule, and orchestration tests
- `build.ps1`: reproducible PyInstaller command
- `README.md`: development, test, use, and build instructions

Each module has one responsibility. Probe results are structured data; UI text is not used as input to diagnostic rules.

## User experience

The application has one window containing:

- The title `NetworkDoctor`
- A `开始诊断` button that becomes `重新诊断` after completion
- Current-step text and progress feedback
- A scrollable Chinese report area
- A `复制结果` button

Diagnosis runs on a worker thread so the Tkinter event loop remains responsive. UI changes are sent back through the Tkinter event loop. Closing the window prevents late worker updates.

The report contains:

1. Overall status
2. Most likely problem
3. Key observations
4. Recommended actions

Individual checks use the states `正常`, `提示`, `异常`, and `无法检测`. Secondary findings remain visible even when a more important primary fault exists.

## Diagnostic flow

Checks run from the computer outward:

1. Find enabled and connected physical network adapters.
2. Identify active Wi-Fi or Ethernet connectivity.
3. Read usable local IPv4 addresses and DHCP state.
4. Detect APIPA addresses in `169.254.0.0/16`.
5. Read the default gateway and DNS servers.
6. Ping the default gateway.
7. Test Internet reachability against both `1.1.1.1` and `8.8.8.8`.
8. If ICMP results are inconclusive, perform short TCP connectivity checks to reduce false Internet-failure diagnoses caused by blocked ping traffic.
9. Resolve two ordinary domain names to evaluate DNS separately from IP connectivity.
10. Read Wi-Fi signal strength when an active Wi-Fi interface exists.
11. Calculate packet loss, average round-trip latency, and jitter from ping samples.
12. Apply ordered rules and render the Chinese report.

A single unresponsive public target does not establish Internet failure. The analysis uses results from both public targets and the TCP fallback.

## Quality calculations and thresholds

Average latency is the arithmetic mean of successful round-trip samples. Jitter is the arithmetic mean of the absolute differences between adjacent successful round-trip samples. With fewer than two successful samples, jitter is unavailable rather than zero.

### Public-network average latency

- `< 50 ms`: `优秀`
- `50–69 ms`: `良好`
- `70–149 ms`: `略高`
- `150–299 ms`: `较高`
- `>= 300 ms`: `非常高`

### Jitter

- `< 15 ms`: `稳定`
- `15–29 ms`: `轻微波动`
- `30–59 ms`: `存在波动`
- `60–99 ms`: `波动明显`
- `>= 100 ms`: `非常不稳定`

### Packet loss

- `0%`: `正常`
- `1–4%`: `偶发丢包`
- `5–24%`: `连接不稳定`
- `>= 25%`: `严重丢包`

### Wi-Fi signal

- `< 50%`: `较弱`
- `50–69%`: `一般`
- `>= 70%`: `良好`

An Internet connection is rated `良好` only when packet loss is zero, average latency is below 70 ms, and jitter is below 30 ms. It is rated `优秀` only when packet loss is zero, average latency is below 50 ms, and jitter is below 15 ms.

The default gateway uses a separate local-network expectation. Average gateway latency of 20 ms or more produces a local-link warning because it can indicate Wi-Fi interference, a weak local connection, or a cable/router issue.

## Ordered diagnosis rules

Rules are evaluated in this priority order for the primary conclusion:

1. No enabled, connected physical adapter: the computer is not connected to Wi-Fi/Ethernet or the adapter is disabled.
2. Connected adapter without usable IPv4: the computer has not obtained a network address.
3. APIPA IPv4 address: DHCP address acquisition failed.
4. Missing default gateway: DHCP or local network configuration is incomplete.
5. Unreachable default gateway: the fault is likely between the computer and router; Wi-Fi signal and local latency refine the advice.
6. Reachable gateway but no reachability through either public target or TCP fallback: router WAN, modem/ONT, or ISP connectivity is likely faulty.
7. Reachable Internet IP path but failure to resolve both test domains: DNS is likely faulty.
8. Basic connectivity succeeds but thresholds are exceeded: report packet loss, latency, jitter, weak Wi-Fi, or high gateway latency as quality findings.
9. No faults or warnings: report a healthy connection with the measured quality grade.

Recommendations are specific to the primary conclusion and remain non-invasive. Examples include checking Wi-Fi association or cable connection, moving closer to the router, restarting network equipment, checking router WAN state, contacting the ISP, or manually reviewing DNS settings.

## Failure handling

Every external operation has a finite timeout. A failed command, unavailable property, unexpected localized output, permission restriction, or timeout produces an unavailable result for that check and does not terminate the application.

Partial data is shown honestly. The rule engine does not claim a specific fault when required evidence is unavailable. Unexpected worker errors are converted into a concise diagnostic failure message while preserving any observations already collected.

The application performs no automatic repair and never treats an unavailable measurement as a successful one.

## Testing strategy

Development follows test-driven development. Tests do not depend on the development machine's current network state.

- Calculation tests cover average latency, packet loss, jitter, boundary values, and insufficient samples.
- Parser tests cover PowerShell JSON and representative English and Chinese ping/netsh output.
- Rule tests use synthetic snapshots for disconnected adapters, missing IPv4, APIPA, missing gateway, unreachable gateway, Internet failure, DNS failure, weak Wi-Fi, local-link warnings, and every quality threshold boundary.
- Orchestration tests inject deterministic probe functions and verify check order, partial failures, and report inputs without making live network calls.
- A Windows smoke check launches the Tkinter application and a packaged executable for a bounded period to confirm startup without Python tracebacks.

## Packaging

The build script installs or uses development-only tooling and runs PyInstaller with the functional equivalent of:

```text
PyInstaller --onefile --windowed --name NetworkDoctor network_doctor/app.py
```

The final executable is produced under `dist/NetworkDoctor.exe`. PyInstaller and pytest are development dependencies only; the application uses the Python standard library at runtime.

## Explicitly out of scope

- Automatic DNS, DHCP, adapter, or route repair
- Administrator-only diagnostics
- Continuous background monitoring
- Historical charts or stored measurements
- Remote telemetry or cloud services
- Installer creation and automatic updates
- Cross-platform support
