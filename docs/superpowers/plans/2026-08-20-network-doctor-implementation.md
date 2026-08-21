# NetworkDoctor MVP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and package a read-only Windows network-diagnosis desktop application that explains disconnections and instability in Simplified Chinese.

**Architecture:** A Tkinter UI runs an injected diagnostic service on a worker thread. Windows-specific probes return typed data, the orchestrator gathers a snapshot from the computer outward, and a deterministic analysis module applies ordered rules and formats the report.

**Tech Stack:** Python 3.12 during development (application-compatible floor: Python 3.11), Python standard library and Tkinter at runtime, pytest for tests, PyInstaller 6.x for the single-file Windows executable.

**Spec:** `docs/superpowers/specs/2026-08-20-network-doctor-design.md`

## Global Constraints

- Target Windows 10 and Windows 11.
- Use a Simplified Chinese user interface.
- The application must run without Internet access and without administrator privileges.
- Never modify DNS, DHCP, adapters, routes, or system settings.
- Application runtime code must use only the Python standard library and Windows built-in commands.
- Produce one `dist/NetworkDoctor.exe`; the target computer must not need Python.
- Keep all external operations bounded by timeouts and represent unavailable evidence explicitly.
- Evaluate public latency at 50/70/150/300 ms, jitter at 15/30/60/100 ms, loss at 0/5/25 percent, Wi-Fi at 50/70 percent, and gateway latency at 20 ms.

## File map

- `network_doctor/__init__.py`: package metadata only.
- `network_doctor/models.py`: immutable result types and quality calculations.
- `network_doctor/windows_probes.py`: Windows command execution, parsers, and live probes.
- `network_doctor/diagnostics.py`: ordered probe orchestration and progress events.
- `network_doctor/analysis.py`: ordered diagnosis rules and Chinese report formatting.
- `network_doctor/app.py`: Tkinter UI and worker-thread lifecycle.
- `network_doctor_main.py`: minimal executable entry point for PyInstaller.
- `tests/test_models.py`: calculations and boundary behavior.
- `tests/test_windows_probes.py`: language-tolerant parsers and bounded probe behavior.
- `tests/test_analysis.py`: primary diagnosis priority and quality thresholds.
- `tests/test_diagnostics.py`: orchestration order and partial-failure behavior.
- `tests/test_app.py`: safe import and injectable UI runner contract.
- `tests/test_build_contract.py`: packaging-script contract.
- `requirements-dev.txt`: pytest and PyInstaller development dependencies.
- `build.ps1`: test-first, one-file PyInstaller build.
- `README.md`: use, development, test, and build instructions.

---

### Task 1: Typed models and network-quality calculations

**Files:**
- Create: `network_doctor/__init__.py`
- Create: `network_doctor/models.py`
- Create: `tests/test_models.py`
- Create: `requirements-dev.txt`

**Interfaces:**
- Produces: `CheckState`, `AdapterInfo`, `PingStats`, `ProbeSnapshot`, `Finding`, and `DiagnosisReport`.
- Produces: `PingStats.packet_loss_percent`, `average_latency_ms`, `jitter_ms`, and `reachable` properties.
- Consumes: no application interfaces.

- [ ] **Step 1: Add the development dependency file and write failing model tests**

`requirements-dev.txt`:

```text
pytest>=8,<10
pyinstaller>=6,<7
```

`tests/test_models.py`:

```python
from network_doctor.models import PingStats


def test_ping_stats_calculates_loss_average_and_jitter():
    stats = PingStats(target="1.1.1.1", sent=4, latencies_ms=(20.0, 35.0, 25.0))

    assert stats.packet_loss_percent == 25.0
    assert stats.average_latency_ms == pytest.approx(26.67, abs=0.01)
    assert stats.jitter_ms == pytest.approx(12.5)
    assert stats.reachable is True


def test_jitter_is_unavailable_with_fewer_than_two_replies():
    stats = PingStats(target="1.1.1.1", sent=4, latencies_ms=(20.0,))

    assert stats.jitter_ms is None


def test_no_replies_is_unreachable_and_full_loss():
    stats = PingStats(target="1.1.1.1", sent=4, latencies_ms=())

    assert stats.reachable is False
    assert stats.packet_loss_percent == 100.0
    assert stats.average_latency_ms is None
```

Include `import pytest` at the top of the file.

- [ ] **Step 2: Create the isolated development environment**

Use the available Python 3.12 interpreter to create `.venv`, then install only the development dependencies:

```powershell
& "C:\Users\13238\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe" -m venv .venv
& .\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
```

Verify `python --version`, `pytest --version`, and `PyInstaller --version` through `.venv\Scripts\python.exe` before continuing.

- [ ] **Step 3: Run the focused tests and verify RED**

Run:

```powershell
& .\.venv\Scripts\python.exe -m pytest tests/test_models.py -v
```

Expected: collection fails with `ModuleNotFoundError: No module named 'network_doctor'`.

- [ ] **Step 4: Implement the minimal immutable model layer**

Define these exact public types in `network_doctor/models.py`:

```python
class CheckState(str, Enum):
    OK = "正常"
    WARNING = "提示"
    ERROR = "异常"
    UNAVAILABLE = "无法检测"


@dataclass(frozen=True)
class AdapterInfo:
    name: str
    kind: str
    connected: bool
    enabled: bool
    ipv4_addresses: tuple[str, ...] = ()
    dhcp_enabled: bool | None = None
    gateway: str | None = None
    dns_servers: tuple[str, ...] = ()
    wifi_signal_percent: int | None = None


@dataclass(frozen=True)
class PingStats:
    target: str
    sent: int
    latencies_ms: tuple[float, ...] = ()
    error: str | None = None


@dataclass(frozen=True)
class ProbeSnapshot:
    adapters: tuple[AdapterInfo, ...]
    active_adapter: AdapterInfo | None
    gateway_ping: PingStats | None
    internet_pings: tuple[PingStats, ...]
    tcp_reachable: bool | None
    dns_results: tuple[tuple[str, bool | None], ...]
    unavailable_checks: tuple[str, ...] = ()


@dataclass(frozen=True)
class Finding:
    state: CheckState
    title: str
    detail: str


@dataclass(frozen=True)
class DiagnosisReport:
    overall: CheckState
    primary_problem: str
    findings: tuple[Finding, ...]
    recommendations: tuple[str, ...]
    quality_grade: str | None = None
```

Implement `PingStats` properties with `statistics.fmean`; round loss and average latency to two decimals. Calculate jitter as the mean absolute difference between adjacent replies and return `None` for fewer than two replies.

- [ ] **Step 5: Run the model tests and verify GREEN**

Run:

```powershell
& .\.venv\Scripts\python.exe -m pytest tests/test_models.py -v
```

Expected: 3 tests pass with no warnings.

- [ ] **Step 6: Commit Task 1**

```powershell
git add requirements-dev.txt network_doctor/__init__.py network_doctor/models.py tests/test_models.py
git commit -m "feat: add network diagnostic models"
```

---

### Task 2: Windows output parsers and bounded live probes

**Files:**
- Create: `network_doctor/windows_probes.py`
- Create: `tests/test_windows_probes.py`

**Interfaces:**
- Consumes: `AdapterInfo` and `PingStats` from Task 1.
- Produces: `CommandResult(returncode: int, stdout: str, stderr: str, timed_out: bool)`.
- Produces: `parse_ping_output(output: str, target: str, sent: int) -> PingStats`.
- Produces: `parse_wifi_signal(output: str) -> int | None`.
- Produces: `parse_adapter_json(output: str) -> tuple[AdapterInfo, ...]`.
- Produces: `WindowsProbes.collect_adapters()`, `ping()`, `tcp_reachable()`, `resolve()`, and `wifi_signal()`.

- [ ] **Step 1: Write parser tests using English and Chinese samples**

```python
from network_doctor.windows_probes import (
    parse_adapter_json,
    parse_ping_output,
    parse_wifi_signal,
)


def test_ping_parser_handles_english_and_lost_packet():
    output = """Reply from 1.1.1.1: bytes=32 time=18ms TTL=57
Request timed out.
Reply from 1.1.1.1: bytes=32 time=25ms TTL=57
Reply from 1.1.1.1: bytes=32 time<1ms TTL=57"""

    stats = parse_ping_output(output, "1.1.1.1", sent=4)

    assert stats.latencies_ms == (18.0, 25.0, 1.0)
    assert stats.packet_loss_percent == 25.0


def test_ping_parser_handles_chinese_output():
    output = """来自 192.168.1.1 的回复: 字节=32 时间=3ms TTL=64
请求超时。
来自 192.168.1.1 的回复: 字节=32 时间<1ms TTL=64"""

    stats = parse_ping_output(output, "192.168.1.1", sent=3)

    assert stats.latencies_ms == (3.0, 1.0)


def test_wifi_signal_parser_uses_percent_value():
    output = "    Signal                 : 74%\n"
    assert parse_wifi_signal(output) == 74


def test_adapter_json_accepts_single_object_and_normalizes_lists():
    output = '{"Name":"Wi-Fi","Kind":"Wi-Fi","Connected":true,"Enabled":true,"IPv4":"192.168.1.4","DhcpEnabled":true,"Gateway":"192.168.1.1","Dns":["1.1.1.1"]}'

    adapters = parse_adapter_json(output)

    assert adapters[0].ipv4_addresses == ("192.168.1.4",)
    assert adapters[0].dns_servers == ("1.1.1.1",)
```

- [ ] **Step 2: Run parser tests and verify RED**

Run:

```powershell
& .\.venv\Scripts\python.exe -m pytest tests/test_windows_probes.py -v
```

Expected: import fails because `network_doctor.windows_probes` does not exist.

- [ ] **Step 3: Implement parsers and the command runner**

Use this language-independent ping expression:

```python
PING_TIME_RE = re.compile(r"[=<]\s*(\d+(?:\.\d+)?)\s*ms", re.IGNORECASE)
PERCENT_RE = re.compile(r":\s*(\d{1,3})\s*%")
```

Implement:

```python
@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False


def run_command(args: Sequence[str], timeout_seconds: float) -> CommandResult:
    try:
        completed = subprocess.run(
            list(args),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_seconds,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return CommandResult(completed.returncode, completed.stdout, completed.stderr)
    except subprocess.TimeoutExpired as exc:
        return CommandResult(-1, exc.stdout or "", exc.stderr or "", timed_out=True)
```

`parse_adapter_json` must accept an empty value, one JSON object, or a list. Normalize scalar/list properties into tuples, ignore malformed records, and never invent a connected adapter.

- [ ] **Step 4: Run parser tests and verify GREEN**

Run:

```powershell
& .\.venv\Scripts\python.exe -m pytest tests/test_windows_probes.py -v
```

Expected: 4 tests pass.

- [ ] **Step 5: Add failing tests for bounded probe behavior**

Add tests that inject a fake command runner into `WindowsProbes`:

```python
def test_ping_uses_windows_count_and_timeout_flags():
    calls = []

    def fake_runner(args, timeout_seconds):
        calls.append((args, timeout_seconds))
        return CommandResult(0, "Reply from 1.1.1.1: time=12ms", "")

    probes = WindowsProbes(command_runner=fake_runner)
    result = probes.ping("1.1.1.1", count=4, timeout_ms=1000)

    assert calls[0][0] == ["ping.exe", "-n", "4", "-w", "1000", "1.1.1.1"]
    assert calls[0][1] == pytest.approx(6.0)
    assert result.reachable
```

Add a `tcp_reachable` test using an injected `create_connection` function and a `resolve` test using an injected `getaddrinfo` function. Assert that exceptions become `False`, not unhandled errors.

- [ ] **Step 6: Run the new tests and verify RED**

Expected: failures report the missing `WindowsProbes` methods.

- [ ] **Step 7: Implement `WindowsProbes`**

Use constructor injection:

```python
class WindowsProbes:
    def __init__(
        self,
        command_runner=run_command,
        create_connection=socket.create_connection,
        getaddrinfo=socket.getaddrinfo,
    ): ...
```

Required behavior:

- `collect_adapters()` runs one non-interactive PowerShell command that selects active physical adapters and emits the exact JSON keys consumed by `parse_adapter_json`.
- `ping(target, count, timeout_ms)` calls `ping.exe -n ... -w ...` and returns parsed samples even when the process exit code is nonzero.
- `tcp_reachable(endpoints, timeout_seconds)` returns true after the first successful endpoint and false only after all endpoints fail.
- `resolve(hostname, timeout_seconds)` uses a daemon helper thread and bounded wait around `getaddrinfo`; return `None` if the helper does not finish before the timeout.
- `wifi_signal()` runs `netsh.exe wlan show interfaces` and returns the parsed percent or `None`.

Build the PowerShell adapter command from this fixed script and pass it as a single `-Command` argument after `powershell.exe -NoLogo -NoProfile -NonInteractive`:

```powershell
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$rows = foreach ($config in Get-NetIPConfiguration) {
    if ($config.NetAdapter.Status -ne 'Up' -or -not $config.NetAdapter.HardwareInterface) { continue }
    $ipv4Interface = Get-NetIPInterface -InterfaceIndex $config.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
    [pscustomobject]@{
        Name = [string]$config.InterfaceAlias
        Kind = if ([string]$config.NetAdapter.MediaType -match '802.11|Wireless') { 'Wi-Fi' } else { 'Ethernet' }
        Connected = $true
        Enabled = $true
        IPv4 = @($config.IPv4Address | ForEach-Object { $_.IPAddress })
        DhcpEnabled = (@($ipv4Interface | ForEach-Object { [string]$_.Dhcp }) -contains 'Enabled')
        Gateway = [string](@($config.IPv4DefaultGateway | ForEach-Object { $_.NextHop }) | Select-Object -First 1)
        Dns = @($config.DNSServer.ServerAddresses)
    }
}
@($rows) | ConvertTo-Json -Depth 4 -Compress
```

- [ ] **Step 8: Run all Task 2 tests and the existing suite**

```powershell
& .\.venv\Scripts\python.exe -m pytest tests/test_windows_probes.py tests/test_models.py -v
```

Expected: all tests pass without live network access.

- [ ] **Step 9: Commit Task 2**

```powershell
git add network_doctor/windows_probes.py tests/test_windows_probes.py
git commit -m "feat: add bounded Windows network probes"
```

---

### Task 3: Ordered diagnosis rules and Chinese report

**Files:**
- Create: `network_doctor/analysis.py`
- Create: `tests/test_analysis.py`

**Interfaces:**
- Consumes: `ProbeSnapshot`, `PingStats`, `Finding`, `CheckState`, and `DiagnosisReport`.
- Produces: `analyze(snapshot: ProbeSnapshot) -> DiagnosisReport`.
- Produces: `format_report(report: DiagnosisReport) -> str`.
- Produces: `latency_label(value: float | None)`, `jitter_label(value: float | None)`, and `loss_label(value: float)`.

- [ ] **Step 1: Write failing threshold-boundary tests**

```python
from dataclasses import replace

import pytest

from network_doctor.analysis import analyze, jitter_label, latency_label, loss_label
from network_doctor.models import AdapterInfo, CheckState, PingStats, ProbeSnapshot


def healthy_snapshot():
    adapter = AdapterInfo(
        name="Wi-Fi",
        kind="Wi-Fi",
        connected=True,
        enabled=True,
        ipv4_addresses=("192.168.1.20",),
        dhcp_enabled=True,
        gateway="192.168.1.1",
        dns_servers=("1.1.1.1",),
        wifi_signal_percent=80,
    )
    return ProbeSnapshot(
        adapters=(adapter,),
        active_adapter=adapter,
        gateway_ping=PingStats("192.168.1.1", 4, (2.0, 3.0, 2.0, 3.0)),
        internet_pings=(
            PingStats("1.1.1.1", 6, (30.0,) * 6),
            PingStats("8.8.8.8", 6, (32.0,) * 6),
        ),
        tcp_reachable=None,
        dns_results=(("example.com", True), ("cloudflare.com", True)),
    )


@pytest.mark.parametrize(
    ("value", "expected"),
    [(49.99, "优秀"), (50, "良好"), (70, "略高"), (150, "较高"), (300, "非常高")],
)
def test_latency_labels(value, expected):
    assert latency_label(value) == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [(14.99, "稳定"), (15, "轻微波动"), (30, "存在波动"), (60, "波动明显"), (100, "非常不稳定")],
)
def test_jitter_labels(value, expected):
    assert jitter_label(value) == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [(0, "正常"), (1, "偶发丢包"), (5, "连接不稳定"), (25, "严重丢包")],
)
def test_loss_labels(value, expected):
    assert loss_label(value) == expected
```

- [ ] **Step 2: Run and verify RED**

Expected: import fails because `network_doctor.analysis` does not exist.

- [ ] **Step 3: Implement exact threshold helpers**

Use ascending comparisons so every boundary is explicit. Return `无法检测` for `None` latency or jitter. Run the focused parameterized tests and verify GREEN.

- [ ] **Step 4: Write failing rule-priority tests**

Create a `healthy_snapshot()` test factory and cover these independent cases:

```python
def test_apipa_has_priority_over_missing_gateway():
    adapter = replace(
        healthy_snapshot().active_adapter,
        ipv4_addresses=("169.254.10.20",),
        gateway=None,
    )
    snapshot = replace(healthy_snapshot(), active_adapter=adapter)

    report = analyze(snapshot)

    assert report.overall is CheckState.ERROR
    assert report.primary_problem == "DHCP 获取地址失败"


def test_dns_failure_requires_reachable_internet_path():
    snapshot = replace(
        healthy_snapshot(),
        dns_results=(("example.com", False), ("cloudflare.com", False)),
    )

    assert analyze(snapshot).primary_problem == "DNS 服务可能异常"


def test_secondary_wifi_warning_is_preserved():
    adapter = replace(healthy_snapshot().active_adapter, wifi_signal_percent=42)
    report = analyze(replace(healthy_snapshot(), active_adapter=adapter))

    assert any(finding.title == "Wi-Fi 信号较弱" for finding in report.findings)
```

Also add one test for each primary rule: no connected adapter, no IPv4, missing gateway, gateway unreachable, Internet unreachable after TCP fallback, quality warning, and healthy result. Include a gateway-latency test at exactly 20 ms.

- [ ] **Step 5: Run rule tests and verify RED**

Expected: threshold tests pass; rule tests fail because `analyze` is missing.

- [ ] **Step 6: Implement ordered rules with evidence guards**

Implementation requirements:

- Use `ipaddress.ip_address(address).is_link_local` to identify APIPA.
- A public path is reachable when any public ping has replies or `tcp_reachable is True`.
- Declare Internet failure only when the gateway is reachable and all public evidence is explicitly false; unavailable evidence yields `无法完成明确判断`.
- Declare DNS failure only when the public path is reachable and both DNS results are explicitly false.
- Aggregate public samples by summing sent counts and concatenating successful samples.
- Preserve weak Wi-Fi, gateway latency, loss, latency, and jitter as secondary findings.
- Quality grade is `优秀` only for zero loss, latency below 50 ms, and jitter below 15 ms; `良好` requires zero loss, latency below 70 ms, and jitter below 30 ms.

- [ ] **Step 7: Write the report-formatting test, verify RED, then implement**

```python
def test_format_report_contains_required_sections():
    text = format_report(analyze(healthy_snapshot()))

    assert "总体结论" in text
    assert "最可能的问题" in text
    assert "关键检测结果" in text
    assert "建议操作" in text
```

Format one plain-text report with numbered recommendations and symbols `[正常]`, `[提示]`, `[异常]`, and `[无法检测]`; do not use ANSI color codes.

- [ ] **Step 8: Run Task 3 tests and the suite**

```powershell
& .\.venv\Scripts\python.exe -m pytest tests/test_analysis.py tests/test_models.py -v
```

Expected: all tests pass.

- [ ] **Step 9: Commit Task 3**

```powershell
git add network_doctor/analysis.py tests/test_analysis.py
git commit -m "feat: add network diagnosis rules"
```

---

### Task 4: Diagnostic orchestration and progress

**Files:**
- Create: `network_doctor/diagnostics.py`
- Create: `tests/test_diagnostics.py`

**Interfaces:**
- Consumes: `WindowsProbes`, `ProbeSnapshot`, `DiagnosisReport`, and `analyze`.
- Produces: `ProgressCallback = Callable[[str, int], None]`.
- Produces: `collect_snapshot(probes, on_progress=None) -> ProbeSnapshot`.
- Produces: `run_diagnosis(probes=None, on_progress=None) -> DiagnosisReport`.

- [ ] **Step 1: Write an injected fake-provider orchestration test**

```python
from network_doctor.models import AdapterInfo, PingStats


class FakeProbes:
    def __init__(self):
        self.calls = []

    def collect_adapters(self):
        self.calls.append("collect_adapters")
        return (
            AdapterInfo(
                name="Wi-Fi",
                kind="Wi-Fi",
                connected=True,
                enabled=True,
                ipv4_addresses=("192.168.1.20",),
                dhcp_enabled=True,
                gateway="192.168.1.1",
                dns_servers=("1.1.1.1",),
            ),
        )

    def wifi_signal(self):
        self.calls.append("wifi_signal")
        return 80

    def ping(self, target, count, timeout_ms):
        self.calls.append(f"ping:{target}")
        return PingStats(target, count, (3.0,) * count)

    def tcp_reachable(self, endpoints, timeout_seconds):
        self.calls.append("tcp_reachable")
        return True

    def resolve(self, hostname, timeout_seconds):
        self.calls.append(f"resolve:{hostname}")
        return True


def test_collect_snapshot_runs_near_to_far_and_reports_progress():
    probes = FakeProbes()
    progress = []

    snapshot = collect_snapshot(probes, lambda text, percent: progress.append((text, percent)))

    assert probes.calls == [
        "collect_adapters",
        "wifi_signal",
        "ping:192.168.1.1",
        "ping:1.1.1.1",
        "ping:8.8.8.8",
        "resolve:example.com",
        "resolve:cloudflare.com",
    ]
    assert progress[0] == ("正在检查网络适配器……", 10)
    assert progress[-1] == ("正在分析结果……", 95)
    assert snapshot.active_adapter.name == "Wi-Fi"
```

The fake returns one connected Wi-Fi adapter, successful gateway/public pings, true TCP reachability, and true DNS results.

Add a second test in which both public pings have no replies. Its expected call list includes `tcp_reachable` immediately after the second public ping. Assert that the healthy case does not call the TCP fallback.

- [ ] **Step 2: Run and verify RED**

Expected: import fails because `network_doctor.diagnostics` does not exist.

- [ ] **Step 3: Implement the minimal orchestration flow**

Use these targets and sample settings:

```python
PUBLIC_TARGETS = ("1.1.1.1", "8.8.8.8")
DNS_TARGETS = ("example.com", "cloudflare.com")
TCP_ENDPOINTS = (("1.1.1.1", 443), ("8.8.8.8", 443))
GATEWAY_PING_COUNT = 4
PUBLIC_PING_COUNT = 6
PING_TIMEOUT_MS = 1000
```

Select the first adapter where `enabled and connected`, preferring one with a non-link-local IPv4 and gateway. Copy Wi-Fi signal into the immutable active adapter with `dataclasses.replace`.

- [ ] **Step 4: Add and verify a partial-failure test**

Make the fake provider raise `ProbeUnavailable("PowerShell unavailable")` from `collect_adapters`. Assert `collect_snapshot` returns a snapshot with `active_adapter is None` and contains `网络适配器` in `unavailable_checks`, rather than raising.

- [ ] **Step 5: Implement per-stage exception containment**

Define `ProbeUnavailable(RuntimeError)` in `windows_probes.py`. Catch it around each stage, append a Chinese check name to `unavailable_checks`, and continue only when downstream inputs exist. Do not treat skipped downstream checks as success.

- [ ] **Step 6: Test `run_diagnosis` composition**

Inject the fake provider and assert the returned object is a `DiagnosisReport` whose primary problem is `未发现明显网络问题`.

- [ ] **Step 7: Run the complete non-UI suite**

```powershell
& .\.venv\Scripts\python.exe -m pytest tests/test_models.py tests/test_windows_probes.py tests/test_analysis.py tests/test_diagnostics.py -v
```

Expected: all tests pass without making live network calls.

- [ ] **Step 8: Commit Task 4**

```powershell
git add network_doctor/diagnostics.py network_doctor/windows_probes.py tests/test_diagnostics.py
git commit -m "feat: orchestrate network diagnosis"
```

---

### Task 5: Responsive Tkinter application

**Files:**
- Create: `network_doctor/app.py`
- Create: `tests/test_app.py`

**Interfaces:**
- Consumes: `run_diagnosis(on_progress=...)` and `format_report(report)`.
- Produces: `NetworkDoctorApp(root: tk.Tk, diagnosis_runner=run_diagnosis)`.
- Produces: `main() -> None`; module import must never create a window.

- [ ] **Step 1: Write a safe-import test and verify RED**

```python
import importlib


def test_app_import_does_not_start_tkinter():
    module = importlib.import_module("network_doctor.app")

    assert callable(module.main)
    assert module.NetworkDoctorApp.__name__ == "NetworkDoctorApp"
```

Expected: import fails because `network_doctor.app` does not exist.

- [ ] **Step 2: Implement the UI shell without running diagnostics**

Create a 760x560 minimum window, `ttk.Progressbar`, step label, scrollable `tk.Text`, and the two buttons. Only call `main()` under:

```python
if __name__ == "__main__":
    main()
```

Run `tests/test_app.py` and verify GREEN without creating a Tk root in the test.

- [ ] **Step 3: Write failing tests for thread-to-UI message handling**

Test a pure queue-drain method using an instance created with `NetworkDoctorApp.__new__` and small fake widget objects. Cover:

- progress messages update status and percent;
- a result message formats and inserts the report, enables rerun/copy, and stops progress;
- an error message displays `诊断未完成` without a traceback;
- messages are ignored after `_closing` becomes true.

- [ ] **Step 4: Implement worker and queue lifecycle**

Required behavior:

- `start_diagnosis()` disables start/copy, clears output, and launches one daemon `threading.Thread`.
- The worker calls the injected runner and writes only tuples to `queue.Queue`; it never calls Tkinter methods.
- `root.after(80, self._drain_queue)` applies progress/result/error messages on the UI thread.
- `WM_DELETE_WINDOW` sets `_closing = True` and destroys the root.
- `copy_result()` writes the current report through `clipboard_clear()` and `clipboard_append()`.

- [ ] **Step 5: Run the app tests and full suite**

```powershell
& .\.venv\Scripts\python.exe -m pytest -v
```

Expected: all tests pass; no Tk window opens during tests.

- [ ] **Step 6: Perform a source-mode Windows startup smoke check**

Run:

```powershell
& .\.venv\Scripts\python.exe -m network_doctor.app
```

Expected: the window opens, the diagnostic button remains responsive, and closing the window exits without a traceback. Record the manual result in the implementation handoff.

- [ ] **Step 7: Commit Task 5**

```powershell
git add network_doctor/app.py tests/test_app.py
git commit -m "feat: add NetworkDoctor desktop UI"
```

---

### Task 6: Reproducible build, documentation, and packaged verification

**Files:**
- Create: `tests/test_build_contract.py`
- Create: `build.ps1`
- Create: `network_doctor_main.py`
- Create: `README.md`
- Create: `.gitignore`

**Interfaces:**
- Consumes: `network_doctor.app` as the PyInstaller entry module.
- Produces: `dist/NetworkDoctor.exe`.

- [ ] **Step 1: Write the failing build-contract test**

```python
from pathlib import Path


def test_build_script_creates_named_one_file_windowed_executable():
    script = Path("build.ps1").read_text(encoding="utf-8")

    assert "-m PyInstaller" in script
    assert "--onefile" in script
    assert "--windowed" in script
    assert '"NetworkDoctor"' in script
    assert "network_doctor.app" in script
    assert "-m pytest" in script
```

Run it and verify failure because `build.ps1` is absent.

- [ ] **Step 2: Implement the build script**

`build.ps1` must:

1. Stop on errors.
2. Resolve `.venv\Scripts\python.exe` beneath the project root and emit a clear Chinese error if absent.
3. Run `python -m pytest` before packaging.
4. Run `python -m PyInstaller --noconfirm --clean --onefile --windowed --name "NetworkDoctor" --collect-submodules network_doctor network_doctor_main.py`. Keep the string `network_doctor.app` in the script comment documenting the module entry point.
5. Verify `dist\NetworkDoctor.exe` exists and print its absolute path.

Create `network_doctor_main.py` with exactly:

```python
from network_doctor.app import main


if __name__ == "__main__":
    main()
```

- [ ] **Step 3: Run the build-contract test and verify GREEN**

```powershell
& .\.venv\Scripts\python.exe -m pytest tests/test_build_contract.py -v
```

- [ ] **Step 4: Add concise documentation and ignore rules**

`README.md` must cover:

- Supported Windows versions and read-only behavior
- Double-click use of `NetworkDoctor.exe`
- Meaning of the four check states and quality labels
- Source development using `.venv`
- Exact test and `build.ps1` commands
- Limits of ICMP/DNS diagnosis and the absence of automatic repair

`.gitignore` must include `.venv/`, `__pycache__/`, `.pytest_cache/`, `build/`, `dist/`, and `*.spec`.

- [ ] **Step 5: Run fresh full verification**

```powershell
& .\.venv\Scripts\python.exe -m pytest -q
& .\build.ps1
Get-Item .\dist\NetworkDoctor.exe | Select-Object FullName, Length, LastWriteTime
```

Expected: zero test failures, build exit code 0, and a nonempty `dist/NetworkDoctor.exe`.

- [ ] **Step 6: Perform packaged startup smoke check**

Start `dist\NetworkDoctor.exe`, confirm the window appears within 20 seconds, click `开始诊断`, confirm progress text changes, close it, and verify the process exits. If automation launches the process, always terminate only the resolved executable path after the bounded check.

- [ ] **Step 7: Review the implementation against the spec**

Check every ordered rule, threshold, timeout, UI element, out-of-scope constraint, and packaging requirement in `docs/superpowers/specs/2026-08-20-network-doctor-design.md`. Add a failing regression test before correcting any gap.

- [ ] **Step 8: Commit Task 6**

```powershell
git add .gitignore README.md build.ps1 tests/test_build_contract.py network_doctor_main.py
git commit -m "build: package NetworkDoctor for Windows"
```

---

## Final acceptance checklist

- [ ] All pytest tests pass in a fresh run.
- [ ] Source-mode GUI opens, diagnoses, and closes without traceback.
- [ ] `dist/NetworkDoctor.exe` exists, is nonempty, and opens without Python installed on PATH.
- [ ] The executable runs without administrator privileges.
- [ ] Disconnect/APIPA/gateway/Internet/DNS/weak-signal/latency/loss/jitter rules have automated coverage.
- [ ] Values at 50/70/150/300 ms latency, 15/30/60/100 ms jitter, 0/5/25 percent loss, 50/70 percent Wi-Fi, and 20 ms gateway latency have boundary tests.
- [ ] Failures and timeouts appear as unavailable evidence rather than application crashes.
- [ ] No automatic repair, telemetry, monitoring, history, installer, or updater was introduced.
