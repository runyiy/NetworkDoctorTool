# NetworkDoctor

NetworkDoctor is a lightweight, Simplified Chinese network diagnostic tool for Windows 10 and Windows 11. It reads local network information without requiring administrator privileges and never changes DNS, IP address, network adapter, routing, or other system settings.

## Using the Executable

Double-click `NetworkDoctor.exe`, then click **Start Diagnosis** (`开始诊断`). When the diagnosis finishes, review the report or click **Copy Results** (`复制结果`). Click **Run Again** (`重新诊断`) to refresh the report.

Each check uses one of four states:

- **Normal** (`正常`): the available evidence does not indicate a problem.
- **Notice** (`提示`): something may require attention.
- **Error** (`异常`): a clear fault was detected.
- **Unavailable** (`无法检测`): the check could not produce reliable evidence because of a timeout, insufficient permissions, or missing data.

Measured network quality is described with these labels:

- Latency: Excellent, Good, Slightly High, High, or Very High.
- Jitter: Stable, Minor Variation, Noticeable Variation, Significant Variation, or Very Unstable.
- Packet loss: Normal, Occasional Loss, Unstable Connection, or Severe Loss.
- Wi-Fi signal: Weak, Fair, or Good.

## Development and Testing

Create a Python virtual environment named `.venv` in the project root, then install the development dependencies listed in `requirements-dev.txt`.

Run the complete test suite:

```powershell
& .\.venv\Scripts\python.exe -m pytest -q
```

Run the application from source:

```powershell
& .\.venv\Scripts\python.exe .\network_doctor_main.py
```

## Building

The build script runs the complete test suite and then creates a single-file, windowed executable at `dist\NetworkDoctor.exe`:

```powershell
& .\build.ps1
```

## Diagnostic Limitations

Some networks block ICMP (ping), so a missing ping response does not always mean that the Internet connection is down. When the result is inconclusive, NetworkDoctor uses short TCP connection checks to reduce false diagnoses.

DNS checks only confirm whether the selected test domains could be resolved at that moment. They cannot fully evaluate cached responses, split DNS configurations, domain-specific failures, or every upstream DNS service. A failed command, timeout, or lack of evidence is reported as **Unavailable** instead of being treated as a confirmed fault.

NetworkDoctor provides diagnostic conclusions and non-invasive recommendations only. It does not repair the network automatically and does not include background monitoring, telemetry, history, an installer, or an updater.
