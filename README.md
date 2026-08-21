# NetworkDoctor

NetworkDoctor is a lightweight, Simplified Chinese network diagnostic tool for Windows 10 and Windows 11. It reads local network information without requiring administrator privileges and never changes DNS, IP address, network adapter, routing, or other system settings.

## Availability

This repository contains the complete source code. It does not currently include a prebuilt `NetworkDoctor.exe` or a downloadable GitHub Release.

You can use NetworkDoctor in either of these ways:

1. Run `network_doctor_main.py` directly. This provides the same interface and diagnostic features as the packaged application.
2. Build the optional standalone EXE yourself if you want a portable copy that can run without a separate Python installation.

## Running from Source

Requirements:

- Windows 10 or Windows 11.
- Python 3.12 is recommended and is the version used to validate this project.
- Tkinter must be available. The standard Windows installer from python.org normally includes it.

Clone the repository, or download and extract its ZIP archive. Then open PowerShell in the project directory and run:

```powershell
py .\network_doctor_main.py
```

If the `py` launcher is unavailable, use:

```powershell
python .\network_doctor_main.py
```

The application itself uses only the Python standard library. The packages in `requirements-dev.txt` are needed only for testing and building the EXE.

## Using NetworkDoctor

Click **Start Diagnosis** (`开始诊断`). When the diagnosis finishes, review the report or click **Copy Results** (`复制结果`). Click **Run Again** (`重新诊断`) to refresh the report.

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

Public-network quality is measured separately for IPv4 and IPv6. NetworkDoctor sends 10 bounded Ping samples to each of two IPv4 targets and, when the active adapter has a public IPv6 address, each of two IPv6 targets. The independent targets run concurrently to keep the diagnosis time bounded. If one target cannot be tested, the report explicitly says that the statistics are based only on the available target instead of presenting them as complete evidence.

## Building the Optional EXE

Create a Python virtual environment, install the development dependencies, and run the build script:

```powershell
py -m venv .venv
& .\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
& .\build.ps1
```

The build script runs the complete test suite and creates a single-file, windowed executable at `dist\NetworkDoctor.exe`. The resulting EXE can be moved to another folder or compatible Windows 10/11 computer and does not require Python to be installed.

## Testing

After creating `.venv` and installing `requirements-dev.txt`, run the complete test suite with:

```powershell
& .\.venv\Scripts\python.exe -m pytest -q
```

## Diagnostic Limitations

Some networks block ICMP (ping), so a missing ping response does not always mean that the Internet connection is down. When the IPv4 result is inconclusive, NetworkDoctor uses short TCP connection checks to reduce false diagnoses. IPv4 and IPv6 can follow different routes and can have very different loss, latency, and jitter; a healthy result for one family does not hide a warning for the other. A network without a public IPv6 address is reported as not configured, not as a fault.

DNS checks only confirm whether the selected test domains could be resolved at that moment. They cannot fully evaluate cached responses, split DNS configurations, domain-specific failures, or every upstream DNS service. A failed command, timeout, or lack of evidence is reported as **Unavailable** instead of being treated as a confirmed fault.

NetworkDoctor provides diagnostic conclusions and non-invasive recommendations only. It does not repair the network automatically and does not include background monitoring, telemetry, history, an installer, or an updater.
