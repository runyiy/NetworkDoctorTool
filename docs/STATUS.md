# Public implementation and validation status

Repository: NetworkDoctorTool. Internal package/build names remain Losshound.
Upstream: https://github.com/NoSelection/Losshound (MIT; original NoSelection copyright retained).

## Scope and evidence

The current snapshot contains the bounded S1 session, S2 multi-protocol core/GUI integration,
and S3 simulation core plus a narrowly scoped Windows DNS-cache adapter. Partial code batches
have been accepted; complete stages and real Windows delivery have not.

- S1 remains PENDING ACCEPTANCE.
- S2 non-GUI, simulated S3 core/adapter and Fake Qt GUI integration have targeted validation.
- Current Windows Python3.12 stdlib/mock compatibility cohort has eight passing contracts.
- Python3.11 syntax/metadata and mocked output rejection are not real Windows3.11 runtime proof.
- Exact Linux CI Python 3.11.18 and 3.12.16 lightweight compatibility checks PASS on Ubuntu 24.04; see [CI run 40430331423](https://github.com/runyiy/NetworkDoctorTool/actions/runs/40430331423).
- These Linux checks cover syntax, metadata and pure mocked contracts only; they are not real Windows3.11, real GUI or EXE acceptance, or a claim of Linux product support.
- Real Windows3.11, real GUI, frozen EXE output/lifecycle, complete offline EXE and native DNS effects remain unverified.
- Full legacy pytest/native suites are not asserted to have passed for this migration snapshot.

No original local diagnostic evidence, machine/network identifiers, private reports or raw logs
are published here. Synthetic test fixtures remain source code, not user network captures.

## Safety and pending prerequisites

Pillow12.3.0 and setuptools83.0.0 remain blocked by recorded security findings.
The Windows CI test-and-package job FAILED at the dependency gate before installation;
dependency installation, native tests, packaging and GUI/EXE smoke checks were skipped. Windows CI has not passed.
Pillow13.0.0 and setuptools84.1.0 are candidate future updates, not adopted pins or installed packages.
The existing fourteen-day wheel observation, live OSV/PyPI gate, source/hash checks and documented
Qt6.11.2 XML exclusion remain unchanged. A candidate or date does not itself grant installation.

The metadata conflict with Pillow13 is resolved by a project minimum Python>=3.11.
Bounded diagnostic console/file/pipe output still requires native Windows Python>=3.12;
Windows3.11 fails closed. Prefer an independently approved Windows3.12 environment for real acceptance.

After separate approval and a passing current dependency gate: prepare exact reviewed wheels/lock,
verify environment compatibility, then perform real GUI, frozen EXE and offline acceptance.
No stage PASS, real DNS-cache clearance, release or system-network modification is claimed.

The retained CI_SECURITY document includes upstream historical environment/build evidence.
Those records are not a passing current dependency gate or an approved new EXE for this repository.
