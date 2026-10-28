# NetworkDoctorTool

NetworkDoctorTool 是面向 Windows 的本地网络诊断项目，基于
[NoSelection/Losshound](https://github.com/NoSelection/Losshound) 改进开发。
本仓库以新的 Losshound 诊断实现替换此前的 Tkinter 项目，保留仓库 URL 和 Git 历史。
MIT 原版权与许可全文见 [LICENSE](LICENSE)，来源说明见 [NOTICE](NOTICE)。

GitHub 项目名称是 **NetworkDoctorTool**；为保持现有结构，Python 包、命令入口、
GUI 内部应用名和构建文件仍使用 `losshound` / `Losshound.spec`，未做大规模模块重命名。

## 当前状态

这是待完成真实 Windows 交付验收的源码版本，**不是已放行的 EXE 发布**。

| 项目 | 当前证据和限制 |
|---|---|
| 诊断核心、CLI、解释与本地报告 | 已有定向模拟及获准 Windows 只读验证；部分 S2 非 GUI 交付已接受，不代表完整 S2 PASS |
| GUI 集成与本机试用 | Windows 11 / Python 3.14.10 / PySide6 6.12.0 已进行受控真实 GUI 启动、诊断、取消/关闭、脱敏保存及模拟修复/独立复测；这是个人试用证据，完整 GUI 验收仍未通过 |
| 修复核心与 Windows 适配层 | 仅模拟执行器/命令测试已验证；普通诊断不自动修复，当前 GUI 不可调用真实清缓存 |
| 当前兼容检查 | Windows Python 3.12 的8项标准库/模拟契约通过；[Linux CI](https://github.com/runyiy/NetworkDoctorTool/actions/runs/40430331423) 的 Python 3.11.18、3.12.16 轻量兼容性检查已 PASS；不代表 Windows 3.11 实机、真实 GUI 或 EXE 验收 |
| 依赖安全门禁 | Pillow 12.3.0、setuptools 83.0.0 已有安全阻塞；未安装或升级它们、未放宽门禁 |
| GUI、完整离线 EXE 与真实 DNS 修复 | 未通过验收；当前没有本项目新版 EXE Release 可供承诺使用 |

S1 保持 **PENDING ACCEPTANCE**；完整 S1、S2、S3 和 EXE 均不能宣称 PASS。
未宣称本快照的完整旧 pytest/原生套件已通过。Windows 打包任务在依赖门禁失败后，安装、测试、打包及 GUI/EXE smoke 均未执行。
仓库正式依赖 pin 未更新。另经明确的本机个人风险接受，独立测试环境采用 Python 3.14.10、PySide6/Qt 6.12.0、NumPy 2.5.4、ContourPy 1.3.3、Pillow 13.0.0、setuptools 84.1.0 和 pip 26.2.2 等40项已核验依赖；限定风险见 [SECURITY.md](SECURITY.md#本机非发布试用记录)。该环境及观察期例外不构成正式门禁 PASS，也不授权其他环境安装。
本地原始诊断报告、机器信息和测试日志不进入本仓库。

2026-10-27 本机试用的已知限制：默认60秒会话曾因观察器启动盲区及轮尾身份查询来不及完成而缺少可比证据；用户单次主动选择120秒后，在约119.2秒内取得22条按原规则确认的可比证据。默认60秒、300秒上限、Epoch规则及证据过滤均未放宽。证据不足时仍显示UNKNOWN，不能保证每轮都能确定故障原因。

有限HTTPS对照保持完整证书与主机名验证：原目标example.com的产品请求与同IP、同地址族、SNI、ALPN和CA策略的标准库TLS均返回代码20；预选官方对照www.python.org的两条连接均通过TLS1.3验证，产品取得HTTP206且验证链指纹一致。这证明产品实际HTTPS路径可对该官方站点完成有效验证，不代表原目标已修复，也不能据此确定缺失证书或按目标网络干预的根因。没有修改系统信任、代理或DNS。模拟修复仍不修改系统。

历史完整保留套件记录为595项通过、3项失败及405项子测试通过；测试收集、安全静态误报和外层Job观测修正有后续定向证据，不能拼接为当前候选完整PASS。本次追加处理修正了网站与参考目标的精确重复调度，并收敛HTTP503夹具中无关的DNS别名；26项离线S2回归通过，但原60秒真实CLI用例仍只取得一组满足条件的HTTP503证据，未满足两次同Epoch/地址族/实际IP的TCP及503要求。第二轮无网络启动对照不支持更换解释器，未进一步改Worker或放宽时限；两轮上限后停止，尚不能把耗时变化确认为新产品缺陷。原断言及全部失败记录保留。因此本次未进入最终完整套件、EXE构建或启动，真实离线Windows验收未覆盖。

## 平台与 Python 支持

- Windows 10/11；GUI 使用现有 PySide6，保留 CLI 和 SessionController/Worker 分离。
- 项目最低 Python 版本为 **3.11**；具体运行时仍须单独安全核准；本机受控试用实际使用 Python 3.14.10 x64，不扩大最低版本声明或其他Windows版本的验收结论。
- **有界诊断 `--cli` 的控制台、文件及管道输出要求 Windows Python 3.12+**。
  Windows 3.11 会明确记录 `output_error`、退出码 1 并停止采集，不静默切换到其他输出。
  核心 API 的 `StringIO` 内存报告不是 CLI 重定向后备。`--help` 不启动诊断。
- Linux CI（Ubuntu 24.04）的 Python 3.11.18、3.12.16 轻量检查已 PASS；范围仅为源码语法、元数据和纯模拟契约，不代表新增 Linux 产品支持或 Windows 实机验收。

## 诊断能力

- IPv4/IPv6 地址、网关/路由候选及连通性证据；静态候选不冒充实际可达证明。
- DNS、ICMP、TCP 和按目标需要启用的 HTTP(S) 独立交叉检测。
  Ping 失败不会自动跳过其他必要协议；系统解析成功也不证明每一台 DNS 服务器健康。
- 根据多项证据保守地区分本机、Wi-Fi、网关、WAN/ISP 和目标服务等范围。
  结论关联支持证据、反证、替代解释、可信度、局限和具体建议；不是单凭一次超时归因。
- 成功、连接失败、未检测、工具错误、取消和证据不足分别保留；缺失数据不能默认为正常或故障。
- 间歇性判断只使用本轮有限观察窗口内新鲜、可比较的数据；网络 Epoch 改变后不混用不同环境证据。
- 同轮网站目标与参考列表在协议、目标文本、地址族上完全相同的任务只实际探测一次，保留网站目标角色；不同端口、协议或地址及后续轮次仍独立检测，不把同一端点重复当作独立WAN参考。

默认单轮总预算 **60 秒**；只有用户主动选择时最多 **300 秒**，不自动延长。
采集、有限等待、报告和清理共用截止时间。取消/关闭协作停止调度并清理所属进程，
不以强杀共享线程冒充清理完成。

## 本地与离线设计

诊断、分析及报告在本机执行，不依赖 AI 服务、云端故障库或长期后台监控。
报告使用现有 JSON/脱敏逻辑，SQLite 架构保留，没有新增数据库或历史重算引擎。
离线时仍可保留本地事实和明确的未检测/工具错误/UNKNOWN；不能把无法访问公网判成具体 ISP 原因。
完整离线单文件 EXE 运行尚待验收，模拟离线测试不能替代它。

## GUI、模拟修复与独立验证

当前 GUI 将诊断核心放在后台 Worker，由 SessionController 管理有限会话，
展示协议结果、证据及解释，提供进度、取消和脱敏 JSON 保存。

首版唯一修复方案是“清空 Windows 本机 DNS 缓存”。方案必须说明影响、权限和
**缓存不能原样恢复**的限制，要求单独确认，默认拒绝。
目前界面仅接入**明确标记的模拟执行**；真实执行入口保持不可调用，CLI 没有自动修复路径。

模拟操作和修复后验证分开触发，验证使用新的有限诊断会话，比较同目标/协议/网络环境的新鲜证据。
命令或模拟执行成功不等于网络改善；结果不可比、验证失败或间歇故障未复现时保留不确定结论，
不自动重试或启动下一项修复。旧 Optimizer、QoS、Firewall、restore 等修改入口仍被拒绝。

## 源码使用

**当前依赖门禁未通过，不要按此节提前安装依赖、启动真实 GUI/EXE 或执行真实修复。**
正式环境需先完成 [依赖安全要求](SECURITY.md)，保留 14 天观察期、官方来源、
精确版本和哈希检查；门禁通过且获得对应授权后，才准备隔离 `.venv`。
`requirements.txt` / `requirements-dev.txt` 的宽松范围不是已审核锁文件，
不要直接用 `pip install .`、`pip install -e .` 或未审核源码构建绕过该流程。

以下 PowerShell 命令只描述已放行、已准备好环境时的源码入口：

```powershell
$runtime = Join-Path (Get-Location).Path '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $runtime)) { throw 'Reviewed environment missing.' }
$env:PYTHONPATH = Join-Path (Get-Location).Path 'src'

# 一个默认60秒的只读双栈诊断；公网目标探测还需相应网络许可。
& $runtime -m losshound --cli --extended

# 用户明确选择的网站和预算。
& $runtime -m losshound --cli --extended --duration 60 --website https://example.com/

# GUI：仅在真实GUI启动另获放行后。
& $runtime -m losshound
```

CLI 支持重复的 `--ipv6-target IP` 和 `--tcp-target HOST:PORT`，IPv6 TCP 字面量用方括号。
Ctrl+C 请求取消与清理。不要将任意退出码 0 当作所有网络健康，需同时阅读证据、状态和清理/输出错误。

## 测试、CI 与构建

无需安装第三方依赖的当前兼容检查，可用现有 Windows Python 3.12+ 运行：

```powershell
python -I -S -B -c "import sys; sys.path.insert(0, 'scripts'); import run_s1_tests as runner; runner.DETERMINISTIC = ('test_version.PythonCompatibilityTests', 'test_session_output_s1.OutputContractTests', 'test_s1_entrypoints.BoundedCliTests.test_windows_311_public_cli_os_sink_returns_error_without_collection'); raise SystemExit(runner.main())" --mode deterministic --log build/compatibility.log --json build/compatibility.json
```

这些检查只证明标准库/语法/模拟边界，不代表 Windows 3.11 实机、真实 GUI 或 EXE 验收通过。
[Windows CI](.github/workflows/windows-ci.yml) 保留先安全门禁、再安装/测试/构建的顺序，
并在 EXE 启动前检查 Qt XML 未打包。现有依赖安全阻塞会使 Windows job 失败；
不跳过或放宽检查来制造绿色结果。CI 的历史上游记录不等于本仓库新版交付验收。

真实构建仍使用 `Losshound.spec`，预期产物名为 `dist/Losshound.exe`。
正式构建需要单独批准、已审核环境和通过的门禁。本次本机非发布测试EXE虽已获有条件授权，但完整保留测试仍有失败，未跳过前置执行构建；当前未构建、启动或发布新版EXE。
未来只有完成 GUI、冻结进程/输出、取消清理和完整离线验收后，才考虑单独授权发布 Release。
无签名或未验收文件不应被宣传为可安全绕过系统保护运行。


## 提交前隐私检查

提交前运行 `python -I -S -B scripts/check_public_files.py`，检查暂存区中的敏感路径和高置信文本风险；
使用 `--all-tracked` 检查整个 Git 索引。检查读取已暂存的内容，输出仅含路径、行号和规则名。
没有自动安装 Git hook；仍需人工区分合成测试数据，并单独复核图片元数据、提交身份和公开历史。
忽略规则不会停止跟踪现有文件，也不会清除历史提交中的信息。

## 来源与许可证

基于 [NoSelection/Losshound](https://github.com/NoSelection/Losshound) 的 MIT 代码改进。
本仓库保留原 `Copyright (c) 2026 NoSelection` 及完整 [MIT License](LICENSE)。
迁移保留旧 NetworkDoctorTool 的分支与 Git 历史；旧版许可证未声明，不能据新版 MIT 文字追溯宣称旧代码已获相同许可。
