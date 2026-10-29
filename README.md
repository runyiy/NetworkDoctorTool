# NetworkDoctorTool

NetworkDoctorTool 是面向 Windows 的本地网络诊断项目，基于
[NoSelection/Losshound](https://github.com/NoSelection/Losshound) 改进开发。
本仓库以新的 Losshound 诊断实现替换此前的 Tkinter 项目，保留仓库 URL 和 Git 历史。
MIT 原版权与许可全文见 [LICENSE](LICENSE)，来源说明见 [NOTICE](NOTICE)。

GitHub 项目名称是 **NetworkDoctorTool**；为保持现有结构，Python 包、命令入口、
GUI 内部应用名和构建文件仍使用 `losshound` / `Losshound.spec`，未做大规模模块重命名。

## 当前状态

这是待完成真实 Windows 交付验收的源码版本，**不是已放行的 EXE 发布**。

本节的619项/418项及旧EXE实测数字均属于PR #6基线（产品源码`c29b673df92a479f6ea376175667c444c2b067de`，交付Head `3c7e18dbaa604ea5a4a072aac03bf9f3d3ab4741`）；本双语候选的新结果见下文，不混用历史证据。

| 项目 | 当前证据和限制 |
|---|---|
| 诊断核心、CLI、解释与本地报告 | 最终本机完整保留套件619项测试、418项子测试通过，0失败、0跳过，55项既有警告；原60秒真实CLI HTTP503用例通过。部分 S2 非 GUI 交付已接受，完整 S2 尚待验收 |
| GUI 集成与本机试用 | Windows 11 / Python 3.14.10 / PySide6 6.12.0 的源码GUI及本地冻结EXE已受控实测：启动、诊断、取消/关闭、脱敏保存及模拟修复/独立复测；不代替完整阶段的用户接受 |
| 修复核心与 Windows 适配层 | 模拟执行器、命令替身及真实GUI模拟确认/独立验证已验证；普通诊断不自动修复，GUI不可调用真实清缓存 |
| 当前兼容检查 | Windows Python 3.12 的8项标准库/模拟契约通过；[Linux CI](https://github.com/runyiy/NetworkDoctorTool/actions/runs/40430331423) 的 Python 3.11.18、3.12.16 轻量兼容性检查已 PASS；不代表 Windows 3.11 实机、真实 GUI 或 EXE 验收 |
| 依赖安全门禁 | 正式pin中的Pillow 12.3.0、setuptools 83.0.0安全阻塞保留；下述本机候选环境不代表正式门禁放行 |
| 本地EXE与剩余验收 | 原spec构建、实际归档检查、冻结CLI和可见GUI受控实测通过；真实断网离线验收NOT COVERED，真实DNS修复未授权，没有新版EXE Release |

S1 保持 **PENDING ACCEPTANCE**；完整 S1、S2、S3 和完整离线EXE验收均不能宣称 PASS。
上述结果是单独获准环境中的本地技术验证，不替用户接受完整阶段，也不代表当前或未来Head的GitHub CI已通过。正式Windows CI在既有依赖门禁失败后仍不安装、测试或打包。
仓库正式依赖 pin 未更新。另经明确的本机个人风险接受，独立测试环境采用 Python 3.14.10、PySide6/Qt 6.12.0、NumPy 2.5.4、ContourPy 1.3.3、Pillow 13.0.0、setuptools 84.1.0 和 pip 26.2.2 等40项已核验依赖；限定风险见 [SECURITY.md](SECURITY.md#本机非发布试用记录)。该环境及观察期例外不构成正式门禁 PASS，也不授权其他环境安装。
本地原始诊断报告、机器信息和测试日志不进入本仓库。

最终本机受控结果：完整保留套件619项测试及418项子测试通过，耗时140.22秒；原60秒真实CLI HTTP503定向用例与最终完整套件中的同一用例均通过。原spec完成本地非发布EXE构建，实际归档核对93个原生条目、126个数据条目，Qt XML未打包，原生来源与已审核文件一致。冻结CLI的60秒管道输出及5秒文件输出实测通过，所属Job进程归零；在源码不可用的工作目录和不提供Python PATH的条件下仍能运行。这些条件不等于真实断网离线验收。

可见EXE GUI使用打包默认配置、无Python PATH：默认60秒诊断约55.06秒返回，126条证据均按原规则确认可比，包含DNS/DNS6、ICMP、TCP/TCP6和HTTP；脱敏报告保存成功。模拟修复经独立确认显示simulated_success，随后单独60秒验证完成并保留inconclusive，未执行DNS清理。取消后约0.029秒返回；诊断运行中关闭窗口约0.365秒完成，窗口消失，核对的4个所属进程全部结束。默认60秒、300秒上限、Epoch及证据过滤均未放宽，证据不足仍显示UNKNOWN。

PR #6批次的最小修复针对采样与启动时序：在原预算内等待观察器就绪，区分Worker启动耗时与网络超时，预留关闭身份查询/清理时间，稳定优先目标协议。相邻轮仅在连续READY、相同观察器和generation下共用刚完成的真实身份边界；保留原查询时间，发生变化、盲区、失败或取消时重新查询或保持UNKNOWN，不伪造新鲜证据。

有限HTTPS对照保持完整证书与主机名验证：原目标example.com的产品请求与同IP、同地址族、SNI、ALPN和CA策略的标准库TLS均返回代码20；预选官方对照www.python.org的两条连接均通过TLS1.3验证，产品取得HTTP206且验证链指纹一致。这证明产品实际HTTPS路径可对该官方站点完成有效验证，不代表原目标已修复，也不能据此确定缺失证书或按目标网络干预的根因。没有修改系统信任、代理或DNS。模拟修复仍不修改系统。

历史结果索引（摘要保留于PR #6及私有恢复记录，旧测试工作区的原始日志已按用户授权清理）：早期完整套件595项通过、3项失败及405项子测试；精确去重与26项离线S2回归后，原60秒HTTP503用例仍未满足重复证据要求，无网络对照也未支持更换解释器，按当批上限停止。另获授权的最终三轮实现中，首轮完整套件612项通过、1项HTTP503失败及412项子测试，第二轮定向HTTP503仍失败；这些失败结论和累计投入没有改写为通过。最后一轮定向用例及最终完整套件才通过，仍要求30秒窗口内同Epoch、地址族和实际IP的两次TCP成功与两次HTTP503，不拼接旧测试或放宽断言。早期观察器盲区及用户主动120秒试用记录也保留，不能替代本次默认60秒结果。

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
本地单文件EXE已完成受控运行，但真实断网离线验收为NOT COVERED；源码不可用、无Python PATH和模拟离线均不能替代它。

## 中英文界面与用户摘要

本功能分支依赖尚未合并的 PR #6，沿用其采样修复；不从旧 main 覆盖诊断核心。
界面首次默认简体中文，可切换 English。语言选择只保存在本地界面偏好文件
`%LOCALAPPDATA%\Losshound\ui-language.json`，不会重写网络配置；切换语言不重启会话、延长预算或清除确认状态。

默认先显示用户摘要：总体观察、分项响应、疑似范围、最多三条相关确认步骤；技术详情可展开查看证据ID、协议、反证和局限。
摘要直接读取本轮结构化事实，分别呈现网络环境与 IPv4/IPv6，区分已响应、已观察异常但未定位、已有规则支持的疑似范围，以及未检测/工具错误/不可比较。
收到响应不代表全网健康；TCP成功不代表网页正常。未填写或未检测网站时会明确提示，不会自动添加探测目标。

JSON机器字段、状态码和证据ID不随语言切换；新增的固定消息ID只用于呈现，不参与故障条件。
未完成项没有安全原因类别时明确说明原因不可用，继续保护原始异常、网络身份和凭据。
两种语言下的修复均明确标记为模拟，真实DNS清理仍不可调用。

本双语候选在Windows/Python 3.14.10的完整保留套件666项通过，0失败、0跳过，140.29秒；55条既有弃用警告保留。对应产品提交`1a27a325e07f8ba33364e4b09ec0628f31282462`。真实源码GUI验证首次中文、运行中切换、完成后重呈现、语言记忆、取消/关闭与模拟确认/独立验证；同一报告在中英文下导出的JSON字节完全一致。个人候选EXE已按原spec构建，但安装生成的NumPy元数据及缓存对应核验未闭合，已按追加一次核验的停止条件暂停；新EXE尚未启动，冻结GUI/CLI、取消和清理均未计为通过。上述PR #6历史测试数不自动成为新版本通过证据。
正式依赖与Qt安全限制、真实离线/干净机器待验保持不变，个人候选不公开发布。
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
正式构建需要单独批准、已审核环境和通过的门禁。PR #6批次仅在单独接受限定风险的本机环境中，通过最终完整保留套件后完成原spec构建及归档检查；冻结EXE的--help、Qt离屏smoke、CLI管道/文件输出和可见GUI诊断、模拟确认/独立验证、取消及关闭清理均有实际通过证据。
没有上传或发布EXE/Release。真实断网离线运行、完整阶段接受和正式依赖门禁仍未完成；公开发布须另获授权，不能沿用本机例外。
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
