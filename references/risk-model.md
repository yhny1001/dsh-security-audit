# DSH 专用风险模型

## DSH 资产与信任边界

审计器保护的主要资产是 API 密钥、SSH/云凭据、浏览器与开发者会话、私有源码、会话记录、工作区文件、宿主机执行权限和 DSH profile 完整性。

DSH 的扩展面包括：

- 项目与用户 Skill 根：`.dsh/skills`、`.agents/skills`、`$DSH_HOME/skills`、`$DSH_AGENTS_HOME/skills`。
- profile：`$DSH_HOME/profiles/<name>/package.json`、`pnpm-workspace.yaml`、`cordis.patch.yml`、`cordis.yml` 和 profile `node_modules`。
- Bundle：npm 包中声明的 `dsh.bundle.patch` 及其 Cordis patch/plugin 入口。
- MCP：`@deepseek-ai/dsh-mcp-client` 的 stdio 命令、参数、环境变量或 HTTP URL/Headers。
- 主机状态：DSH 进程树、监听端口、引用 DSH/插件路径的用户级持久化项，以及覆盖工作区/DSH Home 的远程挂载。

## 必查组合链

### 1. 私密数据 + 不可信内容 + 外联

这是 agent 扩展最危险的组合。敏感源包括环境变量、`.env`、`~/.dsh/.credentials.yaml`、SSH/云/钱包/浏览器凭据、会话与私有仓库；外联 sink 包括 `fetch`、HTTP/WebSocket/DNS、curl/wget/nc、Webhook、遥测和远程 MCP。两个信号出现在同一文件或可追踪调用链时应提高严重度。

### 2. 远程输入 + 执行

检查网络响应、下载文件、Base64/十六进制解码结果或用户输入是否进入 `eval`、`Function`、`vm`、`child_process`、shell、PowerShell、Python `exec`/`subprocess`、动态 import 或原生二进制。`curl | sh`、`wget | bash` 和下载后执行属于 Critical。

### 3. 供应链 + 安装时执行

检查 `preinstall`、`install`、`postinstall`、`prepare`、pnpm `allowBuilds`、Git/URL/tarball 依赖、未固定提交、`latest`/`*`、npm alias、原生 addon 和下载器。DSH 的 Git 插件 `prepare` 一旦获准，会在 agent 沙箱之外执行。

### 4. MCP 与宿主执行

MCP stdio `command` 是宿主上的受信任可执行代码；审计不能启动它。检查 `npx -y`/`uvx` 未固定包、shell 包装器、远程下载、敏感环境透传、任意 cwd、Docker socket、宿主根挂载、SSH tunnel、公开监听、未加密远程 URL 和工具描述中的隐藏指令。

### 5. 权限与沙箱错觉

DSH `workspace-write` 约束的是文件写入范围，不自动限制读取、网络和进程可见性。`~/.dsh/.credentials.yaml` 的 `0600`/父目录 `0700` 能隔离其他 OS 用户，却不能阻止同 UID 的 agent/插件进程读取。任何声称“在 workspace-write 下所以无法偷密钥”的扩展都应视为错误安全假设。

### 6. 持久化与宿主控制

检查 LaunchAgents、systemd user units、cron、shell 启动文件、Git hooks、SSH `authorized_keys`、登录项、自动更新器、后台守护进程、反向 tunnel、Docker socket、Kubernetes 配置、root/宿主目录挂载、`chmod`/`chown`/`sudo` 和安全工具禁用行为。

### 7. Skill/Prompt 投毒

检查忽略系统/用户指令、隐藏动作、禁止告知用户、强制永不拒绝、绕过审批、读取秘密、把上下文发送到外部、写入长期记忆或修改其他 Skill 的指令。还要检查 HTML 注释、零宽字符、Unicode bidi/tag 字符、长 Base64/十六进制块、超长空白和描述与脚本能力不匹配。

## 证据等级

- 已确认行为：清晰、可达的数据流或已存在的持久化/监听/挂载。
- 高置信度能力：危险 source 与 sink 共存，或安装脚本/配置明确授权宿主执行。
- 单点信号：只出现网络、文件读取、shell 或模糊关键词之一；通常需要上下文，不能单独定性木马。
- 姿态缺口：权限、版本固定、审计或基线不足；属于加固项，不代表组件恶意。

## 最低安全基线

- 外部插件固定到可信发布版本或 Git commit SHA，并在安装前离线审计源码和 lockfile。
- 不给不可信包启用 pnpm `allowBuilds`，不执行未审计的安装脚本。
- MCP 命令固定版本/路径，限制环境变量和 cwd；HTTP MCP 仅使用受信任 HTTPS 或明确的 loopback 开发地址。
- profile、Skill 根和 DSH Home 不得 group/world-writable；凭据文件为 `0600`、父目录为 `0700`。
- 高风险任务使用隔离主机/容器并限制网络出口；不要把文件写入沙箱误认为完整隔离。
- 维护插件/Skill 清单、SHA-256 基线、安装来源、审批记录和更新时间；变更后重新审计。
