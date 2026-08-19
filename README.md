# DSH Security Audit

简体中文 | [English](README.en.md)

`dsh-security-audit` 是面向 [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) 的本地优先安全审计 Skill。它能够在不执行被审计代码的前提下，检查 DSH Skills、profile 插件、Bundle/Cordis 配置、MCP 服务、软件包供应链设置以及部分运行时暴露风险。

扫描器提供的是尽力而为的风险检测，而不是安全认证。报告没有发现并不能证明某个扩展绝对安全。

## 检查范围

- 硬编码 API Key、令牌、私钥、密码和其他密钥形态，并自动脱敏报告证据。
- 敏感环境变量或文件读取与外部网络 sink 同时出现的数据外传组合链。
- 下载后执行、动态求值、子进程、破坏性命令以及不透明二进制载荷。
- macOS LaunchAgents、systemd 用户服务、cron、Shell 启动文件、Git hooks、SSH 持久化、隧道和公开监听。
- 宿主根目录或容器 volume、Docker socket、远程/FUSE 挂载、Kubernetes 凭据以及提权能力。
- npm/pnpm 生命周期脚本、`allowBuilds`、浮动版本以及未固定到 commit 的远程依赖。
- DSH `dsh.bundle.patch`、Cordis `!!js`、危险权限组合、遥测导出和 profile 配置。
- MCP stdio 命令、包运行器、敏感环境变量透传以及不安全的远程 HTTP endpoint。
- Prompt injection、隐藏 HTML 指令、零宽/双向 Unicode、Base64/十六进制载荷及解码后的高风险内容。
- 可选 SHA-256 基线、Markdown/JSON/SARIF 输出、CI 严重度阈值和只读运行时姿态检查。

## DSH 专用安全假设

DSH 的 `workspace-write` 模式主要限制文件写入范围，它不会自动隔离文件读取、网络访问或进程可见性。本地凭据文档仍可能被同一 OS 用户身份运行的进程读取。MCP stdio 命令和获准的软件包生命周期脚本会在 agent 文件写入沙箱之外执行。

因此，本 Skill 永远不会导入被审计模块、运行软件包生命周期脚本、启动 MCP server 或执行扫描到的二进制文件。

## 安装

将仓库克隆到用户级 DSH Skill 根目录：

```sh
mkdir -p ~/.dsh/skills
git clone https://github.com/yhny1001/dsh-security-audit.git ~/.dsh/skills/dsh-security-audit
```

DSH 会将它识别为 `dsh-security-audit`。正在运行的 Web 进程通常会通过文件系统 watcher 发现新 Skill；如果没有出现，重启 DSH。

## 在 DSH 中使用

显式调用：

```text
/dsh-security-audit 审计当前 DSH 环境、相关 Skill 和插件，并包含运行时检查。
```

该 Skill 会指示 agent 运行内置的零依赖 Node.js 扫描器，在不执行可疑样本的情况下确认高风险发现，并生成包含证据的审计报告。

## 直接使用扫描器

需要 Node.js 22.19 或更高版本，与当前 DSH 的运行时最低版本一致。

```sh
node ~/.dsh/skills/dsh-security-audit/scripts/dsh-security-audit.mjs \
  --cwd "$PWD" \
  --runtime \
  --format markdown
```

在安装前扫描一个扩展目录：

```sh
node scripts/dsh-security-audit.mjs \
  --cwd "$PWD" \
  --target /path/to/untrusted-skill-or-plugin \
  --format json
```

CI/SARIF 示例：

```sh
node scripts/dsh-security-audit.mjs \
  --cwd "$PWD" \
  --format sarif \
  --output dsh-security-audit.sarif \
  --fail-on high
```

运行 `node scripts/dsh-security-audit.mjs --help` 可查看 profile 过滤、深层依赖扫描、报告格式、文件限制和基线选项。

## 基线

创建基线会写入只包含摘要的 JSON 文档，必须由操作者显式执行。基线文件应放在所有被扫描根目录之外：

```sh
node scripts/dsh-security-audit.mjs \
  --cwd "$PWD" \
  --write-baseline ../dsh-security-baseline.json \
  --format json
```

之后可以只读比较：

```sh
node scripts/dsh-security-audit.mjs \
  --cwd "$PWD" \
  --baseline ../dsh-security-baseline.json \
  --format markdown
```

## 设计与同类项目

本项目的威胁分类参考了 OWASP Agentic Skills Top 10、OWASP AI Agent Security、Cisco AI Defense Skill Scanner、NVIDIA SkillSpector 和 Snyk Agent Scan。实现代码为独立编写，并额外加入 DSH 专用的 profile、Bundle、Cordis、MCP、权限、遥测和凭据检查。

详细信息及一手资料链接见[风险模型](references/risk-model.md)和[同类工具说明](references/prior-art.md)。

## 局限性

- 正则和文件级 source/sink 关联不是完整的跨模块 taint analysis。
- 混淆、原生代码、运行时生成的载荷和新型攻击手法可能绕过静态分析。
- 运行时检查是某个时间点的快照，并受当前 OS 用户可见范围限制。
- 离线模式不会查询实时 CVE、软件包撤销、发布者信誉或恶意样本数据库。
- 高价值环境还应配合人工审查、不可变依赖固定、网络出口控制、隔离、EDR 和审计日志。

## 许可证

本项目基于 [MIT License](LICENSE) 开源。
