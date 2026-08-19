# 同类工具与规则来源

本 Skill 的实现不复制第三方扫描器代码；规则类别参考公开的一手项目与标准，并增加 DSH profile、Cordis patch、`!!js`、MCP 配置、权限预设和凭据层的专用检查。

## 同类开源工具

- Cisco AI Defense Skill Scanner：`https://github.com/cisco-ai-defense/skill-scanner`
  - 静态规则、YARA、行为数据流和可选 LLM/云分析。
  - 明确声明扫描是 best-effort，不能证明 Skill 安全，仍需人工复核。
- NVIDIA SkillSpector：`https://github.com/NVIDIA/skillspector`
  - 覆盖 prompt injection、凭据外传、供应链、危险代码、taint tracking、YARA、MCP least privilege 和 tool poisoning。
  - 支持 JSON、Markdown、SARIF、基线和可选 OSV/LLM；这些能力启发了本地报告与组合链检查。
- Snyk Agent Scan：`https://github.com/snyk/agent-scan`
  - 自动发现 Agent、MCP 和 Skills，覆盖恶意载荷、敏感数据和 prompt injection。
  - 其文档警告：动态扫描 MCP 会执行配置中的 server 命令。本 Skill 因此坚持不启动待审计 MCP。

## 标准与威胁模型

- OWASP Agentic Skills Top 10：`https://owasp.org/www-project-agentic-skills-top-10/`
  - 强调安装前扫描、版本固定、权限清单、隔离、网络限制、运行监控和持续清点。
- OWASP AI Agent Security Cheat Sheet：`https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html`
  - 覆盖最小权限、prompt injection、memory/context、人工确认、数据保护、监控和对抗测试。
- OWASP NPM Security Cheat Sheet：`https://cheatsheetseries.owasp.org/cheatsheets/NPM_Security_Cheat_Sheet.html`
  - 覆盖 lockfile、可复现安装、生命周期脚本和供应链风险。
- OpenSSF Scorecard：`https://github.com/ossf/scorecard`
  - 可作为发布者和仓库工程实践的外部信誉信号，但不能替代本地源码审计。
- OSV：`https://osv.dev/`
  - 可选在线依赖漏洞查询。离线审计不能把“未查询 OSV”误报成“无已知漏洞”。

## DSH 一手资料

- 官方仓库：`https://github.com/deepseek-ai/deepseek-harness`
- Skill 子系统：`docs/subsystems/skills.md`
- 插件打包与安装：`docs/user/develop/basic/publish.md`
- CLI/profile/MCP 与部署行为：`apps/cli/reference/README.md`
- 进程沙箱：`docs/subsystems/sandbox.md`
- 本地凭据安全边界：`packages/credentials/credentials-local/README.md`
- MCP 客户端：`packages/mcp/mcp-client/README.md`

## 局限性

- 正则与文件级 source/sink 关联不是完整的跨模块 taint analysis，会有误报和漏报。
- 混淆、动态下载、运行时生成代码、原生二进制和零日手法可能绕过静态检查。
- 运行时快照只能看到当时存在且当前用户可观察的进程、监听、挂载和持久化项。
- 本地扫描不查询撤包、发布者信誉、签名、CVE 或恶意样本数据库；需要联网时必须由用户授权并固定外部工具版本。
- 无发现不能作为安装批准的唯一依据。高价值环境应结合人工代码审查、隔离试运行、网络出口控制和 EDR/审计日志。
