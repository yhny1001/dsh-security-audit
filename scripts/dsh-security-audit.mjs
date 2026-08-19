#!/usr/bin/env node

/**
 * Read-only static and runtime posture scanner for DeepSeek Harness skills,
 * profile plugins, Cordis patches, MCP configuration, and host exposure.
 * The scanner never imports or executes target code.
 */

import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { existsSync } from 'node:fs'
import { lstat, mkdir, readFile, readdir, realpath, stat, writeFile } from 'node:fs/promises'
import { homedir, platform } from 'node:os'
import { basename, dirname, extname, isAbsolute, join, relative, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'

const VERSION = '1.0.0'
const SELF_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const SEVERITY_ORDER = Object.freeze({ critical: 0, high: 1, medium: 2, low: 3 })
const SEVERITY_WEIGHT = Object.freeze({ critical: 50, high: 25, medium: 10, low: 5 })
const DEFAULT_MAX_FILE_BYTES = 2 * 1024 * 1024
const DEFAULT_MAX_FILES = 20_000

const TEXT_EXTENSIONS = new Set([
  '', '.bash', '.cjs', '.conf', '.css', '.env', '.html', '.ini', '.js', '.json', '.jsx', '.md', '.mjs',
  '.plist', '.ps1', '.py', '.sh', '.toml', '.ts', '.tsx', '.txt', '.xml', '.yaml', '.yml', '.zsh',
])
const OPAQUE_EXECUTABLE_EXTENSIONS = new Set([
  '.class', '.dll', '.dylib', '.exe', '.jar', '.node', '.so', '.wasm',
])
const SKIP_DIRS = new Set([
  '.git', '.hg', '.svn', '.turbo', '.vite', 'coverage', 'dist', 'lib', 'out', 'target',
])
const SENSITIVE_CONFIG_BASENAMES = new Set([
  '.env', '.npmrc', '.pypirc', '.credentials.yaml', 'credentials.json', 'id_rsa', 'id_ed25519',
])

const SECRET_PATTERNS = [
  /-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/i,
  /\bAKIA[0-9A-Z]{16}\b/,
  /\bASIA[0-9A-Z]{16}\b/,
  /\bgh[pousr]_[A-Za-z0-9]{30,}\b/,
  /\bgithub_pat_[A-Za-z0-9_]{40,}\b/,
  /\bxox[baprs]-[A-Za-z0-9-]{20,}\b/,
  /\bsk-[A-Za-z0-9_-]{24,}\b/,
  /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/,
  /\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|password|private[_-]?key)\s*[:=]\s*["']?[A-Za-z0-9_+/.=-]{16,}/i,
]

const SENSITIVE_SOURCE_PATTERNS = [
  /\bprocess\.env\b/, /\bDeno\.env\b/, /\bos\.environ\b/, /\bgetenv\s*\(/,
  /(?:~|\$HOME|homedir\(\))\/?\.(?:ssh|aws|azure|config|gnupg|kube|docker)/i,
  /\.dsh\/(?:\.credentials\.yaml|\.env|storages|sessions)/i,
  /(?:Login Data|Cookies|Keychains?|wallet\.dat|credentials\.json|id_(?:rsa|ed25519))/i,
  /security\s+(?:find-generic-password|dump-keychain)/i,
]
const FILE_READ_PATTERNS = [
  /\breadFile(?:Sync)?\s*\(/, /\bcreateReadStream\s*\(/, /\bopenSync\s*\(/,
  /\bfs\.read\b/, /\bPath\([^\n]+\)\.read_(?:text|bytes)\b/, /\bopen\([^\n]+["']r/,
  /\bcat\s+(?:~|\$HOME|\/)/, /\bfind\s+(?:~|\$HOME|\/)/,
]
const NETWORK_SINK_PATTERNS = [
  /\bfetch\s*\(/, /\baxios(?:\.|\s*\()/, /\bhttps?\.(?:request|get)\s*\(/,
  /\bnet\.(?:connect|createConnection)\s*\(/, /\bdgram\.createSocket\s*\(/,
  /\bWebSocket\s*\(/, /\brequests\.(?:get|post|put|request)\s*\(/,
  /\b(?:curl|wget|nc|ncat|netcat|socat|scp|rsync)\b/i,
  /\b(?:webhook|telemetry|otlp|collector|exfiltrat)\b/i,
]
const SUBPROCESS_PATTERNS = [
  /(?:node:)?child_process/, /\b(?:exec|execFile|spawn|fork)(?:Sync)?\s*\(/,
  /\bshell\s*:\s*true\b/, /\bos\.(?:system|popen)\s*\(/, /\bsubprocess\.(?:run|Popen|call)\s*\(/,
  /\b(?:bash|sh|zsh|pwsh|powershell)\s+(?:-[lc]|\/c)\b/i,
]
const DYNAMIC_EXEC_PATTERNS = [
  /\beval\s*\(/, /\bnew\s+Function\s*\(/, /\bFunction\s*\([^)]*\)\s*\(/,
  /\bvm\.(?:runIn|compileFunction|Script)\b/, /\bexec\s*\(/,
  /Buffer\.from\([^\n]+["']base64["']\)[^\n]*(?:eval|Function|exec|spawn)/i,
]
const DOWNLOAD_EXEC_PATTERNS = [
  /\b(?:curl|wget)\b[^\n|;&]*(?:\||&&|;)\s*(?:sudo\s+)?(?:bash|sh|zsh|pwsh|powershell|python|node)\b/i,
  /\b(?:curl|wget)\b[^\n]+\s-o\s+[^\n]+(?:&&|;)\s*(?:chmod\s+\+x\s+)?[^\n]*(?:\.\/|bash|sh|node|python)/i,
  /Invoke-WebRequest[^\n]+(?:Invoke-Expression|iex|Start-Process)/i,
]
const PERSISTENCE_PATTERNS = [
  /\blaunchctl\b|Library\/LaunchAgents|Library\/LaunchDaemons/i,
  /\bcrontab\b|\/etc\/cron\.|\.config\/systemd\/user/i,
  /(?:(?:^|[\/~])\.(?:bashrc|zshrc|profile)\b|authorized_keys|login items?|schtasks|Run\\)/im,
  /(?:core\.hooksPath|\.git\/hooks|(?:cp|mv|install|writeFile)[^\n]{0,80}(?:post-checkout|pre-commit)|(?:post-checkout|pre-commit)[^\n]{0,80}(?:chmod|writeFile|cat\s*>))/i,
]
const PRIVILEGE_PATTERNS = [
  /\bsudo\b|\bdoas\b|\bpkexec\b/, /\bchmod\s+(?:777|[ugo]*\+s)\b/i,
  /\bchown\s+(?:root|0)(?::|\s)/i, /\/var\/run\/docker\.sock|\/run\/containerd/i,
  /(?:disable|stop|unload)[^\n]{0,40}(?:firewall|antivirus|defender|edr|gatekeeper|xprotect)/i,
]
const MOUNT_PATTERNS = [
  /\bmount\s+(?:-[^\s]+\s+)*(?:\/|~|\$HOME)/, /\/etc\/fstab|diskutil\s+mount/i,
  /(?:docker|podman)\s+run[^\n]*(?:-v|--volume)\s+(?:\/|~|\$HOME)/i,
  /(?:-v|--volume)[=\s]+\/:\/?(?:host|root|mnt)?\b/i,
  /\/var\/run\/docker\.sock|\.kube\/config|\bsshfs\b|\brclone\s+mount\b/i,
]
const SERVER_PATTERNS = [
  /(?:listen|host|bind)(?:\s*[:=(]|\s+)["']?(?:0\.0\.0\.0|::|\*)/i,
  /\b(?:ngrok|cloudflared|frpc?|localtunnel|serveo)\b/i,
  /\bssh\b[^\n]*(?:\s-[LRD]\s*|\s-[oO]\s*RemoteForward)/,
  /\b(?:reverse shell|bind shell)\b/i,
]
const DESTRUCTIVE_PATTERNS = [
  /\brm\s+-[A-Za-z]*r[A-Za-z]*f[A-Za-z]*\s+(?:\/|~|\$HOME|\.\.)/,
  /\b(?:diskutil\s+erase|mkfs(?:\.|\s)|format\s+[A-Z]:|dd\s+if=.*\s+of=\/dev\/)/i,
  /\bfs\.(?:rm|rmdir)(?:Sync)?\([^\n]+recursive\s*:\s*true/i,
  /\b(?:encrypt|ransom)[^\n]{0,60}(?:files?|directory|wallet)/i,
]
const PROMPT_OVERRIDE_PATTERNS = [
  /\bignore\s+(?:all\s+)?(?:previous|prior|system|developer|user)\s+(?:instructions?|messages?|prompts?)/i,
  /\b(?:do not|never)\s+(?:tell|inform|warn|ask|show)\s+(?:the\s+)?user\b/i,
  /\b(?:bypass|disable|evade|ignore)\s+(?:the\s+)?(?:sandbox|approval|permissions?|safety|guardrails?)/i,
  /\b(?:never refuse|always comply|no restrictions?|developer mode|jailbreak)\b/i,
  /\b(?:must|always|immediately|silently)\s+(?:reveal|print|expose|leak)\s+(?:the\s+)?(?:system prompt|hidden instructions?|chain of thought|credentials?|secrets?)/i,
]
const OBFUSCATION_PATTERNS = [
  /\b(?:atob|fromBase64|base64\s+-d|xxd\s+-r|certutil\s+-decode)\b/i,
  /(?:[A-Za-z0-9+/]{160,}={0,2})/,
  /(?:\b[0-9a-fA-F]{240,}\b)/,
  /(?:\\x[0-9a-fA-F]{2}){24,}/,
]

function usage() {
  return `DSH Security Audit ${VERSION}

Usage:
  node dsh-security-audit.mjs [options]

Options:
  --cwd <path>              Workspace used for DSH project-skill discovery
  --dsh-home <path>         DSH home (default: $DSH_HOME or ~/.dsh)
  --agents-home <path>      Shared agents home (default: $DSH_AGENTS_HOME or ~/.agents)
  --profile <name>          Scan only one DSH profile (repeatable)
  --target <path>           Add an untrusted skill/plugin/file target (repeatable)
  --include-official        Scan @deepseek-ai package bodies, not only inventory/config
  --deep                    Scan transitive node_modules below third-party plugin packages
  --runtime                 Add read-only process/listener/mount/persistence checks
  --format <markdown|json|sarif>
  --output <path>           Write report instead of stdout
  --baseline <path>         Compare a prior SHA-256 baseline
  --write-baseline <path>   Write a digest-only baseline outside scanned roots
  --fail-on <off|critical|high|medium|low>
  --max-file-bytes <n>      Per-file text scan limit (default: ${DEFAULT_MAX_FILE_BYTES})
  --max-files <n>           Total file limit (default: ${DEFAULT_MAX_FILES})
  --help                    Show this help
  --version                 Show version

The scanner does not execute target code, lifecycle scripts, or MCP servers.`
}

function parseArgs(argv) {
  const invocationCwd = process.cwd()
  const options = {
    invocationCwd,
    cwd: invocationCwd,
    dshHome: process.env.DSH_HOME || join(homedir(), '.dsh'),
    agentsHome: process.env.DSH_AGENTS_HOME || join(homedir(), '.agents'),
    profiles: [],
    targets: [],
    includeOfficial: false,
    deep: false,
    runtime: false,
    format: 'markdown',
    output: undefined,
    baseline: undefined,
    writeBaseline: undefined,
    failOn: 'off',
    maxFileBytes: DEFAULT_MAX_FILE_BYTES,
    maxFiles: DEFAULT_MAX_FILES,
  }
  const valueOptions = new Map([
    ['--cwd', 'cwd'], ['--dsh-home', 'dshHome'], ['--agents-home', 'agentsHome'],
    ['--format', 'format'], ['--output', 'output'], ['--baseline', 'baseline'],
    ['--write-baseline', 'writeBaseline'], ['--fail-on', 'failOn'],
    ['--max-file-bytes', 'maxFileBytes'], ['--max-files', 'maxFiles'],
  ])
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i]
    if (arg === '--help') return { action: 'help' }
    if (arg === '--version') return { action: 'version' }
    if (arg === '--include-official') { options.includeOfficial = true; continue }
    if (arg === '--deep') { options.deep = true; continue }
    if (arg === '--runtime') { options.runtime = true; continue }
    if (arg === '--profile' || arg === '--target') {
      const next = argv[++i]
      if (next === undefined) throw new Error(`${arg} requires a value`)
      options[arg === '--profile' ? 'profiles' : 'targets'].push(next)
      continue
    }
    const key = valueOptions.get(arg)
    if (key !== undefined) {
      const next = argv[++i]
      if (next === undefined) throw new Error(`${arg} requires a value`)
      options[key] = next
      continue
    }
    throw new Error(`unknown option: ${arg}`)
  }
  options.cwd = resolve(options.cwd)
  options.dshHome = resolve(options.dshHome)
  options.agentsHome = resolve(options.agentsHome)
  options.targets = options.targets.map(target => resolve(invocationCwd, target))
  if (!['markdown', 'json', 'sarif'].includes(options.format)) throw new Error(`invalid --format: ${options.format}`)
  if (!['off', 'critical', 'high', 'medium', 'low'].includes(options.failOn)) throw new Error(`invalid --fail-on: ${options.failOn}`)
  options.maxFileBytes = parsePositiveInteger(options.maxFileBytes, '--max-file-bytes')
  options.maxFiles = parsePositiveInteger(options.maxFiles, '--max-files')
  return { action: 'scan', options }
}

function parsePositiveInteger(value, name) {
  const parsed = Number.parseInt(String(value), 10)
  if (!Number.isSafeInteger(parsed) || parsed <= 0) throw new Error(`${name} must be a positive integer`)
  return parsed
}

function normalizePath(value) {
  const home = homedir()
  return value === home ? '~' : value.startsWith(`${home}${sep}`) ? `~${sep}${relative(home, value)}` : value
}

function isWithin(root, target) {
  const rel = relative(resolve(root), resolve(target))
  return rel === '' || (!rel.startsWith(`..${sep}`) && rel !== '..' && !isAbsolute(rel))
}

function lineNumber(text, index) {
  let line = 1
  for (let i = 0; i < index; i += 1) if (text.charCodeAt(i) === 10) line += 1
  return line
}

function firstMatch(text, patterns) {
  for (const pattern of patterns) {
    const match = pattern.exec(text)
    if (match !== null) return { match: match[0], index: match.index, pattern }
  }
  return undefined
}

function maskSensitive(value) {
  let text = String(value)
  text = text.replace(/-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/gi, '[REDACTED PRIVATE KEY HEADER]')
  text = text.replace(/\bAKIA[0-9A-Z]{16}\b/g, 'AKIA…[REDACTED]')
  text = text.replace(/\bASIA[0-9A-Z]{16}\b/g, 'ASIA…[REDACTED]')
  text = text.replace(/\bgh[pousr]_[A-Za-z0-9]{20,}\b/g, 'gh…[REDACTED]')
  text = text.replace(/\bgithub_pat_[A-Za-z0-9_]{20,}\b/g, 'github_pat…[REDACTED]')
  text = text.replace(/\bxox[baprs]-[A-Za-z0-9-]{16,}\b/g, 'xox…[REDACTED]')
  text = text.replace(/\bsk-[A-Za-z0-9_-]{16,}\b/g, 'sk-…[REDACTED]')
  text = text.replace(/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g, 'eyJ…[REDACTED JWT]')
  text = text.replace(/((?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|password|private[_-]?key)\s*[:=]\s*)[^\s,;]+/gi, '$1[REDACTED]')
  text = text.replace(/([?&](?:token|key|secret|password|auth)=)[^&\s]+/gi, '$1[REDACTED]')
  return text.length > 260 ? `${text.slice(0, 257)}…` : text
}

function evidenceLine(text, index) {
  const start = text.lastIndexOf('\n', Math.max(0, index - 1)) + 1
  const endIndex = text.indexOf('\n', index)
  return maskSensitive(text.slice(start, endIndex === -1 ? text.length : endIndex).trim())
}

function fingerprint(parts) {
  return createHash('sha256').update(parts.join('\0')).digest('hex').slice(0, 16)
}

function sha256(buffer) {
  return createHash('sha256').update(buffer).digest('hex')
}

function createState(options) {
  return {
    options,
    startedAt: new Date().toISOString(),
    findings: [],
    findingKeys: new Set(),
    errors: [],
    scopes: [],
    scopeKeys: new Set(),
    profiles: [],
    plugins: [],
    skills: [],
    files: [],
    fileKeys: new Set(),
    fileCount: 0,
    skippedCount: 0,
    pluginNames: new Set(),
  }
}

function addFinding(state, finding) {
  const pathValue = finding.path ? resolve(finding.path) : undefined
  const evidence = maskSensitive(finding.evidence ?? '')
  const key = [finding.id, pathValue ?? '', String(finding.line ?? ''), evidence].join('|')
  if (state.findingKeys.has(key)) return
  state.findingKeys.add(key)
  state.findings.push({
    id: finding.id,
    severity: finding.severity,
    category: finding.category,
    title: finding.title,
    path: pathValue,
    line: finding.line,
    evidence,
    impact: finding.impact,
    recommendation: finding.recommendation,
    confidence: finding.confidence ?? 'medium',
    fingerprint: fingerprint([finding.id, pathValue ?? '', String(finding.line ?? ''), evidence]),
  })
}

function addError(state, message, pathValue) {
  state.errors.push({ message: maskSensitive(message), path: pathValue ? resolve(pathValue) : undefined })
}

async function nearestGitRoot(start) {
  let current = resolve(start)
  while (true) {
    if (existsSync(join(current, '.git'))) return current
    const parent = dirname(current)
    if (parent === current) return resolve(start)
    current = parent
  }
}

async function safeRealpath(value) {
  try { return await realpath(value) } catch { return resolve(value) }
}

async function addScope(state, scope) {
  const absolute = resolve(scope.path)
  const actual = await safeRealpath(absolute)
  if (actual === await safeRealpath(SELF_ROOT)) return
  const key = `${scope.kind}:${actual}`
  if (state.scopeKeys.has(key)) return
  state.scopeKeys.add(key)
  state.scopes.push({ ...scope, path: absolute, realpath: actual })
}

async function discoverSkillRoot(state, root, source) {
  if (!existsSync(root)) return
  let entries
  try { entries = await readdir(root, { withFileTypes: true }) } catch (error) { addError(state, `cannot list skill root: ${error.message}`, root); return }
  for (const entry of entries) {
    if (source === 'user-dsh' && entry.name === '.system') continue
    const target = join(root, entry.name)
    if (entry.isDirectory() && existsSync(join(target, 'SKILL.md'))) {
      state.skills.push({ name: entry.name, source, path: target })
      await addScope(state, { path: target, kind: 'skill', source, trust: 'untrusted', recurse: true })
    } else if (entry.isFile() && extname(entry.name).toLowerCase() === '.md') {
      state.skills.push({ name: basename(entry.name, '.md'), source, path: target })
      await addScope(state, { path: target, kind: 'skill', source, trust: 'untrusted', recurse: false })
    }
  }
}

async function readJson(state, filename) {
  try { return JSON.parse(await readFile(filename, 'utf8')) } catch (error) { addError(state, `invalid JSON: ${error.message}`, filename); return undefined }
}

function packageDir(profileDir, packageName) {
  return join(profileDir, 'node_modules', ...packageName.split('/'))
}

async function discoverProfiles(state) {
  const profilesRoot = join(state.options.dshHome, 'profiles')
  if (!existsSync(profilesRoot)) return
  let entries
  try { entries = await readdir(profilesRoot, { withFileTypes: true }) } catch (error) { addError(state, `cannot list profiles: ${error.message}`, profilesRoot); return }
  const filter = new Set(state.options.profiles)
  for (const entry of entries) {
    if (!entry.isDirectory() || (filter.size > 0 && !filter.has(entry.name))) continue
    const dir = join(profilesRoot, entry.name)
    const manifestPath = join(dir, 'package.json')
    if (!existsSync(manifestPath)) continue
    const manifest = await readJson(state, manifestPath)
    if (manifest === undefined) continue
    const dependencies = manifest.dependencies ?? {}
    const bundles = manifest.dsh?.profile?.bundles ?? []
    state.profiles.push({ name: entry.name, path: dir, dependencies, bundles })
    for (const file of ['package.json', 'pnpm-workspace.yaml', 'cordis.patch.yml', 'cordis.yml']) {
      const filename = join(dir, file)
      if (existsSync(filename)) await addScope(state, { path: filename, kind: 'profile-config', profile: entry.name, trust: 'local-config', recurse: false })
    }
    for (const [name, spec] of Object.entries(dependencies)) {
      state.pluginNames.add(name)
      const official = name.startsWith('@deepseek-ai/')
      const dirPath = packageDir(dir, name)
      state.plugins.push({ name, spec: String(spec), profile: entry.name, path: dirPath, official, direct: true })
      if (existsSync(dirPath) && (!official || state.options.includeOfficial)) {
        await addScope(state, { path: dirPath, kind: 'plugin', profile: entry.name, packageName: name, trust: official ? 'official' : 'third-party', recurse: true })
      }
    }
    for (const bundle of bundles) {
      if (typeof bundle !== 'string' || bundle.startsWith('@deepseek-ai/')) continue
      state.pluginNames.add(bundle)
      const dirPath = packageDir(dir, bundle)
      if (!state.plugins.some(item => item.profile === entry.name && item.name === bundle)) {
        state.plugins.push({ name: bundle, spec: '(bundle)', profile: entry.name, path: dirPath, official: false, direct: true })
      }
      if (existsSync(dirPath)) await addScope(state, { path: dirPath, kind: 'plugin', profile: entry.name, packageName: bundle, trust: 'third-party', recurse: true })
    }
  }
  const homePatch = join(state.options.dshHome, 'cordis.patch.yml')
  if (existsSync(homePatch)) await addScope(state, { path: homePatch, kind: 'home-config', trust: 'local-config', recurse: false })
}

async function discoverScopes(state) {
  const projectRoot = await nearestGitRoot(state.options.cwd)
  state.projectRoot = projectRoot
  await discoverSkillRoot(state, join(projectRoot, '.dsh', 'skills'), 'project-dsh')
  await discoverSkillRoot(state, join(projectRoot, '.agents', 'skills'), 'project-agents')
  await discoverSkillRoot(state, join(state.options.dshHome, 'skills'), 'user-dsh')
  await discoverSkillRoot(state, join(state.options.agentsHome, 'skills'), 'user-agents')
  await discoverProfiles(state)
  for (const target of state.options.targets) {
    if (!existsSync(target)) { addError(state, 'target does not exist', target); continue }
    await addScope(state, { path: target, kind: 'target', trust: 'untrusted', recurse: true })
  }
}

function shouldSkipDirectory(name, scope, options) {
  if (name === 'node_modules') return !(options.deep && scope.kind === 'plugin')
  if (SKIP_DIRS.has(name)) {
    if (scope.kind === 'plugin' && (name === 'lib' || name === 'dist')) return false
    return true
  }
  return false
}

async function scanScope(state, scope) {
  let metadata
  try { metadata = await lstat(scope.path) } catch (error) { addError(state, `cannot stat scope: ${error.message}`, scope.path); return }
  if (metadata.isFile() || metadata.isSymbolicLink()) {
    await scanEntry(state, scope.path, scope, scope.realpath ?? scope.path)
    return
  }
  await scanDirectory(state, scope.path, scope, scope.realpath ?? scope.path)
}

async function scanDirectory(state, directory, scope, boundaryRoot) {
  if (state.fileCount >= state.options.maxFiles) return
  let entries
  try { entries = await readdir(directory, { withFileTypes: true }) } catch (error) { addError(state, `cannot list directory: ${error.message}`, directory); return }
  for (const entry of entries) {
    if (state.fileCount >= state.options.maxFiles) break
    const filename = join(directory, entry.name)
    if (entry.isDirectory()) {
      if (!shouldSkipDirectory(entry.name, scope, state.options)) await scanDirectory(state, filename, scope, boundaryRoot)
    } else {
      await scanEntry(state, filename, scope, boundaryRoot)
    }
  }
}

async function scanEntry(state, filename, scope, boundaryRoot) {
  let metadata
  try { metadata = await lstat(filename) } catch (error) { addError(state, `cannot stat file: ${error.message}`, filename); return }
  if (metadata.isSymbolicLink()) {
    let target
    try { target = await realpath(filename) } catch (error) { addFinding(state, {
      id: 'SYMLINK-001', severity: 'high', category: 'filesystem', title: 'Broken or unreadable symbolic link',
      path: filename, evidence: error.message, impact: 'A package may redirect expected resources or fail differently at runtime.',
      recommendation: 'Remove the link or replace it with a reviewed in-bound resource.', confidence: 'high',
    }); return }
    if (!isWithin(boundaryRoot, target)) addFinding(state, {
      id: 'SYMLINK-002', severity: 'high', category: 'filesystem', title: 'Symbolic link escapes the scanned package/skill root',
      path: filename, evidence: `target: ${normalizePath(target)}`,
      impact: 'The extension can smuggle host files or mutable code from outside the reviewed artifact.',
      recommendation: 'Require an in-root regular file or explicitly review and pin the external target.', confidence: 'high',
    })
    return
  }
  if (!metadata.isFile()) return
  const key = resolve(filename)
  if (state.fileKeys.has(key)) return
  state.fileKeys.add(key)
  state.fileCount += 1
  if ((metadata.mode & 0o002) !== 0) addFinding(state, {
    id: 'MODE-001', severity: 'high', category: 'permissions', title: 'Extension file is world-writable', path: filename,
    evidence: `mode ${(metadata.mode & 0o777).toString(8)}`,
    impact: 'Another local process or user may replace reviewed code or configuration after approval.',
    recommendation: 'Remove world-write permission and restore from a trusted source.', confidence: 'high',
  })
  const extension = extname(filename).toLowerCase()
  if (OPAQUE_EXECUTABLE_EXTENSIONS.has(extension)) {
    const buffer = metadata.size <= state.options.maxFileBytes ? await readFile(filename) : Buffer.alloc(0)
    state.files.push({ path: key, size: metadata.size, sha256: buffer.length > 0 ? sha256(buffer) : undefined, scope: scope.kind })
    addFinding(state, {
      id: 'BINARY-001', severity: 'high', category: 'malware', title: 'Opaque executable or native payload requires independent analysis',
      path: filename, evidence: `${extension || 'binary'} file, ${metadata.size} bytes`,
      impact: 'Static text rules cannot determine whether the payload steals data, persists, or controls the host.',
      recommendation: 'Do not execute it; verify publisher signature/hash and scan in an isolated malware-analysis environment.', confidence: 'high',
    })
    return
  }
  if (!TEXT_EXTENSIONS.has(extension) && metadata.size > 0) {
    state.skippedCount += 1
    return
  }
  if (metadata.size > state.options.maxFileBytes) {
    state.skippedCount += 1
    addFinding(state, {
      id: 'SCAN-001', severity: 'medium', category: 'coverage', title: 'File exceeds static scan limit', path: filename,
      evidence: `${metadata.size} bytes > ${state.options.maxFileBytes}`,
      impact: 'Malicious content could be hidden beyond the inspected size boundary.',
      recommendation: 'Review the file separately or rerun with a larger --max-file-bytes limit.', confidence: 'high',
    })
    return
  }
  let buffer
  try { buffer = await readFile(filename) } catch (error) { addError(state, `cannot read file: ${error.message}`, filename); return }
  const digest = sha256(buffer)
  state.files.push({ path: key, size: metadata.size, sha256: digest, scope: scope.kind })
  if (buffer.includes(0)) {
    if ((metadata.mode & 0o111) !== 0) addFinding(state, {
      id: 'BINARY-002', severity: 'high', category: 'malware', title: 'Unrecognized executable binary', path: filename,
      evidence: `executable mode ${(metadata.mode & 0o777).toString(8)}, ${metadata.size} bytes`,
      impact: 'The executable cannot be reviewed by this text scanner and may perform arbitrary host actions.',
      recommendation: 'Do not execute it; verify provenance and analyze it in isolation.', confidence: 'high',
    })
    return
  }
  const text = buffer.toString('utf8')
  await scanText(state, filename, text, scope)
  if (basename(filename) === 'package.json') await scanPackageManifest(state, filename, text, scope)
  if (basename(filename) === 'pnpm-workspace.yaml') scanAllowBuilds(state, filename, text)
  if (/\.(?:ya?ml)$/.test(extension) || basename(filename).startsWith('cordis.')) scanDshConfig(state, filename, text, scope)
}

async function scanText(state, filename, text, scope) {
  const secret = firstMatch(text, SECRET_PATTERNS)
  if (secret !== undefined) addFinding(state, {
    id: 'SECRET-001', severity: 'critical', category: 'secrets', title: 'Hard-coded secret-shaped value', path: filename,
    line: lineNumber(text, secret.index), evidence: evidenceLine(text, secret.index),
    impact: 'A committed or installed extension may expose a live credential to the model, other plugins, logs, or attackers.',
    recommendation: 'Block use, verify whether the value is real, rotate it if exposed, remove it from history, and use a credential reference.', confidence: 'high',
  })
  const sensitive = firstMatch(text, SENSITIVE_SOURCE_PATTERNS)
  const fileRead = firstMatch(text, FILE_READ_PATTERNS)
  const network = firstMatch(text, NETWORK_SINK_PATTERNS)
  const subprocess = firstMatch(text, SUBPROCESS_PATTERNS)
  const dynamicExec = firstMatch(text, DYNAMIC_EXEC_PATTERNS)
  const downloadExec = firstMatch(text, DOWNLOAD_EXEC_PATTERNS)
  const persistence = firstMatch(text, PERSISTENCE_PATTERNS)
  const privilege = firstMatch(text, PRIVILEGE_PATTERNS)
  const mount = firstMatch(text, MOUNT_PATTERNS)
  const server = firstMatch(text, SERVER_PATTERNS)
  const destructive = firstMatch(text, DESTRUCTIVE_PATTERNS)
  const prompt = firstMatch(text, PROMPT_OVERRIDE_PATTERNS)
  const obfuscation = firstMatch(text, OBFUSCATION_PATTERNS)
  const isSkillContent = scope.kind === 'skill' || basename(filename) === 'SKILL.md'

  if (sensitive !== undefined && network !== undefined) addFinding(state, {
    id: 'EXFIL-001', severity: 'critical', category: 'data-exfiltration', title: 'Sensitive-data source and outbound-network sink coexist',
    path: filename, line: lineNumber(text, Math.min(sensitive.index, network.index)),
    evidence: `${evidenceLine(text, sensitive.index)}  ⇢  ${evidenceLine(text, network.index)}`,
    impact: 'The extension has the ingredients to collect credentials/private files and transmit them externally.',
    recommendation: 'Block execution and perform a manual source-to-sink review; rotate affected credentials if this code has run.', confidence: 'high',
  })
  if (fileRead !== undefined && network !== undefined) addFinding(state, {
    id: 'EXFIL-002', severity: sensitive ? 'critical' : 'high', category: 'data-exfiltration', title: 'File-read and outbound-network capabilities coexist',
    path: filename, line: lineNumber(text, Math.min(fileRead.index, network.index)),
    evidence: `${evidenceLine(text, fileRead.index)}  ⇢  ${evidenceLine(text, network.index)}`,
    impact: 'Local or workspace data may be sent to an external destination.',
    recommendation: 'Trace the data flow and require a strict destination/data allowlist with explicit user approval.', confidence: 'medium',
  })
  if (downloadExec !== undefined) addFinding(state, {
    id: 'EXEC-001', severity: 'critical', category: 'code-execution', title: 'Remote download is piped or chained into execution', path: filename,
    line: lineNumber(text, downloadExec.index), evidence: evidenceLine(text, downloadExec.index),
    impact: 'Remote content can gain arbitrary code execution without an immutable reviewed artifact.',
    recommendation: 'Block use; replace with a pinned, checksummed artifact reviewed before execution.', confidence: 'high',
  })
  if ((network !== undefined || obfuscation !== undefined) && (dynamicExec !== undefined || subprocess !== undefined)) addFinding(state, {
    id: 'EXEC-002', severity: 'critical', category: 'code-execution', title: 'External/encoded content and execution sink coexist', path: filename,
    line: lineNumber(text, Math.min(network?.index ?? Infinity, obfuscation?.index ?? Infinity, dynamicExec?.index ?? Infinity, subprocess?.index ?? Infinity)),
    evidence: `${network ? evidenceLine(text, network.index) : evidenceLine(text, obfuscation.index)}  ⇢  ${dynamicExec ? evidenceLine(text, dynamicExec.index) : evidenceLine(text, subprocess.index)}`,
    impact: 'The extension may download or decode a payload and execute it on the host.',
    recommendation: 'Do not execute; manually prove the flow impossible or remove the dynamic execution path.', confidence: 'high',
  })
  if (dynamicExec !== undefined && network === undefined && obfuscation === undefined) addFinding(state, {
    id: 'EXEC-003', severity: 'high', category: 'code-execution', title: 'Dynamic string-to-code execution', path: filename,
    line: lineNumber(text, dynamicExec.index), evidence: evidenceLine(text, dynamicExec.index),
    impact: 'Attacker-influenced strings may become arbitrary code.',
    recommendation: 'Replace with structured parsing/dispatch and prove all inputs are trusted.', confidence: 'medium',
  })
  if (subprocess !== undefined && downloadExec === undefined) addFinding(state, {
    id: 'EXEC-004', severity: 'medium', category: 'code-execution', title: 'Host subprocess or shell capability', path: filename,
    line: lineNumber(text, subprocess.index), evidence: evidenceLine(text, subprocess.index),
    impact: 'The extension can invoke host programs; unsafe argument construction may become command injection.',
    recommendation: 'Review command allowlists, avoid shell strings, and require approval for sensitive commands.', confidence: 'medium',
  })
  if (persistence !== undefined) addFinding(state, {
    id: 'PERSIST-001', severity: 'high', category: 'persistence', title: 'Persistence mechanism or startup-file access', path: filename,
    line: lineNumber(text, persistence.index), evidence: evidenceLine(text, persistence.index),
    impact: 'Code may survive DSH/plugin removal or run outside future approval boundaries.',
    recommendation: 'Require explicit documented need; inspect the exact target and remove persistence only after preserving evidence.', confidence: 'medium',
  })
  if (privilege !== undefined) addFinding(state, {
    id: 'PRIV-001', severity: 'high', category: 'privilege', title: 'Privilege escalation or host-control capability', path: filename,
    line: lineNumber(text, privilege.index), evidence: evidenceLine(text, privilege.index),
    impact: 'The extension may escape ordinary user boundaries or control containers/security tooling.',
    recommendation: 'Block by default; require least-privilege design and isolated manual review.', confidence: 'high',
  })
  if (mount !== undefined) addFinding(state, {
    id: 'MOUNT-001', severity: 'high', category: 'mounts', title: 'Host, remote, or container mount capability', path: filename,
    line: lineNumber(text, mount.index), evidence: evidenceLine(text, mount.index),
    impact: 'A mount can expose host credentials/files, bypass workspace assumptions, or make remote data writable.',
    recommendation: 'Review source and destination; prohibit host-root, credential, Docker socket, and untrusted remote mounts.', confidence: 'medium',
  })
  if (server !== undefined) addFinding(state, {
    id: 'SERVER-001', severity: 'high', category: 'network-exposure', title: 'Public listener, tunnel, or reverse-shell capability', path: filename,
    line: lineNumber(text, server.index), evidence: evidenceLine(text, server.index),
    impact: 'A local agent/plugin service may become reachable from the LAN/Internet or create an outbound control channel.',
    recommendation: 'Bind only to loopback, authenticate callers, remove tunnels, and document any required exposure.', confidence: 'medium',
  })
  if (destructive !== undefined) addFinding(state, {
    id: 'DESTROY-001', severity: 'critical', category: 'destructive-action', title: 'Broad destructive or encryption command', path: filename,
    line: lineNumber(text, destructive.index), evidence: evidenceLine(text, destructive.index),
    impact: 'The command could destroy, encrypt, or irreversibly corrupt host/workspace data.',
    recommendation: 'Block execution and require a narrowly scoped, recoverable alternative with explicit confirmation.', confidence: 'high',
  })
  if (prompt !== undefined && isSkillContent) addFinding(state, {
    id: 'PROMPT-001', severity: 'high', category: 'prompt-injection', title: 'Skill instruction attempts to override trust or approval boundaries',
    path: filename, line: lineNumber(text, prompt.index), evidence: evidenceLine(text, prompt.index),
    impact: 'Loading the Skill may manipulate the agent into hiding actions, bypassing approvals, or disclosing protected context.',
    recommendation: 'Do not load the Skill; review the full instruction chain as untrusted data.', confidence: 'medium',
  })
  if (obfuscation !== undefined) {
    addFinding(state, {
      id: 'OBF-001', severity: 'high', category: 'obfuscation', title: 'Encoded or obfuscated payload indicator', path: filename,
      line: lineNumber(text, obfuscation.index), evidence: evidenceLine(text, obfuscation.index),
      impact: 'Hidden instructions or executable payloads may evade ordinary review.',
      recommendation: 'Decode only as data in isolation, scan the result, and reject unexplained obfuscation.', confidence: 'medium',
    })
    scanDecodedPayload(state, filename, obfuscation.match, text, obfuscation.index)
  }
  const hidden = findHiddenUnicode(text)
  if (hidden !== undefined) addFinding(state, {
    id: 'PROMPT-002', severity: 'high', category: 'prompt-injection', title: 'Invisible or bidirectional Unicode control characters', path: filename,
    line: lineNumber(text, hidden.index), evidence: hidden.description,
    impact: 'Displayed text can differ from model/parser interpretation and conceal malicious instructions or identifiers.',
    recommendation: 'Remove the control characters and review the normalized text.', confidence: 'high',
  })
  if (/<!--[^>]*(?:ignore|secret|system|execute|curl|wget|exfiltrat)[\s\S]*?-->/i.test(text) && isSkillContent) {
    const match = /<!--[^>]*(?:ignore|secret|system|execute|curl|wget|exfiltrat)[\s\S]*?-->/i.exec(text)
    addFinding(state, {
      id: 'PROMPT-003', severity: 'high', category: 'prompt-injection', title: 'Security-sensitive instructions hidden in an HTML comment', path: filename,
      line: lineNumber(text, match.index), evidence: maskSensitive(match[0].replace(/\s+/g, ' ')),
      impact: 'The model may follow content that a reviewer does not see in rendered Markdown.',
      recommendation: 'Reject hidden operational instructions and require visible, reviewable guidance.', confidence: 'high',
    })
  }
}

function scanDecodedPayload(state, filename, match, originalText, index) {
  if (!/^[A-Za-z0-9+/]{160,}={0,2}$/.test(match)) return
  try {
    const decoded = Buffer.from(match, 'base64')
    if (decoded.length === 0 || decoded.includes(0)) return
    const text = decoded.toString('utf8')
    const dangerous = firstMatch(text, [...SECRET_PATTERNS, ...DOWNLOAD_EXEC_PATTERNS, ...PROMPT_OVERRIDE_PATTERNS, ...PERSISTENCE_PATTERNS])
    if (dangerous === undefined) return
    addFinding(state, {
      id: 'OBF-002', severity: 'critical', category: 'obfuscation', title: 'Decoded payload contains a high-risk instruction or command', path: filename,
      line: lineNumber(originalText, index), evidence: `decoded SHA-256 ${sha256(decoded).slice(0, 16)}; ${evidenceLine(text, dangerous.index)}`,
      impact: 'The encoded blob conceals a known secret, execution, persistence, or prompt-manipulation pattern.',
      recommendation: 'Block the artifact; preserve hashes and review the decoded data in isolation without executing it.', confidence: 'high',
    })
  } catch { /* Non-decodable text remains covered by OBF-001. */ }
}

function findHiddenUnicode(text) {
  for (let index = 0; index < text.length; index += 1) {
    const code = text.codePointAt(index)
    if (code === 0x200b || code === 0x200c || code === 0x200d || code === 0x2060
      || (code >= 0x202a && code <= 0x202e) || (code >= 0x2066 && code <= 0x2069)
      || (code >= 0xe0000 && code <= 0xe007f)) {
      return { index, description: `Unicode control U+${code.toString(16).toUpperCase().padStart(4, '0')}` }
    }
    if (code > 0xffff) index += 1
  }
  return undefined
}

async function scanPackageManifest(state, filename, text, scope) {
  let manifest
  try { manifest = JSON.parse(text) } catch { return }
  const scripts = manifest.scripts ?? {}
  for (const name of ['preinstall', 'install', 'postinstall', 'prepare']) {
    if (typeof scripts[name] !== 'string') continue
    const command = scripts[name]
    const suspicious = firstMatch(command, [...DOWNLOAD_EXEC_PATTERNS, ...PERSISTENCE_PATTERNS, ...PRIVILEGE_PATTERNS, ...OBFUSCATION_PATTERNS])
    addFinding(state, {
      id: suspicious ? 'PKG-002' : 'PKG-001', severity: suspicious ? 'critical' : 'high', category: 'supply-chain',
      title: suspicious ? `Suspicious npm lifecycle script: ${name}` : `npm lifecycle script executes during install: ${name}`,
      path: filename, evidence: `${name}: ${maskSensitive(command)}`,
      impact: 'Installing or approving the package can execute code on the host outside the DSH agent sandbox.',
      recommendation: 'Inspect the exact source and dependency tree before install; prefer prebuilt, signed, pinned artifacts and keep allowBuilds disabled.',
      confidence: suspicious ? 'high' : 'medium',
    })
  }
  const dependencyGroups = [manifest.dependencies, manifest.optionalDependencies, manifest.devDependencies]
  for (const group of dependencyGroups) {
    if (group === undefined || group === null || typeof group !== 'object') continue
    for (const [name, rawSpec] of Object.entries(group)) {
      const spec = String(rawSpec)
      const remote = /^(?:git\+|git:|github:|https?:|git@)/i.test(spec) || /\.git(?:#|$)/.test(spec)
      const unpinnedRemote = remote && !/(?:#|@)[0-9a-f]{40}$/i.test(spec)
      const floating = /^(?:\*|latest|next|beta|canary)$/i.test(spec)
      if (!unpinnedRemote && !floating) continue
      addFinding(state, {
        id: unpinnedRemote ? 'PKG-003' : 'PKG-004', severity: unpinnedRemote ? 'high' : 'medium', category: 'supply-chain',
        title: unpinnedRemote ? 'Remote dependency is not pinned to an immutable commit' : 'Dependency uses a floating version/tag',
        path: filename, evidence: `${name}: ${maskSensitive(spec)}`,
        impact: 'A later upstream or registry change can replace the code without a local configuration change.',
        recommendation: unpinnedRemote ? 'Pin a reviewed full commit SHA or signed release artifact.' : 'Pin an exact reviewed version and keep the lockfile.',
        confidence: 'high',
      })
    }
  }
  const patch = manifest.dsh?.bundle?.patch
  if (typeof patch === 'string') {
    const packageRoot = dirname(filename)
    const resolvedPatch = resolve(packageRoot, patch)
    if (!isWithin(packageRoot, resolvedPatch) || !existsSync(resolvedPatch)) addFinding(state, {
      id: 'DSH-BUNDLE-001', severity: 'high', category: 'dsh-plugin', title: 'DSH bundle patch escapes the package or is missing',
      path: filename, evidence: `dsh.bundle.patch: ${maskSensitive(patch)}`,
      impact: 'The package may load mutable host configuration outside the reviewed plugin artifact or fail unpredictably.',
      recommendation: 'Require an existing relative patch file contained in the package.', confidence: 'high',
    })
  }
  if (manifest.bin !== undefined && scope.kind === 'plugin') addFinding(state, {
    id: 'PKG-005', severity: 'medium', category: 'supply-chain', title: 'Plugin package exposes executable binaries', path: filename,
    evidence: `bin: ${maskSensitive(JSON.stringify(manifest.bin))}`,
    impact: 'The package adds executable entry points that may be invoked by scripts or users outside DSH approval flows.',
    recommendation: 'Review every bin target and verify it is necessary and included in the scanned artifact.', confidence: 'high',
  })
}

function scanAllowBuilds(state, filename, text) {
  const lines = text.split(/\r?\n/)
  let inAllowBuilds = false
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index]
    if (/^allowBuilds\s*:/.test(line)) { inAllowBuilds = true; continue }
    if (inAllowBuilds && /^\S/.test(line) && line.trim() !== '') inAllowBuilds = false
    if (!inAllowBuilds) continue
    const match = /^\s+([^#][^:]*):\s*true\s*(?:#.*)?$/.exec(line)
    if (match === null) continue
    addFinding(state, {
      id: 'PKG-006', severity: 'high', category: 'supply-chain', title: 'pnpm build scripts explicitly allowed for a profile dependency',
      path: filename, line: index + 1, evidence: `${match[1].trim()}: true`,
      impact: 'The allowed dependency can execute install/prepare code on the host outside the DSH agent sandbox.',
      recommendation: 'Keep disabled unless the exact pinned source and lifecycle scripts were manually reviewed.', confidence: 'high',
    })
  }
}

function scanDshConfig(state, filename, text, scope) {
  if (/danger-full-access/.test(text) && /(?:approval(?:Policy)?|policy)\s*:\s*(?:never|none)/i.test(text)) {
    addFinding(state, {
      id: 'DSH-PERM-001', severity: 'critical', category: 'dsh-permissions', title: 'Unconfined execution combined with no approval',
      path: filename, evidence: 'danger-full-access + approval never/none',
      impact: 'An injected or compromised Skill/plugin can execute arbitrary host actions without a confirmation boundary.',
      recommendation: 'Use workspace-write/read-only with ask/on-request approval except for an isolated disposable environment.', confidence: 'high',
    })
  }
  const jsTag = /!!js\s+([^\n]+)/g
  for (const match of text.matchAll(jsTag)) {
    addFinding(state, {
      id: 'DSH-CONFIG-001', severity: scope.trust === 'third-party' ? 'high' : 'medium', category: 'dsh-config', title: 'Cordis configuration contains executable !!js expression',
      path: filename, line: lineNumber(text, match.index), evidence: `!!js ${maskSensitive(match[1])}`,
      impact: 'Dynamic configuration is evaluated during composition and may access host process state or execute unsafe behavior.',
      recommendation: 'Review the expression as code; prefer literal validated config and do not accept it from an untrusted bundle.', confidence: 'high',
    })
  }
  if (/@deepseek-ai\/dsh-mcp-client/.test(text)) {
    const command = /\bcommand\s*:\s*([^\n#]+)/.exec(text)
    const args = /\bargs\s*:\s*([^\n#]+)/.exec(text)
    const shellLike = command && /(?:npx|uvx|bash|sh|zsh|pwsh|powershell|docker|podman)/i.test(command[1])
    addFinding(state, {
      id: shellLike ? 'MCP-002' : 'MCP-001', severity: shellLike ? 'high' : 'medium', category: 'mcp',
      title: shellLike ? 'MCP stdio server uses a package runner, shell, or container command' : 'External MCP server executable is configured',
      path: filename, line: command ? lineNumber(text, command.index) : undefined,
      evidence: command ? `command: ${maskSensitive(command[1].trim())}${args ? `; args: ${maskSensitive(args[1].trim())}` : ''}` : '@deepseek-ai/dsh-mcp-client',
      impact: 'DSH trusts and launches the MCP command on the host; it is not made safe by the agent file-write sandbox.',
      recommendation: 'Do not start during audit; pin an immutable executable/package, constrain cwd/env, and review tool descriptions and code.', confidence: 'high',
    })
  }
  const remoteHttp = /\burl\s*:\s*["']?(http:\/\/(?!127\.0\.0\.1|localhost|\[::1\])[^\s"']+)/i.exec(text)
  if (remoteHttp !== null) addFinding(state, {
    id: 'MCP-003', severity: 'high', category: 'mcp', title: 'Remote MCP endpoint uses unencrypted HTTP', path: filename,
    line: lineNumber(text, remoteHttp.index), evidence: maskSensitive(remoteHttp[0]),
    impact: 'Tool schemas, arguments, results, or credentials may be intercepted or modified in transit.',
    recommendation: 'Use authenticated HTTPS with a pinned trusted endpoint, or loopback-only HTTP for local development.', confidence: 'high',
  })
  if (/DSH_TELEMETRY_MODE\s*[=:]\s*(?:FULL|FEEDBACK_ONLY)/i.test(text)) {
    const match = /DSH_TELEMETRY_MODE\s*[=:]\s*(?:FULL|FEEDBACK_ONLY)/i.exec(text)
    addFinding(state, {
      id: 'DSH-TELEM-001', severity: /FULL/i.test(match[0]) ? 'high' : 'medium', category: 'telemetry', title: 'DSH session telemetry export is explicitly enabled',
      path: filename, line: lineNumber(text, match.index), evidence: match[0],
      impact: 'Session messages, tool arguments/results, and workspace paths may be exported without a built-in redaction rule.',
      recommendation: 'Keep telemetry disabled unless the collector, retention, access, and redaction policy are explicitly trusted.', confidence: 'high',
    })
  }
}

async function checkPermissions(state) {
  const checks = [
    { path: state.options.dshHome, required: 0o700, exactSensitive: false, label: 'DSH home' },
    { path: join(state.options.dshHome, '.credentials.yaml'), required: 0o600, exactSensitive: true, label: 'DSH credentials' },
    { path: join(state.options.dshHome, '.env'), required: 0o600, exactSensitive: true, label: 'DSH env file' },
  ]
  for (const check of checks) {
    if (!existsSync(check.path) || platform() === 'win32') continue
    try {
      const metadata = await stat(check.path)
      const actual = metadata.mode & 0o777
      const bad = check.exactSensitive ? (actual & 0o077) !== 0 : (actual & 0o022) !== 0
      if (!bad) continue
      addFinding(state, {
        id: check.exactSensitive ? 'MODE-002' : 'MODE-003', severity: check.exactSensitive ? 'critical' : 'high', category: 'permissions',
        title: `${check.label} permissions are too broad`, path: check.path, evidence: `mode ${actual.toString(8)}`,
        impact: check.exactSensitive ? 'Other local users may read or replace credentials.' : 'Other local users may tamper with profiles, Skills, or settings.',
        recommendation: `Set mode ${check.required.toString(8)} and verify directory ownership.`, confidence: 'high',
      })
    } catch (error) { addError(state, `cannot inspect permissions: ${error.message}`, check.path) }
  }
}

function runReadOnly(command, args, options = {}) {
  try {
    return execFileSync(command, args, {
      encoding: 'utf8', timeout: options.timeout ?? 5000, maxBuffer: options.maxBuffer ?? 4 * 1024 * 1024,
      env: { PATH: process.env.PATH, HOME: homedir(), LANG: 'C', LC_ALL: 'C' },
      stdio: ['ignore', 'pipe', 'pipe'],
    })
  } catch { return '' }
}

function parseProcessTable(output) {
  const rows = []
  for (const line of output.split(/\r?\n/)) {
    const match = /^\s*(\d+)\s+(\d+)\s+(\S+)\s+(.*)$/.exec(line)
    if (match) rows.push({ pid: Number(match[1]), ppid: Number(match[2]), command: match[3], args: match[4] })
  }
  return rows
}

async function collectRuntime(state) {
  const processOutput = runReadOnly('ps', ['-axo', 'pid=,ppid=,comm=,args='])
  const processes = parseProcessTable(processOutput)
  const names = [...state.pluginNames]
  const related = new Set()
  for (const row of processes) {
    if (/deepseek-harness|@deepseek-ai\/dsh|(?:^|\s)dsh(?:\s|$)|\.dsh\/profiles/i.test(row.args)
      || names.some(name => name.length > 2 && row.args.includes(name))) related.add(row.pid)
  }
  let changed = true
  while (changed) {
    changed = false
    for (const row of processes) if (related.has(row.ppid) && !related.has(row.pid)) { related.add(row.pid); changed = true }
  }
  for (const row of processes.filter(item => related.has(item.pid))) {
    const risky = firstMatch(row.args, [...SERVER_PATTERNS, ...PERSISTENCE_PATTERNS, ...PRIVILEGE_PATTERNS])
    if (risky === undefined) continue
    addFinding(state, {
      id: 'RUNTIME-001', severity: 'high', category: 'runtime', title: 'Live DSH/plugin process has a risky listener, tunnel, persistence, or privilege argument',
      evidence: `pid ${row.pid} ${row.command}: ${maskSensitive(row.args)}`,
      impact: 'A currently running process may expose a service, maintain access, or control privileged host resources.',
      recommendation: 'Identify its profile/package provenance; preserve evidence and stop it only with user authorization.', confidence: 'medium',
    })
  }
  const lsof = runReadOnly('lsof', ['-nP', '-iTCP', '-sTCP:LISTEN', '-Fpcn'])
  let current = {}
  const listeners = []
  for (const line of lsof.split(/\r?\n/)) {
    if (line.startsWith('p')) { if (current.pid) listeners.push(current); current = { pid: Number(line.slice(1)) } }
    else if (line.startsWith('c')) current.command = line.slice(1)
    else if (line.startsWith('n')) current.endpoint = line.slice(1)
  }
  if (current.pid) listeners.push(current)
  for (const listener of listeners) {
    if (!related.has(listener.pid)) continue
    const endpoint = listener.endpoint ?? ''
    if (!/^(?:\*|0\.0\.0\.0|\[::\]|::):/i.test(endpoint)) continue
    addFinding(state, {
      id: 'RUNTIME-002', severity: 'high', category: 'network-exposure', title: 'Live DSH/plugin process listens beyond loopback',
      evidence: `pid ${listener.pid} ${listener.command ?? ''}: ${endpoint}`,
      impact: 'The service may be reachable from other hosts and expose agent APIs or unauthenticated plugin endpoints.',
      recommendation: 'Bind to 127.0.0.1/::1 or place behind an authenticated, encrypted proxy.', confidence: 'high',
    })
  }
  const mountOutput = runReadOnly('mount', [])
  const remoteMount = /\((?:[^)]*,)?\s*(?:nfs|smbfs|webdav|sshfs|fuse\.[^,)]*)/i
  for (const line of mountOutput.split(/\r?\n/)) {
    if (!remoteMount.test(line)) continue
    const match = / on (.+?) \(/.exec(line)
    if (!match) continue
    const mountPoint = resolve(match[1])
    const overlaps = state.scopes.some(scope => isWithin(mountPoint, scope.path) || isWithin(scope.path, mountPoint))
    if (!overlaps) continue
    addFinding(state, {
      id: 'RUNTIME-003', severity: 'medium', category: 'mounts', title: 'Scanned DSH/extension path overlaps a remote or FUSE mount',
      evidence: maskSensitive(line),
      impact: 'Reviewed files may change remotely, and data written/read there crosses an additional trust boundary.',
      recommendation: 'Verify mount owner, transport security, write permissions, and immutable artifact hashes.', confidence: 'high',
    })
  }
  await scanPersistenceLocations(state)
}

async function scanPersistenceLocations(state) {
  const roots = platform() === 'darwin'
    ? [join(homedir(), 'Library', 'LaunchAgents')]
    : [join(homedir(), '.config', 'systemd', 'user')]
  const needles = ['deepseek-harness', `${sep}.dsh${sep}`, ...state.pluginNames]
  for (const root of roots) {
    if (!existsSync(root)) continue
    let entries
    try { entries = await readdir(root, { withFileTypes: true }) } catch { continue }
    for (const entry of entries) {
      if (!entry.isFile()) continue
      const filename = join(root, entry.name)
      let text
      try { text = await readFile(filename, 'utf8') } catch { continue }
      if (!needles.some(needle => needle && text.includes(needle))) continue
      addFinding(state, {
        id: 'RUNTIME-004', severity: 'high', category: 'persistence', title: 'User startup item references DSH or an installed plugin',
        path: filename, evidence: `startup item references DSH/plugin content; SHA-256 ${sha256(Buffer.from(text)).slice(0, 16)}`,
        impact: 'The process may run automatically outside normal DSH session and approval boundaries.',
        recommendation: 'Review the full startup item and provenance; preserve evidence before disabling it.', confidence: 'high',
      })
    }
  }
  const cron = runReadOnly('crontab', ['-l'])
  if (cron && needles.some(needle => needle && cron.includes(needle))) addFinding(state, {
    id: 'RUNTIME-005', severity: 'high', category: 'persistence', title: 'User crontab references DSH or an installed plugin',
    evidence: `matching crontab content SHA-256 ${sha256(Buffer.from(cron)).slice(0, 16)}`,
    impact: 'The process may run periodically outside normal DSH session and approval boundaries.',
    recommendation: 'Review the crontab entry and provenance; preserve evidence before editing it.', confidence: 'high',
  })
}

async function compareBaseline(state, filename) {
  let baseline
  try { baseline = JSON.parse(await readFile(filename, 'utf8')) } catch (error) { addError(state, `cannot read baseline: ${error.message}`, filename); return }
  if (!Array.isArray(baseline.files)) { addError(state, 'baseline files must be an array', filename); return }
  const before = new Map(baseline.files.map(file => [resolve(file.path), file]))
  const current = new Map(state.files.map(file => [resolve(file.path), file]))
  for (const [pathValue, file] of current) {
    const previous = before.get(pathValue)
    if (previous === undefined) addBaselineFinding(state, 'BASELINE-001', pathValue, 'New file since baseline', file)
    else if (previous.sha256 !== file.sha256) addBaselineFinding(state, 'BASELINE-002', pathValue, 'File changed since baseline', file)
  }
  for (const [pathValue, file] of before) {
    if (!current.has(pathValue)) addBaselineFinding(state, 'BASELINE-003', pathValue, 'File removed since baseline', file, 'low')
  }
}

function addBaselineFinding(state, id, pathValue, title, file, forcedSeverity) {
  const highRisk = OPAQUE_EXECUTABLE_EXTENSIONS.has(extname(pathValue).toLowerCase())
    || ['package.json', 'pnpm-workspace.yaml', 'cordis.yml', 'cordis.patch.yml', 'SKILL.md'].includes(basename(pathValue))
  addFinding(state, {
    id, severity: forcedSeverity ?? (highRisk ? 'high' : 'medium'), category: 'integrity', title, path: pathValue,
    evidence: `SHA-256 ${String(file.sha256 ?? 'unavailable').slice(0, 16)}`,
    impact: 'Installed content no longer matches the reviewed inventory; a legitimate update or unauthorized replacement is possible.',
    recommendation: 'Verify the change against a trusted source and regenerate the baseline only after review.', confidence: 'high',
  })
}

async function writeBaseline(state, filename) {
  const absolute = resolve(filename)
  const inside = state.scopes.some(scope => isWithin(scope.path, absolute))
  if (inside) throw new Error('--write-baseline must be outside every scanned root')
  const payload = {
    schemaVersion: 1,
    scanner: `dsh-security-audit/${VERSION}`,
    generatedAt: new Date().toISOString(),
    files: state.files.map(file => ({ path: file.path, size: file.size, sha256: file.sha256, scope: file.scope })).sort((a, b) => a.path.localeCompare(b.path)),
  }
  await mkdir(dirname(absolute), { recursive: true })
  await writeFile(absolute, `${JSON.stringify(payload, null, 2)}\n`, { mode: 0o600 })
}

function finalizeReport(state) {
  state.findings.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]
    || (a.path ?? '').localeCompare(b.path ?? '') || (a.line ?? 0) - (b.line ?? 0) || a.id.localeCompare(b.id))
  const counts = { critical: 0, high: 0, medium: 0, low: 0 }
  for (const finding of state.findings) counts[finding.severity] += 1
  const riskScore = Math.min(100, state.findings.reduce((sum, finding) => sum + SEVERITY_WEIGHT[finding.severity], 0))
  const recommendation = counts.critical > 0 ? 'BLOCK_AND_RESPOND'
    : counts.high > 0 ? 'DO_NOT_ENABLE_PENDING_REVIEW'
      : counts.medium > 0 ? 'CAUTION_AND_HARDEN' : 'NO_KNOWN_HIGH_RISK_FINDINGS'
  return {
    schemaVersion: 1,
    scanner: { name: 'dsh-security-audit', version: VERSION },
    generatedAt: new Date().toISOString(),
    complete: state.errors.length === 0 && state.fileCount < state.options.maxFiles,
    limitations: [
      'Best-effort static/runtime posture scan; no findings is not a security certification.',
      'Target code, package lifecycle scripts, MCP servers, and binaries were not executed.',
      'Offline mode does not query CVE, publisher reputation, revocation, or malware databases.',
    ],
    scope: {
      cwd: state.options.cwd,
      projectRoot: state.projectRoot,
      dshHome: state.options.dshHome,
      agentsHome: state.options.agentsHome,
      runtime: state.options.runtime,
      deep: state.options.deep,
      includeOfficial: state.options.includeOfficial,
      profiles: state.profiles,
      plugins: state.plugins,
      skills: state.skills,
      scannedRoots: state.scopes.map(scope => ({ path: scope.path, kind: scope.kind, source: scope.source, profile: scope.profile, packageName: scope.packageName })),
    },
    inventory: { filesScanned: state.fileCount, filesHashed: state.files.length, filesSkipped: state.skippedCount },
    summary: { ...counts, total: state.findings.length, riskScore, recommendation },
    findings: state.findings,
    errors: state.errors,
  }
}

function markdown(report) {
  const out = []
  out.push('# DSH Security Audit Report', '')
  out.push(`- Generated: ${report.generatedAt}`)
  out.push(`- Complete: ${report.complete ? 'yes' : 'no'}`)
  out.push(`- Recommendation: **${report.summary.recommendation}**`)
  out.push(`- Risk score: ${report.summary.riskScore}/100`)
  out.push(`- Findings: Critical ${report.summary.critical}, High ${report.summary.high}, Medium ${report.summary.medium}, Low ${report.summary.low}`)
  out.push(`- Files: scanned ${report.inventory.filesScanned}, hashed ${report.inventory.filesHashed}, skipped ${report.inventory.filesSkipped}`)
  out.push('', '## Scope', '')
  out.push(`- Workspace: ${normalizePath(report.scope.cwd)}`)
  out.push(`- DSH Home: ${normalizePath(report.scope.dshHome)}`)
  out.push(`- Profiles: ${report.scope.profiles.map(item => item.name).join(', ') || '(none)'}`)
  out.push(`- Third-party plugins: ${report.scope.plugins.filter(item => !item.official).map(item => `${item.name}@${item.spec}`).join(', ') || '(none)'}`)
  out.push(`- Skills discovered: ${report.scope.skills.length}`)
  out.push(`- Runtime checks: ${report.scope.runtime ? 'enabled' : 'disabled'}`)
  out.push('', '## Findings', '')
  if (report.findings.length === 0) out.push('No known risk pattern was detected. This is not a security certification.', '')
  for (const finding of report.findings) {
    const location = finding.path ? `${normalizePath(finding.path)}${finding.line ? `:${finding.line}` : ''}` : 'runtime/configuration'
    out.push(`### [${finding.severity.toUpperCase()}] ${finding.id} — ${finding.title}`, '')
    out.push(`- Location: ${location}`)
    out.push(`- Category: ${finding.category}`)
    out.push(`- Confidence: ${finding.confidence}`)
    out.push(`- Evidence: ${finding.evidence || '(structural finding)'}`)
    out.push(`- Impact: ${finding.impact}`)
    out.push(`- Recommendation: ${finding.recommendation}`)
    out.push(`- Fingerprint: ${finding.fingerprint}`, '')
  }
  if (report.errors.length > 0) {
    out.push('## Incomplete checks', '')
    for (const error of report.errors) out.push(`- ${error.path ? `${normalizePath(error.path)}: ` : ''}${error.message}`)
    out.push('')
  }
  out.push('## Limitations', '')
  for (const item of report.limitations) out.push(`- ${item}`)
  out.push('')
  return out.join('\n')
}

function sarif(report) {
  return {
    version: '2.1.0',
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    runs: [{
      tool: { driver: {
        name: report.scanner.name,
        version: report.scanner.version,
        informationUri: 'https://github.com/deepseek-ai/deepseek-harness',
        rules: [...new Map(report.findings.map(finding => [finding.id, {
          id: finding.id,
          shortDescription: { text: finding.title },
          help: { text: finding.recommendation },
          properties: { category: finding.category, severity: finding.severity },
        }])).values()],
      } },
      results: report.findings.map(finding => ({
        ruleId: finding.id,
        level: finding.severity === 'critical' || finding.severity === 'high' ? 'error' : finding.severity === 'medium' ? 'warning' : 'note',
        message: { text: `${finding.title}. ${finding.evidence}` },
        locations: finding.path ? [{ physicalLocation: {
          artifactLocation: { uri: `file://${finding.path}` },
          region: finding.line ? { startLine: finding.line } : undefined,
        } }] : undefined,
        fingerprints: { dshSecurityAudit: finding.fingerprint },
      })),
    }],
  }
}

function shouldFail(report, threshold) {
  if (threshold === 'off') return false
  const limit = SEVERITY_ORDER[threshold]
  return report.findings.some(finding => SEVERITY_ORDER[finding.severity] <= limit)
}

async function main() {
  let parsed
  try { parsed = parseArgs(process.argv.slice(2)) } catch (error) {
    process.stderr.write(`dsh-security-audit: ${error.message}\n\n${usage()}\n`)
    process.exitCode = 2
    return
  }
  if (parsed.action === 'help') { process.stdout.write(`${usage()}\n`); return }
  if (parsed.action === 'version') { process.stdout.write(`${VERSION}\n`); return }
  const state = createState(parsed.options)
  await discoverScopes(state)
  for (const scope of state.scopes) await scanScope(state, scope)
  await checkPermissions(state)
  if (parsed.options.runtime) await collectRuntime(state)
  if (parsed.options.baseline) await compareBaseline(state, resolve(parsed.options.invocationCwd, parsed.options.baseline))
  if (parsed.options.writeBaseline) await writeBaseline(state, resolve(parsed.options.invocationCwd, parsed.options.writeBaseline))
  const report = finalizeReport(state)
  const rendered = parsed.options.format === 'markdown' ? markdown(report)
    : `${JSON.stringify(parsed.options.format === 'sarif' ? sarif(report) : report, null, 2)}\n`
  if (parsed.options.output) {
    const output = resolve(parsed.options.invocationCwd, parsed.options.output)
    await mkdir(dirname(output), { recursive: true })
    await writeFile(output, rendered, { mode: 0o600 })
  } else {
    process.stdout.write(rendered.endsWith('\n') ? rendered : `${rendered}\n`)
  }
  if (shouldFail(report, parsed.options.failOn)) process.exitCode = 1
}

main().catch((error) => {
  process.stderr.write(`dsh-security-audit: fatal: ${maskSensitive(error.stack ?? error.message)}\n`)
  process.exitCode = 2
})
