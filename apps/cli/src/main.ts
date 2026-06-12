import { basename, dirname, isAbsolute, relative, resolve } from "node:path"
import { createHash } from "node:crypto"
import { Database } from "bun:sqlite"
import { serve } from "bun"
import { AuditManager, assertLlmReady } from "@night_agent/core"
import type { AuditOptions, LLMConfig, LLMProvider, AuditReport, AgentBusEvent } from "@night_agent/core"
import { copyFileSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs"

const ENV_API_KEYS: Record<LLMProvider, string> = {
  anthropic: process.env.ANTHROPIC_API_KEY ?? "",
  openai: process.env.OPENAI_API_KEY ?? "",
  deepseek: process.env.DEEPSEEK_API_KEY ?? "",
  glm: process.env.GLM_API_KEY ?? "",
}

const LEGACY_RUNS_DIR = "/tmp/night_agent_runs"
const DEFAULT_RUNS_DIR = resolve(process.cwd(), ".night-agent", "runs")
const RUNS_DIR = resolve(process.env.NIGHT_AGENT_RUNS_DIR ?? DEFAULT_RUNS_DIR)
const USES_DEFAULT_RUNS_DIR = !process.env.NIGHT_AGENT_RUNS_DIR
const GIT_CLONE_TIMEOUT_MS = Number(process.env.NIGHT_AGENT_CLONE_TIMEOUT_MS ?? "180000") || 180_000
const HISTORY_EVENT_LIMIT = Math.max(1000, Number(process.env.NIGHT_AGENT_HISTORY_EVENT_LIMIT ?? "5000") || 5000)

interface ResolvedTarget {
  input: string
  target: string
  outputDir: string
  runId: string
  cloned: boolean
}

interface StoredRunSummary {
  runId: string
  input: string
  target: string
  outputDir: string
  cloned: boolean
  provider: string | null
  model: string | null
  mode: "quick" | "full"
  status: "preparing" | "running" | "completed" | "error" | "interrupted"
  projectName: string | null
  startedAt: number
  completedAt: number | null
  stats: AuditReport["stats"] | null
  observer: AuditReport["observer"] | null
  generatedFiles: string[]
  error: string | null
}

interface StoredRunDetail extends StoredRunSummary {
  report: AuditReport | null
  events: AgentBusEvent[]
  sources: Array<{
    id: string
    kind: string
    paramName: string
    file: string
    line: number
    code: string
    methodName: string
    className?: string
  }>
}

interface StoredModelSettings {
  provider: LLMProvider
  model: string
  baseUrl: string
  apiKey: string
  updatedAt: number | null
}

interface JoernRuntimeConfig {
  traceConcurrency?: number
  joernXmxMb?: number
  joernActiveProcessors?: number
  traceTimeoutMs?: number
  fallbackTimeoutMs?: number
  traceFallback?: boolean
  traceAutoLimit?: boolean
  traceAutoLimitThreshold?: number
  traceAutoLimitCount?: number
  traceMaxHypotheses?: number
  perHypothesisTrace?: boolean
}

interface VerifierRuntimeConfig {
  triageEnabled?: boolean
  maxCandidates?: number
  duplicateRepresentatives?: number
  recheckDeferred?: boolean
  concurrency?: number
}

const DEFAULT_MODEL_SETTINGS: StoredModelSettings = {
  provider: "glm",
  model: "GLM-5.1",
  baseUrl: "https://open.bigmodel.cn/api/coding/paas/v4",
  apiKey: "",
  updatedAt: null,
}

const VALID_PROVIDERS = new Set<LLMProvider>(["anthropic", "openai", "deepseek", "glm"])

async function assertConfiguredLlmReady(config: LLMConfig): Promise<void> {
  if (process.env.NIGHT_AGENT_SKIP_LLM_PREFLIGHT === "1") return
  await assertLlmReady(config)
}

function jsonParse<T>(value: unknown, fallback: T): T {
  if (typeof value !== "string" || !value) return fallback
  try {
    return JSON.parse(value) as T
  } catch {
    return fallback
  }
}

function initAuditDb(): Database {
  mkdirSync(RUNS_DIR, { recursive: true })
  migrateLegacyAuditDbIfNeeded()
  const db = new Database(resolve(RUNS_DIR, "night_agent.sqlite"))
  db.exec(`
    PRAGMA journal_mode = WAL;
    CREATE TABLE IF NOT EXISTS audit_runs (
      run_id TEXT PRIMARY KEY,
      input TEXT NOT NULL,
      target TEXT NOT NULL,
      output_dir TEXT NOT NULL,
      cloned INTEGER NOT NULL,
      provider TEXT,
      model TEXT,
      mode TEXT NOT NULL,
      status TEXT NOT NULL,
      project_name TEXT,
      started_at INTEGER NOT NULL,
      completed_at INTEGER,
      stats_json TEXT,
      observer_json TEXT,
      generated_files_json TEXT,
      report_json TEXT,
      error TEXT
    );
    CREATE TABLE IF NOT EXISTS audit_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      run_id TEXT NOT NULL,
      kind TEXT NOT NULL,
      source TEXT,
      timestamp INTEGER NOT NULL,
      payload_json TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_audit_events_run_id ON audit_events(run_id, id);
    CREATE TABLE IF NOT EXISTS audit_sources (
      run_id TEXT NOT NULL,
      id TEXT NOT NULL,
      kind TEXT,
      param_name TEXT,
      file TEXT,
      line INTEGER,
      code TEXT,
      method_name TEXT,
      class_name TEXT,
      payload_json TEXT,
      PRIMARY KEY (run_id, id)
    );
    CREATE TABLE IF NOT EXISTS app_settings (
      key TEXT PRIMARY KEY,
      value_json TEXT NOT NULL,
      updated_at INTEGER NOT NULL
    );
  `)
  return db
}

function migrateLegacyAuditDbIfNeeded(): void {
  if (!USES_DEFAULT_RUNS_DIR || RUNS_DIR === resolve(LEGACY_RUNS_DIR)) return
  const legacyDb = resolve(LEGACY_RUNS_DIR, "night_agent.sqlite")
  const targetDb = resolve(RUNS_DIR, "night_agent.sqlite")
  if (existsSync(targetDb) || !existsSync(legacyDb)) return

  mkdirSync(RUNS_DIR, { recursive: true })
  for (const suffix of ["", "-wal", "-shm"]) {
    const source = `${legacyDb}${suffix}`
    if (existsSync(source)) copyFileSync(source, `${targetDb}${suffix}`)
  }
  console.log(`[night_agent] migrated audit database: ${legacyDb} -> ${targetDb}`)
}

function markInterruptedRuns(db: Database): void {
  db.query(`
    UPDATE audit_runs
    SET status = ?, completed_at = ?, error = COALESCE(error, ?)
    WHERE status IN ('preparing', 'running')
  `).run("interrupted", Date.now(), "service restarted before audit completed")
}

function rowToRunSummary(row: Record<string, unknown>): StoredRunSummary {
  const outputDir = String(row.output_dir)
  const generatedFiles = discoverGeneratedFiles(outputDir, jsonParse(row.generated_files_json, []))
  return {
    runId: String(row.run_id),
    input: String(row.input),
    target: String(row.target),
    outputDir,
    cloned: Number(row.cloned) === 1,
    provider: row.provider == null ? null : String(row.provider),
    model: row.model == null ? null : String(row.model),
    mode: String(row.mode) === "full" ? "full" : "quick",
    status: String(row.status) as StoredRunSummary["status"],
    projectName: row.project_name == null ? null : String(row.project_name),
    startedAt: Number(row.started_at),
    completedAt: row.completed_at == null ? null : Number(row.completed_at),
    stats: jsonParse(row.stats_json, null),
    observer: jsonParse(row.observer_json, null),
    generatedFiles,
    error: row.error == null ? null : String(row.error),
  }
}

function loadReportFromOutput(outputDir: string): AuditReport | null {
  try {
    const report = JSON.parse(readFileSync(resolve(outputDir, "audit-summary.json"), "utf-8")) as AuditReport
    report.generatedFiles = discoverGeneratedFiles(outputDir, report.generatedFiles)
    return report
  } catch {
    return null
  }
}

function discoverGeneratedFiles(outputDir: string, indexedFiles: string[] = []): string[] {
  const files = new Set<string>()
  for (const file of indexedFiles) {
    if (typeof file === "string" && file && existsSync(file)) files.add(file)
  }

  const knownNames = [
    "phase0-profile.json",
    "phase2-hypotheses.json",
    "phase2-evidence-bundles.json",
    "phase2-agent-artifacts.json",
    "phase2-findings.json",
    "phase3-coverage.json",
    "phase3-stats.json",
    "audit-events.json",
    "audit-graph.json",
    "audit-summary.json",
  ]
  for (const name of knownNames) {
    const file = resolve(outputDir, name)
    if (existsSync(file)) files.add(file)
  }

  try {
    for (const name of readdirSync(outputDir)) {
      if (name.endsWith(".md")) files.add(resolve(outputDir, name))
    }
  } catch {
    // Missing output directories are handled by callers as an absent report.
  }

  return [...files]
}

function sanitizeModelSettings(input: Record<string, unknown>, fallback = DEFAULT_MODEL_SETTINGS): StoredModelSettings {
  const providerRaw = typeof input.provider === "string" ? input.provider.trim() : fallback.provider
  const initialProvider = VALID_PROVIDERS.has(providerRaw as LLMProvider) ? providerRaw as LLMProvider : fallback.provider
  const model = typeof input.model === "string" ? input.model.trim() : fallback.model
  const baseUrl = normalizeStoredBaseUrl(typeof input.baseUrl === "string" ? input.baseUrl.trim() : fallback.baseUrl)
  const provider = inferProvider(initialProvider, model, baseUrl)
  return {
    provider,
    model,
    baseUrl,
    apiKey: typeof input.apiKey === "string" ? input.apiKey.trim() : fallback.apiKey,
    updatedAt: typeof input.updatedAt === "number" ? input.updatedAt : fallback.updatedAt,
  }
}

function normalizeStoredBaseUrl(baseUrl: string): string {
  return baseUrl.replace(/\/+$/, "")
}

function inferProvider(provider: LLMProvider, model: string, baseUrl: string): LLMProvider {
  const text = `${model} ${baseUrl}`.toLowerCase()
  if (/deepseek|api\.deepseek\.com/.test(text)) return "deepseek"
  if (/glm|bigmodel|open\.bigmodel\.cn|zhipu/.test(text)) return "glm"
  if (/anthropic|claude/.test(text)) return "anthropic"
  if (/openai|gpt-|api\.openai\.com|mimo|xiaomimimo|token-plan/.test(text)) return "openai"
  return provider
}

function getModelSettings(db: Database): StoredModelSettings {
  const row = db.query("SELECT value_json, updated_at FROM app_settings WHERE key = ?").get("model") as Record<string, unknown> | null
  if (!row) return DEFAULT_MODEL_SETTINGS
  const parsed = jsonParse<Record<string, unknown>>(row.value_json, {})
  return sanitizeModelSettings({ ...parsed, updatedAt: Number(row.updated_at) }, DEFAULT_MODEL_SETTINGS)
}

function saveModelSettings(db: Database, input: Record<string, unknown>): StoredModelSettings {
  const updatedAt = Date.now()
  const settings = sanitizeModelSettings({ ...input, updatedAt }, getModelSettings(db))
  db.query(`
    INSERT OR REPLACE INTO app_settings (key, value_json, updated_at)
    VALUES (?, ?, ?)
  `).run("model", JSON.stringify({
    provider: settings.provider,
    model: settings.model,
    baseUrl: settings.baseUrl,
    apiKey: settings.apiKey,
  }), updatedAt)
  return settings
}

function applyJoernRuntimeConfig(input: Record<string, unknown>): void {
  const raw = input.joernRuntime
  if (!raw || typeof raw !== "object") return
  const config = raw as JoernRuntimeConfig
  setPositiveEnv("NIGHT_AGENT_TRACE_CONCURRENCY", config.traceConcurrency)
  setPositiveEnv("NIGHT_AGENT_JOERN_XMX_MB", config.joernXmxMb)
  setPositiveEnv("NIGHT_AGENT_JOERN_ACTIVE_PROCESSORS", config.joernActiveProcessors)
  setPositiveEnv("NIGHT_AGENT_TRACE_TIMEOUT_MS", config.traceTimeoutMs)
  setPositiveEnv("NIGHT_AGENT_TRACE_FALLBACK_TIMEOUT_MS", config.fallbackTimeoutMs)
  setBooleanEnv("NIGHT_AGENT_TRACE_FALLBACK", config.traceFallback)
  setBooleanEnv("NIGHT_AGENT_TRACE_AUTO_LIMIT", config.traceAutoLimit)
  setPositiveEnv("NIGHT_AGENT_TRACE_AUTO_LIMIT_THRESHOLD", config.traceAutoLimitThreshold)
  setNonNegativeEnv("NIGHT_AGENT_TRACE_AUTO_LIMIT_COUNT", config.traceAutoLimitCount)
  setNonNegativeEnv("NIGHT_AGENT_TRACE_MAX_HYPOTHESES", config.traceMaxHypotheses)
  setBooleanEnv("NIGHT_AGENT_PER_HYPOTHESIS_TRACE", config.perHypothesisTrace)
  console.log(`[night_agent] joern runtime: traceConcurrency=${process.env.NIGHT_AGENT_TRACE_CONCURRENCY ?? "auto"}, xmx=${process.env.NIGHT_AGENT_JOERN_XMX_MB ?? "auto"}m, activeCpu=${process.env.NIGHT_AGENT_JOERN_ACTIVE_PROCESSORS ?? "auto"}, traceMax=${process.env.NIGHT_AGENT_TRACE_MAX_HYPOTHESES ?? "auto"}, autoLimit=${process.env.NIGHT_AGENT_TRACE_AUTO_LIMIT ?? "1"}, perHypTrace=${process.env.NIGHT_AGENT_PER_HYPOTHESIS_TRACE ?? "1"}`)
}

function applyVerifierRuntimeConfig(input: Record<string, unknown>): void {
  const raw = input.verifierRuntime
  if (!raw || typeof raw !== "object") return
  const config = raw as VerifierRuntimeConfig
  setBooleanEnv("NIGHT_AGENT_VERIFIER_TRIAGE", config.triageEnabled)
  setBoundedEnv("NIGHT_AGENT_VERIFIER_DUP_REPRESENTATIVES", config.duplicateRepresentatives, 1, 4)
  setBooleanEnv("NIGHT_AGENT_VERIFIER_RECHECK_DEFERRED", config.recheckDeferred)
  setBoundedEnv("NIGHT_AGENT_VERIFIER_CONCURRENCY", config.concurrency, 1, 6)

  const maxCandidates = typeof config.maxCandidates === "number" ? config.maxCandidates : Number(config.maxCandidates)
  if (Number.isFinite(maxCandidates)) {
    if (maxCandidates <= 0) delete process.env.NIGHT_AGENT_VERIFIER_MAX_CANDIDATES
    else process.env.NIGHT_AGENT_VERIFIER_MAX_CANDIDATES = String(Math.max(1, Math.min(500, Math.floor(maxCandidates))))
  }

  console.log(`[night_agent] verifier runtime: triage=${process.env.NIGHT_AGENT_VERIFIER_TRIAGE ?? "1"}, max=${process.env.NIGHT_AGENT_VERIFIER_MAX_CANDIDATES ?? "auto"}, dupReps=${process.env.NIGHT_AGENT_VERIFIER_DUP_REPRESENTATIVES ?? "1"}, recheckDeferred=${process.env.NIGHT_AGENT_VERIFIER_RECHECK_DEFERRED ?? "0"}, concurrency=${process.env.NIGHT_AGENT_VERIFIER_CONCURRENCY ?? "3"}`)
}

function setPositiveEnv(name: string, value: unknown): void {
  const parsed = typeof value === "number" ? value : typeof value === "string" && value.trim() ? Number(value) : NaN
  if (Number.isFinite(parsed) && parsed > 0) process.env[name] = String(Math.floor(parsed))
}

function setNonNegativeEnv(name: string, value: unknown): void {
  const parsed = typeof value === "number" ? value : typeof value === "string" && value.trim() ? Number(value) : NaN
  if (Number.isFinite(parsed) && parsed >= 0) process.env[name] = String(Math.floor(parsed))
}

function setBooleanEnv(name: string, value: unknown): void {
  if (typeof value === "boolean") process.env[name] = value ? "1" : "0"
}

function setBoundedEnv(name: string, value: unknown, min: number, max: number): void {
  const parsed = typeof value === "number" ? value : typeof value === "string" && value.trim() ? Number(value) : NaN
  if (Number.isFinite(parsed)) process.env[name] = String(Math.max(min, Math.min(max, Math.floor(parsed))))
}

function looksLikeGitUrl(input: string): boolean {
  return /^(https?|ssh|git):\/\//i.test(input)
    || /^git@[^:]+:.+/.test(input)
    || /^https?:\/\/github\.com\/[^/]+\/[^/]+\/?$/i.test(input)
}

function normalizeGitUrl(input: string): string {
  if (/^https?:\/\/github\.com\/[^/]+\/[^/]+\/?$/i.test(input) && !input.endsWith(".git")) {
    return input.replace(/\/+$/, "") + ".git"
  }
  return input
}

function makeRunId(): string {
  return `${new Date().toISOString().replace(/[:.]/g, "-")}-${crypto.randomUUID().slice(0, 8)}`
}

function assertLocalDirectory(target: string): string {
  const resolved = resolve(target)
  let stat
  try {
    stat = statSync(resolved)
  } catch {
    throw new Error(`target path does not exist: ${resolved}`)
  }
  if (!stat.isDirectory()) {
    throw new Error(`target path is not a directory: ${resolved}`)
  }
  return resolved
}

async function cloneGitTarget(input: string, runId: string, branch?: string): Promise<string> {
  const runDir = resolve(RUNS_DIR, runId)
  const sourceDir = resolve(runDir, "source")
  mkdirSync(runDir, { recursive: true })

  const args = ["clone", "--depth", "1", "--single-branch", "--no-tags", "--quiet"]
  if (branch) args.push("--branch", branch)
  args.push(normalizeGitUrl(input), sourceDir)

  const proc = Bun.spawn(["git", ...args], {
    stdout: "pipe",
    stderr: "pipe",
    env: { ...Bun.env, GIT_TERMINAL_PROMPT: "0" },
  })
  let timedOut = false
  const timeout = setTimeout(() => {
    timedOut = true
    try { proc.kill("SIGTERM") } catch { /* ignore */ }
  }, GIT_CLONE_TIMEOUT_MS)

  const [stdout, stderr, exitCode] = await Promise.all([
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
    proc.exited,
  ]).finally(() => clearTimeout(timeout))
  if (timedOut) {
    throw new Error(`git clone timed out after ${Math.round(GIT_CLONE_TIMEOUT_MS / 1000)}s`)
  }
  if (exitCode !== 0) {
    throw new Error(`git clone failed (${exitCode}): ${(stderr || stdout).slice(0, 500)}`)
  }
  return sourceDir
}

function makePendingTarget(input: string, runId: string, out?: string): ResolvedTarget {
  const trimmed = input.trim()
  if (!trimmed) throw new Error("missing target")

  if (looksLikeGitUrl(trimmed)) {
    const runDir = resolve(RUNS_DIR, runId)
    return {
      input: trimmed,
      target: resolve(runDir, "source"),
      outputDir: resolve(out ?? resolve(runDir, "output")),
      runId,
      cloned: true,
    }
  }

  const target = resolve(trimmed)
  return {
    input: trimmed,
    target,
    outputDir: resolve(out ?? `${target}/output-audit`),
    runId,
    cloned: false,
  }
}

async function resolveAuditTarget(input: string, out?: string, branch?: string, runId = makeRunId()): Promise<ResolvedTarget> {
  const trimmed = input.trim()
  if (!trimmed) throw new Error("missing target")

  if (looksLikeGitUrl(trimmed)) {
    const sourceDir = await cloneGitTarget(trimmed, runId, branch)
    return {
      input: trimmed,
      target: sourceDir,
      outputDir: resolve(out ?? resolve(RUNS_DIR, runId, "output")),
      runId,
      cloned: true,
    }
  }

  const target = assertLocalDirectory(trimmed)
  return {
    input: trimmed,
    target,
    outputDir: resolve(out ?? `${target}/output-audit`),
    runId,
    cloned: false,
  }
}

function detectLLMConfig(args: string[]): LLMConfig | undefined {
  const provider = (readOption(args, "--provider") ?? "anthropic") as LLMProvider
  const model = readOption(args, "--model")
  const baseUrl = readOption(args, "--base-url")
  const apiKey = readOption(args, "--api-key") ?? ENV_API_KEYS[provider]

  if (!apiKey) {
    const envVar = `${provider.toUpperCase()}_API_KEY`
    console.log(`  [!] No API key for ${provider}. Set --api-key or $${envVar}`)
    return undefined
  }

  return { provider, apiKey, ...(model ? { model } : {}), ...(baseUrl ? { baseUrl } : {}) }
}

async function buildOptions(args: string[]): Promise<AuditOptions & { runId: string; inputTarget: string; cloned: boolean }> {
  const target = readOption(args, "--target") ?? (args[1]?.startsWith("--") ? undefined : args[1])
  if (!target) throw new Error("missing target")
  const resolvedTarget = await resolveAuditTarget(target, readOption(args, "--out"), readOption(args, "--branch"))

  const timeoutRaw = readOption(args, "--timeout")
  const timeoutMinutes = timeoutRaw ? parseInt(timeoutRaw, 10) : 30
  const maxHypothesesRaw = readOption(args, "--max-hypotheses")
  const maxHypotheses = maxHypothesesRaw ? parseInt(maxHypothesesRaw, 10) : 200
  const maxReportDetailsRaw = readOption(args, "--max-report-details")
  const maxReportDetails = maxReportDetailsRaw ? parseInt(maxReportDetailsRaw, 10) : 4

  const llmConfig = detectLLMConfig(args)

  return {
    target: resolvedTarget.target,
    outputDir: resolvedTarget.outputDir,
    projectName: readOption(args, "--name") ?? (resolvedTarget.cloned ? basename(resolvedTarget.input.replace(/\.git$/, "")) : undefined),
    runJoern: !args.includes("--no-joern"),
    timeoutMinutes: Number.isNaN(timeoutMinutes) ? 30 : timeoutMinutes,
    llmConfig,
    maxHypotheses: Number.isNaN(maxHypotheses) ? 200 : maxHypotheses,
    maxReportDetails: Number.isNaN(maxReportDetails) ? 4 : maxReportDetails,
    runId: resolvedTarget.runId,
    inputTarget: resolvedTarget.input,
    cloned: resolvedTarget.cloned,
  }
}

function printHelp() {
  console.log(`night_agent — 代码审计 Agent

Usage:
  bun run apps/cli/src/main.ts audit <path-or-git-url> [options]
  bun run apps/cli/src/main.ts audit --target <path-or-git-url> [options]
  bun run apps/cli/src/main.ts batch --reports-dir <folder> <path-or-git-url>... [options]
  bun run apps/cli/src/main.ts batch --targets <file> --reports-dir <folder> [options]
  bun run apps/cli/src/main.ts serve [--port <port>]

Options (audit mode):
  --target <target>   待审计项目目录或 Git URL
  --branch <name>     clone Git URL 时使用指定分支
  --out <path>        输出目录，默认 <target>/output-audit
  --name <name>       报告项目名，默认目标目录名
  --no-joern          跳过 Joern CPG 数据流追踪
  --timeout <min>     最大运行时间（分钟），默认 30
  --provider <name>   LLM provider: anthropic|openai|deepseek|glm (默认 anthropic)
  --model <name>      LLM model (默认 provider 对应的推荐模型)
  --base-url <url>    覆盖 LLM API 地址
  --api-key <key>     LLM API key (也可通过环境变量设置)
  --max-hypotheses N  最多追踪 N 个假设，默认 200
  --max-report-details N  兼容旧参数；当前报告由 ReportAgent 一次生成完整 Markdown
  --help, -h          显示帮助信息

Options (batch mode):
  --targets <file>    批量目标列表文件；每行一个本地路径或 Git URL，# 开头为注释
  --target <target>   追加一个批量目标，可重复传入
  --reports-dir <dir> 集中存放漏洞报告、batch-state.json 和 batch-summary.md
  --out-root <dir>    每个目标的原始审计产物目录，默认 <reports-dir>/.runs
  --rerun             已完成目标也重新执行
  --reset             忽略旧 batch-state.json，按当前目标列表重建批次
  --stop-on-error     任一目标失败后停止后续目标

Options (serve mode):
  --port <port>       HTTP 服务端口，默认 3000
`)
}

function readOption(args: string[], name: string): string | undefined {
  const index = args.indexOf(name)
  if (index === -1) return undefined
  const value = args[index + 1]
  if (!value || value.startsWith("--")) throw new Error(`${name} requires a value`)
  return value
}

// ─── CLI audit mode ───

async function runAudit(args: string[]) {
  const options = await buildOptions(args)

  console.log(`[night_agent] input  : ${options.inputTarget}${options.cloned ? " (cloned)" : ""}`)
  console.log(`[night_agent] target : ${options.target}`)
  console.log(`[night_agent] output : ${options.outputDir}`)
  console.log(`[night_agent] llm    : ${options.llmConfig ? `${options.llmConfig.provider}/${options.llmConfig.model ?? "default"}` : "none (no api key)"}`)
  console.log(`[night_agent] joern  : ${options.runJoern ? "enabled" : "disabled"}`)
  console.log(`[night_agent] timeout: ${options.timeoutMinutes}min`)
  console.log(`[night_agent] report : AI Markdown`)
  console.log()

  if (!options.llmConfig) {
    throw new Error("night_agent requires an AI API key. Set --api-key or provider API key env before starting an audit.")
  }
  await assertConfiguredLlmReady(options.llmConfig)

  const manager = new AuditManager(options)
  const report = await manager.run()

  printReport(report)
}

function printReport(report: AuditReport) {
  console.log()
  console.log(`[+] project  : ${report.profile.name} (${report.profile.language})`)
  console.log(`[+] routes   : ${report.profile.routes.length}`)
  console.log(`[+] hypotheses: ${report.stats.totalHypotheses}`)
  console.log(`[+] confirmed: ${report.stats.confirmedFindings}`)
  console.log(`[+] dismissed: ${report.stats.dismissedHypotheses}`)
  console.log(`[+] coverage : ${report.stats.coveragePercent}%`)
  console.log(`[+] elapsed  : ${report.stats.elapsedSeconds}s`)
  console.log(`[+] joern    : ${report.joern.ran ? "ran" : `skipped (${report.joern.skippedReason})`}`)

  if (report.observer.warnings.length > 0) {
    console.log(`[!] observer warnings:`)
    for (const w of report.observer.warnings) console.log(`    ${w}`)
  }

  console.log()
  console.log("[+] generated files:")
  for (const file of report.generatedFiles) console.log(`    ${file}`)
}

// ─── CLI batch mode ───

type BatchEntryStatus = "pending" | "running" | "interrupted" | "completed" | "failed"

interface BatchEntry {
  id: string
  input: string
  runId: string
  outputDir: string
  target?: string
  cloned?: boolean
  status: BatchEntryStatus
  startedAt?: number
  completedAt?: number
  updatedAt?: number
  error?: string
  reportFiles?: string[]
  generatedFiles?: string[]
  stats?: AuditReport["stats"]
  observerWarnings?: string[]
}

interface BatchState {
  version: 1
  reportsDir: string
  outRoot: string
  running?: boolean
  stopOnError?: boolean
  currentIndex?: number
  createdAt: number
  updatedAt: number
  entries: BatchEntry[]
}

interface ActiveBatchRun {
  statePath: string
  reportsDir: string
  state: BatchState
  currentManager: AuditManager | null
  stopRequested: boolean
  rerun: boolean
  stopOnError: boolean
}

const BATCH_VALUE_OPTIONS = new Set([
  "--targets",
  "--target",
  "--reports-dir",
  "--report-dir",
  "--out-root",
  "--out",
  "--name",
  "--branch",
  "--provider",
  "--model",
  "--base-url",
  "--api-key",
  "--timeout",
  "--max-hypotheses",
  "--max-report-details",
])

async function runBatch(args: string[]) {
  const reportsDirRaw = readOption(args, "--reports-dir") ?? readOption(args, "--report-dir")
  if (!reportsDirRaw) throw new Error("batch mode requires --reports-dir <folder>")

  const reportsDir = resolve(reportsDirRaw)
  const outRoot = resolve(readOption(args, "--out-root") ?? resolve(reportsDir, ".runs"))
  mkdirSync(reportsDir, { recursive: true })
  mkdirSync(outRoot, { recursive: true })

  const targets = collectBatchTargets(args)
  if (targets.length === 0) throw new Error("batch mode requires at least one target path or --targets <file>")

  const llmConfig = detectLLMConfig(args)
  if (!llmConfig) {
    throw new Error("night_agent batch requires an AI API key. Set --api-key or provider API key env before starting.")
  }
  await assertConfiguredLlmReady(llmConfig)

  const statePath = resolve(reportsDir, "batch-state.json")
  const state = prepareBatchState(loadBatchState(statePath), targets, reportsDir, outRoot, args.includes("--reset"))
  saveBatchState(statePath, state)

  const timeoutMinutes = parseIntOption(args, "--timeout", 30)
  const maxHypotheses = parseIntOption(args, "--max-hypotheses", 200)
  const maxReportDetails = parseIntOption(args, "--max-report-details", 4)
  const branch = readOption(args, "--branch")
  const rerun = args.includes("--rerun")
  const stopOnError = args.includes("--stop-on-error")
  let activeEntry: BatchEntry | null = null

  const onSigint = () => {
    if (activeEntry) {
      activeEntry.status = "interrupted"
      activeEntry.updatedAt = Date.now()
      activeEntry.error = "interrupted by SIGINT"
      state.updatedAt = Date.now()
      saveBatchState(statePath, state)
      writeBatchSummary(state, reportsDir)
      console.log(`\n[night_agent] batch interrupted; checkpoint saved for ${activeEntry.input}`)
    }
    process.exit(130)
  }
  process.once("SIGINT", onSigint)

  try {
    console.log(`[night_agent] batch targets : ${state.entries.length}`)
    console.log(`[night_agent] reports dir   : ${reportsDir}`)
    console.log(`[night_agent] state file    : ${statePath}`)
    console.log(`[night_agent] llm           : ${llmConfig.provider}/${llmConfig.model ?? "default"}`)
    console.log(`[night_agent] joern         : ${args.includes("--no-joern") ? "disabled" : "enabled"}`)
    console.log()

    for (let index = 0; index < state.entries.length; index++) {
      const entry = state.entries[index]!
      if (entry.status === "completed" && !rerun) {
        console.log(`[batch ${index + 1}/${state.entries.length}] skip completed: ${entry.input}`)
        continue
      }

      activeEntry = entry
      entry.status = "running"
      entry.startedAt = entry.startedAt ?? Date.now()
      entry.updatedAt = Date.now()
      entry.error = undefined
      state.updatedAt = Date.now()
      saveBatchState(statePath, state)

      console.log(`[batch ${index + 1}/${state.entries.length}] auditing: ${entry.input}`)
      try {
        const resolvedTarget = await resolveBatchTarget(entry, branch)
        entry.target = resolvedTarget.target
        entry.cloned = resolvedTarget.cloned
        entry.outputDir = resolvedTarget.outputDir
        entry.updatedAt = Date.now()
        saveBatchState(statePath, state)

        const resumeFromCheckpoint = !rerun && existsSync(resolve(entry.outputDir, "checkpoints", "run-state.json"))
        const options: AuditOptions = {
          target: resolvedTarget.target,
          outputDir: resolvedTarget.outputDir,
          projectName: batchProjectName(entry.input),
          runJoern: !args.includes("--no-joern"),
          timeoutMinutes,
          llmConfig,
          maxHypotheses,
          maxReportDetails,
          resumeFromCheckpoint,
        }

        const manager = new AuditManager(options)
        const report = await manager.run()
        const reportFiles = copyBatchReportFiles(report, entry.outputDir, reportsDir, index + 1)

        entry.status = "completed"
        entry.completedAt = Date.now()
        entry.updatedAt = Date.now()
        entry.error = undefined
        entry.stats = report.stats
        entry.observerWarnings = report.observer.warnings
        entry.generatedFiles = discoverGeneratedFiles(entry.outputDir, report.generatedFiles)
        entry.reportFiles = reportFiles
        state.updatedAt = Date.now()
        saveBatchState(statePath, state)
        writeBatchSummary(state, reportsDir)

        console.log(`[batch ${index + 1}/${state.entries.length}] completed: ${report.profile.name} confirmed=${report.stats.confirmedFindings} coverage=${report.stats.coveragePercent}%`)
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err)
        entry.status = "failed"
        entry.error = message
        entry.updatedAt = Date.now()
        state.updatedAt = Date.now()
        saveBatchState(statePath, state)
        writeBatchSummary(state, reportsDir)
        console.error(`[batch ${index + 1}/${state.entries.length}] failed: ${entry.input}`)
        console.error(`  ${message}`)
        if (stopOnError) break
      } finally {
        activeEntry = null
      }
    }

    writeBatchSummary(state, reportsDir)
    const completed = state.entries.filter((entry) => entry.status === "completed").length
    const failed = state.entries.filter((entry) => entry.status === "failed").length
    console.log()
    console.log(`[night_agent] batch finished: completed=${completed}, failed=${failed}, total=${state.entries.length}`)
    console.log(`[night_agent] summary: ${resolve(reportsDir, "batch-summary.md")}`)
  } finally {
    process.removeListener("SIGINT", onSigint)
  }
}

function collectBatchTargets(args: string[]): string[] {
  const values: string[] = []
  const targetsFile = readOption(args, "--targets")
  if (targetsFile) {
    const text = readFileSync(resolve(targetsFile), "utf-8")
    for (const line of text.split(/\r?\n/)) {
      const trimmed = line.trim()
      if (!trimmed || trimmed.startsWith("#")) continue
      values.push(trimmed)
    }
  }
  values.push(...readRepeatedOptions(args, "--target"))
  values.push(...readPositionalTargets(args))

  const seen = new Set<string>()
  const targets: string[] = []
  for (const raw of values) {
    const normalized = normalizeBatchInput(raw)
    if (seen.has(normalized)) continue
    seen.add(normalized)
    targets.push(normalized)
  }
  return targets
}

function readRepeatedOptions(args: string[], name: string): string[] {
  const values: string[] = []
  for (let i = 0; i < args.length; i++) {
    if (args[i] !== name) continue
    const value = args[i + 1]
    if (!value || value.startsWith("--")) throw new Error(`${name} requires a value`)
    values.push(value)
    i++
  }
  return values
}

function readPositionalTargets(args: string[]): string[] {
  const values: string[] = []
  for (let i = 1; i < args.length; i++) {
    const value = args[i]!
    if (value.startsWith("--")) {
      if (BATCH_VALUE_OPTIONS.has(value)) i++
      continue
    }
    values.push(value)
  }
  return values
}

function normalizeBatchInput(input: string): string {
  const trimmed = input.trim()
  if (looksLikeGitUrl(trimmed)) return normalizeGitUrl(trimmed)
  return resolve(trimmed)
}

function prepareBatchState(
  existing: BatchState | null,
  targets: string[],
  reportsDir: string,
  outRoot: string,
  reset: boolean,
): BatchState {
  const previous = new Map((existing?.entries ?? []).map((entry) => [entry.id, entry]))
  const entries = targets.map((input) => {
    const id = batchEntryId(input)
    const old = reset ? undefined : previous.get(id)
    if (old) {
      return {
        ...old,
        input,
        status: old.status === "running" ? "interrupted" as const : old.status,
      }
    }
    return {
      id,
      input,
      runId: `batch-${id}`,
      outputDir: resolve(outRoot, id, "output"),
      status: "pending" as const,
    }
  })
  return {
    version: 1,
    reportsDir,
    outRoot,
    createdAt: existing?.createdAt ?? Date.now(),
    updatedAt: Date.now(),
    entries,
  }
}

function loadBatchState(path: string): BatchState | null {
  try {
    return JSON.parse(readFileSync(path, "utf-8")) as BatchState
  } catch {
    return null
  }
}

function saveBatchState(path: string, state: BatchState): void {
  mkdirSync(dirname(path), { recursive: true })
  writeFileSync(path, `${JSON.stringify(state, null, 2)}\n`)
}

async function resolveBatchTarget(entry: BatchEntry, branch?: string): Promise<ResolvedTarget> {
  if (looksLikeGitUrl(entry.input)) {
    const sourceDir = resolve(RUNS_DIR, entry.runId, "source")
    if (!existsSync(resolve(sourceDir, ".git"))) {
      rmSync(sourceDir, { recursive: true, force: true })
      await cloneGitTarget(entry.input, entry.runId, branch)
    }
    return {
      input: entry.input,
      target: sourceDir,
      outputDir: entry.outputDir,
      runId: entry.runId,
      cloned: true,
    }
  }

  return {
    input: entry.input,
    target: assertLocalDirectory(entry.input),
    outputDir: entry.outputDir,
    runId: entry.runId,
    cloned: false,
  }
}

function copyBatchReportFiles(report: AuditReport, outputDir: string, reportsDir: string, index: number): string[] {
  const files = discoverGeneratedFiles(outputDir, report.generatedFiles)
  const prefix = `${String(index).padStart(2, "0")}-${safeFilePart(report.profile.name)}`
  const copied: string[] = []
  const markdownFiles = files.filter((file) => file.endsWith(".md"))

  for (const file of markdownFiles) {
    const suffix = file.includes("完整结果") ? "完整结果.md" : file.includes("审计报告") ? "审计报告.md" : safeFilePart(basename(file))
    const dest = resolve(reportsDir, `${prefix}-${suffix}`)
    copyFileSync(file, dest)
    copied.push(dest)
  }

  const summary = files.find((file) => file.endsWith("audit-summary.json"))
  if (summary) {
    const dest = resolve(reportsDir, `${prefix}-audit-summary.json`)
    copyFileSync(summary, dest)
    copied.push(dest)
  }

  return copied
}

function writeBatchSummary(state: BatchState, reportsDir: string): void {
  const rows = state.entries.map((entry, index) => {
    const stats = entry.stats
    const reports = (entry.reportFiles ?? []).filter((file) => file.endsWith(".md")).map((file) => basename(file)).join("<br>") || "-"
    return `| ${index + 1} | ${entry.status} | ${mdCell(batchProjectName(entry.input))} | ${mdCell(entry.input)} | ${stats?.confirmedFindings ?? "-"} | ${stats?.coveragePercent ?? "-"} | ${reports} | ${mdCell(entry.error ?? "")} |`
  })
  const markdown = `# night_agent 批量审计汇总

- 报告目录：\`${reportsDir}\`
- 总数：${state.entries.length}
- 已完成：${state.entries.filter((entry) => entry.status === "completed").length}
- 失败：${state.entries.filter((entry) => entry.status === "failed").length}
- 更新时间：${new Date(state.updatedAt).toISOString()}

| # | 状态 | 项目 | 输入 | 确认漏洞 | 覆盖率 | 报告文件 | 错误 |
| --- | --- | --- | --- | --- | --- | --- | --- |
${rows.join("\n")}
`
  writeFileSync(resolve(reportsDir, "batch-summary.md"), markdown)
}

function batchEntryId(input: string): string {
  const hash = createHash("sha1").update(input).digest("hex").slice(0, 10)
  return `${safeFilePart(batchProjectName(input))}-${hash}`
}

function batchProjectName(input: string): string {
  if (looksLikeGitUrl(input)) {
    const noSlash = input.replace(/\/+$/, "")
    return basename(noSlash).replace(/\.git$/i, "") || "git-project"
  }
  return basename(input) || "project"
}

function safeFilePart(value: string): string {
  return (value || "project").replace(/[\\/:*?"<>|\s]+/g, "_").replace(/^_+|_+$/g, "").slice(0, 80) || "project"
}

function parseIntOption(args: string[], name: string, fallback: number): number {
  const raw = readOption(args, name)
  if (!raw) return fallback
  const parsed = parseInt(raw, 10)
  return Number.isNaN(parsed) ? fallback : parsed
}

function mdCell(value: unknown): string {
  return String(value ?? "-").replace(/\|/g, "\\|").replace(/\r?\n/g, "<br>").trim() || "-"
}

// ─── Serve mode ───

function findWebDist(): string {
  const candidates = [
    resolve(import.meta.dir, "../../web/dist"),
    resolve(import.meta.dir, "../../../apps/web/dist"),
  ]
  for (const c of candidates) {
    if (existsSync(resolve(c, "index.html"))) return c
  }
  return candidates[0]!
}

function mimeType(path: string): string {
  if (path.endsWith(".html")) return "text/html; charset=utf-8"
  if (path.endsWith(".js")) return "application/javascript"
  if (path.endsWith(".css")) return "text/css"
  if (path.endsWith(".svg")) return "image/svg+xml"
  if (path.endsWith(".json")) return "application/json"
  return "application/octet-stream"
}

async function runServe(args: string[]) {
  const portRaw = readOption(args, "--port")
  const port = portRaw ? parseInt(portRaw, 10) : 3000

  // Shared state for the server
  let currentReport: AuditReport | null = null
  let runningManager: AuditManager | null = null
  let startingAudit = false
  let startingAuditAt = 0
  let currentRun: ResolvedTarget | null = null
  let activeBatch: ActiveBatchRun | null = null
  const db = initAuditDb()
  markInterruptedRuns(db)
  const wsClients = new Set<{ send: (data: string) => void }>()

  const webDist = findWebDist()
  console.log(`[night_agent] serve mode — port ${port}`)
  console.log(`[night_agent] web dist: ${webDist}`)

  const server = serve({
    port,
    fetch(req, server) {
      const url = new URL(req.url)

      // WebSocket upgrade
      if (url.pathname === "/ws") {
        if (server.upgrade(req)) return
        return new Response("WebSocket upgrade failed", { status: 500 })
      }

      // API: start audit
      if (url.pathname === "/api/audit/start" && req.method === "POST") {
        return handleStartAudit(req)
      }

      if (url.pathname === "/api/audit/pause" && req.method === "POST") {
        return handlePauseAudit()
      }

      if (url.pathname === "/api/batch/start" && req.method === "POST") {
        return handleStartBatch(req)
      }

      if (url.pathname === "/api/batch/status" && req.method === "GET") {
        return handleBatchStatus(url)
      }

      if (url.pathname === "/api/settings/model") {
        if (req.method === "GET") return handleGetModelSettings()
        if (req.method === "PUT" || req.method === "POST") return handleSaveModelSettings(req)
      }

      if (url.pathname === "/api/audit/history") {
        return handleHistory()
      }

      const runMatch = url.pathname.match(/^\/api\/audit\/runs\/([^/]+)$/)
      if (runMatch?.[1]) {
        if (req.method === "DELETE") {
          return handleDeleteRun(runMatch[1])
        }
        return handleRunDetail(runMatch[1])
      }

      const resumeMatch = url.pathname.match(/^\/api\/audit\/runs\/([^/]+)\/resume$/)
      if (resumeMatch?.[1] && req.method === "POST") {
        return handleResumeRun(req, resumeMatch[1])
      }

      const reportMatch = url.pathname.match(/^\/api\/audit\/runs\/([^/]+)\/report\/markdown$/)
      if (reportMatch?.[1]) {
        return handleRunReportFile(reportMatch[1], "report")
      }

      const completeReportMatch = url.pathname.match(/^\/api\/audit\/runs\/([^/]+)\/report\/complete-markdown$/)
      if (completeReportMatch?.[1]) {
        return handleRunReportFile(completeReportMatch[1], "complete")
      }

      // API: get status
      if (url.pathname === "/api/audit/status") {
        return handleGetStatus()
      }

      // API: get findings
      if (url.pathname === "/api/audit/findings") {
        return handleGetFindings()
      }

      // API: get report
      if (url.pathname === "/api/audit/report") {
        return handleGetReport()
      }

      // Serve static files
      let filePath = url.pathname === "/" ? "/index.html" : url.pathname
      const fullPath = resolve(webDist, filePath.startsWith("/") ? filePath.slice(1) : filePath)
      const rel = relative(webDist, fullPath)
      if (rel.startsWith("..") || isAbsolute(rel)) {
        return new Response("Not Found", { status: 404 })
      }

      try {
        const content = readFileSync(fullPath)
        return new Response(content, {
          headers: { "Content-Type": mimeType(fullPath) },
        })
      } catch {
        // SPA fallback
        try {
          const indexContent = readFileSync(resolve(webDist, "index.html"))
          return new Response(indexContent, {
            headers: { "Content-Type": "text/html; charset=utf-8" },
          })
        } catch {
          return new Response("Not Found", { status: 404 })
        }
      }
    },
    websocket: {
      open(ws) {
        wsClients.add(ws)
      },
      close(ws) {
        wsClients.delete(ws)
      },
      message() {
        // Client messages ignored
      },
    },
  })

  function broadcast(msg: AgentBusEvent) {
    if (currentRun) persistEvent(currentRun.runId, msg)
    const data = JSON.stringify(msg)
    for (const ws of wsClients) {
      try { ws.send(data) } catch { wsClients.delete(ws) }
    }
  }

  function persistEvent(runId: string, msg: AgentBusEvent): void {
    db.query(`
      INSERT INTO audit_events (run_id, kind, source, timestamp, payload_json)
      VALUES (?, ?, ?, ?, ?)
    `).run(runId, msg.kind, msg.source, msg.timestamp, JSON.stringify(msg.payload ?? null))

    if (msg.kind === "source:extracted" && msg.payload && typeof msg.payload === "object") {
      const p = msg.payload as Record<string, unknown>
      db.query(`
        INSERT OR REPLACE INTO audit_sources
          (run_id, id, kind, param_name, file, line, code, method_name, class_name, payload_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        runId,
        String(p.id ?? crypto.randomUUID()),
        String(p.kind ?? ""),
        String(p.paramName ?? ""),
        String(p.file ?? ""),
        Number(p.line ?? 0),
        String(p.code ?? ""),
        String(p.methodName ?? ""),
        p.className == null ? null : String(p.className),
        JSON.stringify(msg.payload),
      )
    }
  }

  function createRunRecord(run: ResolvedTarget, options: AuditOptions, provider: string, model: string | undefined): void {
    db.query(`
      INSERT OR REPLACE INTO audit_runs
        (run_id, input, target, output_dir, cloned, provider, model, mode, status, project_name, started_at, generated_files_json)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      run.runId,
      run.input,
      run.target,
      run.outputDir,
      run.cloned ? 1 : 0,
      provider,
      model ?? null,
      options.runJoern === false ? "quick" : "full",
      "preparing",
      options.projectName ?? null,
      Date.now(),
      "[]",
    )
  }

  function updateRunRecordStarted(run: ResolvedTarget, options: AuditOptions): void {
    db.query(`
      UPDATE audit_runs
      SET target = ?, output_dir = ?, cloned = ?, status = ?, project_name = ?
      WHERE run_id = ?
    `).run(
      run.target,
      run.outputDir,
      run.cloned ? 1 : 0,
      "running",
      options.projectName ?? null,
      run.runId,
    )
  }

  function completeRunRecord(runId: string, report: AuditReport): void {
    const row = db.query("SELECT output_dir FROM audit_runs WHERE run_id = ?").get(runId) as Record<string, unknown> | null
    const outputDir = row?.output_dir == null ? "" : String(row.output_dir)
    const generatedFiles = outputDir ? discoverGeneratedFiles(outputDir, report.generatedFiles) : report.generatedFiles
    db.query(`
      UPDATE audit_runs
      SET status = ?, project_name = ?, completed_at = ?, stats_json = ?, observer_json = ?,
          generated_files_json = ?, report_json = ?, error = NULL
      WHERE run_id = ?
    `).run(
      "completed",
      report.profile.name,
      Date.now(),
      JSON.stringify(report.stats),
      JSON.stringify(report.observer),
      JSON.stringify(generatedFiles.length > 0 ? generatedFiles : report.generatedFiles),
      null,
      runId,
    )
  }

  function failRunRecord(runId: string, error: string): void {
    db.query(`
      UPDATE audit_runs
      SET status = ?, completed_at = ?, error = ?
      WHERE run_id = ?
    `).run("error", Date.now(), error, runId)
  }

  async function handleStartAudit(req: Request): Promise<Response> {
    if (runningManager || startingAudit) {
      return new Response(JSON.stringify({ error: "audit already running" }), {
        status: 409,
        headers: { "Content-Type": "application/json" },
      })
    }

    startingAudit = true
    startingAuditAt = Date.now()
    try {
      const body = await req.json()
      applyJoernRuntimeConfig(body as Record<string, unknown>)
      applyVerifierRuntimeConfig(body as Record<string, unknown>)
      const storedSettings = getModelSettings(db)
      const { repoUrl, provider, model, apiKey, baseUrl, branch, runJoern } = body
      const requestedProvider = (typeof provider === "string" && provider.trim() ? provider.trim() : storedSettings.provider) as LLMProvider
      const modelName = typeof model === "string" && model.trim() ? model.trim() : storedSettings.model || undefined
      const requestBaseUrl = typeof baseUrl === "string" && baseUrl.trim() ? baseUrl.trim() : storedSettings.baseUrl || undefined
      const providerName = inferProvider(VALID_PROVIDERS.has(requestedProvider) ? requestedProvider : storedSettings.provider, modelName ?? "", requestBaseUrl ?? "")
      const key = typeof apiKey === "string" && apiKey.trim() ? apiKey.trim() : ENV_API_KEYS[providerName] ?? ""
      const resolvedKey = key || (providerName === storedSettings.provider ? storedSettings.apiKey : "")
      if (!resolvedKey) {
        startingAudit = false
        startingAuditAt = 0
        return new Response(JSON.stringify({ error: "night_agent requires an AI API key before starting an audit" }), {
          status: 400,
          headers: { "Content-Type": "application/json" },
        })
      }

      const llmConfig: LLMConfig = {
        provider: providerName,
        apiKey: resolvedKey,
        model: modelName,
        baseUrl: requestBaseUrl,
      }
      await assertConfiguredLlmReady(llmConfig)

      const inputTarget = String(repoUrl ?? "")
      const runId = makeRunId()
      const pendingTarget = makePendingTarget(inputTarget, runId)
      const pendingOptions: AuditOptions = {
        target: pendingTarget.target,
        outputDir: pendingTarget.outputDir,
        llmConfig,
        projectName: pendingTarget.cloned ? basename(pendingTarget.input.replace(/\.git$/, "")) : undefined,
        runJoern: runJoern === false ? false : true,
        timeoutMinutes: 30,
        maxHypotheses: 200,
        maxReportDetails: 4,
      }
      currentRun = pendingTarget
      createRunRecord(pendingTarget, pendingOptions, providerName, modelName)

      runAuditInBackground({
        pendingTarget,
        pendingOptions,
        inputTarget,
        branch: branch ? String(branch) : undefined,
        reuseExistingTarget: false,
      })

      return new Response(JSON.stringify({
        ok: true,
        runId: pendingTarget.runId,
        input: pendingTarget.input,
        target: pendingTarget.target,
        outputDir: pendingTarget.outputDir,
        cloned: pendingTarget.cloned,
      }), {
        headers: { "Content-Type": "application/json" },
      })
    } catch (err) {
      startingAudit = false
      startingAuditAt = 0
      return new Response(JSON.stringify({ error: err instanceof Error ? err.message : String(err) }), {
        status: 400,
        headers: { "Content-Type": "application/json" },
      })
    }
  }

  async function handleResumeRun(req: Request, runId: string): Promise<Response> {
    if (runningManager || startingAudit) {
      return new Response(JSON.stringify({ error: "audit already running" }), {
        status: 409,
        headers: { "Content-Type": "application/json" },
      })
    }

    const row = db.query("SELECT * FROM audit_runs WHERE run_id = ?").get(runId) as Record<string, unknown> | null
    if (!row) {
      return new Response(JSON.stringify({ error: "run not found" }), {
        status: 404,
        headers: { "Content-Type": "application/json" },
      })
    }
    const status = String(row.status)
    if (!["error", "interrupted"].includes(status)) {
      return new Response(JSON.stringify({ error: `run is not resumable: ${status}` }), {
        status: 409,
        headers: { "Content-Type": "application/json" },
      })
    }
    const target = String(row.target)
    const outputDir = String(row.output_dir)
    if (!existsSync(target) || !statSync(target).isDirectory()) {
      return new Response(JSON.stringify({ error: `source directory is missing: ${target}` }), {
        status: 400,
        headers: { "Content-Type": "application/json" },
      })
    }

    let body: Record<string, unknown> = {}
    try {
      body = await req.json() as Record<string, unknown>
    } catch {
      body = {}
    }
    applyJoernRuntimeConfig(body)
    applyVerifierRuntimeConfig(body)
    const storedSettings = getModelSettings(db)
    const requestedProvider = (typeof body.provider === "string" && body.provider.trim() ? body.provider.trim() : String(row.provider ?? storedSettings.provider)) as LLMProvider
    const modelName = typeof body.model === "string" && body.model.trim() ? body.model.trim() : String(row.model ?? storedSettings.model) || undefined
    const requestBaseUrl = typeof body.baseUrl === "string" && body.baseUrl.trim() ? body.baseUrl.trim() : storedSettings.baseUrl || undefined
    const providerName = inferProvider(VALID_PROVIDERS.has(requestedProvider) ? requestedProvider : storedSettings.provider, modelName ?? "", requestBaseUrl ?? "")
    const key = typeof body.apiKey === "string" && body.apiKey.trim() ? body.apiKey.trim() : ENV_API_KEYS[providerName] ?? ""
    const resolvedKey = key || (providerName === storedSettings.provider ? storedSettings.apiKey : "")
    if (!resolvedKey) {
      return new Response(JSON.stringify({ error: "night_agent requires an AI API key before resuming an audit" }), {
        status: 400,
        headers: { "Content-Type": "application/json" },
      })
    }

    const run: ResolvedTarget = {
      input: String(row.input),
      target,
      outputDir,
      runId,
      cloned: Number(row.cloned) === 1,
    }
    const llmConfig: LLMConfig = {
      provider: providerName,
      apiKey: resolvedKey,
      model: modelName,
      baseUrl: requestBaseUrl,
    }
    try {
      await assertConfiguredLlmReady(llmConfig)
    } catch (err) {
      return new Response(JSON.stringify({ error: err instanceof Error ? err.message : String(err) }), {
        status: 400,
        headers: { "Content-Type": "application/json" },
      })
    }

    const options: AuditOptions = {
      target,
      outputDir,
      llmConfig,
      projectName: row.project_name == null ? undefined : String(row.project_name),
      runJoern: String(row.mode) !== "quick",
      resumeFromCheckpoint: true,
      timeoutMinutes: 30,
      maxHypotheses: 200,
      maxReportDetails: 4,
    }
    currentRun = run
    currentReport = null
    startingAudit = true
    startingAuditAt = Date.now()
    db.query(`
      UPDATE audit_runs
      SET provider = ?, model = ?, status = ?, completed_at = NULL, error = NULL
      WHERE run_id = ?
    `).run(providerName, modelName ?? null, "preparing", runId)

    runAuditInBackground({
      pendingTarget: run,
      pendingOptions: options,
      inputTarget: run.input,
      reuseExistingTarget: true,
    })

    return new Response(JSON.stringify({
      ok: true,
      runId: run.runId,
      input: run.input,
      target: run.target,
      outputDir: run.outputDir,
      cloned: run.cloned,
      resumed: true,
    }), {
      headers: { "Content-Type": "application/json" },
    })
  }

  function runAuditInBackground(input: {
    pendingTarget: ResolvedTarget
    pendingOptions: AuditOptions
    inputTarget: string
    branch?: string
    reuseExistingTarget: boolean
  }): void {
    const { pendingTarget, pendingOptions, inputTarget, branch, reuseExistingTarget } = input
    ;(async () => {
      try {
        pauseReason = null
        broadcast({
          kind: "state:enter",
          payload: {
            state: "preparing",
            description: reuseExistingTarget
              ? "正在从 checkpoint 继续审计"
              : pendingTarget.cloned ? "正在克隆 Git 仓库" : "正在校验本地项目路径",
            resumed: reuseExistingTarget,
          },
          timestamp: Date.now(),
          source: "server",
        })
        const resolvedTarget = reuseExistingTarget
          ? pendingTarget
          : await resolveAuditTarget(inputTarget, undefined, branch, pendingTarget.runId)
        currentRun = resolvedTarget

        const options: AuditOptions = {
          ...pendingOptions,
          target: resolvedTarget.target,
          outputDir: resolvedTarget.outputDir,
          projectName: pendingOptions.projectName ?? (resolvedTarget.cloned ? basename(resolvedTarget.input.replace(/\.git$/, "")) : undefined),
          isPauseRequested: () => runningManager === null ? null : pauseReason,
        }
        updateRunRecordStarted(resolvedTarget, options)

        runningManager = new AuditManager(options, broadcast)
        startingAudit = false
        startingAuditAt = 0

        const report = await runningManager.run()
        currentReport = report
        runningManager = null
        completeRunRecord(resolvedTarget.runId, report)
        broadcast({
          kind: "audit:completed",
          payload: { stats: report.stats, runId: resolvedTarget.runId, generatedFiles: report.generatedFiles },
          timestamp: Date.now(),
          source: "server",
        })
      } catch (err) {
        runningManager?.stop()
        runningManager = null
        startingAudit = false
        startingAuditAt = 0
        const msg = err instanceof Error ? err.message : String(err)
        if (msg.startsWith("AUDIT_PAUSED:") || err instanceof Error && err.name === "AuditPausedError") {
          markRunPaused(pendingTarget.runId, msg.replace(/^AUDIT_PAUSED:/, ""))
          broadcast({
            kind: "audit:paused",
            payload: { status: "paused", reason: msg.replace(/^AUDIT_PAUSED:/, ""), runId: pendingTarget.runId },
            timestamp: Date.now(),
            source: "server",
          })
        } else {
          failRunRecord(pendingTarget.runId, msg)
          broadcast({
            kind: "audit:error",
            payload: { error: msg, runId: pendingTarget.runId },
            timestamp: Date.now(),
            source: "server",
          })
        }
      }
    })()
  }

  async function handleStartBatch(req: Request): Promise<Response> {
    if (runningManager || startingAudit) {
      return new Response(JSON.stringify({ error: "single audit is already running" }), {
        status: 409,
        headers: { "Content-Type": "application/json" },
      })
    }
    if (activeBatch?.state.running) {
      return new Response(JSON.stringify({ error: "batch audit is already running" }), {
        status: 409,
        headers: { "Content-Type": "application/json" },
      })
    }

    try {
      const body = await req.json() as Record<string, unknown>
      applyJoernRuntimeConfig(body)
      applyVerifierRuntimeConfig(body)
      const reportsDirRaw = typeof body.reportsDir === "string" ? body.reportsDir.trim() : ""
      if (!reportsDirRaw) {
        return new Response(JSON.stringify({ error: "reportsDir is required" }), {
          status: 400,
          headers: { "Content-Type": "application/json" },
        })
      }

      const targetValues = Array.isArray(body.targets)
        ? body.targets.map((item) => String(item).trim()).filter(Boolean)
        : typeof body.targetsText === "string"
          ? body.targetsText.split(/\r?\n/).map((line) => line.trim()).filter((line) => line && !line.startsWith("#"))
          : []
      const targets = [...new Set(targetValues.map(normalizeBatchInput))]
      if (targets.length === 0) {
        return new Response(JSON.stringify({ error: "at least one batch target is required" }), {
          status: 400,
          headers: { "Content-Type": "application/json" },
        })
      }

      const storedSettings = getModelSettings(db)
      const requestedProvider = (typeof body.provider === "string" && body.provider.trim() ? body.provider.trim() : storedSettings.provider) as LLMProvider
      const modelName = typeof body.model === "string" && body.model.trim() ? body.model.trim() : storedSettings.model || undefined
      const requestBaseUrl = typeof body.baseUrl === "string" && body.baseUrl.trim() ? body.baseUrl.trim() : storedSettings.baseUrl || undefined
      const providerName = inferProvider(VALID_PROVIDERS.has(requestedProvider) ? requestedProvider : storedSettings.provider, modelName ?? "", requestBaseUrl ?? "")
      const key = typeof body.apiKey === "string" && body.apiKey.trim() ? body.apiKey.trim() : ENV_API_KEYS[providerName] ?? ""
      const resolvedKey = key || (providerName === storedSettings.provider ? storedSettings.apiKey : "")
      if (!resolvedKey) {
        return new Response(JSON.stringify({ error: "night_agent requires an AI API key before starting a batch" }), {
          status: 400,
          headers: { "Content-Type": "application/json" },
        })
      }
      const llmConfig: LLMConfig = {
        provider: providerName,
        apiKey: resolvedKey,
        model: modelName,
        baseUrl: requestBaseUrl,
      }
      await assertConfiguredLlmReady(llmConfig)

      const reportsDir = resolve(reportsDirRaw)
      const outRoot = resolve(typeof body.outRoot === "string" && body.outRoot.trim() ? body.outRoot.trim() : resolve(reportsDir, ".runs"))
      mkdirSync(reportsDir, { recursive: true })
      mkdirSync(outRoot, { recursive: true })
      const statePath = resolve(reportsDir, "batch-state.json")
      const state = prepareBatchState(loadBatchState(statePath), targets, reportsDir, outRoot, body.reset === true)
      state.running = true
      state.stopOnError = body.stopOnError === true
      state.updatedAt = Date.now()
      saveBatchState(statePath, state)
      writeBatchSummary(state, reportsDir)

      const batch: ActiveBatchRun = {
        statePath,
        reportsDir,
        state,
        currentManager: null,
        stopRequested: false,
        rerun: body.rerun === true,
        stopOnError: body.stopOnError === true,
      }
      activeBatch = batch

      console.log(`[night_agent] web batch started: targets=${state.entries.length}`)
      console.log(`[night_agent] web batch reports: ${reportsDir}`)
      console.log(`[night_agent] web batch outRoot : ${outRoot}`)
      console.log(`[night_agent] web batch llm     : ${providerName}/${modelName ?? "default"}`)
      console.log(`[night_agent] web batch joern   : ${body.runJoern === false ? "disabled" : "enabled"}`)

      runBatchInBackground(batch, {
        llmConfig,
        branch: typeof body.branch === "string" && body.branch.trim() ? body.branch.trim() : undefined,
        runJoern: body.runJoern === false ? false : true,
        timeoutMinutes: typeof body.timeoutMinutes === "number" ? body.timeoutMinutes : 30,
        maxHypotheses: typeof body.maxHypotheses === "number" ? body.maxHypotheses : 200,
        maxReportDetails: 4,
      })

      return new Response(JSON.stringify(batch.state), {
        headers: { "Content-Type": "application/json" },
      })
    } catch (err) {
      return new Response(JSON.stringify({ error: err instanceof Error ? err.message : String(err) }), {
        status: 400,
        headers: { "Content-Type": "application/json" },
      })
    }
  }

  function handleBatchStatus(url: URL): Response {
    const reportsDir = url.searchParams.get("reportsDir")
    if (activeBatch && (!reportsDir || resolve(reportsDir) === activeBatch.reportsDir)) {
      return new Response(JSON.stringify(activeBatch.state), {
        headers: { "Content-Type": "application/json" },
      })
    }
    if (reportsDir) {
      const statePath = resolve(reportsDir, "batch-state.json")
      const state = normalizeInactiveBatchState(loadBatchState(statePath), statePath)
      if (state) {
        return new Response(JSON.stringify(state), {
          headers: { "Content-Type": "application/json" },
        })
      }
    }
    return new Response(JSON.stringify({ version: 1, running: false, reportsDir: reportsDir ? resolve(reportsDir) : "", outRoot: "", createdAt: 0, updatedAt: 0, entries: [] }), {
      headers: { "Content-Type": "application/json" },
    })
  }

  function normalizeInactiveBatchState(state: BatchState | null, statePath: string): BatchState | null {
    if (!state?.running && !state?.entries.some((entry) => entry.status === "running")) return state
    const now = Date.now()
    let changed = false
    for (const entry of state.entries) {
      if (entry.status !== "running") continue
      entry.status = "interrupted"
      entry.updatedAt = now
      entry.error = entry.error ?? "service restarted before batch item completed"
      changed = true
    }
    if (state.running || state.currentIndex !== undefined) {
      state.running = false
      state.currentIndex = undefined
      changed = true
    }
    if (changed) {
      state.updatedAt = now
      saveBatchState(statePath, state)
      writeBatchSummary(state, state.reportsDir || dirname(statePath))
    }
    return state
  }

  function persistBatchState(batch: ActiveBatchRun): void {
    batch.state.updatedAt = Date.now()
    saveBatchState(batch.statePath, batch.state)
    writeBatchSummary(batch.state, batch.reportsDir)
  }

  function runBatchInBackground(batch: ActiveBatchRun, input: {
    llmConfig: LLMConfig
    branch?: string
    runJoern: boolean
    timeoutMinutes: number
    maxHypotheses: number
    maxReportDetails: number
  }): void {
    ;(async () => {
      try {
        console.log(`[night_agent] web batch running: ${batch.state.entries.length} target(s)`)
        for (let index = 0; index < batch.state.entries.length; index++) {
          if (batch.stopRequested) break
          const entry = batch.state.entries[index]!
          if (entry.status === "completed" && !batch.rerun) {
            console.log(`[web-batch ${index + 1}/${batch.state.entries.length}] skip completed: ${entry.input}`)
            continue
          }

          batch.state.running = true
          batch.state.currentIndex = index
          entry.status = "running"
          entry.startedAt = entry.startedAt ?? Date.now()
          entry.updatedAt = Date.now()
          entry.error = undefined
          persistBatchState(batch)

          const pendingTarget = makePendingTarget(entry.input, entry.runId, entry.outputDir)
          const pendingOptions: AuditOptions = {
            target: pendingTarget.target,
            outputDir: pendingTarget.outputDir,
            projectName: batchProjectName(entry.input),
            runJoern: input.runJoern,
            timeoutMinutes: input.timeoutMinutes,
            llmConfig: input.llmConfig,
            maxHypotheses: input.maxHypotheses,
            maxReportDetails: input.maxReportDetails,
          }
          createRunRecord(pendingTarget, pendingOptions, input.llmConfig.provider, input.llmConfig.model)
          persistEvent(entry.runId, {
            kind: "state:enter",
            payload: {
              state: "preparing",
              description: "批量审计子任务开始准备",
              batchIndex: index + 1,
              batchTotal: batch.state.entries.length,
              reportsDir: batch.reportsDir,
            },
            timestamp: Date.now(),
            source: "server",
          })

          console.log(`[web-batch ${index + 1}/${batch.state.entries.length}] auditing: ${entry.input}`)
          try {
            const resolvedTarget = await resolveBatchTarget(entry, input.branch)
            entry.target = resolvedTarget.target
            entry.cloned = resolvedTarget.cloned
            entry.outputDir = resolvedTarget.outputDir
            entry.updatedAt = Date.now()
            persistBatchState(batch)

            const options: AuditOptions = {
              target: resolvedTarget.target,
              outputDir: resolvedTarget.outputDir,
              projectName: batchProjectName(entry.input),
              runJoern: input.runJoern,
              timeoutMinutes: input.timeoutMinutes,
              llmConfig: input.llmConfig,
              maxHypotheses: input.maxHypotheses,
              maxReportDetails: input.maxReportDetails,
              resumeFromCheckpoint: !batch.rerun && existsSync(resolve(entry.outputDir, "checkpoints", "run-state.json")),
            }
            updateRunRecordStarted(resolvedTarget, options)
            persistEvent(entry.runId, {
              kind: "state:enter",
              payload: {
                state: "running",
                description: "批量审计子任务进入 Agent 流程",
                target: resolvedTarget.target,
                outputDir: resolvedTarget.outputDir,
              },
              timestamp: Date.now(),
              source: "server",
            })
            console.log(`[web-batch ${index + 1}/${batch.state.entries.length}] target: ${resolvedTarget.target}`)

            const manager = new AuditManager(options, (event) => persistEvent(entry.runId, event))
            batch.currentManager = manager
            const report = await manager.run()
            batch.currentManager = null

            entry.status = "completed"
            entry.completedAt = Date.now()
            entry.updatedAt = Date.now()
            entry.error = undefined
            entry.stats = report.stats
            entry.observerWarnings = report.observer.warnings
            entry.generatedFiles = discoverGeneratedFiles(entry.outputDir, report.generatedFiles)
            entry.reportFiles = copyBatchReportFiles(report, entry.outputDir, batch.reportsDir, index + 1)
            persistBatchState(batch)
            completeRunRecord(entry.runId, report)
            persistEvent(entry.runId, {
              kind: "audit:completed",
              payload: { stats: report.stats, runId: entry.runId, generatedFiles: report.generatedFiles },
              timestamp: Date.now(),
              source: "server",
            })
            console.log(`[web-batch ${index + 1}/${batch.state.entries.length}] completed: ${report.profile.name} confirmed=${report.stats.confirmedFindings} coverage=${report.stats.coveragePercent}%`)
          } catch (err) {
            batch.currentManager = null
            const message = err instanceof Error ? err.message : String(err)
            entry.status = "failed"
            entry.error = message
            entry.updatedAt = Date.now()
            persistBatchState(batch)
            failRunRecord(entry.runId, message)
            persistEvent(entry.runId, {
              kind: "audit:error",
              payload: { error: message, runId: entry.runId },
              timestamp: Date.now(),
              source: "server",
            })
            console.error(`[web-batch ${index + 1}/${batch.state.entries.length}] failed: ${entry.input}`)
            console.error(`  ${message}`)
            if (batch.stopOnError) break
          }
        }
      } finally {
        batch.currentManager = null
        batch.state.running = false
        batch.state.currentIndex = undefined
        persistBatchState(batch)
        const completed = batch.state.entries.filter((entry) => entry.status === "completed").length
        const failed = batch.state.entries.filter((entry) => entry.status === "failed").length
        console.log(`[night_agent] web batch finished: completed=${completed}, failed=${failed}, total=${batch.state.entries.length}`)
        console.log(`[night_agent] web batch summary : ${resolve(batch.reportsDir, "batch-summary.md")}`)
      }
    })()
  }

  let pauseReason: string | null = null

  function handlePauseAudit(): Response {
    if (!runningManager || !currentRun) {
      return new Response(JSON.stringify({ error: "no running audit" }), {
        status: 409,
        headers: { "Content-Type": "application/json" },
      })
    }
    pauseReason = "paused by user"
    runningManager.requestPause(pauseReason)
    markRunPaused(currentRun.runId, pauseReason)
    return new Response(JSON.stringify({ ok: true, runId: currentRun.runId }), {
      headers: { "Content-Type": "application/json" },
    })
  }

  function markRunPaused(runId: string, reason: string): void {
    db.query(`
      UPDATE audit_runs
      SET status = ?, completed_at = ?, error = ?
      WHERE run_id = ?
    `).run("interrupted", Date.now(), reason || "paused by user", runId)
    pauseReason = null
  }

  function handleGetModelSettings(): Response {
    return new Response(JSON.stringify(getModelSettings(db)), {
      headers: { "Content-Type": "application/json" },
    })
  }

  async function handleSaveModelSettings(req: Request): Promise<Response> {
    try {
      const body = await req.json()
      const settings = saveModelSettings(db, body && typeof body === "object" ? body as Record<string, unknown> : {})
      return new Response(JSON.stringify(settings), {
        headers: { "Content-Type": "application/json" },
      })
    } catch (err) {
      return new Response(JSON.stringify({ error: err instanceof Error ? err.message : String(err) }), {
        status: 400,
        headers: { "Content-Type": "application/json" },
      })
    }
  }

  function handleGetStatus(): Response {
    if (startingAudit) {
      if (!currentRun && Date.now() - startingAuditAt > 60_000) {
        startingAudit = false
        startingAuditAt = 0
      } else {
        return new Response(JSON.stringify({ state: "preparing", run: currentRun }), {
          headers: { "Content-Type": "application/json" },
        })
      }
    }
    if (runningManager) {
      const state = runningManager.getState()
      if (pauseReason) {
        return new Response(JSON.stringify({ ...state, state: "pausing", currentState: "pausing", run: currentRun }), {
          headers: { "Content-Type": "application/json" },
        })
      }
      return new Response(JSON.stringify({ ...state, run: currentRun }), {
        headers: { "Content-Type": "application/json" },
      })
    }
    if (currentReport) {
      return new Response(JSON.stringify({
        state: "terminated",
        findings: currentReport.findings,
        stats: currentReport.stats,
        observer: currentReport.observer,
        generatedFiles: currentReport.generatedFiles,
        run: currentRun,
        coverageGrid: {
          totalUnits: currentReport.coverageGrid.totalUnits,
          byModule: Object.fromEntries(currentReport.coverageGrid.byModule),
        },
      }), {
        headers: { "Content-Type": "application/json" },
      })
    }
    return new Response(JSON.stringify({ state: "idle" }), {
      headers: { "Content-Type": "application/json" },
    })
  }

  function handleHistory(): Response {
    const rows = db.query(`
      SELECT * FROM audit_runs
      ORDER BY started_at DESC
      LIMIT 100
    `).all() as Array<Record<string, unknown>>
    return new Response(JSON.stringify(rows.map(rowToRunSummary)), {
      headers: { "Content-Type": "application/json" },
    })
  }

  function handleRunDetail(runId: string): Response {
    const row = db.query("SELECT * FROM audit_runs WHERE run_id = ?").get(runId) as Record<string, unknown> | null
    if (!row) {
      return new Response(JSON.stringify({ error: "run not found" }), {
        status: 404,
        headers: { "Content-Type": "application/json" },
      })
    }
    const eventRows = db.query(`
      SELECT kind, source, timestamp, payload_json FROM (
        SELECT id, kind, source, timestamp, payload_json FROM audit_events
        WHERE run_id = ?
        ORDER BY id DESC
        LIMIT ?
      )
      ORDER BY id ASC
    `).all(runId, HISTORY_EVENT_LIMIT) as Array<Record<string, unknown>>
    const sourceRows = db.query(`
      SELECT payload_json FROM audit_sources
      WHERE run_id = ?
      ORDER BY id ASC
    `).all(runId) as Array<Record<string, unknown>>

    const summary = rowToRunSummary(row)
    const storedReport = jsonParse<AuditReport | null>(row.report_json, null)
    const report = storedReport ?? loadReportFromOutput(summary.outputDir)
    const detail: StoredRunDetail = {
      ...summary,
      report,
      events: eventRows.map((event) => ({
        kind: String(event.kind) as AgentBusEvent["kind"],
        source: String(event.source ?? ""),
        timestamp: Number(event.timestamp),
        payload: jsonParse(event.payload_json, null),
      })),
      sources: sourceRows
        .map((source) => jsonParse<StoredRunDetail["sources"][number] | null>(source.payload_json, null))
        .filter((source): source is StoredRunDetail["sources"][number] => source != null),
    }
    return new Response(JSON.stringify(detail), {
      headers: { "Content-Type": "application/json" },
    })
  }

  function handleDeleteRun(runId: string): Response {
    if (currentRun?.runId === runId && (runningManager || startingAudit)) {
      return new Response(JSON.stringify({ error: "cannot delete a running audit" }), {
        status: 409,
        headers: { "Content-Type": "application/json" },
      })
    }

    const row = db.query("SELECT run_id FROM audit_runs WHERE run_id = ?").get(runId) as Record<string, unknown> | null
    if (!row) {
      return new Response(JSON.stringify({ error: "run not found" }), {
        status: 404,
        headers: { "Content-Type": "application/json" },
      })
    }

    db.query("DELETE FROM audit_events WHERE run_id = ?").run(runId)
    db.query("DELETE FROM audit_sources WHERE run_id = ?").run(runId)
    db.query("DELETE FROM audit_runs WHERE run_id = ?").run(runId)

    if (currentRun?.runId === runId) {
      currentRun = null
      currentReport = null
    }

    return new Response(JSON.stringify({ ok: true }), {
      headers: { "Content-Type": "application/json" },
    })
  }

  function handleRunReportFile(runId: string, kind: "report" | "complete"): Response {
    const row = db.query("SELECT output_dir, generated_files_json FROM audit_runs WHERE run_id = ?").get(runId) as Record<string, unknown> | null
    if (!row) {
      return new Response("Not Found", { status: 404 })
    }
    const outputDir = String(row.output_dir)
    const files = discoverGeneratedFiles(outputDir, jsonParse(row.generated_files_json, [] as string[]))
    const file = kind === "complete"
      ? files.find((f) => f.endsWith(".md") && f.includes("完整结果"))
      : files.find((f) => f.endsWith(".md") && f.includes("审计报告"))
    if (!file) return new Response("Not Found", { status: 404 })
    try {
      return new Response(readFileSync(file), {
        headers: { "Content-Type": "text/markdown; charset=utf-8" },
      })
    } catch {
      return new Response("Not Found", { status: 404 })
    }
  }

  function handleGetFindings(): Response {
    if (currentReport) {
      return new Response(JSON.stringify(currentReport.findings), {
        headers: { "Content-Type": "application/json" },
      })
    }
    return new Response(JSON.stringify([]), {
      headers: { "Content-Type": "application/json" },
    })
  }

  function handleGetReport(): Response {
    if (currentReport) {
      return new Response(JSON.stringify(currentReport), {
        headers: { "Content-Type": "application/json" },
      })
    }
    if (currentRun) {
      const report = loadReportFromOutput(currentRun.outputDir)
      if (report) {
        return new Response(JSON.stringify(report), {
          headers: { "Content-Type": "application/json" },
        })
      }
    }
    return new Response(JSON.stringify({ error: "no report available" }), {
      status: 404,
      headers: { "Content-Type": "application/json" },
    })
  }

  console.log(`[night_agent] listening on http://localhost:${port}`)
  console.log(`[night_agent] WebSocket at ws://localhost:${port}/ws`)
}

// ─── Main ───

async function main() {
  const args = process.argv.slice(2)
  if (args.length === 0 || args.includes("--help") || args.includes("-h")) {
    printHelp()
    return
  }

  const command = args[0]
  if (command === "audit") {
    await runAudit(args)
  } else if (command === "batch") {
    await runBatch(args)
  } else if (command === "serve") {
    await runServe(args)
  } else {
    throw new Error(`unknown command: ${command}. Use 'audit', 'batch' or 'serve'.`)
  }
}

main().catch((error) => {
  console.error(`[!] ${error instanceof Error ? error.message : String(error)}`)
  process.exitCode = 1
})
