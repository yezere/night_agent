import { appendFileSync, readFileSync } from "node:fs"
import { isAbsolute, relative, resolve } from "node:path"
import type { AuditReport, ProjectProfile, Hypothesis, LLMProvider, LLMConfig, SourceEntry, EvidenceBundle, VerifierVerdict } from "../types/index.ts"
import { tryLoadPrompt } from "./prompt-loader.ts"
import { runArchiveTool, type ArchiveToolCall } from "../tools/archive-tool.ts"
import { runJoernTool, type JoernToolCall } from "../tools/joern-tool.ts"
import { compactProjectTree, runFileTreeTool, type FileTreeToolCall } from "../tools/file-tree.ts"
import { readContextualFile } from "../utils/contextual-file.ts"
import { JAVA_SINK_CONTEXT_PATTERNS, JAVA_SOURCE_CONTEXT_PATTERNS } from "../scanner/java-web-hints.ts"

const SKILLS_DIR = resolve(import.meta.dir, "../../../../skills")

const PRIMARY_TIMEOUT = 600_000   // 10 min for full generation
const SOURCE_AGENT_TIMEOUT = 180_000
const REPORT_AGENT_TIMEOUT = clampEnvInt("NIGHT_AGENT_REPORT_TIMEOUT_MS", 600_000, 60_000, 1_200_000)
const LLM_HTTP_MAX_ATTEMPTS = 3
const LLM_PREFLIGHT_TIMEOUT_MS = clampEnvInt("NIGHT_AGENT_LLM_PREFLIGHT_TIMEOUT_MS", 20_000, 5_000, 120_000)

const DEFAULT_MODELS: Record<LLMProvider, string> = {
  anthropic: "claude-sonnet-4-6",
  openai: "gpt-4o",
  deepseek: "deepseek-v4-flash",
  glm: "glm-5.1",
}

function providerBaseUrl(provider: LLMProvider): string {
  switch (provider) {
    case "anthropic": return "https://api.anthropic.com/v1/messages"
    case "openai": return "https://api.openai.com/v1/chat/completions"
    case "deepseek": return "https://api.deepseek.com/v1/chat/completions"
    case "glm": return "https://open.bigmodel.cn/api/coding/paas/v4"
  }
}

type LLMProtocol = "anthropic" | "chat"

function normalizeUrl(config: LLMConfig): { url: string; protocol: LLMProtocol } {
  const raw = (config.baseUrl ?? providerBaseUrl(config.provider)).replace(/\/+$/, "")
  if (config.provider === "glm") {
    if (/\/api\/paas\/v4\/chat\/completions$/.test(raw)) return { url: raw, protocol: "chat" }
    if (/\/api\/paas\/v4$/.test(raw)) return { url: `${raw}/chat/completions`, protocol: "chat" }
    if (/\/api\/coding\/paas\/v4\/chat\/completions$/.test(raw)) return { url: raw, protocol: "chat" }
    if (/\/api\/coding\/paas\/v4$/.test(raw)) return { url: `${raw}/chat/completions`, protocol: "chat" }
    if (/\/chat\/completions$/.test(raw)) return { url: raw, protocol: "chat" }
    return { url: `${raw}/chat/completions`, protocol: "chat" }
  }
  // Anthropic protocol detection: endpoint path contains /anthropic/ or /coding/, or ends with /messages
  const anthropicLike = config.provider === "anthropic"
    || /\/anthropic(?:\/|$)/.test(raw)
    || /\/coding(?:\/|$)/.test(raw)
    || /\/messages$/.test(raw)
  if (anthropicLike) {
    if (/\/messages$/.test(raw)) return { url: raw, protocol: "anthropic" }
    if (/\/v1$/.test(raw)) return { url: `${raw}/messages`, protocol: "anthropic" }
    return { url: `${raw}/messages`, protocol: "anthropic" }
  }
  if (config.provider === "openai" && isBareHttpOrigin(raw)) {
    return { url: `${raw}/v1/chat/completions`, protocol: "chat" }
  }
  if (/\/chat\/completions$/.test(raw)) return { url: raw, protocol: "chat" }
  return { url: `${raw}/chat/completions`, protocol: "chat" }
}

function isBareHttpOrigin(raw: string): boolean {
  try {
    const url = new URL(raw)
    return url.pathname === "/" || url.pathname === ""
  } catch {
    return false
  }
}

interface LLMCallResult {
  ok: boolean
  text: string
  timedOut: boolean
}

interface LLMHttpResult extends LLMCallResult {
  status?: number
  rawError?: string
}

export interface LLMHealthResult {
  ok: boolean
  provider: LLMProvider
  model: string
  url: string
  status?: number
  error?: string
  reason?: "auth" | "model" | "endpoint" | "quota" | "timeout" | "transient" | "unknown"
}

export interface SourceFileCandidate {
  file: string
  content: string
}

export interface LlmSinkEntry {
  category: string
  severity: Hypothesis["severity"]
  sinkPattern: string
  file: string
  line: number
  code: string
  description: string
  confidence?: "high" | "medium" | "low"
  reason?: string
}

type ToolAgentKind = "source" | "sink" | "verifier" | "discovery" | "poc"

interface ToolCall {
  tool: "file_tree" | "list_files" | "select_files" | "rg" | "read_file" | "archive_list" | "jar_entries" | "jar_extract_source" | "jar_javap" | "jar_decompile" | "joern_search" | "joern_script"
  pattern?: string
  globs?: string[] | string
  file?: string
  files?: string[]
  reason?: string
  startLine?: number
  endLine?: number
  maxResults?: number
  query?: string
  script?: string
  sinkPattern?: string
  sourcePattern?: string
}

interface ToolRunContext {
  cpgPath?: string
  outputDir?: string
  allowJoern?: boolean
  refineContext?: string
  verifierContext?: string
  verifierChallenge?: string
  verifierBatch?: boolean
  pocContext?: string
  traceMeta?: Record<string, unknown>
  minInspectedFiles?: number
  maxToolSteps?: number
}

async function writeLlmDebug(outputDir: string | undefined, name: string, text: string): Promise<void> {
  if (!outputDir) return
  try {
    const dir = resolve(outputDir, "llm-debug")
    await Bun.$`mkdir -p ${dir}`
    const file = resolve(dir, `${name}-${Date.now().toString(36)}.txt`)
    await Bun.write(file, text.slice(0, 120_000))
  } catch {
    // Debug persistence must never affect audit execution.
  }
}

async function appendToolTrace(outputDir: string | undefined, event: Record<string, unknown>): Promise<void> {
  if (!outputDir) return
  try {
    const dir = resolve(outputDir, "llm-debug")
    await Bun.$`mkdir -p ${dir}`
    appendFileSync(resolve(dir, "llm-tool-trace.jsonl"), `${JSON.stringify({ at: new Date().toISOString(), ...event })}\n`)
  } catch {
    // Tool tracing must never affect audit execution.
  }
}

function summarizeToolCall(call: ToolCall): Record<string, unknown> {
  return {
    tool: call.tool,
    pattern: call.pattern,
    globs: call.globs,
    file: call.file,
    files: call.files,
    reason: call.reason,
    startLine: call.startLine,
    endLine: call.endLine,
    maxResults: call.maxResults,
    query: call.query,
    hasScript: Boolean(call.script),
    sinkPattern: call.sinkPattern,
    sourcePattern: call.sourcePattern,
  }
}

async function callLLM(
  config: LLMConfig,
  system: string,
  user: string,
  timeoutMs: number = 120_000,
): Promise<LLMCallResult> {
  const model = config.model ?? DEFAULT_MODELS[config.provider]
  const { url, protocol } = normalizeUrl(config)

  let body: Record<string, unknown>
  let headers: Record<string, string>

  if (protocol === "anthropic") {
    headers = {
      "x-api-key": config.apiKey,
      "Authorization": `Bearer ${config.apiKey}`,
      "anthropic-version": "2023-06-01",
      "content-type": "application/json",
    }
    body = {
      model,
      system,
      messages: [{ role: "user", content: user }],
    }
    applyTokenLimit(body, config, model, 8192)
  } else {
    headers = {
      "Authorization": `Bearer ${config.apiKey}`,
      "content-type": "application/json",
    }
    body = {
      model,
      stream: false,
      messages: [
        { role: "system", content: system },
        { role: "user", content: user },
      ],
    }
    applyTokenLimit(body, config, model, 8192)
    if (config.provider === "deepseek" && /v4-pro/i.test(model)) {
      body.thinking = { type: "enabled" }
      body.reasoning_effort = "high"
    }
    if (config.provider === "glm" && /^glm-5/i.test(model)) {
      body.thinking = { type: "enabled" }
      body.temperature = 1.0
    }
  }

  let primary = await postLlmJson(url, headers, body, protocol, timeoutMs, "messages")
  if (primary.ok || primary.timedOut) return primary

  const tokenLimitRetryBody = buildAlternateTokenLimitBody(body, primary.status, primary.rawError ?? primary.text)
  if (tokenLimitRetryBody) {
    const tokenLimitRetry = await postLlmJson(url, headers, tokenLimitRetryBody, protocol, timeoutMs, "messages token-limit")
    if (tokenLimitRetry.ok || tokenLimitRetry.timedOut) return tokenLimitRetry
    primary = {
      ok: false,
      text: `${primary.text}; token-limit retry failed: ${tokenLimitRetry.text}`,
      timedOut: false,
      status: tokenLimitRetry.status ?? primary.status,
      rawError: tokenLimitRetry.rawError ?? primary.rawError,
    }
  }

  if (shouldRetryWithPromptBody(primary.status, primary.rawError ?? primary.text)) {
    const promptRetry = await postLlmJson(
      url,
      headers,
      buildPromptBody(model, system, user, body),
      "prompt",
      timeoutMs,
      "prompt",
    )
    if (promptRetry.ok || promptRetry.timedOut) return promptRetry
    return {
      ok: false,
      text: `${primary.text}; prompt retry failed: ${promptRetry.text}`,
      timedOut: false,
    }
  }

  return primary
}

async function postLlmJson(
  url: string,
  headers: Record<string, string>,
  body: Record<string, unknown>,
  extractProtocol: LLMProtocol | "prompt",
  timeoutMs: number,
  label: string,
): Promise<LLMHttpResult> {
  let lastFailure: LLMHttpResult | null = null
  for (let attempt = 1; attempt <= LLM_HTTP_MAX_ATTEMPTS; attempt += 1) {
    try {
      const resp = await fetch(url, {
        method: "POST",
        headers,
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(timeoutMs),
      })

      if (resp.ok) {
        const data = (await resp.json()) as Record<string, unknown>
        return { ok: true, text: extractLlmText(data, extractProtocol), timedOut: false }
      }

      const rawError = await resp.text().catch(() => resp.statusText)
      lastFailure = {
        ok: false,
        text: formatLlmHttpFailure(label, resp.status, rawError, attempt),
        timedOut: false,
        status: resp.status,
        rawError,
      }
      if (attempt < LLM_HTTP_MAX_ATTEMPTS && shouldRetryTransientLlmError(resp.status, rawError)) {
        await sleep(llmRetryDelayMs(attempt))
        continue
      }
      return lastFailure
    } catch (err) {
      if (err instanceof DOMException && err.name === "TimeoutError") {
        return { ok: false, text: "", timedOut: true }
      }
      const rawError = err instanceof Error ? err.message : String(err)
      lastFailure = {
        ok: false,
        text: formatLlmTransportFailure(label, rawError, attempt),
        timedOut: false,
        rawError,
      }
      if (attempt < LLM_HTTP_MAX_ATTEMPTS) {
        await sleep(llmRetryDelayMs(attempt))
        continue
      }
      return lastFailure
    }
  }
  return lastFailure ?? { ok: false, text: "LLM call failed before request execution", timedOut: false }
}

function shouldRetryWithPromptBody(status: number | undefined, rawError: string): boolean {
  if (status !== 400) return false
  return /prompt|未正常接收到prompt参数|code["']?\s*:\s*["']?1213/i.test(rawError)
}

function applyTokenLimit(body: Record<string, unknown>, config: LLMConfig, model: string, tokenLimit: number): void {
  if (prefersMaxCompletionTokens(config, model)) {
    body.max_completion_tokens = tokenLimit
    return
  }
  body.max_tokens = tokenLimit
}

function prefersMaxCompletionTokens(config: LLMConfig, model: string): boolean {
  if (config.provider !== "openai") return false
  return /^(gpt-5|o\d|o-|chatgpt-|mimo-)/i.test(model)
}

function buildAlternateTokenLimitBody(
  original: Record<string, unknown>,
  status: number | undefined,
  rawError: string,
): Record<string, unknown> | null {
  if (status !== 400) return null
  if (!/max_tokens|max_completion_tokens|unsupported parameter|not supported/i.test(rawError)) return null

  const body = { ...original }
  if (typeof original.max_tokens === "number") {
    delete body.max_tokens
    body.max_completion_tokens = original.max_tokens
    return body
  }
  if (typeof original.max_completion_tokens === "number") {
    delete body.max_completion_tokens
    body.max_tokens = original.max_completion_tokens
    return body
  }
  return null
}

function shouldRetryTransientLlmError(status: number | undefined, rawError: string): boolean {
  if (status === undefined) return true
  if (status === 408 || status === 409 || status === 429 || status >= 500) return true
  return /code["']?\s*:\s*["']?1234|网络错误|network error|ECONNRESET|ETIMEDOUT|EAI_AGAIN/i.test(rawError)
}

function llmRetryDelayMs(attempt: number): number {
  return Math.min(2_500, 500 * 2 ** (attempt - 1))
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolveSleep) => setTimeout(resolveSleep, ms))
}

function clampEnvInt(name: string, fallback: number, min: number, max: number): number {
  const parsed = Number(process.env[name])
  if (!Number.isFinite(parsed)) return fallback
  return Math.max(min, Math.min(max, Math.floor(parsed)))
}

function formatLlmHttpFailure(label: string, status: number, rawError: string, attempt: number): string {
  const suffix = attempt > 1 ? ` after ${attempt} attempts` : ""
  return `LLM ${label} call failed${suffix} (${status}): ${rawError.slice(0, 300)}`
}

function formatLlmTransportFailure(label: string, rawError: string, attempt: number): string {
  const suffix = attempt > 1 ? ` after ${attempt} attempts` : ""
  return `LLM ${label} call failed${suffix}: ${rawError.slice(0, 300)}`
}

function sanitizeLlmError(rawError: string): string {
  return rawError
    .replace(/sk-[A-Za-z0-9_-]{12,}/g, "sk-***")
    .slice(0, 500)
}

function classifyLlmFailure(status: number | undefined, rawError: string): LLMHealthResult["reason"] {
  const text = rawError.toLowerCase()
  if (status === 401 || status === 403 || /invalid token|invalid api key|incorrect api key|unauthorized|forbidden|auth/.test(text)) return "auth"
  if (status === 404 || /model.*not.*found|model_not_found|does not exist|invalid model|unknown model/.test(text)) return "model"
  if (/not found|unknown endpoint|invalid url|route/.test(text)) return "endpoint"
  if (status === 429 || /quota|rate limit|too many requests|insufficient/.test(text)) return "quota"
  if (status === 408 || status === undefined && /timeout|timed out/.test(text)) return "timeout"
  if (status !== undefined && status >= 500) return "transient"
  return "unknown"
}

function formatLlmHealthFailure(health: LLMHealthResult): string {
  const reason = health.reason ? `${health.reason} ` : ""
  const status = health.status ? `HTTP ${health.status}` : "transport error"
  const detail = health.error ? `: ${health.error}` : ""
  return `LLM preflight failed for ${health.provider}/${health.model} at ${health.url} (${reason}${status})${detail}`
}

function buildPromptBody(
  model: string,
  system: string,
  user: string,
  original: Record<string, unknown>,
): Record<string, unknown> {
  const body: Record<string, unknown> = {
    model,
    prompt: `${system.trim()}\n\n${user.trim()}`.trim(),
    max_tokens: original.max_tokens ?? original.max_completion_tokens ?? 8192,
    stream: false,
  }
  if (typeof original.temperature === "number") body.temperature = original.temperature
  return body
}

function extractLlmText(data: Record<string, unknown>, protocol: LLMProtocol | "prompt"): string {
  if (protocol === "anthropic") {
    const content = data.content
    if (Array.isArray(content)) {
      return content.map((item) => isRecord(item) && typeof item.text === "string" ? item.text : "").join("")
    }
  }

  const choices = data.choices
  if (Array.isArray(choices)) {
    const first = choices.find((item) => isRecord(item)) as Record<string, unknown> | undefined
    const message = first && isRecord(first.message) ? first.message : undefined
    if (message && typeof message.content === "string") return message.content
    if (first && typeof first.text === "string") return first.text
    if (first && typeof first.content === "string") return first.content
  }

  for (const key of ["output_text", "text", "content", "answer"]) {
    const value = data[key]
    if (typeof value === "string") return value
  }

  const output = data.output
  if (isRecord(output)) {
    for (const key of ["text", "content", "answer"]) {
      const value = output[key]
      if (typeof value === "string") return value
    }
  }

  const dataField = data.data
  if (isRecord(dataField)) {
    for (const key of ["text", "content", "answer", "output_text"]) {
      const value = dataField[key]
      if (typeof value === "string") return value
    }
  }

  return ""
}

async function runToolAssistedExtraction(
  config: LLMConfig,
  profile: ProjectProfile,
  files: SourceFileCandidate[],
  kind: ToolAgentKind,
  timeoutMs: number,
  toolContext: ToolRunContext = {},
): Promise<unknown | null> {
  const model = config.model ?? DEFAULT_MODELS[config.provider]
  const traceMeta = toolContext.traceMeta ?? {}
  const traceLabel = typeof traceMeta.hypothesisId === "string" ? `${kind}:${traceMeta.hypothesisId}` : kind
  console.log(`  [llm] ${traceLabel} agent using rg/read_file tools via ${config.provider}/${model}...`)
  const traceOutputDir = toolContext.outputDir ?? resolve(profile.root, "output-audit")

  const largeProject = files.length > 40 || profile.routes.length > 80
  const refineMode = Boolean(toolContext.refineContext)
  const verifierMode = kind === "verifier"
  const pocMode = kind === "poc"
  const minInspectedFiles = toolContext.minInspectedFiles ?? (verifierMode ? 2 : pocMode ? 1 : largeProject ? (kind === "source" ? 6 : 5) : 1)
  const maxToolSteps = toolContext.maxToolSteps ?? (verifierMode || pocMode ? 7 : largeProject ? 8 : 5)
  const inspectedFiles = new Set<string>()
  const selectedFiles = new Set<string>()
  const visibleCandidateLimit = largeProject ? 60 : 160
  const fileList = files.slice(0, visibleCandidateLimit)
    .map((file) => `- ${relative(profile.root, file.file)} (${file.content.length} chars loaded)`)
    .join("\n")
  const preloadedVerifierEvidence = verifierMode
    ? formatPreloadedVerifierEvidence(profile, files, 95_000)
    : ""
  const projectTree = await compactProjectTree(profile.root, 180)
  const routes = profile.routes.slice(0, 60)
    .map((route) => `- ${route.method} ${route.path} @ ${route.sourceFile}:${route.line}`)
    .join("\n")
  const deps = profile.dependencies
    .filter((dep) => /spring|mybatis|jdbc|shiro|fastjson|jackson|freemarker|velocity|ognl|spel|groovy|log4j|struts|commons-fileupload|tomcat/i.test(dep.name))
    .map((dep) => `${dep.name}${dep.version ? ` ${dep.version}` : ""}`)
    .join(", ")

  const finalKey = kind === "source" ? "sources" : kind === "sink" ? "sinks" : kind === "discovery" ? "discoveries" : kind === "poc" ? "pocs" : "verdicts"
  const suggestedRg = kind === "source"
    ? "@RequestParam|@RequestBody|@PathVariable|@RequestHeader|@CookieValue|getParameter|getParameterValues|getParameterMap|getHeader|getInputStream|getReader|getPart|getParts|HttpServletRequest|@WebServlet|extends HttpServlet|doGet|doPost|service|\\$\\{\\s*(param|header|cookie)|<jsp:setProperty|@GetMapping|@PostMapping|@RequestMapping"
      : kind === "sink" || kind === "discovery"
      ? "Runtime\\.getRuntime\\(\\)\\.exec|ProcessBuilder|new URL|openConnection|InitialContext|lookup|JSON\\.parseObject|parseObject|readObject|Statement|executeQuery|executeUpdate|\\.execute\\(|new File|Paths\\.get|Files\\.(read|copy|write|newInputStream|newOutputStream)|FileInputStream|FileOutputStream|getOutputStream|FileUtil\\.(file|exist|ls|del|read|write)|Template|\\.process\\(|parseExpression|Ognl|MultipartFile|transferTo|getOriginalFilename|getSubmittedFileName|\\b(part|filePart|uploadPart)\\s*\\.write\\(|sendRedirect|getRequestDispatcher|\\.forward\\(|\\.include\\(|response\\.getWriter|out\\.(print|println|write)|<%="
      : kind === "poc"
        ? "@RequestMapping|@GetMapping|@PostMapping|@PutMapping|@DeleteMapping|@PatchMapping|@PathVariable|@RequestParam|@RequestBody|@RequestHeader|@CookieValue|getParameter|getHeader|getInputStream|getPart|getParts|MultipartFile|doGet|doPost|service|web.xml"
        : "sanitize|escape|validate|whitelist|blacklist|canonical|normalize|encodingFilename|hash|md5|sha|FilenameUtils|getExtension|parseObject|autoType|JSONUtil|Template|process|iframe|OutputStream|captcha|FileUtil|File\\.separator|executeSql|findHql|\\$\\{|#\\{"

  const finalSchema = kind === "source"
    ? `{"sources":[{"kind":"param|body|header|cookie|pathvar|request-attr|input-stream","paramName":"name","file":"relative/or/absolute/path","line":123,"code":"exact source line","methodName":"handler","className":"ClassName"}]}`
    : kind === "sink"
      ? `{"sinks":[{"category":"cmdi|sqli|xss|file-download|file-upload|path-traversal|ssrf|ssti|spel|ognl|expression|deser|xxe|jndi|auth-bypass|redirect|crypto|other","severity":"critical|high|medium|low|info","sinkPattern":"Runtime.exec","file":"relative/or/absolute/path","line":123,"code":"exact dangerous source line","description":"short risk","confidence":"high|medium|low","reason":"why this is security-relevant"}]}`
      : kind === "discovery"
        ? `{"discoveries":[{"type":"source","kind":"param|body|header|cookie|pathvar|request-attr|input-stream","paramName":"name","file":"relative/or/absolute/path","line":123,"code":"exact source line","methodName":"handler","className":"ClassName","reason":"why this source is externally controllable"},{"type":"sink","category":"cmdi|sqli|xss|file-download|file-upload|path-traversal|ssrf|ssti|spel|ognl|expression|deser|xxe|jndi|auth-bypass|redirect|crypto|other","severity":"critical|high|medium|low|info","sinkPattern":"Runtime.exec","file":"relative/or/absolute/path","line":123,"code":"exact dangerous source line","description":"short risk","confidence":"high|medium|low","reason":"why this is security-relevant"}]}`
        : kind === "poc"
          ? `{"pocs":[{"hypothesisId":"hyp-xxxx","route":"METHOD /correct/path","trigger":"which source parameter/header/body/path variable/cookie is controlled and where it is placed","packets":["GET /path?name=value HTTP/1.1\\nHost: target.example\\n\\n"],"notes":["why this packet reaches the sink"]}]}`
          : toolContext.verifierBatch
            ? `{"verdicts":[{"hypothesisId":"hyp-xxxx","status":"confirmed|maybe_revisit|dismissed","confidence":"high|medium|low","reason":"concise Chinese static verification conclusion","sourceSinkTrace":["explicit external source with file:line","transform/helper with file:line","sink with file:line"],"barrierAnalysis":["barrier/check with file:line and whether it cuts attacker control; write none-found only after checking"],"evidence":["file:line exact fact"],"checkedFiles":["relative/or/absolute/path"],"toolCalls":["read_file path:line-range"],"sanitizerSummary":["same as barrierAnalysis if no separate list"],"missingEvidence":["what is still unproven; [] required for confirmed"]}]}`
            : `{"verdicts":[{"status":"confirmed|maybe_revisit|dismissed","confidence":"high|medium|low","reason":"concise Chinese static verification conclusion","sourceSinkTrace":["explicit external source with file:line","transform/helper with file:line","sink with file:line"],"barrierAnalysis":["barrier/check with file:line and whether it cuts attacker control; write none-found only after checking"],"evidence":["file:line exact fact"],"checkedFiles":["relative/or/absolute/path"],"toolCalls":["read_file path:line-range"],"sanitizerSummary":["same as barrierAnalysis if no separate list"],"missingEvidence":["what is still unproven; [] required for confirmed"]}]}`

  const agentName = kind === "source" ? "SourceAgent" : kind === "sink" ? "SinkAgent" : kind === "discovery" ? "JoernDiscoveryAgent" : kind === "poc" ? "PocAgent" : "StaticVerifierAgent"
  const system = `You are ${agentName} with access to backend tools. Output ONLY JSON.`
  let transcript = `Project root: ${profile.root}
Language: ${profile.language}
Routes:
${routes || "(none)"}

High-risk dependencies: ${deps || "(none)"}

${kind === "discovery" ? `Joern discovery mode:
You are a CPG-backed discovery agent. Use Joern tools plus rg/read_file when helpful to find missed Source and Sink candidates. Do NOT decide final vulnerability truth here. Submit candidates for later tracing and StaticVerifierAgent.

Look for generic Java Web source/sink families:
- Sources: Spring MVC annotations, Servlet/JSP request APIs, upload parts/files, headers/cookies, path variables, request bodies, mapper/XML parameters, filters/listeners/interceptors.
- Sinks: command execution, SQL/HQL/MyBatis dynamic SQL, file read/write/download/upload/path APIs, response output streams backed by files, template/expression rendering, deserialization, SSRF, XXE, JNDI.
- Project wrappers: methods that decode/normalize/encrypt/check request data and later pass it to File/SQL/Process/Template/Network APIs should be submitted as candidate sinks or sources with the concrete API line.

Prefer Joern searches first, then read_file the concrete methods before finalizing. Return both missed sources and missed sinks in one discoveries array. Do not repeat entries already listed in the context.
` : ""}

	${verifierMode ? `Static verification target:
${toolContext.verifierContext || "(missing verifier context)"}
${toolContext.verifierChallenge ? `\nObserver challenge to resolve before final verdict:\n${toolContext.verifierChallenge}\n` : ""}

Your job is to decide whether this candidate should become a confirmed vulnerability.
Do this by reading code, not by keyword matching. Verify:
- the claimed Source is externally controllable and reaches the Sink;
- the Sink is semantically dangerous in this code path, not just an API name match;
- helper methods, sanitizers, canonicalization, escaping, parameter binding, auth/permission barriers, template files, mapper XML, dependency versions, and library defaults;
- file-upload/path cases: whether original filename/path remains user-controlled after hashing, extension handling, canonical path checks, base directory checks, and executable storage checks;
- file-download/output-stream cases: whether the user controls a file path/name, or whether the stream only returns generated data such as captcha/json/image bytes;
- suffix constraint discipline: if the path appends a fixed suffix such as ".docx", ".xlsx", ".json", ".png", or ".zip" after user input, do NOT call it arbitrary file read/write unless code proves the suffix can be bypassed. Classify as suffix-limited read/write and adjust confidence/severity accordingly.
- encoded slash discipline: for Spring MVC path variables or path segments using %2f/%5c traversal payloads, confirmed requires runtime/config evidence that Spring Security/Tomcat allows encoded slashes (for example StrictHttpFirewall.setAllowUrlEncodedSlash(true), UDecoder.ALLOW_ENCODED_SLASH, allow_encoded_slash). If not proven, use maybe_revisit or dismissed depending on default behavior.
- route/source selection: treat "Selected route" and SourceAgent handoff as hints only. The decisive route is the method that actually contains the sink line. If a nearby earlier route differs from the sink-containing method, read the sink method and judge that method instead.
- custom short check values, checksums, truncated MACs, hex/base64 wrapping, or tokens returned by another endpoint are not automatically sanitizers. For file path sinks, dismiss only if code proves the path is bound to a server-chosen allowlisted base/file and cannot be user-supplied or re-derived by an attacker; otherwise use confirmed or maybe_revisit depending on exploitability.
- barrier discipline: before returning confirmed or dismissed, identify every condition/check/verify/token/sign/mac/encrypt/decrypt/decode/encode/hash/whitelist/allowlist/canonical/normalize/filter/escape/sanitize/permission step on the source-to-sink path. Explain whether each barrier actually cuts attacker control of the sink-critical value.
- helper discipline: if a barrier depends on a helper method, utility class, constant, template, mapper, or config value and the preloaded evidence does not show its implementation, call read_file/rg to inspect it. If you cannot inspect it, do not return high-confidence confirmed or high-confidence dismissed; use maybe_revisit and list the missing helper evidence.
- control discipline: if attacker controls both the guarded value and the guard input (for example path and checkCode), still check whether a server secret/state/nonce binds them. If a server secret/state may be required and you cannot prove attacker can obtain or construct the guard value for arbitrary sink input, use maybe_revisit.
- path discipline: for file path download/read/write traversal cases, confirmed requires evidence that the sink-critical path remains attacker-controlled after transforms and that no canonical/base-directory allowlist blocks it. If a custom token/signature is present but helper/state evidence is incomplete, use maybe_revisit.
- output discipline: response.getOutputStream/ServletOutputStream is a vulnerability only when the bytes written come from attacker-influenced file/template/command/SQL/etc. Dismiss generated captcha/json/report bytes unless an attacker-controlled file/path/content source is proven.
- upload discipline: for file uploads, inspect filename generation, extension allowlist, content/MIME checks, and storage directory semantics. If the original filename is hashed/server-renamed and executable storage is unproven, use maybe_revisit or dismissed depending on the sink semantics.
- upload RCE severity discipline: for Spring Boot executable-jar or non-external-Tomcat deployments, uploaded .jsp/.war files are usually not directly executed by the container. Treat it as medium unless you prove executable web root/JSP parsing or a concrete combination chain to RCE. If only arbitrary/suffix-limited file write is proven, report that impact instead of high RCE.
- deserialization cases: library family and version, autoType/default typing configuration, direction of serialization vs deserialization, and whether data is user-controlled;
- SSTI/template cases: whether the user-controlled variable is actually referenced by the template and rendered by the engine.

	Your returned verdict must include a sourceSinkTrace and barrierAnalysis:
	- sourceSinkTrace must show the decisive route/source, important transforms/helpers, and final sink with file:line facts.
	- confirmed is forbidden if the evidence only proves the sink. You must name the externally controllable source with file:line, parameter/header/body/path variable/cookie name, and how it reaches the sink.
	- barrierAnalysis must list each checked barrier as "file:line barrier -> cuts control / does not cut control / unknown". If no barrier exists, write "none found after checking <files/helpers>".
- confirmed is allowed only when missingEvidence is [] and every relevant barrier is either absent or proven not to cut attacker control.
- dismissed is allowed only when a semantic mismatch or effective barrier is proven with file:line evidence.
- maybe_revisit is mandatory when helper code, token/signature/key provenance, route reachability, template usage, executable upload storage, or runtime config is still unproven.

${toolContext.verifierBatch ? "Return exactly one verdict object for every listed hypothesisId. Include hypothesisId in each verdict." : "Return exactly one verdict."} Use:
- confirmed: source-to-sink is reachable and security impact is concrete;
- dismissed: a clear barrier or semantic mismatch proves it is not this vulnerability;
- maybe_revisit: evidence is incomplete, weak, or needs manual route/runtime confirmation.
	` : ""}

${pocMode ? `HTTP PoC generation target:
${toolContext.pocContext || "(missing PoC context)"}

Your job is to write a minimal, reproducible HTTP request packet that triggers the confirmed source-to-sink path. Read code when needed before finalizing. Requirements:
- Use the actual route mapping for the method that receives the source. Do not use a nearby unrelated route.
- Put the payload in the exact source location: query/form parameter, path variable segment, request body, header, cookie, multipart file field, or input stream.
- For POST/PUT/PATCH @RequestParam, prefer application/x-www-form-urlencoded unless code clearly expects JSON.
- For @PathVariable, place the payload in the path segment, not as a query parameter.
- For @RequestBody/input stream, choose Content-Type and body shape from the handler parameter type and source code.
- For multipart upload, generate multipart/form-data with the correct field name.
- Use harmless payloads such as id/whoami for command execution and non-destructive probe values for file/template tests.
- If no directly triggerable HTTP source or route is proven, return {"pocs":[]} instead of inventing a packet.
Return final JSON only with one pocs item for this hypothesis when a packet is justified.
` : ""}

${refineMode ? `Second-pass refinement mode:
You are running AFTER an initial AI extraction and a file-read pre-scan. Use the pre-scan hits as hints, not as ground truth. Call file_tree/rg/read_file again to verify nearby code and find missed entries. Return only NEW missed ${finalKey}; do not repeat entries already listed in existing AI results. If no additional entries are justified, return {"${finalKey}":[]}.

Refinement context:
${toolContext.refineContext}
` : ""}

${verifierMode
  ? `Backend preloaded ${files.length} verifier evidence pack/file/window(s). EvidenceGraph verifier packs are structured, already-read evidence and may use virtual .night-agent paths; do not call read_file on those virtual packs. Use graph snippets first, then call read_file only for missing real helper/template/mapper/sanitizer/runtime code. Evidence list:`
  : pocMode
    ? `Backend preloaded ${files.length} PoC evidence file/window(s). Use this code as already-read evidence; call read_file only if route/source/body format remains unclear. Evidence list:`
  : largeProject
    ? `Backend preselected ${files.length} fallback files, but do not rely on that shortlist. Use file_tree first, choose the files you want to inspect, then call read_file for those files. Fallback shortlist sample:`
    : "Candidate files already selected by the profiler:"}
${fileList || "(none)"}

${verifierMode ? `Preloaded verifier code evidence:
${preloadedVerifierEvidence || "(none)"}
` : ""}

Compact project tree, sorted by audit relevance:
${projectTree}

Available tools:
1. {"tool":"file_tree","pattern":"optional regex","globs":["*.java","*.jsp","*.xml","*.jar"],"maxResults":220}
   Lists project files sorted by audit relevance. Use this first when you need to choose controllers, JSPs, listeners, filters, mappers, services, or archives to inspect.
2. {"tool":"select_files","files":["path/from/file_tree","another/path.jsp"],"reason":"why these files cover likely source/sink families","maxResults":14}
   Submit a file-reading plan. The backend records selected_files and automatically reads relevant source/sink windows from each selected file. Prefer this after file_tree for SourceAgent/SinkAgent in large projects.
3. {"tool":"rg","pattern":"REGEX","globs":["*.java"],"maxResults":80}
   Runs ripgrep under the project root. Always provide a non-empty pattern.
4. {"tool":"read_file","file":"path/from/tree/or/rg","startLine":10,"endLine":80}
   Reads a bounded line range from one project file.
5. {"tool":"archive_list","pattern":"optional regex","maxResults":120}
   Lists jar/war/zip archives under the project. Use when source is distributed across jars.
6. {"tool":"jar_entries","file":"path/to.jar","pattern":"optional regex","maxResults":160}
   Lists entries in one archive.
7. {"tool":"jar_extract_source","file":"path/to-sources.jar","maxResults":120}
   Extracts bounded .java files from a source jar into the audit output area and returns previews.
8. {"tool":"jar_javap","file":"path/to.jar","pattern":"ClassName|package regex","maxResults":8}
   Uses javap on a bounded number of classes from a class jar.
9. {"tool":"jar_decompile","file":"path/to.jar","pattern":"ClassName|package regex","maxResults":6}
   Decompiles a bounded number of classes from a class jar with CFR and returns source previews.
${toolContext.allowJoern && toolContext.cpgPath ? `10. {"tool":"joern_search","query":"sources|sinks|dataflow","sinkPattern":"regex","sourcePattern":"regex","file":"optional file","line":123,"maxResults":80}
   Runs a bounded built-in Joern query against the current CPG.
11. {"tool":"joern_script","script":"Scala Joern DSL","maxResults":120}
   Runs a bounded custom Joern Scala script. Import io.shiftleft.semanticcpg.language._ if needed.` : ""}

  ${largeProject && !verifierMode && !pocMode ? `This is a large project (${files.length} fallback files, ${profile.routes.length} routes). You must NOT rely only on the fallback shortlist. Your first response MUST be a file_tree tool call, not final ${finalKey} JSON. Start with:
{"tool":"file_tree","pattern":"controller|action|servlet|filter|listener|interceptor|jsp|upload|download|auth|login|mapper|service|util|jar","globs":["*.java","*.jsp","*.jspx","*.xml","*.jar","*.war"],"maxResults":260}` : "Start by inspecting the project tree and candidate files."}
  ${verifierMode
    ? "The preloaded verifier evidence already contains sink/source code windows. Read that evidence first. You may finalize from it when it proves the verdict; use tools only to resolve missing helper/template/mapper/sanitizer details."
    : pocMode
      ? "The preloaded PoC context already contains source, sink, route, and chain hints. Read that evidence first, then call read_file/rg only to resolve the exact route, parameter binding, body format, multipart field, or helper method."
    : "After file_tree returns, use select_files to submit the files you plan to inspect and let the backend batch-read relevant windows. Then use rg/read_file only for gaps or precise line ranges. Prioritize Controller/Action, JSP/JSPX, Servlet, Filter, Listener, Interceptor, Mapper XML, Service, Util, upload/download handlers, auth/security code, and archives."}
${largeProject && minInspectedFiles > 0 ? `For this large project, do not finalize until you have inspected at least ${minInspectedFiles} distinct files with read_file/jar_extract_source/jar_decompile, unless there are fewer relevant files. Use rg to find targets, then read_file the most relevant files.` : ""}
Use rg when you need more evidence. Suggested rg pattern:
${suggestedRg}

If the project has few direct source files, many lib/WEB-INF/lib archives, vendor SDK jars, or source jars, call archive_list, jar_entries, jar_extract_source, jar_javap, or jar_decompile to inspect those archives before finalizing. Prefer source jars when present; use jar_decompile or jar_javap for ordinary class jars.

When you have enough evidence, output final JSON only:
${finalSchema}
`

  if (largeProject && !verifierMode && !pocMode) {
    const forcedTreeCall: ToolCall = {
      tool: "file_tree",
      pattern: "controller|action|servlet|filter|listener|interceptor|jsp|upload|download|auth|login|mapper|service|util|jar",
      globs: ["*.java", "*.jsp", "*.jspx", "*.xml", "*.jar", "*.war"],
      maxResults: 260,
    }
    const observation = await runFileTreeTool(profile.root, forcedTreeCall as FileTreeToolCall)
    console.log(`  [llm-tool] ${traceLabel} step=0 tool=file_tree forced=true`)
    const callSummary = summarizeToolCall(forcedTreeCall)
    await appendToolTrace(traceOutputDir, {
      ...traceMeta,
      agent: kind,
      step: 0,
      type: "tool_call",
      forced: true,
      call: callSummary,
      reason: "large_project_tree_first",
    })
    await appendToolTrace(traceOutputDir, {
      ...traceMeta,
      agent: kind,
      step: 0,
      type: "tool_observation",
      forced: true,
      call: callSummary,
      observationChars: observation.length,
      observationHead: observation.slice(0, 500),
    })
    transcript += `\n\nTool observation 0 (forced file_tree because this is a large project):\n${observation.slice(0, 26_000)}\n\nNow choose the files you want with select_files, then use rg/read_file only for gaps. Return final ${finalKey} JSON only after inspecting enough evidence.`
  }

  for (let step = 0; step < maxToolSteps; step++) {
    const result = await callLLM(config, system, transcript, timeoutMs)
    if (!result.ok) {
      await appendToolTrace(traceOutputDir, {
        ...traceMeta,
        agent: kind,
        step,
        type: "llm_call_failed",
        response: result.text.slice(0, 500),
        timedOut: result.timedOut,
      })
      return null
    }

    let parsed: unknown
    try {
      parsed = extractJsonPayload(result.text)
    } catch {
      transcript += `\n\nTool observation: invalid JSON. Respond with either a tool JSON object or final ${finalKey} JSON.`
      continue
    }

    const hasFinal = hasFinalRows(parsed, finalKey)
      || (kind === "discovery" && isRecord(parsed) && (Array.isArray(parsed.sources) || Array.isArray(parsed.sinks)))
    if (hasFinal) {
      if ((largeProject || verifierMode || pocMode) && inspectedFiles.size < minInspectedFiles) {
        transcript += `\n\nTool observation: final ${finalKey} rejected for now. Only ${inspectedFiles.size}/${minInspectedFiles} distinct inspected file(s). Call select_files/read_file/jar_extract_source/jar_decompile on the sink, source, helper, template, mapper, dependency, or sanitizer files before finalizing.`
        await appendToolTrace(traceOutputDir, {
          ...traceMeta,
          agent: kind,
          step,
          type: "premature_final_insufficient_files",
          inspectedFiles: [...inspectedFiles],
          minInspectedFiles,
          responseChars: result.text.length,
        })
        continue
      }
      const finalRows = collectRows(parsed, [finalKey, "sources", "sinks", "entries", "results", "items", "findings", "vulnerabilities", "candidates"])
      await appendToolTrace(traceOutputDir, {
        ...traceMeta,
        agent: kind,
        step,
        type: "final_result",
        finalKey,
        rows: finalRows.length,
        files: uniqueRowFiles(finalRows).slice(0, 40),
      })
      return parsed
    }

    const calls = extractToolCalls(parsed)
    if (calls.length === 0) {
      await appendToolTrace(traceOutputDir, {
        ...traceMeta,
        agent: kind,
        step,
        type: "no_tool_call",
        responseChars: result.text.length,
      })
        if (largeProject && !pocMode && step === 0) {
        const forcedTreeCall: ToolCall = {
          tool: "file_tree",
          pattern: "controller|action|servlet|filter|listener|interceptor|jsp|upload|download|auth|login|mapper|service|util|jar",
          globs: ["*.java", "*.jsp", "*.jspx", "*.xml", "*.jar", "*.war"],
          maxResults: 260,
        }
        const observation = await runFileTreeTool(profile.root, forcedTreeCall as FileTreeToolCall)
        console.log(`  [llm-tool] ${traceLabel} step=${step + 1} tool=file_tree forced=true`)
        const callSummary = summarizeToolCall(forcedTreeCall)
        await appendToolTrace(traceOutputDir, {
          ...traceMeta,
          agent: kind,
          step: step + 1,
          type: "tool_call",
          forced: true,
          call: callSummary,
        })
        await appendToolTrace(traceOutputDir, {
          ...traceMeta,
          agent: kind,
          step: step + 1,
          type: "tool_observation",
          forced: true,
          call: callSummary,
          observationChars: observation.length,
          observationHead: observation.slice(0, 500),
        })
        transcript += `\n\nTool observation ${step + 1} (forced file_tree because this is a large project):\n${observation.slice(0, 26_000)}\n\nNow choose the files you want with select_files, then use read_file for precise gaps.`
      } else {
        transcript += `\n\nTool observation: no tool call and no final ${finalKey}. Respond with valid JSON.`
      }
      continue
    }

    const observations: string[] = []
    for (const call of calls.slice(0, 3)) {
      const callSummary = summarizeToolCall(call)
      console.log(`  [llm-tool] ${traceLabel} step=${step + 1} tool=${call.tool}${call.file ? ` file=${call.file}` : ""}${call.pattern ? ` pattern=${call.pattern}` : ""}`)
      if (call.file && (call.tool === "read_file" || call.tool === "jar_extract_source" || call.tool === "jar_decompile" || call.tool === "jar_javap")) {
        inspectedFiles.add(String(call.file))
      }
      if (call.tool === "select_files") {
        const plannedFiles = normalizeSelectedFiles(profile.root, call.files ?? (call.file ? [call.file] : []))
        for (const file of plannedFiles) inspectedFiles.add(file)
        await appendToolTrace(traceOutputDir, {
          ...traceMeta,
          agent: kind,
          step: step + 1,
          type: "selected_files",
          files: plannedFiles,
          reason: call.reason,
        })
      }
      await appendToolTrace(traceOutputDir, {
        ...traceMeta,
        agent: kind,
        step: step + 1,
        type: "tool_call",
        call: callSummary,
        inspectedFiles: [...inspectedFiles],
      })
      let observation = ""
      if (call.tool === "file_tree" || call.tool === "list_files") {
        observation = await runFileTreeTool(profile.root, call as FileTreeToolCall)
      } else if (call.tool === "select_files") {
        observation = await runSelectFilesTool(profile.root, call, kind, selectedFiles)
      } else if (call.tool === "rg") {
        observation = await runRgTool(profile.root, call)
      } else if (call.tool === "read_file") {
        observation = await runReadFileTool(profile.root, call)
      } else if (call.tool.startsWith("jar_") || call.tool === "archive_list") {
        observation = await runArchiveTool(profile.root, traceOutputDir, call as ArchiveToolCall)
      } else if ((call.tool === "joern_search" || call.tool === "joern_script") && toolContext.allowJoern && toolContext.cpgPath) {
        observation = await runJoernTool(toolContext.cpgPath, traceOutputDir, call as JoernToolCall)
      } else if (call.tool === "joern_search" || call.tool === "joern_script") {
        observation = `[${call.tool}] error: Joern CPG is not available in this phase`
      }
      observations.push(observation)
      await appendToolTrace(traceOutputDir, {
        ...traceMeta,
        agent: kind,
        step: step + 1,
        type: "tool_observation",
        call: callSummary,
        observationChars: observation.length,
        observationHead: observation.slice(0, 500),
      })
    }
    transcript += `\n\nTool observation ${step + 1}:\n${observations.join("\n\n").slice(0, 26_000)}`
  }

  const final = await callLLM(config, system, `${transcript}\n\nNo more tool calls. Output final ${finalKey} JSON now.`, timeoutMs)
  if (!final.ok) {
    await appendToolTrace(traceOutputDir, {
      ...traceMeta,
      agent: kind,
      step: "final",
      type: "llm_call_failed",
      response: final.text.slice(0, 500),
      timedOut: final.timedOut,
    })
    return null
  }
  try {
    const parsed = extractJsonPayload(final.text)
    const finalRows = collectRows(parsed, [finalKey, "sources", "sinks", "entries", "results", "items", "findings", "vulnerabilities", "candidates"])
    await appendToolTrace(traceOutputDir, {
      ...traceMeta,
      agent: kind,
      step: "final",
      type: hasFinalRows(parsed, finalKey) ? "final_result" : "final_invalid",
      finalKey,
      rows: finalRows.length,
      files: uniqueRowFiles(finalRows).slice(0, 40),
    })
    return parsed
  } catch {
    await appendToolTrace(traceOutputDir, {
      ...traceMeta,
      agent: kind,
      step: "final",
      type: "final_missing",
      finalKey,
      responseChars: final.text.length,
    })
    return null
  }
}

export async function __testRunToolAssistedExtraction(
  config: LLMConfig,
  profile: ProjectProfile,
  files: SourceFileCandidate[],
  kind: ToolAgentKind,
  outputDir: string,
): Promise<unknown | null> {
  return runToolAssistedExtraction(config, profile, files, kind, 30_000, { outputDir })
}

function hasFinalRows(parsed: unknown, finalKey: string): boolean {
  if (Array.isArray(parsed)) {
    return parsed.some((row) => isRecord(row) && !("tool" in row) && !("action" in row) && looksLikeFindingRow(row))
  }
  return isRecord(parsed) && Array.isArray(parsed[finalKey])
}

function extractToolCalls(parsed: unknown): ToolCall[] {
  const rows: unknown[] = Array.isArray(parsed)
    ? parsed
    : isRecord(parsed) && Array.isArray(parsed.tool_calls)
      ? parsed.tool_calls
      : isRecord(parsed) && Array.isArray(parsed.tools)
        ? parsed.tools
        : isRecord(parsed)
          ? [parsed]
          : []

  const calls: ToolCall[] = []
  for (const row of rows) {
    if (!isRecord(row)) continue
    const rawTool = String(row.tool ?? row.name ?? row.action ?? "").toLowerCase()
    const args = isRecord(row.arguments) ? row.arguments : isRecord(row.input) ? row.input : row
    if (rawTool === "file_tree" || rawTool === "tree" || rawTool === "list_files" || rawTool === "ls") {
      calls.push({ ...args, tool: rawTool === "list_files" ? "list_files" : "file_tree" } as ToolCall)
      continue
    }
    if (rawTool === "select_files" || rawTool === "select" || rawTool === "plan_files" || rawTool === "read_files") {
      calls.push({ ...args, tool: "select_files" } as ToolCall)
      continue
    }
    if (rawTool === "rg" || rawTool === "ripgrep" || rawTool === "search") {
      calls.push({ ...args, tool: "rg" } as ToolCall)
      continue
    }
    if (rawTool === "read_file" || rawTool === "read" || rawTool === "open") {
      calls.push({ ...args, tool: "read_file" } as ToolCall)
      continue
    }
    if (rawTool === "archive_list" || rawTool === "list_archives" || rawTool === "find_artifact") {
      calls.push({ ...args, tool: "archive_list" } as ToolCall)
      continue
    }
    if (rawTool === "jar_entries" || rawTool === "list_jar" || rawTool === "zipinfo") {
      calls.push({ ...args, tool: "jar_entries" } as ToolCall)
      continue
    }
    if (rawTool === "jar_extract_source" || rawTool === "extract_source_jar") {
      calls.push({ ...args, tool: "jar_extract_source" } as ToolCall)
      continue
    }
    if (rawTool === "jar_javap" || rawTool === "javap") {
      calls.push({ ...args, tool: "jar_javap" } as ToolCall)
      continue
    }
    if (rawTool === "jar_decompile" || rawTool === "decompile_jar" || rawTool === "cfr") {
      calls.push({ ...args, tool: "jar_decompile" } as ToolCall)
      continue
    }
    if (rawTool === "joern_search" || rawTool === "joern_query") {
      calls.push({ ...args, tool: "joern_search" } as ToolCall)
      continue
    }
    if (rawTool === "joern_script") {
      calls.push({ ...args, tool: "joern_script" } as ToolCall)
    }
  }
  return calls
}

function uniqueRowFiles(rows: unknown[]): string[] {
  const files = new Set<string>()
  for (const row of rows) {
    if (!isRecord(row)) continue
    const value = firstNestedString(row, ["file", "path", "sourceFile", "filePath", "filename", "location.file", "location.path"])
    if (value) files.add(value)
  }
  return [...files]
}

async function runRgTool(root: string, call: ToolCall): Promise<string> {
  const pattern = typeof call.pattern === "string" ? call.pattern.trim() : ""
  if (!pattern) return "[rg] error: missing pattern"

  const globs = Array.isArray(call.globs)
    ? call.globs.filter((glob): glob is string => typeof glob === "string" && glob.trim().length > 0).slice(0, 8)
    : typeof call.globs === "string" && call.globs.trim()
      ? [call.globs.trim()]
      : ["*.java", "*.xml", "*.jsp", "*.properties"]
  const maxResults = clampNumber(call.maxResults, 1, 200, 80)

  const args = [
    "--line-number",
    "--no-heading",
    "--color", "never",
    "--glob", "!target/**",
    "--glob", "!build/**",
    "--glob", "!dist/**",
    "--glob", "!output-audit/**",
    "--glob", "!.night-agent/**",
    "--glob", "!.night_agent/**",
    "--glob", "!node_modules/**",
  ]
  for (const glob of globs) args.push("--glob", glob)
  args.push(pattern, root)

  const proc = Bun.spawn(["rg", ...args], { stdout: "pipe", stderr: "pipe" })
  const timer = setTimeout(() => proc.kill(), 20_000)
  const stdout = await new Response(proc.stdout).text()
  const stderr = await new Response(proc.stderr).text()
  const exitCode = await proc.exited
  clearTimeout(timer)

  if (exitCode > 1) return `[rg] error: ${stderr.slice(0, 500)}`
  const lines = stdout.split("\n").filter(Boolean).slice(0, maxResults)
  return `[rg] pattern=${pattern}\n${lines.join("\n") || "(no matches)"}`
}

async function runSelectFilesTool(
  root: string,
  call: ToolCall,
  kind: ToolAgentKind,
  selectedFiles: Set<string>,
): Promise<string> {
  const rawFiles = Array.isArray(call.files)
    ? call.files
    : typeof call.file === "string"
      ? [call.file]
      : []
  const files = [...new Set(rawFiles
    .filter((file): file is string => typeof file === "string" && file.trim().length > 0)
    .map((file) => file.trim()))]
    .slice(0, clampNumber(call.maxResults, 1, 30, 14))
  if (files.length === 0) return "[select_files] error: missing files"

  const windows: string[] = []
  const selectedRelFiles: string[] = []
  let totalChars = 0
  const maxTotalChars = 90_000

  for (const rawFile of files) {
    const file = constrainProjectPath(root, rawFile)
    if (!file) {
      windows.push(`=== ${rawFile} ===\n[select_files] skipped: file outside project root`)
      continue
    }
    const rel = relative(root, file)
    if (selectedFiles.has(rel)) {
      windows.push(`=== ${rel} ===\n[select_files] skipped: already selected in this tool session`)
      continue
    }
    selectedFiles.add(rel)
    selectedRelFiles.push(rel)
    try {
      const content = await readContextualFile(file, {
        patterns: toolReadPatterns(kind),
        maxWholeChars: 70_000,
        maxWindowChars: 26_000,
        windowRadius: 24,
        fallbackHeadChars: 18_000,
      })
      const rendered = `=== ${rel} ===\n${content ?? "[select_files] no readable source/sink window"}`
      const remaining = maxTotalChars - totalChars
      if (remaining <= 0) break
      windows.push(rendered.slice(0, remaining))
      totalChars += Math.min(rendered.length, remaining)
    } catch (err) {
      windows.push(`=== ${rel} ===\n[select_files] error: ${err instanceof Error ? err.message : String(err)}`)
    }
  }

  const reason = typeof call.reason === "string" && call.reason.trim() ? call.reason.trim() : "(none)"
  return `[select_files] reason=${reason}\nselected=${selectedRelFiles.join(", ") || "(none)"}\n\n${windows.join("\n\n") || "(no files read)"}`
}

function toolReadPatterns(kind: ToolAgentKind): RegExp[] {
  if (kind === "source") {
    return JAVA_SOURCE_CONTEXT_PATTERNS
  }
  return JAVA_SINK_CONTEXT_PATTERNS
}

async function runReadFileTool(root: string, call: ToolCall): Promise<string> {
  const rawFile = typeof call.file === "string" ? call.file.trim() : ""
  if (!rawFile) return "[read_file] error: missing file"
  const parsedFile = rawFile.match(/^(.*?):(\d+)(?::\d+)??$/)
  const fileInput = parsedFile?.[1] ?? rawFile
  const file = constrainProjectPath(root, fileInput)
  if (!file) return "[read_file] error: file outside project root"

  const hintedLine = parsedFile?.[2] ? parseInt(parsedFile[2], 10) : undefined
  const start = clampNumber(call.startLine ?? (hintedLine ? hintedLine - 20 : undefined), 1, 1_000_000, 1)
  const end = clampNumber(call.endLine, start, start + 220, start + 80)
  try {
    const text = await Bun.file(file).text()
    const lines = text.split("\n")
    const output = lines.slice(start - 1, end).map((line, idx) => `${start + idx} | ${line}`)
    return `[read_file] ${relative(root, file)}:${start}-${Math.min(end, lines.length)}\n${output.join("\n")}`
  } catch (err) {
    return `[read_file] error: ${err instanceof Error ? err.message : String(err)}`
  }
}

function constrainProjectPath(root: string, file: string): string | null {
  const target = isAbsolute(file) ? resolve(file) : resolve(root, file)
  const rel = relative(root, target)
  if (rel.startsWith("..") || isAbsolute(rel)) return null
  return target
}

function normalizeSelectedFiles(root: string, files: unknown): string[] {
  if (!Array.isArray(files)) return []
  const normalized: string[] = []
  for (const raw of files) {
    if (typeof raw !== "string" || !raw.trim()) continue
    const file = constrainProjectPath(root, raw.trim())
    if (!file) continue
    normalized.push(relative(root, file))
  }
  return [...new Set(normalized)]
}

function clampNumber(value: unknown, min: number, max: number, fallback: number): number {
  const parsed = typeof value === "number" ? value : parseInt(String(value ?? ""), 10)
  if (!Number.isFinite(parsed)) return fallback
  return Math.max(min, Math.min(max, parsed))
}

// ─── Prompt templates (external files with builtin fallback) ───

function joernQueriesPrompt(
  profile: ProjectProfile,
  hypotheses: Hypothesis[],
  sources: SourceEntry[] = [],
): { system: string; user: string } {
  const confirmedH = hypotheses.filter((h) => h.status === "confirmed" || h.status === "pending")
  const sinkList = confirmedH.slice(0, 30).map((h) =>
    `  - ${h.category}: ${h.sinkPattern} @ ${h.sinkFile}:${h.sinkLine}`
  ).join("\n")
  const sourceList = sources.slice(0, 40).map((s) =>
    `  - ${s.kind}:${s.paramName} @ ${s.file}:${s.line} ${s.code}`
  ).join("\n")

  const depList = profile.dependencies
    .filter((d) => /fastjson|shiro|freemarker|mybatis|jackson|log4j/i.test(d.name))
    .map((d) => d.name)
    .join(", ")

  // Build extra queries for specific dependencies
  let extraQueries = ""
  if (depList.includes("shiro")) {
    extraQueries += `### auth-bypass.sc\nFind Shiro permission checks and detect paths without them. Use cpg.method.name(".*hasRole.*|.*requiresPermissions.*|.*isPermitted.*").\n\n`
  }
  if (depList.includes("freemarker")) {
    extraQueries += `### ssti.sc\nTrace dataflow from Controller params to Template.process() calls. Sink: cpg.call.code(".*process\\\\(.*").\n\n`
  }
  if (depList.includes("fastjson")) {
    extraQueries += `### deser.sc\nTrace dataflow from HTTP params to JSON.parseObject / parseArray calls. Sink: cpg.call.code(".*parseObject\\\\(.*|.*parseArray\\\\(.*").\n\n`
  }

  // Try external prompt template first, fall back to builtin
  const loaded = tryLoadPrompt("joern-audit", "query-generation", {
    dependencies: depList || "spring-boot only",
    sink_list: sinkList || "  (none yet — run SinkAgent first)",
    source_list: sourceList || "  (none yet — run SourceAgent first)",
    extra_queries: extraQueries,
  })
  if (loaded) return loaded

  // Builtin fallback
  return {
    system: `You are JoernQueryAgent, a Joern CPG expert writing project-specific Scala query scripts. Output ONLY valid Scala code using Joern's DSL.

CRITICAL — Correct Joern DSL MUST be used (these are non-negotiable):
1. For getting filenames, USE .file.name.headOption.getOrElse("?") — NEVER use .filename (it does NOT exist on Call/Method/Parameter nodes)
2. For annotation name matching, USE .annotation.name("regexPattern") with a SINGLE regex string — NEVER pass Set(...) to .name()
3. For filtering Java files: .filter(n => n.file.name.headOption.exists(_.endsWith(".java")))
4. For method full name in println: ${"$"}{m.file.name.headOption.getOrElse("?")}
5. Import ONLY: import io.shiftleft.semanticcpg.language._
6. Every script must define or apply Java-file filtering; do not report non-Java nodes.
7. Output findings with bracket tags such as [Source], [Sink], [SSRF], [SQLi], [Cmdi], [Dataflow].

FORMAT RULES:
- Each script MUST start with "=== FILENAME.sc ===" on its own line as a separator.
- Example: === sources.sc === [newline] import io.shiftleft.semanticcpg.language._ [newline] [code]
- No markdown fences, no explanations — ONLY the separator lines and Scala code.`,
    user: `Write Joern CPG query scripts for a Java project. Project context:
- Dependencies: ${depList || "spring-boot only"}
- SourceAgent inputs:
${sourceList || "  (none yet — write generic Spring source queries)"}
- SinkAgent candidates:
${sinkList || "  (none yet — run SinkAgent first)"}

CRITICAL API REMINDER:
- To read filename: node.file.name.headOption.getOrElse("?") NOT .filename
- For annotation: .annotation.name(".*GetMapping.*|.*PostMapping.*") NOT .annotation.name(Set(...))
- Filter .java: .filter(x => x.file.name.headOption.exists(_.endsWith(".java")))

Write these query scripts:

### sources.sc
Find HTTP entry points and user-controlled parameters in Spring Controllers. Include annotation-bound params, @RequestBody, headers/cookies/path variables, HttpServletRequest.getParameter/getHeader/getInputStream/getReader. Print: [Source] kind | fullName | filename | lineNumber | code

### sinks.sc
List every call matching these patterns, one foreach block per category:
${confirmedH.map((h) => `  - ${h.sinkPattern}`).filter((v, i, a) => a.indexOf(v) === i).join("\n") || "  - Runtime.exec, ProcessBuilder, readObject, execute, lookup, process"}

For each category use cpg.call.code("regex").filter(c => c.file.name.headOption.exists(_.endsWith(".java"))).take(100).foreach { c => println(s"[Sink] category | ${"$"}{c.file.name.headOption.getOrElse("?")} | ${"$"}{c.lineNumber.getOrElse(-1)} | ${"$"}{c.code}") }

### dataflow.sc
For source/sink candidates found above, trace dataflow from Controller sources. Use:
def source = cpg.method.where(_.annotation.name(".*Mapping.*"))
def sink = cpg.call.code(".*exec\\\\(.*") // and other sink patterns from above
sink.reachableByFlows(source).take(100).foreach { flow => ... }

${extraQueries}`,
  }
}

// ─── Public API ───

export async function generateJoernQueries(
  config: LLMConfig,
  profile: ProjectProfile,
  hypotheses: Hypothesis[],
  sources: SourceEntry[] = [],
  outputDir?: string,
): Promise<string[]> {
  const { system, user } = joernQueriesPrompt(profile, hypotheses, sources)
  const model = config.model ?? DEFAULT_MODELS[config.provider]
  console.log(`  [llm] generating joern queries via ${config.provider}/${model}...`)

  const result = await callLLM(config, system, user, PRIMARY_TIMEOUT)
  if (!result.ok) {
    throw new Error(`Joern query generation failed: ${result.timedOut ? "timeout" : result.text.slice(0, 200)}`)
  }
  const queriesDir = outputDir ? resolve(outputDir, "ai-joern-queries") : resolve(SKILLS_DIR, "joern-audit", "queries")
  await Bun.$`mkdir -p ${queriesDir}`

  const files: string[] = []

  // Strip markdown fences and leading commentary
  const cleanText = result.text
    .replace(/^```scala\s*\n?/gm, "")
    .replace(/^```\s*\n?/gm, "")
    .replace(/^[\s\S]*?(?====)/, "") // strip preamble before first ===

  // Parse multi-file output: "=== FILENAME.sc ===" separators
  const parts = cleanText.split(/=== (.+?) ===\s*\n/)
  for (let i = 1; i < parts.length; i += 2) {
    const filename = parts[i]?.trim()
    const content = parts[i + 1]?.trim()
    if (filename && content && filename.endsWith(".sc")) {
      const filePath = resolve(queriesDir, filename)
      await Bun.write(filePath, content
        .replace(/```scala\s*\n?/g, "")
        .replace(/```\s*\n?/g, ""))
      files.push(filePath)
    }
  }

  // If no separator-based files found, try writing everything as sources.sc
  if (files.length === 0) {
    const cleaned = result.text
      .replace(/^```scala\s*\n?/gm, "")
      .replace(/^```\s*\n?/gm, "")
      .replace(/^[\s\S]*?(?=import\s)/, "") // strip preamble before first import
      .trim()
    if (cleaned) {
      const filePath = resolve(queriesDir, "sources.sc")
      await Bun.write(filePath, cleaned)
      files.push(filePath)
    }
  }

  return files
}

export async function generateJoernQueriesWithTools(
  config: LLMConfig,
  profile: ProjectProfile,
  hypotheses: Hypothesis[],
  sources: SourceEntry[] = [],
  outputDir?: string,
  cpgPath?: string,
): Promise<string[]> {
  if (!cpgPath || !outputDir) {
    return generateJoernQueries(config, profile, hypotheses, sources, outputDir)
  }

  const model = config.model ?? DEFAULT_MODELS[config.provider]
  console.log(`  [llm] joern query agent using Joern tools via ${config.provider}/${model}...`)

  const sinkList = hypotheses.slice(0, 40).map((h) =>
    `- ${h.category}: ${h.sinkPattern} @ ${h.sinkFile}:${h.sinkLine} ${h.sinkCode}`
  ).join("\n")
  const sourceList = sources.slice(0, 50).map((s) =>
    `- ${s.kind}:${s.paramName} @ ${s.file}:${s.line} ${s.code}`
  ).join("\n")

  const system = `You are JoernQueryAgent with access to Joern tools. Output ONLY JSON.`
  let transcript = `Project root: ${profile.root}
CPG: ${cpgPath}

Sources:
${sourceList || "(none)"}

Sink hypotheses:
${sinkList || "(none)"}

Available tools:
1. {"tool":"joern_search","query":"sources|sinks|dataflow","sinkPattern":"regex","sourcePattern":"regex","file":"optional file","line":123,"maxResults":80}
2. {"tool":"joern_script","script":"Scala Joern DSL","maxResults":120}

Use Joern tools to inspect the CPG. When done, output final JSON:
{"scripts":[{"filename":"sinks.sc","content":"import io.shiftleft.semanticcpg.language._\\n..."}]}
`

  let parsed: unknown | null = null
  for (let step = 0; step < 4; step++) {
    const result = await callLLM(config, system, transcript, SOURCE_AGENT_TIMEOUT)
    if (!result.ok) break
    try {
      parsed = extractJsonPayload(result.text)
    } catch {
      transcript += "\n\nTool observation: invalid JSON. Use a Joern tool JSON object or final scripts JSON."
      continue
    }
    if (isRecord(parsed) && Array.isArray(parsed.scripts)) break
    const calls = extractToolCalls(parsed).filter((call) => call.tool === "joern_search" || call.tool === "joern_script")
    if (calls.length === 0) {
      transcript += "\n\nTool observation: no Joern tool call and no final scripts JSON."
      continue
    }
    const observations: string[] = []
    for (const call of calls.slice(0, 2)) {
      observations.push(await runJoernTool(cpgPath, outputDir, call as JoernToolCall))
    }
    transcript += `\n\nJoern observation ${step + 1}:\n${observations.join("\n\n").slice(0, 26_000)}`
  }

  if (!isRecord(parsed) || !Array.isArray(parsed.scripts)) {
    const final = await callLLM(config, system, `${transcript}\n\nNo more tools. Output final scripts JSON now.`, SOURCE_AGENT_TIMEOUT)
    if (final.ok) {
      try {
        parsed = extractJsonPayload(final.text)
      } catch {
        parsed = null
      }
    }
  }

  const scriptsDir = resolve(outputDir, "ai-joern-queries")
  await Bun.$`mkdir -p ${scriptsDir}`
  const files: string[] = []
  const rows = isRecord(parsed) && Array.isArray(parsed.scripts) ? parsed.scripts : []
  for (const row of rows) {
    if (!isRecord(row)) continue
    const filename = typeof row.filename === "string" && row.filename.endsWith(".sc") ? basenameSafe(row.filename) : ""
    const content = typeof row.content === "string" ? row.content.trim() : ""
    if (!filename || !content) continue
    const filePath = resolve(scriptsDir, filename)
    await Bun.write(filePath, sanitizeJoernScript(content))
    files.push(filePath)
  }

  if (files.length > 0) return files
  return generateJoernQueries(config, profile, hypotheses, sources, outputDir)
}

function basenameSafe(filename: string): string {
  return filename.split(/[\\/]/).pop()?.replace(/[^a-zA-Z0-9_.-]/g, "_") ?? ""
}

function sanitizeJoernScript(content: string): string {
  const cleaned = content
    .replace(/^```scala\s*\n?/gm, "")
    .replace(/^```\s*\n?/gm, "")
    .replace(/```\s*$/gm, "")
    .trim()
  return cleaned.includes("import io.shiftleft.semanticcpg.language._")
    ? cleaned
    : `import io.shiftleft.semanticcpg.language._\n${cleaned}`
}

function extractJsonPayload(text: string): unknown {
  const cleaned = text
    .replace(/^```json\s*\n?/gm, "")
    .replace(/^```\s*\n?/gm, "")
    .trim()

  try {
    return JSON.parse(cleaned)
  } catch {
    const arrayStart = cleaned.indexOf("[")
    const arrayEnd = cleaned.lastIndexOf("]")
    if (arrayStart !== -1 && arrayEnd > arrayStart) {
      return JSON.parse(cleaned.slice(arrayStart, arrayEnd + 1))
    }

    const objectStart = cleaned.indexOf("{")
    const objectEnd = cleaned.lastIndexOf("}")
    if (objectStart !== -1 && objectEnd > objectStart) {
      return JSON.parse(cleaned.slice(objectStart, objectEnd + 1))
    }
    throw new Error("no JSON payload found")
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === "object" && !Array.isArray(value))
}

function collectRows(parsed: unknown, keys: string[]): unknown[] {
  if (Array.isArray(parsed)) return parsed
  if (!isRecord(parsed)) return []

  for (const key of keys) {
    const value = parsed[key]
    if (Array.isArray(value)) return value
    if (isRecord(value)) return [value]
  }

  if (looksLikeFindingRow(parsed)) return [parsed]
  return []
}

function looksLikeFindingRow(row: Record<string, unknown>): boolean {
  const hasFile = ["file", "path", "sourceFile", "filePath", "filename"].some((key) => typeof row[key] === "string")
    || isRecord(row.location)
  const hasLine = ["line", "lineNumber", "startLine", "lineNo"].some((key) => row[key] !== undefined)
    || isRecord(row.location)
  return hasFile && hasLine
}

function firstString(row: Record<string, unknown>, keys: string[]): string {
  for (const key of keys) {
    const value = row[key]
    if (typeof value === "string" && value.trim()) return value.trim()
  }
  return ""
}

function firstNestedString(row: Record<string, unknown>, keys: string[]): string {
  for (const key of keys) {
    const parts = key.split(".")
    let current: unknown = row
    for (const part of parts) {
      if (!isRecord(current)) {
        current = undefined
        break
      }
      current = current[part]
    }
    if (typeof current === "string" && current.trim()) return current.trim()
  }
  return ""
}

function firstNumber(row: Record<string, unknown>, keys: string[]): number {
  for (const key of keys) {
    const parts = key.split(".")
    let current: unknown = row
    for (const part of parts) {
      if (!isRecord(current)) {
        current = undefined
        break
      }
      current = current[part]
    }
    if (typeof current === "number" && Number.isFinite(current)) return current
    if (typeof current === "string" && current.trim()) {
      const parsed = parseInt(current.trim(), 10)
      if (Number.isFinite(parsed)) return parsed
    }
  }
  return NaN
}

function resolveCandidateFile(rawFile: string, root: string, files: SourceFileCandidate[]): string {
  if (!rawFile) return ""
  const normalizedRaw = rawFile.replace(/\\/g, "/")
  const byAbs = new Map(files.map((f) => [resolve(f.file).replace(/\\/g, "/"), f.file]))
  const byRel = new Map(files.map((f) => [relative(root, f.file).replace(/\\/g, "/"), f.file]))

  const asAbs = resolve(normalizedRaw).replace(/\\/g, "/")
  if (byAbs.has(asAbs)) return byAbs.get(asAbs)!
  if (byRel.has(normalizedRaw)) return byRel.get(normalizedRaw)!

  const rooted = resolve(root, normalizedRaw).replace(/\\/g, "/")
  if (byAbs.has(rooted)) return byAbs.get(rooted)!

  const matches = files.filter((f) => {
    const abs = resolve(f.file).replace(/\\/g, "/")
    const rel = relative(root, f.file).replace(/\\/g, "/")
    return abs.endsWith(normalizedRaw) || rel.endsWith(normalizedRaw) || normalizedRaw.endsWith(rel)
  })
  if (matches.length === 1) return matches[0]!.file

  const constrained = constrainProjectPath(root, normalizedRaw)
  return constrained ?? ""
}

function sourceLineFromCandidate(file: string, line: number, files: SourceFileCandidate[]): string {
  const candidate = files.find((f) => f.file === file)
  if (!Number.isFinite(line) || line <= 0) return ""
  if (candidate) {
    const lines = candidate.content.split("\n")
    const marker = new RegExp(`^/\\*L${line}\\*/\\s*(.*)$`)
    for (const candidateLine of lines) {
      const matched = candidateLine.match(marker)
      if (matched) return matched[1]?.trim() ?? ""
    }
    return stripLineMarker(lines[line - 1] ?? "").trim()
  }
  try {
    return readFileSync(file, "utf-8").split("\n")[line - 1]?.trim() ?? ""
  } catch {
    return ""
  }
}

function stripLineMarker(line: string): string {
  return line.replace(/^\/\*L\d+\*\/\s*/, "")
}

function markedLineNumber(line: string, fallback: number): number {
  const matched = line.match(/^\/\*L(\d+)\*\//)
  if (!matched) return fallback
  const parsed = parseInt(matched[1] ?? "", 10)
  return Number.isFinite(parsed) ? parsed : fallback
}

function sinkHintLines(files: SourceFileCandidate[]): string {
  const hits: string[] = []
  for (const file of files) {
    const lines = file.content.split("\n")
    lines.forEach((line, index) => {
      const trimmed = stripLineMarker(line.trim())
      if (!trimmed || trimmed.startsWith("import ")) return
      if (JAVA_SINK_CONTEXT_PATTERNS.some((pattern) => {
        pattern.lastIndex = 0
        return pattern.test(trimmed)
      })) {
        hits.push(`${file.file}:${markedLineNumber(line, index + 1)} ${trimmed}`)
      }
    })
  }
  return hits.slice(0, 120).join("\n")
}

function normalizeSourceKind(kind: unknown): SourceEntry["kind"] {
  const raw = String(kind ?? "").toLowerCase()
  if (raw.includes("body")) return "body"
  if (raw.includes("header")) return "header"
  if (raw.includes("cookie")) return "cookie"
  if (raw.includes("path")) return "pathvar"
  if (raw.includes("stream") || raw.includes("reader")) return "input-stream"
  if (raw.includes("attr")) return "request-attr"
  return "param"
}

export async function extractSourceEntriesWithLLM(
  config: LLMConfig,
  profile: ProjectProfile,
  files: SourceFileCandidate[],
  outputDir?: string,
): Promise<Array<Omit<SourceEntry, "id">>> {
  if (files.length === 0) return []

  const toolParsed = await runToolAssistedExtraction(config, profile, files, "source", SOURCE_AGENT_TIMEOUT, { outputDir })
  const toolSources = toolParsed ? parseSourceRows(toolParsed, profile, files) : []
  if (toolSources.length > 0) return toolSources

  const model = config.model ?? DEFAULT_MODELS[config.provider]
  console.log(`  [llm] source agent extracting inputs via ${config.provider}/${model}...`)

  const fileBlocks = files.slice(0, 25).map((f) => {
    const clipped = f.content.length > 18_000 ? `${f.content.slice(0, 18_000)}\n/* clipped */` : f.content
    return `=== ${f.file} ===\n${clipped}`
  }).join("\n\n")

  const system = `You are SourceAgent, an AI security auditor. Read source files and output ONLY JSON, no markdown.`
  const user = `Extract externally controllable input points from this ${profile.language} project.

Return a JSON array. Each item must have:
- kind: one of param, body, header, cookie, pathvar, request-attr, input-stream
- paramName: parameter or request field name, or "unknown"
- file: exact file path from the input block header
- line: 1-based line number
- code: the relevant source line
- methodName: method or handler name
- className: class name if visible

Include all security-relevant external entry sources:
- Spring MVC annotations: @RequestParam, @RequestBody, @PathVariable, @RequestHeader, @CookieValue, MultipartFile, @ModelAttribute
- Servlet/Tomcat entries: @WebServlet, web.xml servlet-mapping targets, HttpServlet doGet/doPost/service parameters, Filter/Listener request objects
- Servlet APIs: HttpServletRequest.getParameter/getParameterValues/getParameterMap/getParameterNames/getHeader/getCookies/getInputStream/getReader/getPart/getParts/getQueryString/getRequestURI/getPathInfo
- JSP inputs: request.getParameter/getHeader in scriptlets, JSP EL ${"$"}{param.*}, ${"$"}{paramValues.*}, ${"$"}{header.*}, ${"$"}{cookie.*}, and <jsp:setProperty property="*">
- Upload/download names or paths controlled by request fields
- JSON/XML/RPC/deserialization entry parameters if they are public handler inputs
- Filter/interceptor/controller advice inputs if they read request data
- Framework equivalents in routes, APIs, handlers, servlets, web actions, mapper XML parameters, JSP request access

Do not include sinks or internal variables that are not externally controllable. Prefer precise line numbers and exact source lines.

Files:
${fileBlocks}`

  const result = await callLLM(config, system, user, SOURCE_AGENT_TIMEOUT)
  if (!result.ok) {
    throw new Error(`Source extraction failed: ${result.timedOut ? "timeout" : result.text.slice(0, 200)}`)
  }

  try {
    const parsed = extractJsonPayload(result.text)
    return parseSourceRows(parsed, profile, files)
  } catch (err) {
    await writeLlmDebug(outputDir, "source-extraction-invalid-json", result.text)
    throw new Error(`Source extraction JSON parse failed: ${err instanceof Error ? err.message : String(err)}`)
  }
}

export async function refineSourceEntriesWithLLM(
  config: LLMConfig,
  profile: ProjectProfile,
  files: SourceFileCandidate[],
  existing: Array<Omit<SourceEntry, "id">>,
  preScan: Array<Omit<SourceEntry, "id">>,
  outputDir?: string,
): Promise<Array<Omit<SourceEntry, "id">>> {
  if (files.length === 0 || preScan.length === 0) return []
  const context = `Existing AI sources (${existing.length}, do not repeat):
${sourceSummaryLines(existing, profile.root, 80)}

File-read pre-scan source hints (${preScan.length}, verify and find missed entries):
${sourceSummaryLines(preScan, profile.root, 160)}`
  const parsed = await runToolAssistedExtraction(config, profile, files, "source", SOURCE_AGENT_TIMEOUT, {
    outputDir,
    refineContext: context,
    minInspectedFiles: Math.min(4, Math.max(2, Math.ceil(preScan.length / 60))),
    maxToolSteps: 6,
  })
  return parsed ? parseSourceRows(parsed, profile, files) : []
}

export interface JoernDiscoveryResult {
  sources: Array<Omit<SourceEntry, "id">>
  sinks: LlmSinkEntry[]
}

export async function discoverSourceSinkWithJoernLLM(
  config: LLMConfig,
  profile: ProjectProfile,
  files: SourceFileCandidate[],
  existingSources: SourceEntry[],
  existingSinks: Hypothesis[],
  outputDir: string,
  cpgPath: string,
): Promise<JoernDiscoveryResult> {
  if (!cpgPath || files.length === 0) return { sources: [], sinks: [] }

  const context = `Existing SourceAgent sources (${existingSources.length}, do not repeat):
${sourceSummaryLines(existingSources, profile.root, 120)}

Existing SinkAgent hypotheses (${existingSinks.length}, do not repeat):
${sinkSummaryLines(existingSinks.map((hyp) => ({
  category: hyp.category,
  severity: hyp.severity,
  sinkPattern: hyp.sinkPattern,
  file: hyp.sinkFile,
  line: hyp.sinkLine,
  code: hyp.sinkCode,
  description: hyp.description,
  reason: hyp.resolutionNote,
})), profile.root, 120)}

Your goal is to find missed candidates through CPG inspection, not to re-list these entries.`

  const parsed = await runToolAssistedExtraction(config, profile, files, "discovery", SOURCE_AGENT_TIMEOUT, {
    outputDir,
    cpgPath,
    allowJoern: true,
    refineContext: context,
    traceMeta: {
      phase: "joern-discovery",
      existingSources: existingSources.length,
      existingSinks: existingSinks.length,
    },
    minInspectedFiles: Math.min(5, Math.max(2, Math.ceil(files.length / 40))),
    maxToolSteps: 8,
  })
  if (!parsed) return { sources: [], sinks: [] }

  const discoveryRows = Array.isArray(parsed) ? parsed : collectRows(parsed, ["discoveries", "items", "results", "entries"])
  const explicitSourceRows = Array.isArray(parsed) ? [] : collectRows(parsed, ["sources"])
  const explicitSinkRows = Array.isArray(parsed) ? [] : collectRows(parsed, ["sinks", "findings", "vulnerabilities", "candidates"])
  const sourceRows = [...explicitSourceRows, ...discoveryRows.filter((row) => {
    if (!isRecord(row)) return false
    const type = String(row.type ?? "").toLowerCase()
    if (type === "source") return true
    if (type === "sink") return false
    return !("category" in row) && !("sinkPattern" in row) && !("sink" in row)
  })]
  const sinkRows = [...explicitSinkRows, ...discoveryRows.filter((row) => {
    if (!isRecord(row)) return false
    const type = String(row.type ?? "").toLowerCase()
    return type === "sink" || "category" in row || "sinkPattern" in row || "sink" in row
  })]
  return {
    sources: parseSourceRows({ sources: sourceRows }, profile, files),
    sinks: parseSinkRows({ sinks: sinkRows }, profile, files),
  }
}

function parseSourceRows(parsed: unknown, profile: ProjectProfile, files: SourceFileCandidate[]): Array<Omit<SourceEntry, "id">> {
  const rows = collectRows(parsed, ["sources", "entries", "results", "items"])
  const sources: Array<Omit<SourceEntry, "id">> = []
  for (const row of rows) {
    if (!row || typeof row !== "object") continue
    const item = row as Record<string, unknown>
    const file = resolveCandidateFile(firstNestedString(item, ["file", "path", "sourceFile", "filePath", "filename", "location.file", "location.path"]), profile.root, files)
    const line = firstNumber(item, ["line", "lineNumber", "startLine", "lineNo", "location.line", "location.start.line"])
    if (!file || !Number.isFinite(line) || line <= 0) continue
    sources.push({
      kind: normalizeSourceKind(item.kind),
      paramName: firstString(item, ["paramName", "parameter", "name", "field"]) || "unknown",
      file,
      line,
      code: firstString(item, ["code", "snippet", "lineText"]) || sourceLineFromCandidate(file, line, files),
      methodName: firstString(item, ["methodName", "method", "handler"]) || "unknown",
      className: firstString(item, ["className", "class"]) || undefined,
    })
  }
  return sources
}

function sourceSummaryLines(sources: Array<Omit<SourceEntry, "id">>, root: string, limit: number): string {
  return sources.slice(0, limit).map((source) => {
    const file = source.file.startsWith(root) ? relative(root, source.file) : source.file
    return `- ${source.kind}:${source.paramName} @ ${file}:${source.line} ${source.code}`.slice(0, 500)
  }).join("\n") || "(none)"
}

function normalizeSinkSeverity(value: unknown): Hypothesis["severity"] {
  const raw = String(value ?? "").toLowerCase()
  if (raw.includes("critical")) return "critical"
  if (raw.includes("high") || raw.includes("error")) return "high"
  if (raw.includes("low")) return "low"
  if (raw.includes("info")) return "info"
  return "medium"
}

function normalizeSinkConfidence(value: unknown): "high" | "medium" | "low" | undefined {
  const raw = String(value ?? "").toLowerCase()
  if (raw.includes("high")) return "high"
  if (raw.includes("medium")) return "medium"
  if (raw.includes("low")) return "low"
  return undefined
}

function parseSinkRows(parsed: unknown, profile: ProjectProfile, files: SourceFileCandidate[]): LlmSinkEntry[] {
  const rows = collectRows(parsed, ["sinks", "findings", "results", "items", "vulnerabilities", "candidates"])
  const sinks: LlmSinkEntry[] = []
  for (const row of rows) {
    if (!row || typeof row !== "object") continue
    const item = row as Record<string, unknown>
    const file = resolveCandidateFile(firstNestedString(item, ["file", "path", "sourceFile", "filePath", "filename", "location.file", "location.path"]), profile.root, files)
    const line = firstNumber(item, ["line", "lineNumber", "startLine", "lineNo", "location.line", "location.start.line"])
    if (!file || !Number.isFinite(line) || line <= 0) continue
    const code = firstString(item, ["code", "snippet", "lineText"]) || sourceLineFromCandidate(file, line, files)
    const sinkPattern = firstString(item, ["sinkPattern", "sink", "sinkApi", "api", "function", "method", "call"]) || "unknown"
    sinks.push({
      category: firstString(item, ["category", "type", "vulnerability", "vulnType"]).toLowerCase() || "other",
      severity: normalizeSinkSeverity(item.severity ?? item.risk),
      sinkPattern,
      file,
      line,
      code,
      description: firstString(item, ["description", "title", "message", "risk"]) || `${sinkPattern} candidate sink`,
      confidence: normalizeSinkConfidence(item.confidence),
      reason: firstString(item, ["reason", "why", "evidence"]) || undefined,
    })
  }
  return sinks
}

export async function extractSinkEntriesWithLLM(
  config: LLMConfig,
  profile: ProjectProfile,
  files: SourceFileCandidate[],
  outputDir?: string,
): Promise<LlmSinkEntry[]> {
  if (files.length === 0) return []

  const toolParsed = await runToolAssistedExtraction(config, profile, files, "sink", SOURCE_AGENT_TIMEOUT, { outputDir })
  const toolSinks = toolParsed ? parseSinkRows(toolParsed, profile, files) : []
  if (toolSinks.length > 0) return toolSinks

  const model = config.model ?? DEFAULT_MODELS[config.provider]
  console.log(`  [llm] sink agent extracting dangerous calls via ${config.provider}/${model}...`)

  const fileBlocks = files.slice(0, 45).map((f) => {
    const clipped = f.content.length > 22_000 ? `${f.content.slice(0, 22_000)}\n/* clipped */` : f.content
    return `=== ${f.file} ===\n${clipped}`
  }).join("\n\n")

  const deps = profile.dependencies
    .filter((d) => /spring|mybatis|jdbc|shiro|fastjson|jackson|freemarker|velocity|ognl|spel|groovy|log4j|struts|commons-fileupload|tomcat/i.test(d.name))
    .map((d) => `${d.name}${d.version ? ` ${d.version}` : ""}`)
    .join(", ")

  const routes = profile.routes.slice(0, 40)
    .map((r) => `${r.method} ${r.path} @ ${r.sourceFile}:${r.line}`)
    .join("\n")
  const hints = sinkHintLines(files)

  const system = `You are SinkAgent, an AI security auditor. Read source files and output ONLY JSON, no markdown.`
  const user = `Extract dangerous sink calls from this ${profile.language} project.

Return a JSON array. Each item must have:
- category: one of cmdi, sqli, xss, file-download, file-upload, path-traversal, ssrf, ssti, spel, ognl, expression, deser, xxe, jndi, auth-bypass, redirect, crypto, other
- severity: critical, high, medium, low, info
- sinkPattern: short sink API name, e.g. Runtime.exec, ProcessBuilder, Statement.execute, new File, Files.readAllBytes, MultipartFile.transferTo, Template.process, SpEL.parseExpression, JSON.parseObject
- file: exact file path from the input block header
- line: 1-based line number of the dangerous call
- code: exact dangerous source line
- description: short human-readable risk description
- confidence: high, medium, or low
- reason: why this is security-relevant

Focus on sinks that can lead to command execution, SQL injection, XSS/unsafe response writes, redirect/forward abuse, file upload/download/path traversal, expression/template execution, deserialization, SSRF, XXE, JNDI, auth bypass, or high-impact data exposure.
For Tomcat/JSP/Servlet projects, include true dangerous sinks in JSP/scriptlets and servlet handlers: response.sendRedirect, getRequestDispatcher(...).forward/include, response.getWriter().write/print, out.print/println/write, <%= request-controlled expressions, Part.write/getSubmittedFileName, FileInputStream/FileOutputStream, and request-controlled File/Paths/Files APIs.
Do not report harmless framework annotations or source-only request parameters as sinks.
If a call is dangerous only when input is user-controlled, still include it as a candidate sink and explain the condition.

Project routes:
${routes || "(none)"}

High-risk dependencies:
${deps || "(none)"}

Potential sink-looking lines from a plain-text pre-scan. Review these carefully and include the true dangerous sinks:
${hints || "(none)"}

Files:
${fileBlocks}`

  const result = await callLLM(config, system, user, SOURCE_AGENT_TIMEOUT)
  if (!result.ok) {
    throw new Error(`Sink extraction failed: ${result.timedOut ? "timeout" : result.text.slice(0, 200)}`)
  }

  try {
    const parsed = extractJsonPayload(result.text)
    const sinks = parseSinkRows(parsed, profile, files)
    if (sinks.length > 0 || !hints.trim()) {
      return sinks
    }

    const retry = await callLLM(config, system, `Your previous extraction returned zero sinks, but the project contains these sink-looking lines from a plain-text pre-scan.
Review each line and return ONLY a JSON array of true dangerous sink candidates using the same schema. Do not return an empty array unless every line is harmless.

${hints}`, SOURCE_AGENT_TIMEOUT)
    if (!retry.ok) return sinks
    const retryParsed = extractJsonPayload(retry.text)
    return parseSinkRows(retryParsed, profile, files)
  } catch (err) {
    throw new Error(`Sink extraction JSON parse failed: ${err instanceof Error ? err.message : String(err)}`)
  }
}

export async function refineSinkEntriesWithLLM(
  config: LLMConfig,
  profile: ProjectProfile,
  files: SourceFileCandidate[],
  existing: LlmSinkEntry[],
  preScan: LlmSinkEntry[],
  outputDir?: string,
): Promise<LlmSinkEntry[]> {
  if (files.length === 0 || preScan.length === 0) return []
  const context = `Existing AI sinks (${existing.length}, do not repeat):
${sinkSummaryLines(existing, profile.root, 80)}

File-read pre-scan sink hints (${preScan.length}, verify and find missed dangerous calls):
${sinkSummaryLines(preScan, profile.root, 160)}`
  const parsed = await runToolAssistedExtraction(config, profile, files, "sink", SOURCE_AGENT_TIMEOUT, {
    outputDir,
    refineContext: context,
    minInspectedFiles: Math.min(4, Math.max(2, Math.ceil(preScan.length / 50))),
    maxToolSteps: 6,
  })
  return parsed ? parseSinkRows(parsed, profile, files) : []
}

function sinkSummaryLines(sinks: LlmSinkEntry[], root: string, limit: number): string {
  return sinks.slice(0, limit).map((sink) => {
    const file = sink.file.startsWith(root) ? relative(root, sink.file) : sink.file
    return `- ${sink.category}/${sink.sinkPattern} @ ${file}:${sink.line} ${sink.code}`.slice(0, 500)
  }).join("\n") || "(none)"
}

function normalizeVerifierStatus(value: unknown): VerifierVerdict["status"] {
  const raw = String(value ?? "").toLowerCase()
  if (raw.includes("dismiss") || raw.includes("false") || raw.includes("误报") || raw.includes("排除")) return "dismissed"
  if (raw.includes("confirm") || raw.includes("true") || raw.includes("确认")) return "confirmed"
  return "maybe_revisit"
}

function normalizeVerifierConfidence(value: unknown): VerifierVerdict["confidence"] {
  const raw = String(value ?? "").toLowerCase()
  if (raw.includes("high") || raw.includes("高")) return "high"
  if (raw.includes("low") || raw.includes("低")) return "low"
  return "medium"
}

function stringArray(value: unknown): string[] {
  if (Array.isArray(value)) {
    return value
      .map((item) => typeof item === "string" ? item.trim() : JSON.stringify(item))
      .filter((item) => item.length > 0)
      .slice(0, 40)
  }
  if (typeof value === "string" && value.trim()) return [value.trim()]
  return []
}

function parseVerifierVerdict(parsed: unknown): VerifierVerdict | null {
  const rows = collectRows(parsed, ["verdicts", "verdict", "results", "items"])
  const row = rows.find((item) => isRecord(item))
  if (!isRecord(row)) return null
  return verifierVerdictFromRow(row)
}

function verifierVerdictFromRow(row: Record<string, unknown>): VerifierVerdict {
  const status = normalizeVerifierStatus(row.status ?? row.verdict ?? row.result)
  const sourceSinkTrace = stringArray(row.sourceSinkTrace ?? row.trace ?? row.dataflow ?? row.path)
  const evidence = [
    ...sourceSinkTrace,
    ...stringArray(row.evidence ?? row.evidenceFacts ?? row.checkedEvidence),
  ].slice(0, 40)
  const sanitizerSummary = [
    ...stringArray(row.sanitizerSummary ?? row.barriers ?? row.safetyChecks),
    ...stringArray(row.barrierAnalysis ?? row.securityBarriers ?? row.controlBarriers),
  ].slice(0, 40)
  return {
    status,
    confidence: normalizeVerifierConfidence(row.confidence ?? row.riskConfidence),
    reason: firstString(row, ["reason", "summary", "conclusion", "why"]) || "StaticVerifierAgent did not provide a detailed reason",
    sourceSinkTrace,
    barrierAnalysis: stringArray(row.barrierAnalysis ?? row.securityBarriers ?? row.controlBarriers),
    evidence,
    checkedFiles: stringArray(row.checkedFiles ?? row.files ?? row.file),
    toolCalls: stringArray(row.toolCalls ?? row.tools ?? row.inspections),
    sanitizerSummary,
    missingEvidence: stringArray(row.missingEvidence ?? row.gaps ?? row.unproven ?? row.unknowns ?? row.exploitabilityGaps),
    recommendedStatus: status,
    createdAt: Date.now(),
  }
}

function parseVerifierVerdicts(parsed: unknown): Map<string, VerifierVerdict> {
  const rows = collectRows(parsed, ["verdicts", "results", "items"])
  const verdicts = new Map<string, VerifierVerdict>()
  for (const item of rows) {
    if (!isRecord(item)) continue
    const id = firstString(item, ["hypothesisId", "id", "hypId"])
    if (!id) continue
    verdicts.set(id, verifierVerdictFromRow(item))
  }
  return verdicts
}

function verifierContext(profile: ProjectProfile, hyp: Hypothesis, bundle?: EvidenceBundle): string {
  const rel = (file: string) => file.startsWith(profile.root) ? relative(profile.root, file) : file
  const sinkRoutes = routeCandidatesForSink(profile, hyp)
    .map((route, index) => `  ${index + 1}. ${route.method} ${route.path} @ ${route.sourceFile}:${route.line} distance=${Math.abs(route.line - hyp.sinkLine)}`)
    .join("\n")
  const sourceLinks = (bundle?.sourceLinks ?? hyp.sourceLinks ?? []).slice(0, 8)
    .map((link, index) => `  ${index + 1}. score=${link.score} ${link.reason} source=${link.source.kind}:${link.source.paramName} @ ${rel(link.source.file)}:${link.source.line} code=${link.source.code}`)
    .join("\n")
  const dataflow = (bundle?.dataflow ?? hyp.dataflowResult)?.paths?.slice(0, 2).map((path, index) => {
    const edges = path.edges.map((edge) => `    - ${edge.kind} @ ${rel(edge.file)}:${edge.line} ${edge.code}`).join("\n")
    return `  path ${index + 1} ${path.sourceLabel} -> ${path.sinkLabel}\n${edges}`
  }).join("\n") || "(no Joern path)"
  const route = bundle?.route
    ? `${bundle.route.method} ${bundle.route.path} @ ${bundle.route.sourceFile}:${bundle.route.line}`
    : "(no route selected)"
  const deps = profile.dependencies
    .filter((dep) => /fastjson|hutool|jackson|freemarker|velocity|mybatis|spring|shiro|commons-fileupload|tomcat|redis/i.test(dep.name))
    .slice(0, 80)
    .map((dep) => `- ${dep.name}${dep.version ? ` ${dep.version}` : ""} (${dep.sourceFile})`)
    .join("\n")

  return `Hypothesis:
- id: ${hyp.id}
- status before verification: ${hyp.status}
- category: ${hyp.category}
- severity: ${hyp.severity}
- description: ${hyp.description}
- sink: ${hyp.sinkPattern} @ ${rel(hyp.sinkFile)}:${hyp.sinkLine}
- sink code: ${hyp.sinkCode}
- origin: ${hyp.origin ?? "unknown"}
- prior note: ${hyp.resolutionNote ?? "(none)"}

Selected route:
${route}

Routes in the sink file near the sink line:
${sinkRoutes || "(none)"}

SourceAgent handoff candidates:
${sourceLinks || "(none)"}

Joern/dataflow evidence:
${dataflow}

Security-relevant dependencies:
${deps || "(none)"}
  `
}

function verifierBatchContext(profile: ProjectProfile, items: Array<{ hypothesis: Hypothesis; bundle?: EvidenceBundle }>): string {
  const rel = (file: string) => file.startsWith(profile.root) ? relative(profile.root, file) : file
  const hypotheses = items.map(({ hypothesis: hyp, bundle }, index) => {
    const sinkRoutes = routeCandidatesForSink(profile, hyp)
      .map((route, routeIndex) => `    ${routeIndex + 1}. ${route.method} ${route.path} @ ${route.sourceFile}:${route.line} distance=${Math.abs(route.line - hyp.sinkLine)}`)
      .join("\n")
    const sourceLinks = (bundle?.sourceLinks ?? hyp.sourceLinks ?? []).slice(0, 5)
      .map((link, linkIndex) => `    ${linkIndex + 1}. score=${link.score} ${link.source.kind}:${link.source.paramName} @ ${rel(link.source.file)}:${link.source.line} ${link.reason}`)
      .join("\n")
    const dataflow = (bundle?.dataflow ?? hyp.dataflowResult)?.paths?.slice(0, 1).map((path) => {
      const edges = path.edges.slice(0, 8).map((edge) => `      - ${edge.kind} @ ${rel(edge.file)}:${edge.line} ${edge.code}`).join("\n")
      return `    ${path.sourceLabel} -> ${path.sinkLabel}\n${edges}`
    }).join("\n") || "    (no Joern path)"
    const route = bundle?.route ? `${bundle.route.method} ${bundle.route.path} @ ${bundle.route.sourceFile}:${bundle.route.line}` : "(no selected route)"
    return `${index + 1}. hypothesisId=${hyp.id}
   status before verification: ${hyp.status}
   category/severity: ${hyp.category}/${hyp.severity}
   sink: ${hyp.sinkPattern} @ ${rel(hyp.sinkFile)}:${hyp.sinkLine}
   sink code: ${hyp.sinkCode}
   origin: ${hyp.origin ?? "unknown"}
   description: ${hyp.description}
   prior note: ${hyp.resolutionNote ?? "(none)"}
   selected route: ${route}
   sink-file route candidates:
${sinkRoutes || "    (none)"}
   SourceAgent handoff:
${sourceLinks || "    (none)"}
   Joern/dataflow:
${dataflow}`
  }).join("\n\n")

  const deps = profile.dependencies
    .filter((dep) => /fastjson|hutool|jackson|freemarker|velocity|mybatis|spring|shiro|commons-fileupload|tomcat|redis/i.test(dep.name))
    .slice(0, 80)
    .map((dep) => `- ${dep.name}${dep.version ? ` ${dep.version}` : ""} (${dep.sourceFile})`)
    .join("\n")

  return `Grouped hypotheses for one semantic review batch:
${hypotheses}

Security-relevant dependencies:
${deps || "(none)"}
`
}

function routeCandidatesForSink(profile: ProjectProfile, hyp: Hypothesis): Array<{ method: string; path: string; sourceFile: string; line: number }> {
  return profile.routes
    .filter((route) => {
      const routeFile = route.sourceFile.startsWith("/") ? route.sourceFile : `${profile.root}/${route.sourceFile}`
      return hyp.sinkFile === routeFile || hyp.sinkFile.endsWith(route.sourceFile)
    })
    .filter((route) => route.line <= hyp.sinkLine)
    .sort((a, b) => Math.abs(a.line - hyp.sinkLine) - Math.abs(b.line - hyp.sinkLine))
    .slice(0, 5)
}

function formatPreloadedVerifierEvidence(profile: ProjectProfile, files: SourceFileCandidate[], maxChars: number): string {
  const chunks: string[] = []
  let total = 0
  for (const file of files) {
    const rel = file.file.startsWith(profile.root) ? relative(profile.root, file.file) : file.file
    const content = file.content.trim()
    if (!content) continue
    const header = `--- ${rel} (${content.length} chars) ---\n`
    const remaining = maxChars - total - header.length
    if (remaining <= 0) break
    const clipped = content.length > remaining
      ? `${content.slice(0, Math.max(0, remaining - 80))}\n/* clipped verifier evidence for token budget */`
      : content
    chunks.push(`${header}${clipped}`)
    total += header.length + clipped.length + 2
  }
  return chunks.join("\n\n")
}

export async function verifyHypothesisWithLLM(
  config: LLMConfig,
  profile: ProjectProfile,
  hypothesis: Hypothesis,
  bundle: EvidenceBundle | undefined,
  files: SourceFileCandidate[],
  outputDir?: string,
  cpgPath?: string,
  verifierChallenge?: string,
): Promise<VerifierVerdict | null> {
  const parsed = await runToolAssistedExtraction(config, profile, files, "verifier", SOURCE_AGENT_TIMEOUT, {
    outputDir,
    cpgPath,
    allowJoern: Boolean(cpgPath),
    verifierContext: verifierContext(profile, hypothesis, bundle),
    verifierChallenge,
    traceMeta: {
      hypothesisId: hypothesis.id,
      category: hypothesis.category,
      severity: hypothesis.severity,
      sinkFile: relative(profile.root, hypothesis.sinkFile),
      sinkLine: hypothesis.sinkLine,
      origin: hypothesis.origin ?? "unknown",
      statusBeforeVerifier: hypothesis.status,
    },
    minInspectedFiles: 0,
    maxToolSteps: 7,
  })
  const verdict = parsed ? parseVerifierVerdict(parsed) : null
  if (!verdict) return null
  if (verdict.checkedFiles.length === 0) {
    verdict.checkedFiles = [...new Set(files.map((file) => relative(profile.root, file.file)).slice(0, 12))]
  }
  return verdict
}

export async function verifyHypothesisBatchWithLLM(
  config: LLMConfig,
  profile: ProjectProfile,
  items: Array<{ hypothesis: Hypothesis; bundle?: EvidenceBundle }>,
  files: SourceFileCandidate[],
  outputDir?: string,
  cpgPath?: string,
): Promise<Map<string, VerifierVerdict>> {
  if (items.length === 0) return new Map()
  const parsed = await runToolAssistedExtraction(config, profile, files, "verifier", SOURCE_AGENT_TIMEOUT, {
    outputDir,
    cpgPath,
    allowJoern: Boolean(cpgPath),
    verifierBatch: true,
    verifierContext: verifierBatchContext(profile, items),
    traceMeta: {
      batchId: `verify-${items[0]!.hypothesis.id}`,
      hypothesisIds: items.map((item) => item.hypothesis.id),
      category: items[0]!.hypothesis.category,
      sinkFile: relative(profile.root, items[0]!.hypothesis.sinkFile),
      origin: "grouped-verifier",
    },
    minInspectedFiles: 0,
    maxToolSteps: 7,
  })
  const verdicts = parsed ? parseVerifierVerdicts(parsed) : new Map()
  for (const verdict of verdicts.values()) {
    if (verdict.checkedFiles.length === 0) {
      verdict.checkedFiles = [...new Set(files.map((file) => relative(profile.root, file.file)).slice(0, 12))]
    }
  }
  return verdicts
}

export interface HttpPocDraft {
  packets: string[]
  route?: string
  source?: string
  notes: string[]
}

export async function generateHttpPocWithLLM(
  config: LLMConfig,
  profile: ProjectProfile,
  hypothesis: Hypothesis,
  files: SourceFileCandidate[],
  pocContext: string,
  outputDir?: string,
): Promise<HttpPocDraft | null> {
  const parsed = await runToolAssistedExtraction(config, profile, files, "poc", SOURCE_AGENT_TIMEOUT, {
    outputDir,
    pocContext,
    traceMeta: {
      hypothesisId: hypothesis.id,
      category: hypothesis.category,
      severity: hypothesis.severity,
      sinkFile: relative(profile.root, hypothesis.sinkFile),
      sinkLine: hypothesis.sinkLine,
      agentTask: "http-poc",
    },
    minInspectedFiles: 0,
    maxToolSteps: 6,
  })
  if (!parsed) return null
  return parseHttpPocDraft(parsed, hypothesis.id)
}

function parseHttpPocDraft(parsed: unknown, hypothesisId: string): HttpPocDraft | null {
  const rows = collectRows(parsed, ["pocs", "poc", "results", "items", "packets", "requests"])
  const row = rows.find((item) => {
    if (!isRecord(item)) return false
    const id = firstString(item, ["hypothesisId", "id", "hypId"])
    return !id || id === hypothesisId
  })
  if (!isRecord(row)) return null
  const packets = stringArray(row.packets ?? row.pocPackets ?? row.httpPackets ?? row.requests ?? row.request ?? row.packet)
    .map((packet) => packet.trim())
    .filter((packet) => /^([A-Z]+)\s+\S+\s+HTTP\/1\.[01]/.test(packet))
  if (packets.length === 0) return null
  return {
    packets,
    route: firstString(row, ["route", "path", "endpoint"]),
    source: firstString(row, ["source", "trigger", "param", "parameter"]),
    notes: stringArray(row.notes ?? row.note ?? row.reason ?? row.explanation),
  }
}

export async function generateMarkdownReportWithLLM(
  config: LLMConfig,
  report: AuditReport,
): Promise<string | null> {
  const model = config.model ?? DEFAULT_MODELS[config.provider]
  console.log(`  [llm] report agent drafting full markdown via ${config.provider}/${model}...`)

  const highValue = new Set(["cmdi", "sqli", "path-traversal", "file-download", "file-upload", "upload", "ssti", "spel", "ognl", "expression", "template-injection"])
  const severityRank: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
  const trimContext = (value: string | undefined, limit: number): string | undefined => {
    if (!value) return undefined
    return value.length > limit ? `${value.slice(0, limit)}\n...[context truncated by ReportAgent input budget]` : value
  }
  const rankedHypotheses = report.hypotheses
    .filter((h) => h.status === "confirmed")
    .sort((a, b) => {
      const severity = (severityRank[a.severity] ?? 9) - (severityRank[b.severity] ?? 9)
      if (severity !== 0) return severity
      const category = (highValue.has(a.category) ? 0 : 1) - (highValue.has(b.category) ? 0 : 1)
      if (category !== 0) return category
      return `${a.sinkFile}:${a.sinkLine}`.localeCompare(`${b.sinkFile}:${b.sinkLine}`)
    })
  const hypotheses = rankedHypotheses.map((h, index) => {
    const bundle = report.evidenceBundles.find((item) => item.hypothesisId === h.id)
    const includeFullContext = h.status === "confirmed" || highValue.has(h.category) || index < 60
    const bundleSourceLinks = bundle?.sourceLinks ?? h.sourceLinks ?? []
    const selectedSource = bundle?.selectedSource
    const orderedSourceLinks = selectedSource
      ? [
        ...bundleSourceLinks.filter((link) =>
          link.source.id === selectedSource.id
            || (link.source.file === selectedSource.file && link.source.line === selectedSource.line && link.source.paramName === selectedSource.paramName)
        ),
        ...bundleSourceLinks.filter((link) =>
          link.source.id !== selectedSource.id
            && !(link.source.file === selectedSource.file && link.source.line === selectedSource.line && link.source.paramName === selectedSource.paramName)
        ),
      ]
      : bundleSourceLinks
    return {
      id: h.id,
      order: index + 1,
      status: h.status,
      severity: h.severity,
      category: h.category,
      description: h.description,
      sink: `${h.sinkPattern} @ ${h.sinkFile}:${h.sinkLine}`,
      sinkCode: h.sinkCode,
      resolutionNote: h.resolutionNote,
      verifier: bundle?.verifierVerdict ?? h.verifierVerdict,
      sourceLinks: orderedSourceLinks.slice(0, 3).map((link) => ({
        score: link.score,
        reason: link.reason,
        source: `${link.source.kind}:${link.source.paramName} @ ${link.source.file}:${link.source.line}`,
        code: link.source.code,
      })),
      omittedSourceLinks: Math.max(0, orderedSourceLinks.length - 3),
      dataflow: h.dataflowResult?.paths?.[0]?.edges?.map((edge) => `${edge.kind} ${edge.file}:${edge.line} ${edge.code}`) ?? [],
      codeContext: includeFullContext ? trimContext(bundle?.reportContext?.codeContext, 12_000) : undefined,
      chainText: trimContext(bundle?.reportContext?.chainText, 4_000),
      pocPackets: bundle?.reportContext?.pocPackets ?? [],
      route: bundle?.route,
    }
  })
  const allHypothesisIds = rankedHypotheses.map((h) => h.id)

  const system = `你是一个资深中文代码审计 ReportAgent。你要直接输出完整 Markdown 报告，不要 JSON，不要 HTML，不要解释你的思考过程。`
  const user = `请基于下面这些 Agent 已经读取和整理过的事实，自由组织一份中文代码审计 Markdown 报告。

写作要求：
- 不要套固定八股模板，但必须让安全工程师能直接复核。
- 只写“已确认 confirmed”的漏洞；未确认、待复查、追踪中、已排除的结果不要写入这份 AI 报告，它们会进入后端生成的“完整结果 Markdown”。
- 重点写命令执行、SQL 注入、文件下载/上传、路径遍历、表达式执行/SSTI/SpEL/OGNL 等能导致 RCE 或高影响的链路。
- 每个重要漏洞都要包含：漏洞代码、source 到 sink 的进入链路、关键文件路径和行号、可触发的 HTTP PoC 数据包。
- 必须覆盖“漏洞与证据上下文”数组里的每一条记录，报告中必须出现每个 Hypothesis ID；不允许使用“其余略”“...”“共 N 个不展开”代替逐条结果。
- 报告顺序按输入数组的 order 展开：已确认和严重/重要类别写在前面；后面的重复类型可以表格化，但每条仍必须有 ID、状态、风险、类别、文件行号、source/sink 摘要和 PoC/复核建议。
- 同一个 Sink 点关联多个 Source 时，只详细展开 sourceLinks 中前 3 个最高分入口；其余入口只写数量和简短摘要，不要重复展开相同 Sink 的完整代码块。
- 如果输出很长，优先保证所有 ID 都出现和证据完整，再考虑文字润色。
- 如果链路来自弱关联或没有完整数据流，明确写“候选/待复查”，不要伪造已验证结论。
- 如果多个 HTTP 包才能触发，按 0、1、2... 的顺序写。
- PoC 使用最小可复核 payload，命令执行只用 id/whoami 这类非破坏命令。
- 允许根据代码上下文自由发挥结构，尽量写得像人工审计报告，不要机械复述字段。

项目概况：
${JSON.stringify({
  name: report.profile.name,
  root: report.profile.root,
  language: report.profile.language,
  routes: report.profile.routes,
  highRiskDependencies: report.profile.dependencies.filter((d) => /fastjson|shiro|freemarker|velocity|mybatis|jackson|ognl|spel|spring/i.test(d.name)),
  stats: report.stats,
  observerWarnings: report.observer.warnings,
}, null, 2)}

Agent 协作产物：
${report.agentArtifacts.map((artifact) => `- [${artifact.kind}] ${artifact.agent}: ${artifact.title} — ${artifact.content}`).join("\n")}

完整性检查：
- 需要覆盖的 Hypothesis 总数：${allHypothesisIds.length}
- 必须出现在报告中的 Hypothesis ID：${allHypothesisIds.join(", ")}

漏洞与证据上下文（按重要性排序，必须全部覆盖）：
${JSON.stringify(hypotheses, null, 2)}
`

  const result = await callLLM(config, system, user, REPORT_AGENT_TIMEOUT)
  if (!result.ok) {
    console.log(`  [llm] full markdown report failed: ${result.timedOut ? "timeout" : result.text.slice(0, 120)}`)
    return null
  }
  return result.text
    .replace(/^```markdown\s*\n?/i, "")
    .replace(/^```\s*\n?/i, "")
    .replace(/```\s*$/i, "")
    .trim()
}

export async function checkLlmHealth(config: LLMConfig): Promise<LLMHealthResult> {
  const model = config.model ?? DEFAULT_MODELS[config.provider]
  const { url, protocol } = normalizeUrl(config)
  const headers: Record<string, string> = protocol === "anthropic"
    ? {
        "x-api-key": config.apiKey,
        "Authorization": `Bearer ${config.apiKey}`,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
      }
    : {
        "Authorization": `Bearer ${config.apiKey}`,
        "content-type": "application/json",
      }
  const body: Record<string, unknown> = protocol === "anthropic"
    ? {
        model,
        messages: [{ role: "user", content: "hi" }],
      }
    : {
        model,
        stream: false,
        messages: [{ role: "user", content: "hi" }],
      }
  applyTokenLimit(body, config, model, 1)

  let primary = await postLlmJson(url, headers, body, protocol, LLM_PREFLIGHT_TIMEOUT_MS, "availability")
  if (primary.ok) return { ok: true, provider: config.provider, model, url }
  const tokenLimitRetryBody = buildAlternateTokenLimitBody(body, primary.status, primary.rawError ?? primary.text)
  if (tokenLimitRetryBody) {
    const tokenLimitRetry = await postLlmJson(url, headers, tokenLimitRetryBody, protocol, LLM_PREFLIGHT_TIMEOUT_MS, "availability token-limit")
    if (tokenLimitRetry.ok) return { ok: true, provider: config.provider, model, url }
    primary = {
      ok: false,
      text: `${primary.text}; token-limit retry failed: ${tokenLimitRetry.text}`,
      timedOut: false,
      status: tokenLimitRetry.status ?? primary.status,
      rawError: tokenLimitRetry.rawError ?? primary.rawError,
    }
  }
  if (shouldRetryWithPromptBody(primary.status, primary.rawError ?? primary.text)) {
    const promptRetry = await postLlmJson(url, headers, buildPromptBody(model, "", "hi", body), "prompt", LLM_PREFLIGHT_TIMEOUT_MS, "availability prompt")
    if (promptRetry.ok) return { ok: true, provider: config.provider, model, url }
    primary = {
      ok: false,
      text: `${primary.text}; prompt retry failed: ${promptRetry.text}`,
      timedOut: false,
      status: promptRetry.status ?? primary.status,
      rawError: promptRetry.rawError ?? primary.rawError,
    }
  }
  const rawError = primary.rawError ?? primary.text
  return {
    ok: false,
    provider: config.provider,
    model,
    url,
    status: primary.status,
    error: sanitizeLlmError(rawError),
    reason: primary.timedOut ? "timeout" : classifyLlmFailure(primary.status, rawError),
  }
}

export async function assertLlmReady(config: LLMConfig): Promise<void> {
  const health = await checkLlmHealth(config)
  if (!health.ok) throw new Error(formatLlmHealthFailure(health))
}

export async function llmAvailable(config: LLMConfig): Promise<boolean> {
  return (await checkLlmHealth(config)).ok
}
