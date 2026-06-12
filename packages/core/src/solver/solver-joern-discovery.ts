import { relative, resolve } from "node:path"
import { BaseSolver, type SolverContext } from "./base-solver.ts"
import { discoverSourceSinkWithJoernLLM, type LlmSinkEntry, type SourceFileCandidate } from "../llm/llm-runner.ts"
import { readContextualFile } from "../utils/contextual-file.ts"
import { addEvent } from "../runtime/event-log.ts"
import { AuditWorkspace } from "../runtime/audit-workspace.ts"
import type { AuditOptions, EvidenceOrigin, Hypothesis, ProjectProfile, SourceEntry } from "../types/index.ts"

const DISCOVERY_CONTEXT_PATTERNS = [
  /@RequestMapping|@GetMapping|@PostMapping|@PutMapping|@DeleteMapping|@PatchMapping/,
  /@RequestParam|@RequestBody|@PathVariable|@RequestHeader|@CookieValue|HttpServletRequest|MultipartFile/,
  /getParameter|getHeader|getInputStream|getReader|getPart|getParts|getOutputStream/,
  /Runtime\.getRuntime|ProcessBuilder|executeSql|findHql|createQuery|Statement|\$\{|#\{/,
  /new\s+File|FileUtil|Paths\.get|Files\.|FileInputStream|FileOutputStream|ServletOutputStream|download|upload/i,
  /Template|\.process|parseExpression|Ognl|parseObject|readObject|DocumentBuilder|SAXParser|InitialContext|lookup/i,
]

export interface JoernDiscoverySummary {
  addedSources: number
  addedSinks: number
  rawSources: number
  rawSinks: number
}

export class JoernDiscoveryAgent extends BaseSolver {
  private options: AuditOptions
  private profile: ProjectProfile
  private workspace: AuditWorkspace
  private sources: SourceEntry[]
  private cpgPath?: string
  private summary: JoernDiscoverySummary = { addedSources: 0, addedSinks: 0, rawSources: 0, rawSinks: 0 }
  private discoveredSources: SourceEntry[] = []
  private discoveredHypotheses: Hypothesis[] = []

  constructor(ctx: SolverContext, options: AuditOptions, profile: ProjectProfile, workspace: AuditWorkspace, sources: SourceEntry[], cpgPath?: string) {
    super(ctx)
    this.options = options
    this.profile = profile
    this.workspace = workspace
    this.sources = sources
    this.cpgPath = cpgPath
  }

  async start(): Promise<void> {
    this.setStatus("busy")
    try {
      this.summary = await this.discover()
      for (const source of this.discoveredSources) this.emit("source:extracted", source)
      for (const hyp of this.discoveredHypotheses) this.emit("hypothesis:created", hyp)
    } finally {
      this.setStatus("idle")
    }
  }

  async stop(): Promise<void> {
    this.setStatus("idle")
  }

  getSummary(): JoernDiscoverySummary {
    return { ...this.summary }
  }

  getSources(): SourceEntry[] {
    return this.discoveredSources.map((source) => ({ ...source }))
  }

  private async discover(): Promise<JoernDiscoverySummary> {
    if (!this.options.llmConfig || this.options.runJoern === false || !this.cpgPath) {
      this.log("JoernDiscoveryAgent skipped: AI config or CPG unavailable")
      return this.summary
    }

    const files = await this.loadDiscoveryFiles()
    if (files.length === 0) {
      this.log("JoernDiscoveryAgent found no readable context files")
      return this.summary
    }

    const existingSinks = this.workspace.getHypotheses()
    this.log(`JoernDiscoveryAgent inspecting CPG with ${this.sources.length} source(s), ${existingSinks.length} sink(s), ${files.length} context file(s)`)
    addEvent("explore", "info", "JoernDiscoveryAgent started", `${this.sources.length} source(s), ${existingSinks.length} sink(s)`)

    const result = await discoverSourceSinkWithJoernLLM(
      this.options.llmConfig,
      this.profile,
      files,
      this.sources,
      existingSinks,
      this.options.outputDir,
      this.cpgPath,
    )
    const summary: JoernDiscoverySummary = {
      rawSources: result.sources.length,
      rawSinks: result.sinks.length,
      addedSources: 0,
      addedSinks: 0,
    }

    const sourceSeen = new Set(this.sources.map(sourceKey))
    result.sources.forEach((source, index) => {
      const item: SourceEntry = {
        ...source,
        file: absoluteFile(this.profile.root, source.file),
        id: `joern-src-${Date.now().toString(36)}-${index}`,
        origin: "joern-ai",
      }
      const key = sourceKey(item)
      if (sourceSeen.has(key)) return
      sourceSeen.add(key)
      this.discoveredSources.push(item)
      summary.addedSources++
      this.log(`discovered source ${item.kind}:${item.paramName} @ ${relative(this.profile.root, item.file)}:${item.line}`)
    })

    const sinkSeen = new Set(existingSinks.map((hyp) => hypothesisKey(hyp.sinkFile, hyp.sinkLine, hyp.sinkPattern)))
    for (const sink of result.sinks) {
      const hyp = this.hypothesisFromDiscoverySink(sink, sinkSeen, "joern-ai")
      if (!hyp) continue
      this.discoveredHypotheses.push(hyp)
      summary.addedSinks++
      this.log(`discovered sink ${hyp.category}/${hyp.sinkPattern} @ ${relative(this.profile.root, hyp.sinkFile)}:${hyp.sinkLine}`)
    }

    addEvent("explore", summary.addedSinks > 0 || summary.addedSources > 0 ? "success" : "info", "JoernDiscoveryAgent completed", `${summary.addedSources} source(s), ${summary.addedSinks} sink(s) added`)
    return summary
  }

  private hypothesisFromDiscoverySink(sink: LlmSinkEntry, seen: Set<string>, origin: EvidenceOrigin): Hypothesis | null {
    const file = absoluteFile(this.profile.root, sink.file)
    const pattern = normalizeSinkPattern(sink.sinkPattern, sink.code)
    const category = normalizeCategory(sink.category, pattern, sink.code)
    const key = hypothesisKey(file, sink.line, pattern)
    if (seen.has(key)) return null
    seen.add(key)

    return this.workspace.addHypothesis({
      description: `[${pattern}] ${sink.description} at ${file}:${sink.line}`,
      severity: sink.severity,
      category,
      sinkFile: file,
      sinkLine: sink.line,
      sinkPattern: pattern,
      sinkCode: sink.code,
      resolutionNote: `JoernDiscoveryAgent: ${sink.reason ?? "AI/CPG discovered candidate"}${sink.confidence ? ` (confidence=${sink.confidence})` : ""}`,
      origin,
    })
  }

  private async loadDiscoveryFiles(): Promise<SourceFileCandidate[]> {
    const candidates = new Set<string>()
    for (const route of this.profile.routes.slice(0, 160)) candidates.add(resolve(this.profile.root, route.sourceFile))
    for (const file of this.profile.highRiskFiles.slice(0, 120)) candidates.add(resolve(this.profile.root, file))
    for (const hyp of this.workspace.getHypotheses().slice(0, 160)) candidates.add(hyp.sinkFile)
    for (const source of this.sources.slice(0, 160)) candidates.add(source.file)

    const files: SourceFileCandidate[] = []
    for (const file of [...candidates].slice(0, 120)) {
      const absolute = absoluteFile(this.profile.root, file)
      try {
        const content = await readContextualFile(absolute, {
          patterns: DISCOVERY_CONTEXT_PATTERNS,
          maxWholeChars: 180_000,
          maxWindowChars: 90_000,
          windowRadius: 24,
        })
        if (content) files.push({ file: absolute, content })
      } catch {
        // Joern tools can still inspect CPG even when a file read fails.
      }
    }
    return files
  }
}

function absoluteFile(root: string, file: string): string {
  return file.startsWith("/") ? file : resolve(root, file)
}

function sourceKey(source: Pick<SourceEntry, "file" | "kind" | "paramName" | "line">): string {
  return `${source.file}:${source.kind}:${source.paramName}:${source.line}`
}

function hypothesisKey(file: string, line: number, pattern: string): string {
  return `${file}:${line}:${pattern.toLowerCase()}`
}

function normalizeSinkPattern(rawPattern: string, code: string): string {
  const text = `${rawPattern} ${code}`
  if (/Runtime\.getRuntime\(\)\.exec|Runtime\.exec|\.exec\s*\(/i.test(text)) return "Runtime.exec"
  if (/ProcessBuilder/i.test(text)) return "ProcessBuilder"
  if (/ObjectInputStream|readObject\s*\(/i.test(text)) return "ObjectInputStream.readObject"
  if (/JSON\.parse|parseObject|parseArray|fastjson/i.test(text)) return "fastjson.parse"
  if (/ObjectMapper|readValue\s*\(/i.test(text)) return "ObjectMapper.readValue"
  if (/Statement|\.execute(Query|Update)?\s*\(|stmt\.execute|findHql|executeSql|createQuery/i.test(text)) return "Statement.execute"
  if (/new\s+URL\s*\(|openConnection\s*\(|RestTemplate|HttpClient|network-request/i.test(text)) return "network-request"
  if (/MultipartFile|transferTo\s*\(|getOriginalFilename|getFileMap/i.test(text)) return "file-upload"
  if (/Files\.read|FileInputStream|ServletOutputStream|OutputStream|ResponseEntity|download|getOutputStream/i.test(text)) return "file-download"
  if (/FileUtil\.(?:file|exist|ls|del|read|readBytes|readUtf8String|write)|new\s+File\s*\(|Paths\.get|Files\./i.test(text)) return "file-path"
  if (/DocumentBuilder|SAXParser|Unmarshaller|\.parse\s*\(/i.test(text) && /xml|xxe/i.test(text)) return "xml-parse"
  if (/Template|\.process\s*\(/i.test(text)) return "Template.process"
  if (/SpelExpressionParser|parseExpression/i.test(text)) return "SpEL.parseExpression"
  if (/Ognl|ognl/i.test(text)) return "OGNL"
  if (/InitialContext|lookup\s*\(|ldap:|rmi:/i.test(text)) return "jndi-lookup"
  return rawPattern || "unknown"
}

function normalizeCategory(rawCategory: string, sinkPattern: string, code: string): string {
  const text = `${rawCategory} ${sinkPattern} ${code}`
  if (/Runtime\.exec|ProcessBuilder|cmdi|command|\.exec\s*\(/i.test(text)) return "cmdi"
  if (/ObjectInputStream|readObject|fastjson|ObjectMapper|readValue|parseObject|parseArray|deser/i.test(text)) return "deser"
  if (/Statement\.execute|\.execute(Query|Update)?\s*\(|stmt\.execute|findHql|executeSql|createQuery|sqli|sql/i.test(text)) return "sqli"
  if (/network-request|new\s+URL\s*\(|openConnection|RestTemplate|HttpClient|ssrf/i.test(text)) return "ssrf"
  if (/file-upload|MultipartFile|transferTo|getOriginalFilename|getFileMap|upload/i.test(text)) return "file-upload"
  if (/file-download|download|getOutputStream|Files\.read|FileInputStream|ResponseEntity/i.test(text)) return "file-download"
  if (/path-traversal|file-path|FileUtil\.(?:file|exist|ls|del|read|write)|new\s+File\s*\(|Paths\.get|Files\./i.test(text)) return "path-traversal"
  if (/xml-parse|DocumentBuilder|SAXParser|Unmarshaller|xxe/i.test(text)) return "xxe"
  if (/Template\.process|\.process\s*\(|ssti|template/i.test(text)) return "ssti"
  if (/SpEL|parseExpression|spel|expression/i.test(text)) return "spel"
  if (/OGNL|ognl/i.test(text)) return "ognl"
  if (/jndi|InitialContext|lookup\s*\(/i.test(text)) return "jndi"
  return rawCategory || "other"
}
