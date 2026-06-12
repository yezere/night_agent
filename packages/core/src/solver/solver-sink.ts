import { relative, resolve } from "node:path"
import { BaseSolver, type SolverContext } from "./base-solver.ts"
import { extractSinkEntriesWithLLM, refineSinkEntriesWithLLM, type LlmSinkEntry, type SourceFileCandidate } from "../llm/llm-runner.ts"
import { addEvent } from "../runtime/event-log.ts"
import { AuditWorkspace } from "../runtime/audit-workspace.ts"
import { readContextualFile } from "../utils/contextual-file.ts"
import type { AuditOptions, EvidenceOrigin, Hypothesis, ProjectProfile } from "../types/index.ts"
import { compareSeverity } from "../types/index.ts"
import { JAVA_SINK_CONTEXT_PATTERNS, JAVA_TEXT_SINK_HINTS, normalizeJavaSinkCategory, normalizeJavaSinkPattern } from "../scanner/java-web-hints.ts"
import { configuredAgentFileLimit, sortJavaAuditFiles } from "../scanner/file-priority.ts"

const DEFAULT_SINK_FILE_LIMIT = 220

function normalizeSinkPattern(rawPattern: string, code: string): string {
  return normalizeJavaSinkPattern(rawPattern, code)
}

function normalizeCategory(rawCategory: string, sinkPattern: string, code: string): string {
  return normalizeJavaSinkCategory(rawCategory, sinkPattern, code)
}

function absoluteFile(root: string, file: string): string {
  return file.startsWith("/") ? file : resolve(root, file)
}

function keyFor(file: string, line: number, pattern: string): string {
  return `${file}:${line}:${pattern.toLowerCase()}`
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

function looksLikeSafeFrameworkReturn(code: string): boolean {
  return /new\s+ResponseEntity\s*\(\s*(?:HttpStatus|headers|BeanValidators|task|[^,]+,\s*HttpStatus\.(?:OK|CREATED|NO_CONTENT|NOT_FOUND|BAD_REQUEST))/.test(code)
    || /^public\s+ResponseEntity<\?>\s+\w+\s*\(/.test(code)
}

function isSpecificTextScanSink(category: string, code: string): boolean {
  if (category === "xxe") {
    return /DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|TransformerFactory|SchemaFactory|SAXReader|Unmarshaller|\.parse\s*\(\s*(?:request|input|stream|reader|xml|file|path|source)/i.test(code)
  }
  if (category === "file-upload") {
    return /transferTo\s*\(|getOriginalFilename\s*\(|getFileMap\s*\(|getPart\s*\(|getParts\s*\(|\b(?:part|filePart|uploadPart)\s*\.write\s*\(|getSubmittedFileName\s*\(/i.test(code)
  }
  if (category === "file-download") {
    return /ServletOutputStream|OutputStream|InputStreamResource|ByteArrayResource|Files\.read|FileInputStream|ResponseEntity\s*<\s*(?:byte\[\]|Resource)/i.test(code)
  }
  if (category === "path-traversal") {
    return /new\s+File\s*\(\s*(?:path|file|filename|name|request|param|dir)|Paths\.get\s*\(\s*(?:path|file|filename|name|request|param|dir)|Files\.(?:read|copy|write|newInputStream|newOutputStream)\s*\(|getRequestDispatcher\s*\(|\.forward\s*\(|\.include\s*\(|pageContext\.forward/i.test(code)
  }
  if (category === "redirect") {
    return /sendRedirect\s*\(|setHeader\s*\(\s*["']Location["']|addHeader\s*\(\s*["']Location["']/i.test(code)
  }
  if (category === "xss") {
    return /(<%=\s*request\.|request\.|getParameter\s*\(|getHeader\s*\(|\$\{\s*(?:param|header|cookie)\b|response\.getWriter\s*\(\)|out\.(?:print|println|write)\s*\(|JspWriter)/i.test(code)
  }
  return true
}

export class SinkAgent extends BaseSolver {
  private options: AuditOptions
  private profile: ProjectProfile
  private workspace: AuditWorkspace
  private focusFiles: string[]

  constructor(ctx: SolverContext, options: AuditOptions, profile: ProjectProfile, workspace: AuditWorkspace, focusFiles: string[] = []) {
    super(ctx)
    this.options = options
    this.profile = profile
    this.workspace = workspace
    this.focusFiles = focusFiles.map((file) => file.startsWith("/") ? file : resolve(this.profile.root, file))
  }

  async start(): Promise<void> {
    this.setStatus("busy")
    try {
      const hypotheses = await this.scanSinks()
      for (const hyp of hypotheses) {
        this.emit("hypothesis:created", hyp)
      }
    } finally {
      this.setStatus("idle")
    }
  }

  async stop(): Promise<void> {
    this.setStatus("idle")
  }

  private async scanSinks(): Promise<Hypothesis[]> {
    if (!this.options.llmConfig) {
      throw new Error("SinkAgent requires an AI config")
    }

    const outputDir = resolve(this.options.outputDir)
    const files = await this.loadCandidateFiles()
    this.log(`AI SinkAgent reading ${files.length} candidate file(s)`)
    addEvent("bootstrap", "info", "SinkAgent reading candidate files", `${files.length} file(s)`)

    const hypotheses: Hypothesis[] = []
    const seen = new Set(this.workspace.getHypotheses().map((hyp) =>
      keyFor(absoluteFile(this.profile.root, hyp.sinkFile), hyp.sinkLine, normalizeSinkPattern(hyp.sinkPattern, hyp.sinkCode))
    ))

    let aiSinks: LlmSinkEntry[] = []
    try {
      aiSinks = await extractSinkEntriesWithLLM(this.options.llmConfig, this.profile, files, outputDir)
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err)
      this.log(`AI SinkAgent extraction warning: ${msg}; using file-read pre-scan recovery`)
      addEvent("bootstrap", "warn", "SinkAgent AI output invalid", msg)
    }
    for (const sink of aiSinks) {
      const hyp = this.hypothesisFromAiSink(sink, seen, "ai-first")
      if (hyp) hypotheses.push(hyp)
    }
    this.log(`AI SinkAgent submitted ${aiSinks.length} sink candidate(s), accepted ${hypotheses.length}`)
    addEvent("bootstrap", "success", "SinkAgent AI sink extraction completed", `${aiSinks.length} candidate sink(s)`)

    const preScanSinks = this.rankTextScanSinks(this.extractTextScanSinks(files)).slice(0, 260)
    let refinedSinks: LlmSinkEntry[] = []
    if (preScanSinks.length > 0) {
      for (const batch of buildSinkRefineBatches(preScanSinks)) {
        try {
          this.log(`SinkAgent second-pass AI refinement bucket=${batch.name} from ${batch.sinks.length} pre-scan hint(s)`)
          const batchRefined = await refineSinkEntriesWithLLM(
            this.options.llmConfig,
            this.profile,
            files,
            [...aiSinks, ...refinedSinks],
            batch.sinks,
            outputDir,
          )
          refinedSinks.push(...batchRefined)
          let refinedAdded = 0
          for (const sink of batchRefined) {
            const hyp = this.hypothesisFromAiSink(sink, seen, "ai-refine")
            if (!hyp) continue
            hypotheses.push(hyp)
            refinedAdded++
          }
          if (refinedAdded > 0) this.log(`SinkAgent second-pass AI bucket=${batch.name} accepted ${refinedAdded} additional sink candidate(s)`)
        } catch (err) {
          const msg = err instanceof Error ? err.message : String(err)
          this.log(`SinkAgent second-pass AI refinement bucket=${batch.name} skipped: ${msg}`)
          addEvent("bootstrap", "warn", "SinkAgent second-pass refinement skipped", `${batch.name}: ${msg}`)
        }
      }
    }

    let preScanAdded = 0
    for (const sink of preScanSinks) {
      const hyp = this.hypothesisFromAiSink(sink, seen, "pre-scan")
      if (!hyp) continue
      hypotheses.push(hyp)
      preScanAdded++
    }
    if (preScanAdded > 0) {
      this.log(`SinkAgent file-read pre-scan supplemented ${preScanAdded} sink candidate(s)`)
      addEvent("bootstrap", "warn", "SinkAgent supplemented sinks from file-read pre-scan", `${preScanAdded} candidate sink(s)`)
    }
    this.log(`SinkAgent merged ${hypotheses.length} sink hypothesis/hypotheses after AI + pre-scan`)

    if (hypotheses.length === 0) {
      this.log("SinkAgent produced no sink hypotheses")
      addEvent("bootstrap", "warn", "SinkAgent produced no sink hypotheses", "No AI or file-read pre-scan sink candidates were accepted")
    }

    hypotheses.sort((a, b) => {
      const aJava = a.sinkFile.endsWith(".java") ? 0 : 1
      const bJava = b.sinkFile.endsWith(".java") ? 0 : 1
      if (aJava !== bJava) return aJava - bJava
      return compareSeverity(a.severity, b.severity)
    })

    if (this.options.maxHypotheses && hypotheses.length > this.options.maxHypotheses) {
      const overflow = hypotheses.slice(this.options.maxHypotheses)
      for (const hyp of overflow) {
        this.workspace.markCandidateDeferred(hyp.id, `deferred by --max-hypotheses=${this.options.maxHypotheses}`)
      }
      addEvent("bootstrap", "warn", "SinkAgent queue capped", `${overflow.length} lower-priority sink(s) deferred`)
    }

    return hypotheses.slice(0, this.options.maxHypotheses ?? hypotheses.length)
  }

  private extractTextScanSinks(files: SourceFileCandidate[]): LlmSinkEntry[] {
    const sinks: LlmSinkEntry[] = []
    for (const file of files) {
      const lines = file.content.split("\n")
      lines.forEach((line, index) => {
        const lineNo = markedLineNumber(line, index + 1)
        const code = stripLineMarker(line.trim())
        if (!code || code.startsWith("import ")) return
        if (looksLikeSafeFrameworkReturn(code)) return
        for (const rule of JAVA_TEXT_SINK_HINTS) {
          if (!rule.pattern.test(code)) continue
          if (!isSpecificTextScanSink(rule.category, code)) continue
          sinks.push({
            category: rule.category,
            severity: rule.severity,
            sinkPattern: rule.sinkPattern,
            file: file.file,
            line: lineNo,
            code,
            description: rule.description,
            confidence: "medium",
            reason: "Recovered from SinkAgent file-read pre-scan for review",
          })
          break
        }
      })
    }
    return sinks
  }

  private rankTextScanSinks(sinks: LlmSinkEntry[]): LlmSinkEntry[] {
    const categoryRank: Record<string, number> = {
      cmdi: 0,
      spel: 1,
      ognl: 1,
      ssti: 2,
      sqli: 3,
      deser: 4,
      jndi: 5,
      ssrf: 6,
      redirect: 7,
      xss: 8,
      "file-upload": 9,
      "file-download": 10,
      "path-traversal": 11,
      xxe: 12,
    }
    return [...sinks].sort((a, b) => {
      const rank = (categoryRank[a.category] ?? 99) - (categoryRank[b.category] ?? 99)
      if (rank !== 0) return rank
      return a.file.localeCompare(b.file) || a.line - b.line
    })
  }

  private hypothesisFromAiSink(sink: LlmSinkEntry, seen: Set<string>, origin: EvidenceOrigin): Hypothesis | null {
    const file = absoluteFile(this.profile.root, sink.file)
    const pattern = normalizeSinkPattern(sink.sinkPattern, sink.code)
    const category = normalizeCategory(sink.category, pattern, sink.code)
    const key = keyFor(file, sink.line, pattern)
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
      resolutionNote: sink.reason ? `AI SinkAgent: ${sink.reason}${sink.confidence ? ` (confidence=${sink.confidence})` : ""}` : undefined,
      origin,
    })
  }

  private async loadCandidateFiles(): Promise<SourceFileCandidate[]> {
    const candidateFiles = new Set<string>()

    if (this.focusFiles.length > 0) {
      for (const file of this.focusFiles) candidateFiles.add(file)
      this.log(`SinkAgent focused coverage rescan scope=${candidateFiles.size} file(s)`)
    } else {
      for (const route of this.profile.routes) {
        candidateFiles.add(resolve(this.profile.root, route.sourceFile))
      }
      for (const file of this.profile.highRiskFiles) {
        candidateFiles.add(resolve(this.profile.root, file))
      }

      const globs = [
        "**/*.java",
        "**/*.xml",
        "**/*.jsp",
        "**/*.properties",
      ]
      for (const pattern of globs) {
        for await (const entry of new Bun.Glob(pattern).scan({ cwd: this.profile.root, dot: false })) {
          if (/\/(\.night-agent|\.night_agent|target|build|dist|output-audit|node_modules)\//.test(`/${entry}`)) continue
          if (!this.shouldReadFile(entry)) continue
          candidateFiles.add(resolve(this.profile.root, entry))
        }
      }
    }

    const orderedFiles = sortJavaAuditFiles(this.profile.root, candidateFiles)
      .slice(0, configuredAgentFileLimit("NIGHT_AGENT_SINK_FILE_LIMIT", DEFAULT_SINK_FILE_LIMIT, 50, 800))

    const files: SourceFileCandidate[] = []
    for (const file of orderedFiles) {
      try {
        const content = await readContextualFile(file, {
          patterns: JAVA_SINK_CONTEXT_PATTERNS,
          maxWholeChars: 180_000,
          maxWindowChars: 90_000,
          windowRadius: 22,
        })
        if (content) files.push({ file, content })
      } catch {
        // skip unreadable files
      }
    }
    return files
  }

  private shouldReadFile(file: string): boolean {
    if (this.profile.fileStats.reduce((sum, stat) => sum + stat.count, 0) <= 80) return true
    return /\.(jsp|jspx)$/i.test(file)
      || /controller|action|servlet|filter|listener|handler|endpoint|service|dao|mapper|repository|util|security|auth|upload|download|file|template|report|json|xml|exec|command|process|sql|jdbc|jndi|deser|serialize|route|api|web|redirect|response/i.test(file)
      || this.profile.routes.some((route) => file === route.sourceFile || file.endsWith(route.sourceFile))
      || this.profile.highRiskFiles.some((risk) => file === risk || file.endsWith(relative(this.profile.root, risk)))
  }
}

function buildSinkRefineBatches(sinks: LlmSinkEntry[]): Array<{ name: string; sinks: LlmSinkEntry[] }> {
  if (sinks.length <= 100) return [{ name: "all", sinks }]
  const buckets = new Map<string, LlmSinkEntry[]>()
  for (const sink of sinks) {
    const name = sinkRefineBucket(sink)
    const entries = buckets.get(name) ?? []
    entries.push(sink)
    buckets.set(name, entries)
  }
  return [
    "sqli-mybatis-hql",
    "file-upload",
    "file-download-path",
    "servlet-jsp-response",
    "expression-template",
    "deser-xml-jndi-ssrf",
    "other",
  ].map((name) => ({ name, sinks: (buckets.get(name) ?? []).slice(0, 120) }))
    .filter((batch) => batch.sinks.length > 0)
}

function sinkRefineBucket(sink: LlmSinkEntry): string {
  const text = `${sink.category} ${sink.sinkPattern} ${sink.file} ${sink.code} ${sink.description}`.toLowerCase()
  if (/sqli|sql|mybatis|hql|statement|executequery|executeupdate|\$\{/.test(text)) return "sqli-mybatis-hql"
  if (/file-upload|multipart|transferto|getoriginalfilename|getsubmittedfilename|part\.write/.test(text)) return "file-upload"
  if (/file-download|path-traversal|fileinputstream|files\.read|paths\.get|new\s+file|getrequestdispatcher|forward|include/.test(text)) return "file-download-path"
  if (/xss|redirect|sendredirect|response\.getwriter|jspwriter|out\.print|<%=|location/.test(text)) return "servlet-jsp-response"
  if (/ssti|template|spel|ognl|expression|parseexpression|process\s*\(/.test(text)) return "expression-template"
  if (/deser|xxe|jndi|ssrf|parseobject|readobject|documentbuilder|saxparser|unmarshaller|initialcontext|openconnection|new url/.test(text)) return "deser-xml-jndi-ssrf"
  return "other"
}
