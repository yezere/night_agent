import { relative, resolve } from "node:path"
import { BaseSolver, type SolverContext } from "./base-solver.ts"
import { extractSourceEntriesWithLLM, refineSourceEntriesWithLLM } from "../llm/llm-runner.ts"
import { readContextualFile } from "../utils/contextual-file.ts"
import { addEvent } from "../runtime/event-log.ts"
import type { AuditOptions, ProjectProfile, SourceEntry } from "../types/index.ts"
import { JAVA_SOURCE_CONTEXT_PATTERNS } from "../scanner/java-web-hints.ts"
import { configuredAgentFileLimit, sortJavaAuditFiles } from "../scanner/file-priority.ts"

const DEFAULT_SOURCE_FILE_LIMIT = 180

export class SolverReader extends BaseSolver {
  private targetPath: string
  private profile: ProjectProfile
  private options: AuditOptions
  private focusFiles: string[]

  constructor(ctx: SolverContext, targetPath: string, profile: ProjectProfile, options: AuditOptions, focusFiles: string[] = []) {
    super(ctx)
    this.targetPath = resolve(targetPath)
    this.profile = profile
    this.options = options
    this.focusFiles = focusFiles.map((file) => file.startsWith("/") ? file : resolve(this.profile.root, file))
  }

  async start(): Promise<void> {
    this.setStatus("busy")
    try {
      const sources = await this.extractSources()
      for (const source of sources) {
        this.emit("source:extracted", source)
      }
      this.logSourceHypothesisCoverage(sources)
    } finally {
      this.setStatus("idle")
    }
  }

  async stop(): Promise<void> {
    this.setStatus("idle")
  }

  private async extractSources(): Promise<SourceEntry[]> {
    if (!this.options.llmConfig) {
      throw new Error("SourceAgent requires an AI config; rule-based source extraction has been removed")
    }

    this.log(`AI SourceAgent reading project files from ${this.targetPath}...`)
    const files = await this.loadCandidateFiles()
    if (files.length === 0) {
      this.log("SourceAgent found no readable candidate files")
      return []
    }

    this.log(`source agent reviewing ${files.length} candidate file(s)`)
    let semantic: Array<Omit<SourceEntry, "id">> = []
    try {
      semantic = await extractSourceEntriesWithLLM(this.options.llmConfig, this.profile, files, this.options.outputDir)
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err)
      this.log(`AI SourceAgent extraction warning: ${msg}; using file-read pre-scan recovery`)
      addEvent("bootstrap", "warn", "SourceAgent AI output invalid", msg)
    }

    const recovered = this.extractTextScanSources(files)
    this.log(`AI SourceAgent submitted ${semantic.length} source candidate(s)`)
    let refined: Array<Omit<SourceEntry, "id">> = []
    if (recovered.length > 0) {
      for (const batch of buildSourceRefineBatches(recovered)) {
        try {
          this.log(`SourceAgent second-pass AI refinement bucket=${batch.name} from ${batch.sources.length} pre-scan hint(s)`)
          const batchRefined = await refineSourceEntriesWithLLM(
            this.options.llmConfig,
            this.profile,
            files,
            [...semantic, ...refined],
            batch.sources,
            this.options.outputDir,
          )
          refined.push(...batchRefined)
          if (batchRefined.length > 0) this.log(`SourceAgent second-pass AI bucket=${batch.name} submitted ${batchRefined.length} additional source candidate(s)`)
        } catch (err) {
          const msg = err instanceof Error ? err.message : String(err)
          this.log(`SourceAgent second-pass AI refinement bucket=${batch.name} skipped: ${msg}`)
          addEvent("bootstrap", "warn", "SourceAgent second-pass refinement skipped", `${batch.name}: ${msg}`)
        }
      }
    }

    const merged = [
      ...semantic.map((source) => ({ ...source, origin: "ai-first" as const })),
      ...refined.map((source) => ({ ...source, origin: "ai-refine" as const })),
      ...recovered.map((source) => ({ ...source, origin: "pre-scan" as const })),
    ]
    const sources = this.deduplicateSources(merged.map((source, index) => ({ ...source, id: `src-${index}` })))
    if (semantic.length === 0 && recovered.length > 0) {
      this.log(`SourceAgent file-read pre-scan recovered ${recovered.length} source candidate(s)`)
      addEvent("bootstrap", "warn", "SourceAgent recovered sources from file-read pre-scan", `${recovered.length} candidate source(s)`)
    } else if (recovered.length > 0) {
      this.log(`SourceAgent file-read pre-scan supplemented ${recovered.length} source candidate(s)`)
    }
    this.log(`SourceAgent merged ${sources.length} source(s) after AI + pre-scan`)
    return sources.map((source, index) => ({ ...source, id: `src-${index}` }))
  }

  private async loadCandidateFiles(): Promise<Array<{ file: string; content: string }>> {
    const candidateFiles = new Set<string>()

    if (this.focusFiles.length > 0) {
      for (const file of this.focusFiles) candidateFiles.add(file)
      this.log(`SourceAgent focused coverage rescan scope=${candidateFiles.size} file(s)`)
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
      .slice(0, configuredAgentFileLimit("NIGHT_AGENT_SOURCE_FILE_LIMIT", DEFAULT_SOURCE_FILE_LIMIT, 40, 600))

    const files: Array<{ file: string; content: string }> = []
    for (const file of orderedFiles) {
      try {
        const content = await readContextualFile(file, {
          patterns: JAVA_SOURCE_CONTEXT_PATTERNS,
          maxWholeChars: 180_000,
          maxWindowChars: 90_000,
          windowRadius: 22,
        })
        if (content) files.push({ file, content })
      } catch {
        // skip unreadable candidate
      }
    }
    return files
  }

  private shouldReadFile(file: string): boolean {
    if (this.profile.fileStats.reduce((sum, stat) => sum + stat.count, 0) <= 80) return true
    return /\.(jsp|jspx)$/i.test(file)
      || /controller|action|servlet|filter|listener|handler|endpoint|route|upload|download|api|web|request|response|auth|login|security|gateway|interceptor|advice|service|dao|mapper|repository|deserialize|json|xml|file|template|report/i.test(file)
      || this.profile.routes.some((route) => file === route.sourceFile || file.endsWith(route.sourceFile))
      || this.profile.highRiskFiles.some((risk) => {
        const rel = risk.startsWith("/") ? relative(this.profile.root, risk) : risk
        return file === rel || file.endsWith(rel)
      })
  }

  private deduplicateSources(sources: SourceEntry[]): SourceEntry[] {
    const byKey = new Map<string, SourceEntry>()
    for (const source of sources) {
      byKey.set(`${source.file}:${source.kind}:${source.paramName}:${source.line}`, source)
    }
    return [...byKey.values()]
  }

  private extractTextScanSources(files: Array<{ file: string; content: string }>): Array<Omit<SourceEntry, "id">> {
    const sources: Array<Omit<SourceEntry, "id">> = []

    for (const file of files) {
      const lines = file.content.split("\n")
      lines.forEach((line, index) => {
        const lineNo = markedLineNumber(line, index + 1)
        const code = stripLineMarker(line.trim())
        if (!code || code.startsWith("import ")) return

        const annotationKind = annotatedSourceKind(code)
        if (annotationKind) {
          sources.push({
            kind: annotationKind,
            paramName: annotatedParamName(code) || "unknown",
            file: file.file,
            line: lineNo,
            code,
            methodName: methodNameForFile(file.file, lines, index),
            className: classNameForFile(file.file, lines, index),
          })
          return
        }

        const servletRequestParam = servletRequestSource(code)
        if (servletRequestParam) {
          sources.push({
            kind: servletRequestParam.kind,
            paramName: servletRequestParam.paramName,
            file: file.file,
            line: lineNo,
            code,
            methodName: methodNameForFile(file.file, lines, index),
            className: classNameForFile(file.file, lines, index),
          })
        }

        const requestCall = requestApiSource(code)
        if (requestCall) {
          sources.push({
            kind: requestCall.kind,
            paramName: requestCall.paramName,
            file: file.file,
            line: lineNo,
            code,
            methodName: methodNameForFile(file.file, lines, index),
            className: classNameForFile(file.file, lines, index),
          })
        }

        for (const jspSource of jspImplicitSources(code)) {
          sources.push({
            kind: jspSource.kind,
            paramName: jspSource.paramName,
            file: file.file,
            line: lineNo,
            code,
            methodName: methodNameForFile(file.file, lines, index),
            className: classNameForFile(file.file, lines, index),
          })
        }
      })
    }

    return sources.slice(0, 400)
  }

  private logSourceHypothesisCoverage(sources: SourceEntry[]): void {
    const state = this.getSharedState()
    const hypotheses = state.stats.totalHypotheses > 0 ? state.stats.totalHypotheses : 0
    const sourceFiles = new Set(sources.map((source) => source.file))
    this.log(`source extraction produced ${sourceFiles.size} source-bearing file(s); sink association will be checked by Observer (${hypotheses} current hypotheses)`)
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

function annotatedSourceKind(code: string): SourceEntry["kind"] | null {
  if (/@RequestBody\b|MultipartFile\b|FileItem\b|Part\s+\w+/i.test(code)) return "body"
  if (/@RequestHeader\b/i.test(code)) return "header"
  if (/@CookieValue\b/i.test(code)) return "cookie"
  if (/@PathVariable\b/i.test(code)) return "pathvar"
  if (/@RequestParam\b|@ModelAttribute\b/i.test(code)) return "param"
  return null
}

function annotatedParamName(code: string): string {
  const annotationValue = code.match(/@(RequestParam|RequestBody|PathVariable|RequestHeader|CookieValue|ModelAttribute)\s*\(\s*(?:value\s*=\s*|name\s*=\s*)?["']([^"']+)["']/i)?.[2]
  if (annotationValue) return annotationValue

  const annotationParam = code.match(/@(RequestParam|RequestBody|PathVariable|RequestHeader|CookieValue|ModelAttribute)\b(?:\([^)]*\))?\s+(?:final\s+)?[\w.$<>, ?\[\]]+\s+([A-Za-z_$][\w$]*)/i)?.[2]
  if (annotationParam) return annotationParam

  const multipart = code.match(/\b(?:MultipartFile|FileItem|Part)\s+([A-Za-z_$][\w$]*)/i)?.[1]
  return multipart ?? "unknown"
}

function servletRequestSource(code: string): { kind: SourceEntry["kind"]; paramName: string } | null {
  if (!/\b(?:doGet|doPost|doPut|doDelete|doPatch|doHead|doOptions|service)\s*\(/.test(code)) return null
  const param = code.match(/\b(?:HttpServletRequest|ServletRequest)\s+([A-Za-z_$][\w$]*)/)?.[1]
  if (!param) return null
  return { kind: "param", paramName: param }
}

function requestApiSource(code: string): { kind: SourceEntry["kind"]; paramName: string } | null {
  const quoted = code.match(/\.\s*(getParameter|getParameterValues|getHeader|getAttribute|getPart)\s*\(\s*["']([^"']+)["']/)
  if (quoted?.[1]) {
    const api = quoted[1]
    const kind: SourceEntry["kind"] = api === "getHeader" ? "header" : api === "getAttribute" ? "request-attr" : api === "getPart" ? "body" : "param"
    return { kind, paramName: quoted[2] ?? "unknown" }
  }
  if (/\.getParameterMap\s*\(/.test(code)) return { kind: "param", paramName: "parameterMap" }
  if (/\.getParameterNames\s*\(/.test(code)) return { kind: "param", paramName: "parameterNames" }
  if (/\.getCookies\s*\(/.test(code)) return { kind: "cookie", paramName: "cookies" }
  if (/\.getInputStream\s*\(|\.getReader\s*\(/.test(code)) return { kind: "input-stream", paramName: "requestBody" }
  if (/\.getParts\s*\(/.test(code)) return { kind: "body", paramName: "parts" }
  if (/\.getQueryString\s*\(/.test(code)) return { kind: "param", paramName: "queryString" }
  if (/\.getRequestURI\s*\(/.test(code)) return { kind: "pathvar", paramName: "requestURI" }
  if (/\.getPathInfo\s*\(/.test(code)) return { kind: "pathvar", paramName: "pathInfo" }
  if (/\.getServletPath\s*\(/.test(code)) return { kind: "pathvar", paramName: "servletPath" }
  return null
}

function jspImplicitSources(code: string): Array<{ kind: SourceEntry["kind"]; paramName: string }> {
  const sources: Array<{ kind: SourceEntry["kind"]; paramName: string }> = []
  for (const match of code.matchAll(/\$\{\s*(param|paramValues|header|cookie)(?:\.([A-Za-z_$][\w$-]*)|\[['"]([^'"]+)['"]\]|\["([^"]+)"\])?/g)) {
    const family = match[1] ?? "param"
    const paramName = match[2] ?? match[3] ?? match[4] ?? family
    const kind: SourceEntry["kind"] = family === "header" ? "header" : family === "cookie" ? "cookie" : "param"
    sources.push({ kind, paramName })
  }
  if (/<jsp:setProperty\b[^>]*\bproperty\s*=\s*["']\*["']/i.test(code)) {
    sources.push({ kind: "param", paramName: "jsp:setProperty:*" })
  }
  return sources
}

function methodNameForFile(file: string, lines: string[], index: number): string {
  const method = methodNameNear(lines, index)
  if (method !== "unknown") return method
  return /\.(jsp|jspx)$/i.test(file) ? "_jspService" : "unknown"
}

function classNameForFile(file: string, lines: string[], index: number): string | undefined {
  return classNameNear(lines, index) ?? (/\.(jsp|jspx)$/i.test(file) ? jspClassName(file) : undefined)
}

function methodNameNear(lines: string[], index: number): string {
  for (let i = index; i >= Math.max(0, index - 35); i--) {
    const code = stripLineMarker(lines[i]?.trim() ?? "")
    const matched = code.match(/\b([A-Za-z_$][\w$]*)\s*\([^;]*\)\s*(?:throws\s+[^{]+)?\{?\s*$/)
    if (matched?.[1] && !["if", "for", "while", "switch", "catch", "return", "new"].includes(matched[1])) return matched[1]
  }
  return "unknown"
}

function classNameNear(lines: string[], index: number): string | undefined {
  for (let i = index; i >= 0; i--) {
    const code = stripLineMarker(lines[i]?.trim() ?? "")
    const matched = code.match(/\b(class|interface|enum)\s+([A-Za-z_$][\w$]*)/)
    if (matched?.[2]) return matched[2]
  }
  return undefined
}

function jspClassName(file: string): string {
  const name = file.split(/[\\/]/).pop()?.replace(/\.(jsp|jspx)$/i, "") ?? "jsp"
  return name.replace(/[^A-Za-z0-9_$]+/g, "_")
}

function buildSourceRefineBatches(sources: Array<Omit<SourceEntry, "id">>): Array<{ name: string; sources: Array<Omit<SourceEntry, "id">> }> {
  if (sources.length <= 80) return [{ name: "all", sources }]
  const buckets = new Map<string, Array<Omit<SourceEntry, "id">>>()
  for (const source of sources) {
    const name = sourceRefineBucket(source)
    const entries = buckets.get(name) ?? []
    entries.push(source)
    buckets.set(name, entries)
  }
  return ["controller-request", "jsp-request", "servlet-filter-listener", "upload-download-input", "other"]
    .map((name) => ({ name, sources: (buckets.get(name) ?? []).slice(0, 90) }))
    .filter((batch) => batch.sources.length > 0)
}

function sourceRefineBucket(source: Omit<SourceEntry, "id">): string {
  const text = `${source.kind} ${source.paramName} ${source.file} ${source.code} ${source.methodName} ${source.className ?? ""}`.toLowerCase()
  if (/\.jspx?$|\$\{\s*(param|header|cookie)|<%|jsp:setproperty/.test(text)) return "jsp-request"
  if (/servlet|filter|listener|doget|dopost|service\s*\(|httpservletrequest/.test(text)) return "servlet-filter-listener"
  if (/upload|download|multipart|fileitem|part\s|filename|filepath/.test(text)) return "upload-download-input"
  if (/controller|requestmapping|getmapping|postmapping|requestparam|requestbody|pathvariable/.test(text)) return "controller-request"
  return "other"
}
