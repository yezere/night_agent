import { BaseSolver, type SolverContext } from "./base-solver.ts"
import { readMultipleSnippets } from "../tools/file-reader.ts"
import { buildEvidenceDecisionIndex, evidenceDecisionText, traceFromEvidenceDecision, type EvidenceFlowDecision } from "../graph/evidence-decision.ts"
import { AuditWorkspace } from "../runtime/audit-workspace.ts"
import type {
  Hypothesis,
  Finding,
  DataflowTrace,
  EvidenceLink,
  ProjectProfile,
  SourceEntry,
  SourceRef,
  SinkRef,
} from "../types/index.ts"
import { compareSeverity } from "../types/index.ts"

export class SolverJudge extends BaseSolver {
  private evidenceDecisions = new Map<string, EvidenceFlowDecision>()
  private workspace: AuditWorkspace

  constructor(ctx: SolverContext, workspace: AuditWorkspace) {
    super(ctx)
    this.workspace = workspace
  }

  async start(): Promise<void> {
    // Judge is reactive — it processes confirmed hypotheses
  }

  async stop(): Promise<void> {
    this.setStatus("idle")
  }

  private normalizeHypothesisCategory(hyp: Hypothesis, verdict: NonNullable<Hypothesis["verifierVerdict"]>): void {
    const categoryCorrection = categoryCorrectionFromVerifier(hyp, verdict, this.evidenceDecisions.get(hyp.id))
    if (!categoryCorrection) return
    const before = `${hyp.category}/${hyp.sinkPattern}`
    hyp.category = categoryCorrection.category
    if (categoryCorrection.sinkPattern) hyp.sinkPattern = categoryCorrection.sinkPattern
    hyp.updatedAt = Date.now()
    hyp.resolutionNote = appendResolutionNote(
      hyp.resolutionNote,
      `Judge category normalization: ${before} -> ${hyp.category}/${hyp.sinkPattern}; ${categoryCorrection.reason}`,
    )
    this.emit("hypothesis:updated", hyp)
    this.log(`category normalized ${hyp.id}: ${before} -> ${hyp.category}/${hyp.sinkPattern}`)
  }

  /**
   * Judge a single hypothesis: read code along dataflow path and produce a Finding.
   */
  async judgeHypothesis(hyp: Hypothesis, source?: SourceEntry): Promise<Finding | null> {
    this.setStatus("busy")

    const bundle = this.workspace.getEvidenceBundle(hyp.id)
    const verdict = bundle?.verifierVerdict ?? hyp.verifierVerdict
    if (!verdict) {
      this.emit("hypothesis:updated", this.workspace.markJudgeNeedsReview(hyp.id, "Judge skipped: missing StaticVerifierAgent verdict", hyp.dataflowResult))
      this.log(`skip judge for ${hyp.id}: missing verifier verdict`)
      this.setStatus("idle")
      return null
    }

    if (verdict.status !== "confirmed") {
      this.emit("hypothesis:updated", this.workspace.markJudgeRejected(hyp.id, verdict.status, `StaticVerifierAgent: ${verdict.reason}`, hyp.dataflowResult))
      this.log(`skip judge for ${hyp.id}: verifier=${verdict.status}`)
      this.setStatus("idle")
      return null
    }

    const decision = this.evidenceDecisions.get(hyp.id)
    this.normalizeHypothesisCategory(hyp, verdict)

    const graphTrace = traceFromEvidenceDecision(decision, verdict.confidence)
    const realTrace = bundle?.dataflow ?? hyp.dataflowResult ?? graphTrace
    const selectedSource = source ?? decision?.source
    const trace = realTrace ?? emptyVerifierTrace(hyp, verdict, selectedSource)
    const evidenceChain = await this.buildEvidenceChain(trace)

    // Determine confidence based on evidence quality
    // Following BreachWeave's failure conservatism: downgrade weak evidence instead of discarding
    let confidence: "high" | "medium" | "low"
    let resolutionNote: string | undefined

    if (evidenceChain.length === 0) {
      confidence = verdict.confidence
      resolutionNote = "StaticVerifierAgent confirmed by code reading; no Joern path edges were attached"
    } else if (evidenceChain.length === 1) {
      confidence = verdict.confidence === "high" ? "medium" : verdict.confidence
      resolutionNote = "StaticVerifierAgent confirmed, but trace chain contains only one edge"
    } else {
      confidence = verdict.confidence
    }

    const topSourceScore = Math.max(
      bundle?.sourceLinks[0]?.score ?? hyp.sourceLinks?.[0]?.score ?? 0,
      decision?.hasGraphSource ? decision.confidence === "high" ? 90 : decision.confidence === "medium" ? 70 : 45 : 0,
    )
    const uploadDownloadGate = conservativeFileTransferGate(hyp, verdict, realTrace, topSourceScore, confidence, decision)
    if (uploadDownloadGate) {
      this.emit("hypothesis:updated", this.workspace.markJudgeNeedsReview(hyp.id, uploadDownloadGate, realTrace ?? hyp.dataflowResult))
      this.log(`judge downgraded ${hyp.id} to maybe_revisit: ${uploadDownloadGate}`)
      this.setStatus("idle")
      return null
    }

    const sourceRef: SourceRef = selectedSource
      ? { kind: selectedSource.kind, file: selectedSource.file, line: selectedSource.line, snippet: selectedSource.code }
      : { kind: "unknown", file: hyp.sinkFile, line: hyp.sinkLine, snippet: hyp.sinkCode }

    const sinkRef: SinkRef = {
      kind: hyp.sinkPattern,
      file: hyp.sinkFile,
      line: hyp.sinkLine,
      snippet: hyp.sinkCode,
    }

    const finding: Finding = {
      id: "",
      hypothesisId: hyp.id,
      title: `${hyp.category.toUpperCase()} via ${hyp.sinkPattern}`,
      severity: hyp.severity,
      category: hyp.category,
      source: sourceRef,
      sink: sinkRef,
      evidenceChain,
      status: "confirmed",
      confidence,
      createdAt: Date.now(),
    }

    const stored = this.workspace.addFinding(finding)
    if (resolutionNote) {
      this.workspace.markFindingConfirmed(hyp.id, trace, resolutionNote)
    } else {
      this.workspace.markFindingConfirmed(hyp.id, trace, `StaticVerifierAgent: ${verdict.reason}`)
    }
    this.emit("finding:confirmed", stored)
    const updated = this.workspace.getHypothesis(hyp.id)
    if (updated) this.emit("hypothesis:updated", updated)
    this.log(`finding confirmed: ${stored.id} (confidence: ${stored.confidence}) — ${stored.title}`)
    this.setStatus("idle")
    return stored
  }

  /**
   * Judge all confirmed hypotheses with dataflow results.
   */
  async judgeAll(sourceMap?: Map<string, SourceEntry>, evidenceContext?: { profile: ProjectProfile; sources?: SourceEntry[] }): Promise<Finding[]> {
    const rebuildDecisionIndex = () => {
      if (!evidenceContext?.profile) {
        this.evidenceDecisions = new Map()
        return
      }
      this.evidenceDecisions = buildEvidenceDecisionIndex({
        profile: evidenceContext.profile,
        hypotheses: this.workspace.getHypotheses(),
        sources: evidenceContext.sources ?? [...(sourceMap?.values() ?? [])],
        evidenceBundles: this.workspace.getEvidenceBundles(),
        findings: this.workspace.getFindings(),
      }).byHypothesisId
    }
    rebuildDecisionIndex()

    const confirmed = this.workspace.getHypotheses().filter((hyp) => {
      const verdict = this.workspace.getEvidenceBundle(hyp.id)?.verifierVerdict ?? hyp.verifierVerdict
      return verdict?.status === "confirmed"
    })
    for (const hyp of confirmed) {
      const verdict = this.workspace.getEvidenceBundle(hyp.id)?.verifierVerdict ?? hyp.verifierVerdict
      if (verdict?.status === "confirmed") this.normalizeHypothesisCategory(hyp, verdict)
    }
    rebuildDecisionIndex()
    const findings: Finding[] = []
    const groups = this.groupSemanticDuplicates(confirmed)

    for (const group of groups) {
      const ordered = group.sort((a, b) => this.primaryRank(b) - this.primaryRank(a)
        || compareSeverity(a.severity, b.severity)
        || a.sinkLine - b.sinkLine)
      const hyp = ordered[0]!
      for (const duplicate of ordered.slice(1)) {
        this.emit("hypothesis:updated", this.workspace.markJudgeDuplicate(duplicate.id, hyp.id, duplicate.dataflowResult))
        this.log(`duplicate merged: ${duplicate.id} -> ${hyp.id}`)
      }

      const source = this.selectBestSource(hyp, sourceMap)
      const finding = await this.judgeHypothesis(hyp, source)
      if (finding) findings.push(finding)
    }

    return findings
  }

  private groupSemanticDuplicates(hypotheses: Hypothesis[]): Hypothesis[][] {
    const groups = new Map<string, Hypothesis[]>()
    for (const hyp of hypotheses) {
      const bundle = this.workspace.getEvidenceBundle(hyp.id)
      const sinkBucket = Math.floor(Math.max(0, hyp.sinkLine) / 80)
      const sinkPattern = semanticSinkPattern(hyp)
      const decision = this.evidenceDecisions.get(hyp.id)
      const trigger = semanticTriggerSignature(hyp, decision)
      const graphIdentity = decision?.identitySignature
      const key = graphIdentity && !graphIdentity.includes("unknown-trigger")
        ? graphIdentity
        : bundle?.route
        ? `${hyp.category}:${bundle.route.sourceFile}:${bundle.route.method}:${bundle.route.path}:${trigger}:${sinkBucket}:${sinkPattern}`
        : `${hyp.category}:${hyp.sinkFile}:${trigger}:${sinkBucket}:${sinkPattern}`
      const group = groups.get(key)
      if (group) group.push(hyp)
      else groups.set(key, [hyp])
    }
    return [...groups.values()].sort((a, b) => compareSeverity(a[0]!.severity, b[0]!.severity)
      || a[0]!.sinkFile.localeCompare(b[0]!.sinkFile)
      || a[0]!.sinkLine - b[0]!.sinkLine)
  }

  private primaryRank(hyp: Hypothesis): number {
    const code = `${hyp.sinkPattern}\n${hyp.sinkCode}`.toLowerCase()
    let rank = 0
    if (/runtime\.getruntime|processbuilder|engine\.eval|parseexpression|template\.process|readobject|parseobject/.test(code)) rank += 60
    if (/executequery|executeupdate|executesql|findhql|createquery|statement\.execute|\$\{/.test(code)) rank += 55
    if (/fileinputstream|files\.read|inputstreamresource|fileutil\.(file|read|ls)|new\s+file/.test(code)) rank += 50
    if (/transferto|files\.copy|fileoutputstream|fileutil\.(write|copy)/.test(code)) rank += 50
    if (/getoutputstream|servletoutputstream/.test(code)) rank += 25
    if (/bytearrayoutputstream|getoriginalfilename|available\(\)/.test(code)) rank -= 10
    const verdict = this.workspace.getEvidenceBundle(hyp.id)?.verifierVerdict ?? hyp.verifierVerdict
    if (verdict?.confidence === "high") rank += 8
    if (verdict?.confidence === "medium") rank += 4
    if ((hyp.dataflowResult?.paths.length ?? 0) > 0) rank += 5
    const decision = this.evidenceDecisions.get(hyp.id)
    if (decision?.status === "confirmed" || decision?.status === "verified") rank += 6
    if (decision?.hasTrace) rank += 5
    if (decision?.hasGraphRoute && decision?.hasGraphSource) rank += 4
    return rank
  }

  private selectBestSource(hyp: Hypothesis, sourceMap?: Map<string, SourceEntry>): SourceEntry | undefined {
    const bundle = this.workspace.getEvidenceBundle(hyp.id)
    const decision = this.evidenceDecisions.get(hyp.id)
    if (decision?.source) {
      this.workspace.updateSelectedSource(hyp.id, decision.source)
      return decision.source
    }
    const links = bundle?.sourceLinks ?? hyp.sourceLinks ?? []
    if (links.length === 0) return hyp.sourceHint ?? sourceMap?.get(hyp.sinkFile)

    const verifier = bundle?.verifierVerdict ?? hyp.verifierVerdict
    const verifierText = [
      verifier?.reason,
      ...(verifier?.evidence ?? []),
      ...(verifier?.sanitizerSummary ?? []),
    ].join("\n").toLowerCase()
    const dataflowSources = new Set<string>()
    for (const path of (bundle?.dataflow ?? hyp.dataflowResult)?.paths ?? []) {
      for (const edge of path.edges) {
        if (edge.kind === "source") dataflowSources.add(`${edge.file}:${edge.line}`)
      }
    }

    const sorted = [...links].sort((a, b) => sourceScore(b.source, b.score) - sourceScore(a.source, a.score))
    const selected = sorted[0]?.source
    if (selected) {
      this.workspace.updateSelectedSource(hyp.id, selected)
    }
    return selected ?? hyp.sourceHint ?? sourceMap?.get(hyp.sinkFile)

    function sourceScore(source: SourceEntry, handoffScore: number): number {
      const code = `${source.paramName}\n${source.code}`.toLowerCase()
      let score = handoffScore
      if (dataflowSources.has(`${source.file}:${source.line}`)) score += 80
      if (verifierText.includes(source.paramName.toLowerCase())) score += 70
      if (source.paramName && verifierText.includes(`"${source.paramName.toLowerCase()}"`)) score += 20
      const sourceCodeHead = source.code.toLowerCase().slice(0, 80)
      if (sourceCodeHead.length > 20 && verifierText.includes(sourceCodeHead)) score += 30
      score += sourceKindRank(source.kind)
      const distance = Math.abs(source.line - hyp.sinkLine)
      if (source.file === hyp.sinkFile && source.line <= hyp.sinkLine) score += Math.max(0, 20 - Math.floor(distance / 5))
      if (source.kind === "header" && !verifierText.includes(source.paramName.toLowerCase())) score -= 25
      if (/requestparam|requestbody|pathvariable|getparameter|multipartfile|getinputstream|getreader/.test(code)) score += 10
      return score
    }
  }

  private async buildEvidenceChain(trace: DataflowTrace): Promise<EvidenceLink[]> {
    const chain: EvidenceLink[] = []

    if (!trace.paths || trace.paths.length === 0) {
      return chain
    }

    // Use the first reachable path
    const path = trace.paths[0]!
    let step = 0

    // Collect unique file:line entries to avoid duplicate reads
    const toRead = new Map<string, { file: string; line: number }>()
    for (const edge of path.edges) {
      const key = `${edge.file}:${edge.line}`
      if (!toRead.has(key)) {
        toRead.set(key, { file: edge.file, line: edge.line })
      }
    }

    // Read all unique snippets
    const snippets = await readMultipleSnippets(
      [...toRead.values()],
      5,
    )

    for (const edge of path.edges) {
      step++
      const key = `${edge.file}:${edge.line}`
      const snippet = snippets.get(key)
      const code = snippet ? snippet.lines.join("\n").replace(/^>>>(.+)$/gm, "$1").trim() : edge.code

      chain.push({
        step,
        file: edge.file,
        line: edge.line,
        code,
        role: edge.kind === "sink" ? "sink"
          : edge.kind === "sanitizer" ? "sanitizer"
          : edge.kind === "source" ? "source"
          : "transform",
        note: edge.kind === "sanitizer" ? "security barrier detected" : undefined,
      })
    }

    return chain
  }
}

function conservativeFileTransferGate(
  hyp: Hypothesis,
  verdict: NonNullable<Hypothesis["verifierVerdict"]>,
  realTrace: DataflowTrace | undefined,
  topSourceScore: number,
  confidence: "high" | "medium" | "low",
  decision?: EvidenceFlowDecision,
): string | null {
  if (hyp.category !== "file-upload" && hyp.category !== "file-download") return null

  const text = [
    hyp.origin,
    hyp.sinkPattern,
    hyp.sinkCode,
    verdict.reason,
    ...(verdict.sourceSinkTrace ?? []),
    ...(verdict.barrierAnalysis ?? []),
    ...(verdict.evidence ?? []),
    ...(verdict.missingEvidence ?? []),
    evidenceDecisionText(decision),
  ].join("\n").toLowerCase()

  const hasRealDataflow = Boolean(realTrace?.reachable && realTrace.paths.some((path) => path.edges.length >= 2))
    || Boolean(decision?.hasTrace && decision.status !== "blocked" && decision.status !== "unknown")
  const hasStrongSource = topSourceScore >= 70

  if (hyp.origin === "pre-scan" && confidence === "low") {
    return "Judge conservative gate: pre-scan-only low-confidence file transfer API requires manual/static recheck before confirmation"
  }
  if (!hasRealDataflow && !hasStrongSource) {
    return `Judge conservative gate: ${hyp.category} lacks Joern path or strong SourceAgent link (top score=${topSourceScore})`
  }

  const protectiveSignal = /canonical|getcanonical|normalize|allowlist|whitelist|base[- ]?dir|base directory|safe filename|uuid|random|rename|server[- ]?chosen|固定目录|白名单|规范化|随机文件名|服务端生成/.test(text)
  const protectiveNegated = /no .{0,40}(canonical|allowlist|whitelist|base[- ]?dir|random|rename)|without .{0,40}(canonical|allowlist|whitelist|base[- ]?dir)|未.{0,20}(校验|规范化|白名单)|没有.{0,20}(校验|规范化|白名单)|does not cut|not sanitized|not validate|bypass|绕过|不切断|无有效/.test(text)
  if (protectiveSignal && !protectiveNegated) {
    return `Judge conservative gate: ${hyp.category} mentions protective filename/path controls but verifier did not prove bypass`
  }

  if (hyp.category === "file-upload") {
    const controllableNameOrPath = /getoriginalfilename|getsubmittedfilename|request\.getparameter|@requestparam|param:|pathvar|filename.{0,80}(attacker|external|user|外部|可控)|path.{0,80}(attacker|external|user|外部|可控)|\.\.\/|\.\.\\/.test(text)
    const riskyStorage = /webroot|webapps|web-root|jsp|jspx|war|unzip|extract|overwrite|path traversal|任意文件|目录穿越|路径遍历|可执行|executable|transferto\s*\(\s*new\s+file|files\.copy|fileoutputstream|part\.write|new\s+file/.test(text)
    if (!controllableNameOrPath) {
      return "Judge conservative gate: file-upload confirmation lacks evidence that uploaded filename/path is externally controllable"
    }
    if (!riskyStorage) {
      return "Judge conservative gate: file-upload confirmation lacks executable/webroot/overwrite/path-concat risk evidence"
    }
  }

  if (hyp.category === "file-download") {
    const controllablePath = /request\.getparameter|@requestparam|param:|pathvar|getquerystring|getpathinfo|filename|filepath|file(name)?|path.{0,80}(attacker|external|user|外部|可控)|外部可控|用户可控/.test(text)
    const directPathSink = /new\s+file|fileinputstream|files\.read|files\.newinputstream|paths\.get|fileutil\.(file|read|getinputstream|ls)|inputstreamresource/.test(text)
    if (!controllablePath) {
      return "Judge conservative gate: file-download confirmation lacks evidence that requested path/name is externally controllable"
    }
    if (!directPathSink) {
      return "Judge conservative gate: file-download confirmation lacks direct file path read sink evidence"
    }
  }

  return null
}

function categoryCorrectionFromVerifier(
  hyp: Hypothesis,
  verdict: NonNullable<Hypothesis["verifierVerdict"]>,
  decision?: EvidenceFlowDecision,
): { category: string; sinkPattern?: string; reason: string } | null {
  const text = [
    hyp.category,
    hyp.sinkPattern,
    hyp.sinkCode,
    hyp.description,
    verdict.reason,
    ...(verdict.sourceSinkTrace ?? []),
    ...(verdict.barrierAnalysis ?? []),
    ...(verdict.evidence ?? []),
    ...(verdict.sanitizerSummary ?? []),
    evidenceDecisionText(decision),
  ].join("\n").toLowerCase()

  const originalLooksUpload = hyp.category === "file-upload"
    || hyp.category === "upload"
    || /file[- ]?upload|upload/.test(hyp.sinkPattern.toLowerCase())
  const actualUploadEvidence = /multipartfile|getpart|getparts|part\.write|getoriginalfilename|getsubmittedfilename|fileitem/.test(text)
  const readPathEvidence = /files\.newinputstream|fileinputstream|files\.read|readallbytes|inputstreamresource|fileutil\.(read|getinputstream)|archivefilegateway\.open|任意文件读取|文件读取|文件下载|download/.test(text)
  const traversalEvidence = /path traversal|路径遍历|目录穿越|\.\.\/|\.\.\\|base\.resolve|resolve\s*\(|canonical|normalize|基目录/.test(text)
  const archiveTraversalEvidence = isArchiveEntryTraversal(text) && traversalEvidence
  const uploadNegated = /非\s*file[- ]?upload|not\s+file[- ]?upload|不是.{0,12}上传|非上传|actual(?:ly)? .{0,24}(file read|arbitrary file|path traversal)|实际为.{0,24}(文件读取|文件下载|路径遍历|目录穿越)/.test(text)

  if ((originalLooksUpload || hyp.category === "file-download" || hyp.category === "path-traversal") && archiveTraversalEvidence) {
    return {
      category: "path-traversal",
      sinkPattern: "archive-entry-path",
      reason: "verifier proved archive entry name traversal / Zip Slip semantics",
    }
  }

  if (originalLooksUpload && (uploadNegated || (readPathEvidence && !actualUploadEvidence))) {
    const category = traversalEvidence ? "path-traversal" : "file-download"
    return {
      category,
      sinkPattern: category === "path-traversal" ? "file-path" : "file-read",
      reason: "verifier proved the confirmed impact is path/file read, not an upload sink",
    }
  }

  if (hyp.category === "file-download" && traversalEvidence) {
    return {
      category: "path-traversal",
      sinkPattern: /getrequestdispatcher|forward\s*\(|include\s*\(/.test(text) ? "dispatcher-path" : "file-path",
      reason: "verifier proved traversal/path control semantics",
    }
  }

  return null
}

function appendResolutionNote(existing: string | undefined, note: string): string {
  if (!existing) return note
  if (existing.includes(note)) return existing
  return `${existing}; ${note}`
}

function sourceKindRank(kind: SourceEntry["kind"]): number {
  if (kind === "param" || kind === "pathvar" || kind === "body" || kind === "input-stream") return 24
  if (kind === "request-attr") return 16
  if (kind === "cookie") return 8
  if (kind === "header") return 4
  return 0
}

function semanticSinkPattern(hyp: Hypothesis): string {
  return `${hyp.sinkPattern}\n${hyp.sinkCode}`
    .toLowerCase()
    .replace(/["'`]/g, "")
    .replace(/\s+/g, " ")
    .replace(/\bline\s+\d+\b/g, "line")
    .slice(0, 120)
}

function semanticTriggerSignature(hyp: Hypothesis, decision?: EvidenceFlowDecision): string {
  if (decision?.triggerSignature && decision.triggerSignature !== "unknown-trigger") return decision.triggerSignature
  const verdict = hyp.verifierVerdict
  const text = [
    hyp.sourceHint?.paramName,
    hyp.sourceHint?.code,
    verdict?.reason,
    ...(verdict?.sourceSinkTrace ?? []),
    ...(verdict?.evidence ?? []),
  ].join("\n")
  const routes = [...text.matchAll(/\b(GET|POST|PUT|DELETE|PATCH)\s+(\/[A-Za-z0-9_./{}:-]+)/gi)]
    .map((match) => `${match[1]!.toUpperCase()} ${match[2]!.replace(/[),.;，。；]+$/g, "")}`)
  const params = [
    "transformScript",
    "validationRules",
    "dynSentence",
    "caseResult",
    "sourceConfig",
    "apiUrl",
    "reportCode",
    "file",
  ].filter((candidate) => text.toLowerCase().includes(candidate.toLowerCase()))
  const sourcePart = hyp.sourceHint?.paramName && hyp.sourceHint.paramName !== "unknown" ? `${hyp.sourceHint.kind}:${hyp.sourceHint.paramName}` : ""
  return [
    routes[0] ?? "",
    params.join(","),
    sourcePart,
  ].filter(Boolean).join("|") || "unknown-trigger"
}

function isArchiveEntryTraversal(text: string): boolean {
  return /zip[- ]?slip|zipentry|zip entry|entry\.getname|zipentryname|archive entry|decompress|unzip|解压|压缩包|zip条目|条目名/.test(text)
}

function emptyVerifierTrace(hyp: Hypothesis, verdict: NonNullable<Hypothesis["verifierVerdict"]>, source?: SourceEntry): DataflowTrace {
  const sourceEdge = source
    ? {
        file: source.file,
        line: source.line,
        code: source.code,
        kind: "source" as const,
      }
    : undefined
  const sinkEdge = {
    file: hyp.sinkFile,
    line: hyp.sinkLine,
    code: hyp.sinkCode,
    kind: "sink" as const,
  }
  return {
    reachable: true,
    confidence: verdict.confidence,
    sanitizers: [],
    paths: [{
      sourceLabel: source ? `${source.kind}:${source.paramName}` : "StaticVerifierAgent code reading",
      sinkLabel: `${hyp.category}:${hyp.sinkPattern}`,
      edges: sourceEdge ? [sourceEdge, sinkEdge] : [sinkEdge],
    }],
  }
}
