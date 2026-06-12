import { relative, resolve } from "node:path"
import { buildHttpPoc, buildHttpPocExpectation, formatChainMd, readCodeContext, type PocExpectation } from "./report-writer.ts"
import { evidenceDecisionForReport, evidenceDecisionText } from "../graph/evidence-decision.ts"
import { submitAgentResult } from "../runtime/agent-submission.ts"
import { generateHttpPocWithLLM, type SourceFileCandidate } from "../llm/llm-runner.ts"
import type { AuditOptions, AuditReport, EvidenceBundle, Hypothesis } from "../types/index.ts"
import type { EventBus } from "../runtime/event-bus.ts"

const HIGH_VALUE_POC_CATEGORIES = new Set([
  "cmdi",
  "sqli",
  "file-download",
  "file-upload",
  "upload",
  "ssti",
  "spel",
  "ognl",
  "expression",
  "path-traversal",
])

function isHighValuePocTarget(hypothesis: Hypothesis): boolean {
  return HIGH_VALUE_POC_CATEGORIES.has(hypothesis.category)
}

function statusWeight(hypothesis: Hypothesis): number {
  switch (hypothesis.status) {
    case "confirmed": return 40
    case "pending": return 20
    case "maybe_revisit": return 10
    default: return 0
  }
}

function pocPriority(report: AuditReport, hypothesis: Hypothesis): number {
  const bundleScore = bundleFor(report, hypothesis)?.sourceLinks[0]?.score ?? hypothesis.sourceLinks?.[0]?.score ?? 0
  const sinkScore = /Runtime\.exec|ProcessBuilder|Statement\.execute|Template\.process|file|upload|spel|ognl|expression/i.test(hypothesis.sinkPattern) ? 20 : 0
  return statusWeight(hypothesis) + Math.min(bundleScore, 100) + sinkScore
}

export interface PocAgentResult {
  generated: number
  skipped: number
  hypothesisIds: string[]
  aiGenerated: number
  fallbackGenerated: number
}

export async function runPocAgent(report: AuditReport, bus: EventBus, options: AuditOptions, maxItems: number = 20): Promise<PocAgentResult> {
  const candidates = report.hypotheses
    .filter(isHighValuePocTarget)
    .filter((hypothesis) => hypothesis.status === "confirmed")
    .sort((a, b) => pocPriority(report, b) - pocPriority(report, a))
    .slice(0, maxItems)

  const generatedIds: string[] = []
  const aiGeneratedIds: string[] = []
  const fallbackIds: string[] = []

  for (const hypothesis of candidates) {
    const codeContext = readCodeContext(hypothesis.sinkFile, hypothesis.sinkLine, 4)
    const chainText = formatChainMd(report, hypothesis)
    const fallbackPackets = buildHttpPoc(report, hypothesis)
    const expectation = buildHttpPocExpectation(report, hypothesis)
    const aiDraft = options.llmConfig
      ? await generateHttpPocWithLLM(
        options.llmConfig,
        report.profile,
        hypothesis,
        pocEvidenceFiles(report, hypothesis),
        pocPromptContext(report, hypothesis, fallbackPackets),
        options.outputDir,
      )
      : null
    const aiPackets = aiDraft?.packets ?? []
    const validAiPackets = expectation
      ? aiPackets.filter((packet) => packetMatchesPocExpectation(packet, expectation))
      : aiPackets
    const usedAi = validAiPackets.length > 0 || (fallbackPackets.length === 0 && aiPackets.length > 0)
    const pocPackets = validAiPackets.length > 0
      ? validAiPackets
      : fallbackPackets.length > 0
        ? fallbackPackets
        : aiPackets
    updateReportContext(report, hypothesis.id, {
      codeContext,
      chainText,
      pocPackets,
    })
    if (pocPackets.length > 0) {
      generatedIds.push(hypothesis.id)
      if (usedAi) aiGeneratedIds.push(hypothesis.id)
      else fallbackIds.push(hypothesis.id)
    }
  }

  const categoryCounts = candidates.reduce<Record<string, number>>((acc, hypothesis) => {
    acc[hypothesis.category] = (acc[hypothesis.category] ?? 0) + 1
    return acc
  }, {})

  submitAgentResult(bus, "poc", {
    kind: "poc",
    agent: "PocAgent",
    title: "PocAgent 提交 HTTP PoC 草案",
    content: candidates.length > 0
      ? `已为 ${generatedIds.length}/${candidates.length} 个已确认高价值漏洞生成 HTTP 数据包草案，其中 AI 生成 ${aiGeneratedIds.length} 个，fallback ${fallbackIds.length} 个。`
      : "未发现需要生成 HTTP PoC 草案的已确认高价值漏洞。",
    refs: generatedIds,
    artifacts: {
      generated: generatedIds.length,
      attempted: candidates.length,
      skipped: Math.max(0, candidates.length - generatedIds.length),
      aiGenerated: aiGeneratedIds.length,
      fallbackGenerated: fallbackIds.length,
      categories: categoryCounts,
      hypothesisIds: generatedIds,
    },
  })

  return {
    generated: generatedIds.length,
    skipped: Math.max(0, candidates.length - generatedIds.length),
    hypothesisIds: generatedIds,
    aiGenerated: aiGeneratedIds.length,
    fallbackGenerated: fallbackIds.length,
  }
}

interface ParsedPocHttpPacket {
  method: string
  target: string
  headers: Map<string, string>
  body: string
}

function packetMatchesPocExpectation(packet: string, expectation: PocExpectation): boolean {
  const parsed = parsePocHttpPacket(packet)
  if (!parsed) return false
  const actualPath = parsed.target.split("?")[0] || "/"
  if (parsed.method !== expectation.method || actualPath !== expectation.routePath) return false

  const encodedParam = encodeURIComponent(expectation.paramName)
  const encodedPayload = encodeURIComponent(expectation.payload)
  const query = parsed.target.includes("?") ? parsed.target.slice(parsed.target.indexOf("?") + 1) : ""

  if (expectation.triggerLocation === "path") {
    return actualPath === expectation.routePath && !query.includes(`${encodedParam}=`)
  }
  if (expectation.triggerLocation === "query" || expectation.triggerLocation === "form") {
    return requestCarriesParameter(parsed, query, encodedParam, encodedPayload, expectation)
  }
  if (expectation.triggerLocation === "body") {
    return parsed.body.trim().length > 0
      && (parsed.body.includes(expectation.payload) || parsed.body.includes(encodedPayload))
  }
  if (expectation.triggerLocation === "header") {
    return (parsed.headers.get(expectation.paramName.toLowerCase()) ?? "") === expectation.payload
  }
  if (expectation.triggerLocation === "cookie") {
    return (parsed.headers.get("cookie") ?? "").includes(`${expectation.paramName}=${encodedPayload}`)
  }
  if (expectation.triggerLocation === "multipart") {
    const contentType = parsed.headers.get("content-type") ?? ""
    return /multipart\/form-data/i.test(contentType)
      && parsed.body.includes(`name="${expectation.paramName}"`)
      && parsed.body.includes(expectation.payload)
  }
  return false
}

function parsePocHttpPacket(packet: string): ParsedPocHttpPacket | null {
  const normalized = packet.replace(/\r\n/g, "\n")
  const [head = "", ...bodyParts] = normalized.split("\n\n")
  const lines = head.split("\n").map((line) => line.trimEnd()).filter(Boolean)
  const first = lines[0]
  const match = first?.match(/^([A-Z]+)\s+(\S+)\s+HTTP\/1\.[01]$/)
  if (!match) return null
  const headers = new Map<string, string>()
  for (const line of lines.slice(1)) {
    const idx = line.indexOf(":")
    if (idx <= 0) continue
    const key = line.slice(0, idx).trim().toLowerCase()
    const value = line.slice(idx + 1).trim()
    headers.set(key, headers.has(key) ? `${headers.get(key)}\n${value}` : value)
  }
  return {
    method: match[1]!,
    target: match[2]!,
    headers,
    body: bodyParts.join("\n\n"),
  }
}

function requestCarriesParameter(
  packet: ParsedPocHttpPacket,
  query: string,
  encodedParam: string,
  encodedPayload: string,
  expectation: PocExpectation,
): boolean {
  if (query.includes(`${encodedParam}=${encodedPayload}`)) return true
  if (packet.body.includes(`${encodedParam}=${encodedPayload}`)) return true
  if (packet.body.includes(`"${expectation.paramName}"`)
    && (packet.body.includes(expectation.payload) || packet.body.includes(encodedPayload) || isStructuredRequestBody(packet))) return true
  return false
}

function isStructuredRequestBody(packet: ParsedPocHttpPacket): boolean {
  const contentType = packet.headers.get("content-type") ?? ""
  return /json|xml|text\/plain/i.test(contentType) && !/x-www-form-urlencoded|multipart\/form-data/i.test(contentType)
}

function pocEvidenceFiles(report: AuditReport, hyp: Hypothesis): SourceFileCandidate[] {
  const bundle = bundleFor(report, hyp)
  const decision = evidenceDecisionForReport(report, hyp)
  const windows = new Map<string, { file: string; line: number; label: string }>()
  const add = (file: string | undefined, line: number | undefined, label: string) => {
    if (!file || !line || line < 1) return
    const absolute = file.startsWith("/") ? file : resolve(report.profile.root, file)
    const key = `${absolute}:${line}:${label}`
    if (!windows.has(key)) windows.set(key, { file: absolute, line, label })
  }

  add(hyp.sinkFile, hyp.sinkLine, "sink")
  if (decision.source) add(decision.source.file, decision.source.line, `EvidenceGraph source ${decision.source.kind}:${decision.source.paramName}`)
  if (decision.route) add(resolve(report.profile.root, decision.route.sourceFile), decision.route.line, `EvidenceGraph route ${decision.route.method} ${decision.route.path}`)
  if (bundle?.selectedSource) add(bundle.selectedSource.file, bundle.selectedSource.line, "selected source")
  for (const link of (bundle?.sourceLinks ?? hyp.sourceLinks ?? []).slice(0, 4)) add(link.source.file, link.source.line, `source ${link.source.kind}:${link.source.paramName}`)
  if (bundle?.route) add(resolve(report.profile.root, bundle.route.sourceFile), bundle.route.line, "route")
  for (const edge of decision.graphEdges.slice(0, 10)) add(edge.file, edge.line, `EvidenceGraph ${edge.kind}`)
  for (const edge of (bundle?.dataflow ?? hyp.dataflowResult)?.paths?.[0]?.edges ?? []) add(edge.file, edge.line, `dataflow ${edge.kind}`)

  return [...windows.values()].slice(0, 14).map((window) => ({
    file: window.file,
    content: `// PoC evidence: ${window.label} @ ${relative(report.profile.root, window.file)}:${window.line}
${readCodeContext(window.file, window.line, 70)}`,
  }))
}

function pocPromptContext(report: AuditReport, hyp: Hypothesis, fallbackPackets: string[]): string {
  const bundle = bundleFor(report, hyp)
  const expectation = buildHttpPocExpectation(report, hyp)
  const decision = evidenceDecisionForReport(report, hyp)
  const verifier = bundle?.verifierVerdict ?? hyp.verifierVerdict
  const sourceLinks = bundle?.sourceLinks ?? hyp.sourceLinks ?? []
  const sources = [
    ...(decision.source ? [{
      source: decision.source,
      score: decision.confidence === "high" ? 100 : decision.confidence === "medium" ? 75 : 50,
      reason: `EvidenceGraph primary flow ${decision.status}`,
    }] : []),
    ...sourceLinks.filter((link) => !decision.source
      || link.source.id !== decision.source.id
      || link.source.paramName !== decision.source.paramName
      || link.source.line !== decision.source.line),
  ].slice(0, 5).map((link, index) =>
    `${index + 1}. score=${link.score} ${link.source.kind}:${link.source.paramName} @ ${relative(report.profile.root, link.source.file)}:${link.source.line} code=${link.source.code} reason=${link.reason}`
  ).join("\n")
  const route = expectation?.route ?? decision.route ?? bundle?.route
  const routeLine = route ? `${route.method} ${route.path} @ ${route.sourceFile}:${route.line}` : "(no route selected)"
  const chain = formatChainMd(report, hyp)

  return `Hypothesis:
- id: ${hyp.id}
- category/severity: ${hyp.category}/${hyp.severity}
- sink: ${hyp.sinkPattern} @ ${relative(report.profile.root, hyp.sinkFile)}:${hyp.sinkLine}
- sink code: ${hyp.sinkCode}
- status: ${hyp.status}

Selected route hint:
${routeLine}

EvidenceGraph primary flow:
status=${decision.status}, confidence=${decision.confidence}, route=${decision.routeSignature || "(none)"}, trigger=${decision.triggerSignature}, source=${decision.source ? `${decision.source.kind}:${decision.source.paramName} @ ${relative(report.profile.root, decision.source.file)}:${decision.source.line}` : "(none)"}
${evidenceDecisionText(decision).slice(0, 1200) || "(none)"}

Selected trigger expectation from backend fallback:
${expectation ? `${expectation.method} ${expectation.requestTarget}; source=${expectation.source.kind}:${expectation.paramName} @ ${relative(report.profile.root, expectation.source.file)}:${expectation.source.line}; triggerLocation=${expectation.triggerLocation}` : "(none; inspect code before deciding whether a PoC is possible)"}

Source candidates:
${sources || "(none)"}

StaticVerifierAgent verdict:
${verifier ? `${verifier.status}/${verifier.confidence}: ${verifier.reason}
sourceSinkTrace=${JSON.stringify(verifier.sourceSinkTrace ?? [])}
barrierAnalysis=${JSON.stringify(verifier.barrierAnalysis ?? verifier.sanitizerSummary ?? [])}` : "(none)"}

Source-to-sink chain:
${chain}

Backend template fallback packet, only as a hint. Prefer your own packet if code proves a different route, method, body format, field name, or required placeholder:
${fallbackPackets.length ? fallbackPackets.join("\n\n---\n\n") : "(none)"}
`
}

function bundleFor(report: AuditReport, hyp: Hypothesis): EvidenceBundle | undefined {
  return report.evidenceBundles.find((item) => item.hypothesisId === hyp.id || item.id === hyp.evidenceBundleId)
}

function updateReportContext(report: AuditReport, hypothesisId: string, context: NonNullable<EvidenceBundle["reportContext"]>): void {
  const bundle = report.evidenceBundles.find((item) => item.hypothesisId === hypothesisId)
  if (!bundle) return
  bundle.reportContext = context
  bundle.updatedAt = Date.now()
}
