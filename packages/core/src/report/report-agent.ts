import {
  appendCompleteFindingsAppendix,
  buildHttpPoc,
  formatChainMd,
  readCodeContext,
  relatedSources,
} from "./report-writer.ts"
import { generateMarkdownReportWithLLM } from "../llm/llm-runner.ts"
import { addEvent } from "../runtime/event-log.ts"
import type { AuditOptions, AuditReport, EvidenceBundle, Hypothesis } from "../types/index.ts"
import { compareSeverity } from "../types/index.ts"

const HIGH_VALUE_REPORT_CATEGORIES = new Set([
  "cmdi",
  "sqli",
  "path-traversal",
  "file-download",
  "file-upload",
  "upload",
  "ssti",
  "spel",
  "ognl",
  "expression",
  "template-injection",
])

function reportPriority(report: AuditReport, hyp: Hypothesis): number {
  let score = 0
  if (HIGH_VALUE_REPORT_CATEGORIES.has(hyp.category)) score += 100
  if (hyp.status === "confirmed") score += 40
  else if (hyp.status === "pending") score += 15
  const handoffScore = bundleFor(report, hyp)?.sourceLinks[0]?.score ?? hyp.sourceLinks?.[0]?.score ?? 0
  if (handoffScore >= 70) score += 15
  if (/Runtime\.exec|ProcessBuilder|Statement\.execute|Template\.process|file-path|upload|expression/i.test(hyp.sinkPattern)) score += 20
  return score
}

export async function enrichReportDetails(
  report: AuditReport,
  options: AuditOptions,
  log: (msg: string) => void,
): Promise<void> {
  prepareReportEvidence(report)

  if (!options.llmConfig) throw new Error("ReportAgent requires an AI config")

  const candidateCount = report.hypotheses
    .filter((h) => h.status === "confirmed")
    .length

  if (candidateCount === 0) return

  addEvent("report", "info", "ReportAgent started", `${candidateCount} confirmed candidate(s), markdown drafting`)
  const markdown = await generateMarkdownReportWithLLM(options.llmConfig, report)
  if (markdown) {
    report.markdownReport = appendCompleteFindingsAppendix(markdown, report)
    addEvent("report", "success", "ReportAgent markdown generated", `${report.markdownReport.length} chars`)
  } else {
    throw new Error("ReportAgent failed to generate Markdown")
  }
}

function prepareReportEvidence(report: AuditReport): void {
  const hypotheses = report.hypotheses
    .filter((h) => h.status === "confirmed")
    .sort((a, b) => reportPriority(report, b) - reportPriority(report, a) || compareSeverity(a.severity, b.severity))

  for (const hyp of hypotheses) {
    const bundle = bundleFor(report, hyp)
    const sources = bundle?.selectedSource
      ? [
        bundle.selectedSource,
        ...bundle.sourceLinks.map((link) => link.source).filter((source) =>
          source.id !== bundle.selectedSource?.id
            && !(source.file === bundle.selectedSource?.file && source.line === bundle.selectedSource?.line && source.paramName === bundle.selectedSource?.paramName)
        ),
      ]
      : bundle?.sourceLinks.map((link) => link.source) ?? relatedSources(report, hyp)
    const codeBlocks: string[] = []
    const seen = new Set<string>()

    for (const source of sources.slice(0, 3)) {
      const key = `${source.file}:${source.line}`
      if (seen.has(key)) continue
      seen.add(key)
      codeBlocks.push(`### Source ${source.kind}:${source.paramName} @ ${source.file}:${source.line}\n\`\`\`java\n${readCodeContext(source.file, source.line, 5)}\n\`\`\``)
    }

    const flowEdges = bundle?.dataflow?.paths?.[0]?.edges ?? hyp.dataflowResult?.paths?.[0]?.edges ?? []
    for (const edge of flowEdges.slice(0, 10)) {
      const key = `${edge.file}:${edge.line}`
      if (seen.has(key)) continue
      seen.add(key)
      codeBlocks.push(`### ${edge.kind} @ ${edge.file}:${edge.line}\n\`\`\`java\n${readCodeContext(edge.file, edge.line, 4)}\n\`\`\``)
    }

    const sinkKey = `${hyp.sinkFile}:${hyp.sinkLine}`
    if (!seen.has(sinkKey)) {
      codeBlocks.push(`### Sink ${hyp.sinkPattern} @ ${hyp.sinkFile}:${hyp.sinkLine}\n\`\`\`java\n${readCodeContext(hyp.sinkFile, hyp.sinkLine, 5)}\n\`\`\``)
    }

    const chainText = formatChainMd(report, hyp)
    const draftPackets = buildHttpPoc(report, hyp)
    updateReportContext(report, hyp.id, {
      codeContext: codeBlocks.join("\n\n"),
      chainText,
      pocPackets: bundle?.reportContext?.pocPackets?.length ? bundle.reportContext.pocPackets : draftPackets,
    })
  }
}

function bundleFor(report: AuditReport, hyp: Hypothesis): EvidenceBundle | undefined {
  return report.evidenceBundles.find((bundle) => bundle.hypothesisId === hyp.id || bundle.id === hyp.evidenceBundleId)
}

function updateReportContext(report: AuditReport, hypothesisId: string, context: NonNullable<EvidenceBundle["reportContext"]>): void {
  const bundle = report.evidenceBundles.find((item) => item.hypothesisId === hypothesisId)
  if (!bundle) return
  bundle.reportContext = context
  bundle.updatedAt = Date.now()
}
