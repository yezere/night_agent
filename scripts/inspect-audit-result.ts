import { existsSync, readFileSync } from "node:fs"
import { dirname, resolve } from "node:path"

interface Args {
  summary?: string
  outputDir?: string
  match: string[]
  categories: Set<string>
  max: number
}

const args = parseArgs(process.argv.slice(2))
const summaryPath = args.summary
  ? resolve(args.summary)
  : args.outputDir
    ? resolve(args.outputDir, "audit-summary.json")
    : ""

if (!summaryPath || !existsSync(summaryPath)) {
  usage(`Missing audit summary. Pass --summary /path/audit-summary.json or --output-dir /path/output-audit`)
}

const report = JSON.parse(readFileSync(summaryPath, "utf-8"))
const outputDir = args.outputDir ? resolve(args.outputDir) : dirname(summaryPath)
const queries = args.match.map((item) => item.toLowerCase())

const hypotheses = Array.isArray(report.hypotheses) ? report.hypotheses : []
const sources = Array.isArray(report.sources) ? report.sources : []
const findings = Array.isArray(report.findings) ? report.findings : []

const matchedHypotheses = hypotheses.filter((hyp: any) => {
  if (args.categories.size > 0 && !args.categories.has(String(hyp.category ?? "").toLowerCase())) return false
  return matches(hyp, queries)
})

const matchedSources = sources.filter((source: any) => matches(source, queries))
const reportTexts = loadReportTexts(report)

console.log(`summary: ${summaryPath}`)
console.log(`project: ${report.profile?.name ?? "(unknown)"}`)
console.log(`hypotheses: ${hypotheses.length}, findings: ${findings.length}, sources: ${sources.length}`)
console.log(`match: ${queries.join(", ") || "(none)"}`)
if (args.categories.size > 0) console.log(`categories: ${[...args.categories].join(", ")}`)
console.log("")

console.log(`matched hypotheses: ${matchedHypotheses.length}`)
for (const hyp of matchedHypotheses.slice(0, args.max)) {
  const verifier = hyp.verifierVerdict
  const sourceLinks = Array.isArray(hyp.sourceLinks) ? hyp.sourceLinks : []
  const dataflow = hyp.dataflowResult
  const matchedFinding = findMatchingFinding(hyp, findings)
  const aiReportHit = reportTexts.ai.includes(String(hyp.id))
  const completeReportHit = reportTexts.complete.includes(String(hyp.id))
  console.log(`- ${hyp.id} ${hyp.status} ${hyp.severity}/${hyp.category} origin=${hyp.origin ?? "unknown"} finding=${matchedFinding ? matchedFinding.id : "no"} aiReport=${aiReportHit ? "yes" : "no"} complete=${completeReportHit ? "yes" : "no"}`)
  console.log(`  sink: ${hyp.sinkPattern} @ ${hyp.sinkFile}:${hyp.sinkLine}`)
  console.log(`  code: ${String(hyp.sinkCode ?? "").slice(0, 220)}`)
  if (hyp.description) console.log(`  desc: ${String(hyp.description).slice(0, 260)}`)
  if (verifier) {
    console.log(`  verifier: ${verifier.status}/${verifier.confidence} ${String(verifier.reason ?? "").slice(0, 260)}`)
    if (Array.isArray(verifier.checkedFiles) && verifier.checkedFiles.length > 0) {
      console.log(`  checked: ${verifier.checkedFiles.slice(0, 6).join(", ")}`)
    }
    if (Array.isArray(verifier.missingEvidence) && verifier.missingEvidence.length > 0) {
      console.log(`  missing: ${verifier.missingEvidence.slice(0, 3).join(" | ")}`)
    }
  }
  if (dataflow) {
    const paths = Array.isArray(dataflow.paths) ? dataflow.paths.length : 0
    const sanitizers = Array.isArray(dataflow.sanitizers) ? dataflow.sanitizers.map((s: any) => s.kind).join(", ") : ""
    console.log(`  dataflow: reachable=${Boolean(dataflow.reachable)} confidence=${dataflow.confidence ?? "unknown"} paths=${paths} sanitizers=${sanitizers || "none"}`)
  }
  if (sourceLinks.length > 0) {
    for (const link of sourceLinks.slice(0, 3)) {
      const source = link.source ?? {}
      console.log(`  source: score=${link.score ?? "?"} ${source.kind ?? "?"}:${source.paramName ?? "?"} @ ${source.file ?? "?"}:${source.line ?? "?"}`)
    }
  }
  if (matchedFinding) {
    console.log(`  finding-source: ${matchedFinding.source?.kind ?? "?"} @ ${matchedFinding.source?.file ?? "?"}:${matchedFinding.source?.line ?? "?"}`)
    console.log(`  finding-sink: ${matchedFinding.sink?.kind ?? "?"} @ ${matchedFinding.sink?.file ?? "?"}:${matchedFinding.sink?.line ?? "?"}`)
  }
}
if (matchedHypotheses.length > args.max) console.log(`  ... ${matchedHypotheses.length - args.max} more`)
console.log("")

console.log(`matched sources: ${matchedSources.length}`)
for (const source of matchedSources.slice(0, args.max)) {
  console.log(`- ${source.kind}:${source.paramName} origin=${source.origin ?? "unknown"} @ ${source.file}:${source.line}`)
  console.log(`  code: ${String(source.code ?? "").slice(0, 220)}`)
}
if (matchedSources.length > args.max) console.log(`  ... ${matchedSources.length - args.max} more`)
console.log("")

const tracePath = resolve(outputDir, "llm-debug", "llm-tool-trace.jsonl")
if (existsSync(tracePath)) {
  const traceLines = readFileSync(tracePath, "utf-8").split("\n").filter(Boolean)
  const hypIds = new Set(matchedHypotheses.map((hyp: any) => String(hyp.id)))
  const matchedTrace = traceLines
    .map((line) => safeJson(line))
    .filter((event) => event && (matches(event, queries) || hypIds.has(String(event.hypothesisId ?? ""))))
  console.log(`matched tool trace: ${matchedTrace.length} (${tracePath})`)
  for (const event of matchedTrace.slice(0, args.max * 2)) {
    const call = event.call ? JSON.stringify(event.call).slice(0, 220) : ""
    const head = event.observationHead ? String(event.observationHead).replace(/\n/g, " ").slice(0, 220) : ""
    console.log(`- ${event.at ?? ""} ${event.agent ?? ""} ${event.hypothesisId ?? ""} step=${event.step ?? ""} ${event.type ?? ""} ${call}`)
    if (head) console.log(`  obs: ${head}`)
  }
  if (matchedTrace.length > args.max * 2) console.log(`  ... ${matchedTrace.length - args.max * 2} more`)
} else {
  console.log(`matched tool trace: unavailable (${tracePath})`)
}

function parseArgs(argv: string[]): Args {
  const parsed: Args = { match: [], categories: new Set(), max: 20 }
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]
    if (arg === "--summary") parsed.summary = argv[++i]
    else if (arg === "--output-dir") parsed.outputDir = argv[++i]
    else if (arg === "--match") parsed.match.push(argv[++i] ?? "")
    else if (arg === "--category") {
      for (const item of String(argv[++i] ?? "").split(",")) {
        if (item.trim()) parsed.categories.add(item.trim().toLowerCase())
      }
    } else if (arg === "--max") {
      const max = parseInt(argv[++i] ?? "", 10)
      if (Number.isFinite(max) && max > 0) parsed.max = max
    } else if (arg.trim()) {
      parsed.match.push(arg)
    }
  }
  parsed.match = parsed.match.filter(Boolean)
  return parsed
}

function matches(value: unknown, needles: string[]): boolean {
  if (needles.length === 0) return true
  const text = JSON.stringify(value ?? {}).toLowerCase()
  return needles.some((needle) => text.includes(needle))
}

function safeJson(line: string): any | null {
  try {
    return JSON.parse(line)
  } catch {
    return null
  }
}

function loadReportTexts(report: any): { ai: string; complete: string } {
  const generatedFiles = Array.isArray(report.generatedFiles) ? report.generatedFiles.map(String) : []
  const aiPath = generatedFiles.find((file) => file.endsWith("审计报告.md"))
  const completePath = generatedFiles.find((file) => file.endsWith("完整结果.md"))
  return {
    ai: String(report.markdownReport ?? "") + (aiPath && existsSync(aiPath) ? `\n${readFileSync(aiPath, "utf-8")}` : ""),
    complete: completePath && existsSync(completePath) ? readFileSync(completePath, "utf-8") : "",
  }
}

function findMatchingFinding(hyp: any, findings: any[]): any | undefined {
  const sinkFile = String(hyp.sinkFile ?? "")
  const sinkLine = Number(hyp.sinkLine ?? -1)
  const category = String(hyp.category ?? "")
  return findings.find((finding) => {
    const findingFile = String(finding?.sink?.file ?? "")
    const findingLine = Number(finding?.sink?.line ?? -9999)
    const findingCategory = String(finding?.category ?? "")
    if (findingFile !== sinkFile || findingCategory !== category) return false
    return Math.abs(findingLine - sinkLine) <= 3
  }) ?? findings.find((finding) => {
    const findingFile = String(finding?.sink?.file ?? "")
    const findingCategory = String(finding?.category ?? "")
    const findingSnippet = String(finding?.sink?.snippet ?? "")
    return findingFile === sinkFile
      && findingCategory === category
      && (findingSnippet === String(hyp.sinkCode ?? "") || Math.abs(Number(finding?.sink?.line ?? -9999) - sinkLine) <= 20)
  })
}

function usage(message: string): never {
  console.error(message)
  console.error("usage: bun run scripts/inspect-audit-result.ts --summary output/audit-summary.json --match SysLicenseController --category file-download,path-traversal")
  process.exit(1)
}
