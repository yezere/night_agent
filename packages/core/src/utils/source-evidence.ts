import type { Hypothesis, SourceEntry, VerifierVerdict } from "../types/index.ts"

const SOURCE_SIGNAL_RE = /source|entry|route|入口|外部可控|用户可控|攻击者|attacker|request|@requestparam|@requestbody|@pathvariable|@requestheader|@cookievalue|getparameter|getparametervalues|getparametermap|getheader|getinputstream|getreader|getpart|getparts|multipart|servletrequest|httpservletrequest|param:|body:|header:|cookie:|pathvar:/i
const LINE_ANCHOR_RE = /(?:^|\s|`)[\w./\\-]+:\d+\b|\bline\s+\d+\b|第\s*\d+\s*行|L\d+\b/

export function verifierSourceEvidenceProblem(hyp: Hypothesis, verdict: VerifierVerdict): string | null {
  if (verdict.status !== "confirmed") return null
  if (hasExplicitSourceEvidence(hyp, verdict)) return null
  return "confirmed verdict lacks explicit source evidence; StaticVerifierAgent must identify an externally controllable source with file:line before confirming, not only the sink"
}

export function hasExplicitSourceEvidence(hyp: Hypothesis, verdict: VerifierVerdict): boolean {
  const facts = compactStrings([
    ...(verdict.sourceSinkTrace ?? []),
    ...(verdict.evidence ?? []),
  ])

  if (facts.some((fact) => hasLineAnchor(fact) && SOURCE_SIGNAL_RE.test(fact))) {
    return true
  }

  const sources = knownSources(hyp)
  if (sources.length > 0 && facts.some((fact) => sources.some((source) => factMentionsSource(fact, source)))) {
    return true
  }

  const flowSources = hyp.dataflowResult?.paths.flatMap((path) => path.edges.filter((edge) => edge.kind === "source")) ?? []
  if (flowSources.length > 0 && facts.some((fact) => SOURCE_SIGNAL_RE.test(fact) || /joern|dataflow|reachable/i.test(fact))) {
    return true
  }

  return false
}

export function knownSources(hyp: Hypothesis): SourceEntry[] {
  const sources: SourceEntry[] = []
  const seen = new Set<string>()
  for (const source of [
    hyp.sourceHint,
    ...(hyp.sourceLinks ?? []).map((link) => link.source),
  ]) {
    if (!source) continue
    const key = `${source.file}:${source.line}:${source.kind}:${source.paramName}`
    if (seen.has(key)) continue
    seen.add(key)
    sources.push(source)
  }
  return sources
}

function factMentionsSource(fact: string, source: SourceEntry): boolean {
  const lower = fact.toLowerCase()
  const fileLine = `${source.file}:${source.line}`.toLowerCase()
  const basenameLine = `${source.file.split("/").pop() ?? source.file}:${source.line}`.toLowerCase()
  if (lower.includes(fileLine) || lower.includes(basenameLine)) return true
  if (!SOURCE_SIGNAL_RE.test(fact)) return false

  const param = source.paramName?.toLowerCase()
  if (param && param !== "unknown" && lower.includes(param)) return true

  const sourceCode = source.code.trim().toLowerCase()
  if (sourceCode.length >= 20 && lower.includes(sourceCode.slice(0, Math.min(80, sourceCode.length)))) {
    return true
  }

  return false
}

function hasLineAnchor(value: string): boolean {
  return LINE_ANCHOR_RE.test(value)
}

function compactStrings(values: Array<string | undefined>): string[] {
  return values.map((value) => value?.trim() ?? "").filter(Boolean)
}
