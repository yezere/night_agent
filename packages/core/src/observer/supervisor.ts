import type {
  AuditReport,
  Hypothesis,
  ObserverReport,
  CheckpointResult,
  CheckpointPhase,
  CoverageGrid,
  ObserverAction,
  ProjectProfile,
  SourceEntry,
  EvidenceBundle,
} from "../types/index.ts"
import { coveragePercent } from "../context/coverage-grid.ts"
import { buildEvidenceDecisionIndex, evidenceDecisionIndexForReport, evidenceDecisionText, type EvidenceDecisionIndex } from "../graph/evidence-decision.ts"
import { verifierSourceEvidenceProblem } from "../utils/source-evidence.ts"
import { buildHttpPoc, buildHttpPocExpectation, type PocExpectation } from "../report/report-writer.ts"
import { evaluateVerifierIntegrity } from "../policies/verifier-integrity.ts"

// ─── Phase mapping for new state machine ───

function mapPhase(phase: CheckpointPhase): "bootstrap" | "explore" | "reason" {
  if (phase === "scanning" || phase === "bootstrap") return "bootstrap"
  if (phase === "tracing" || phase === "enriching" || phase === "explore") return "explore"
  return "reason"
}

// ─── Existing checks ───

interface ObserverActionPlan {
  checkpoint: CheckpointResult
  actions: ObserverAction[]
}

export function planDeduplicateHypotheses(hypotheses: Hypothesis[]): ObserverActionPlan {
  const seen = new Map<string, Hypothesis[]>()
  for (const h of hypotheses) {
    const key = `${h.sinkFile}:${h.sinkLine}:${h.sinkPattern}`
    const group = seen.get(key) ?? []
    group.push(h)
    seen.set(key, group)
  }

  const mergedIds: string[][] = []
  const actions: ObserverAction[] = []
  for (const [, group] of seen) {
    if (group.length > 1) {
      mergedIds.push(group.map((h) => h.id))
      for (let i = 1; i < group.length; i++) {
        const duplicate = group[i]!
        const primary = group[0]!
        if (duplicate.status !== "dismissed") {
          actions.push({
            kind: "dismiss-duplicate-hypothesis",
            hypothesisId: duplicate.id,
            primaryHypothesisId: primary.id,
            reason: `duplicate — merged with ${primary.id}`,
          })
        }
      }
    }
  }

  return {
    checkpoint: {
      phase: "scanning",
      check: "dedup",
      passed: mergedIds.length === 0,
      detail: mergedIds.length > 0
        ? `planned ${actions.length} duplicate dismissal(s) across ${mergedIds.length} group(s) (${mergedIds.flat().length} hypotheses)`
        : "no duplicates found",
      mergedIds: mergedIds.length > 0 ? mergedIds : undefined,
    },
    actions,
  }
}

export function deduplicateHypotheses(hypotheses: Hypothesis[]): CheckpointResult {
  return planDeduplicateHypotheses(hypotheses).checkpoint
}

export function checkScopeDrift(
  hypotheses: Hypothesis[],
  coverageGrid: CoverageGrid,
  maxImbalance: number = 3,
): CheckpointResult {
  const byFile = new Map<string, number>()
  for (const h of hypotheses.filter((h) => h.status === "tracing" || h.status === "pending")) {
    byFile.set(h.sinkFile, (byFile.get(h.sinkFile) ?? 0) + 1)
  }

  const counts = [...byFile.values()]
  if (counts.length < 2) {
    return { phase: "tracing", check: "scope-drift", passed: true, detail: "not enough files to assess drift" }
  }

  const avg = counts.reduce((a, b) => a + b, 0) / counts.length
  const max = Math.max(...counts)
  const maxFile = [...byFile.entries()].find(([, c]) => c === max)?.[0] ?? "?"

  const imbalanced = max > avg * maxImbalance
  return {
    phase: "tracing",
    check: "scope-drift",
    passed: !imbalanced,
    detail: imbalanced
      ? `scope drift: ${maxFile} has ${max} hypotheses (avg ${avg.toFixed(1)}) — consider distributing audit effort`
      : `hypothesis distribution balanced (max ${max}, avg ${avg.toFixed(1)})`,
  }
}

export function checkPrematureEnd(
  hypotheses: Hypothesis[],
  coverageGrid: CoverageGrid,
  minCoverageThreshold: number = 20,
): CheckpointResult {
  const cov = coveragePercent(coverageGrid)
  const pending = hypotheses.filter((h) => h.status === "pending").length
  const premature = cov < minCoverageThreshold && pending > 0

  return {
    phase: "reviewing",
    check: "premature-end",
    passed: !premature,
    detail: premature
      ? `premature termination warning: ${cov}% coverage with ${pending} pending hypotheses remaining`
      : `coverage ${cov}%, ${pending} pending — proceeding to report`,
  }
}

export function checkEvidenceQuality(hypotheses: Hypothesis[], decisionIndex?: EvidenceDecisionIndex, evidenceBundles: EvidenceBundle[] = []): CheckpointResult {
  const confirmedWithoutTraceOrVerifier = hypotheses.filter((h) => {
    if (h.status !== "confirmed") return false
    const decision = decisionIndex?.byHypothesisId.get(h.id)
    const hasFlow = Boolean(h.dataflowResult?.paths.length)
      || Boolean(bundleFor(h, evidenceBundles)?.dataflow?.paths.length)
      || Boolean(decision?.hasTrace || decision?.graphEdges.length)
    const verifier = bundleFor(h, evidenceBundles)?.verifierVerdict ?? h.verifierVerdict
    const hasVerifierEvidence = verifier?.status === "confirmed" && (verifier.evidence.length > 0 || verifier.checkedFiles.length > 0)
    return !hasFlow && !hasVerifierEvidence
  })
  const verifierBacked = hypotheses.filter((h) => {
    const decision = decisionIndex?.byHypothesisId.get(h.id)
    if (h.status !== "confirmed" || h.dataflowResult?.paths.length || bundleFor(h, evidenceBundles)?.dataflow?.paths.length || decision?.hasTrace) return false
    const verifier = bundleFor(h, evidenceBundles)?.verifierVerdict ?? h.verifierVerdict
    return verifier?.status === "confirmed" && (verifier.evidence.length > 0 || verifier.checkedFiles.length > 0)
  }).length

  return {
    phase: "judging",
    check: "evidence-quality",
    passed: confirmedWithoutTraceOrVerifier.length === 0,
    detail: confirmedWithoutTraceOrVerifier.length === 0
      ? verifierBacked > 0
        ? `all confirmed hypotheses include dataflow or StaticVerifier evidence (${verifierBacked} verifier-backed)`
        : "all confirmed hypotheses include dataflow evidence"
      : `${confirmedWithoutTraceOrVerifier.length} confirmed hypothesis/hypotheses lack both dataflow and StaticVerifier evidence`,
  }
}

export function checkEvidenceGraphCoverage(hypotheses: Hypothesis[], decisionIndex?: EvidenceDecisionIndex): CheckpointResult {
  if (!decisionIndex) {
    return { phase: "judging", check: "evidence-graph", passed: true, detail: "EvidenceGraph decision index unavailable for this observer run" }
  }
  const confirmed = hypotheses.filter((hyp) => hyp.status === "confirmed")
  const backed = confirmed.filter((hyp) => {
    const decision = decisionIndex.byHypothesisId.get(hyp.id)
    return Boolean(decision?.flow?.sinkNodeId && (decision.hasGraphSource || decision.flow.verifierNodeId))
  })
  const missing = confirmed.filter((hyp) => !backed.includes(hyp))

  return {
    phase: "judging",
    check: "evidence-graph",
    passed: missing.length === 0,
    detail: missing.length === 0
      ? `EvidenceGraph backs ${backed.length}/${confirmed.length} confirmed finding(s) with source/sink/verifier flow decisions`
      : `${missing.length} confirmed finding(s) lack a complete EvidenceGraph decision flow: ${missing.slice(0, 8).map((hyp) => hyp.id).join(", ")}`,
  }
}

export function checkVerifierIntegrity(hypotheses: Hypothesis[], decisionIndex?: EvidenceDecisionIndex, evidenceBundles: EvidenceBundle[] = []): CheckpointResult {
  const challenged: string[] = []
  let verifierBacked = 0

  for (const hyp of hypotheses) {
    if (hyp.status !== "confirmed") continue
    const verifier = bundleFor(hyp, evidenceBundles)?.verifierVerdict ?? hyp.verifierVerdict
    if (!verifier || verifier.status !== "confirmed") continue
    verifierBacked++

    const problems = evaluateVerifierIntegrity(hyp, verifier, {
      decisionText: evidenceDecisionText(decisionIndex?.byHypothesisId.get(hyp.id)),
      includeSourceEvidenceProblem: false,
    }).problems
    if (problems.length > 0) challenged.push(`${hyp.id}(${problems.join(", ")})`)
  }

  return {
    phase: "judging",
    check: "verifier-integrity",
    passed: challenged.length === 0,
    detail: challenged.length === 0
      ? `StaticVerifier confirmed evidence shape is valid (${verifierBacked} verifier-backed confirmed)`
      : `${challenged.length} verifier-backed confirmed finding(s) still need verifier challenge review: ${challenged.slice(0, 8).join("; ")}`,
  }
}

export function checkVerifierSourceEvidence(hypotheses: Hypothesis[], decisionIndex?: EvidenceDecisionIndex, evidenceBundles: EvidenceBundle[] = []): CheckpointResult {
  const challenged: string[] = []
  let checked = 0
  for (const hyp of hypotheses) {
    const verifier = bundleFor(hyp, evidenceBundles)?.verifierVerdict ?? hyp.verifierVerdict
    if (hyp.status !== "confirmed" || verifier?.status !== "confirmed") continue
    checked++
    const problem = verifierSourceEvidenceProblem(hyp, verifier)
    const decision = decisionIndex?.byHypothesisId.get(hyp.id)
    const graphHasSource = Boolean(decision?.hasGraphSource && decision.graphEdges.some((edge) => edge.kind === "source"))
    if (problem && !graphHasSource) challenged.push(`${hyp.id}(${problem})`)
  }

  return {
    phase: "judging",
    check: "verifier-source-evidence",
    passed: challenged.length === 0,
    detail: challenged.length === 0
      ? `StaticVerifier confirmed items include explicit source evidence (${checked} checked)`
      : `${challenged.length} confirmed verifier result(s) lack explicit source evidence: ${challenged.slice(0, 8).join("; ")}`,
  }
}

export function checkPocRouteAccuracy(report: AuditReport): CheckpointResult {
  const problems: string[] = []
  let checked = 0
  for (const hyp of pocTargets(report)) {
    const packets = pocPacketsFor(report, hyp)
    if (packets.length === 0) continue
    const expectation = buildHttpPocExpectation(report, hyp)
    if (!expectation) {
      problems.push(`${hyp.id}(missing route/source expectation)`)
      continue
    }
    for (const packet of packets) {
      checked++
      const parsed = parseHttpPacket(packet)
      if (!parsed) {
        problems.push(`${hyp.id}(invalid HTTP packet start line)`)
        continue
      }
      const actualPath = parsed.target.split("?")[0] || "/"
      if (parsed.method !== expectation.method || actualPath !== expectation.routePath) {
        problems.push(`${hyp.id}(expected ${expectation.method} ${expectation.routePath}, got ${parsed.method} ${actualPath})`)
      }
    }
  }

  return {
    phase: "reviewing",
    check: "poc-route",
    passed: problems.length === 0,
    detail: problems.length === 0
      ? `PoC route check passed for ${checked} generated packet(s)`
      : `${problems.length} PoC packet(s) have incorrect route/method: ${problems.slice(0, 8).join("; ")}`,
  }
}

export function checkPocTriggerAccuracy(report: AuditReport): CheckpointResult {
  const problems: string[] = []
  let checked = 0
  for (const hyp of pocTargets(report)) {
    const packets = pocPacketsFor(report, hyp)
    const expectation = buildHttpPocExpectation(report, hyp)
    if (!expectation) {
      problems.push(`${hyp.id}(no direct HTTP source/route for PoC)`)
      continue
    }
    if (packets.length === 0) {
      problems.push(`${hyp.id}(no generated PoC packet)`)
      continue
    }
    for (const packet of packets) {
      checked++
      const parsed = parseHttpPacket(packet)
      if (!parsed || !packetTriggersExpectation(parsed, expectation)) {
        problems.push(`${hyp.id}(packet does not trigger ${expectation.source.kind}:${expectation.paramName} via ${expectation.triggerLocation})`)
      }
    }
  }

  return {
    phase: "reviewing",
    check: "poc-trigger",
    passed: problems.length === 0,
    detail: problems.length === 0
      ? `PoC trigger check passed for ${checked} generated packet(s)`
      : `${problems.length} PoC target(s) have missing/incorrect trigger packets: ${problems.slice(0, 8).join("; ")}`,
  }
}

export function checkCoverageGap(coverageGrid: CoverageGrid): CheckpointResult {
  const unvisited = [...coverageGrid.units.values()].filter((u) => u.depth === "unvisited").length
  const ratio = coverageGrid.totalUnits === 0 ? 0 : unvisited / coverageGrid.totalUnits
  return {
    phase: "reviewing",
    check: "coverage-gap",
    passed: ratio < 0.5,
    detail: `${unvisited}/${coverageGrid.totalUnits} high-risk unit(s) unvisited`,
  }
}

// ─── New checks ───

export function checkSourceCoverage(
  sources: SourceEntry[],
  hypotheses: Hypothesis[],
): CheckpointResult {
  const filesWithSources = new Set(sources.map((s) => s.file))
  const filesWithHypotheses = new Set(hypotheses.map((h) => h.sinkFile))
  const orphanSources = [...filesWithSources].filter((f) => !filesWithHypotheses.has(f))

  return {
    phase: "enriching",
    check: "source-coverage",
    passed: orphanSources.length === 0,
    detail: orphanSources.length > 0
      ? `${orphanSources.length} file(s) have extracted sources but no associated sink hypotheses`
      : "all source files are covered by at least one hypothesis",
  }
}

export function checkSinkCoverage(hypotheses: Hypothesis[]): CheckpointResult {
  const sinkFiles = new Set(hypotheses.map((h) => h.sinkFile))
  const withoutCode = hypotheses.filter((h) => h.sinkCode.trim().length === 0)

  return {
    phase: "scanning",
    check: "sink-coverage",
    passed: hypotheses.length > 0 && withoutCode.length === 0,
    detail: hypotheses.length === 0
      ? "SinkAgent did not produce sink hypotheses"
      : withoutCode.length > 0
        ? `${withoutCode.length}/${hypotheses.length} sink hypothesis/hypotheses have no code snippet`
        : `SinkAgent produced ${hypotheses.length} sink hypothesis/hypotheses across ${sinkFiles.size} file(s)`,
  }
}

export function checkSourceSinkLinkage(
  sources: SourceEntry[],
  hypotheses: Hypothesis[],
  decisionIndex?: EvidenceDecisionIndex,
): CheckpointResult {
  return planSourceSinkLinkage(sources, hypotheses, decisionIndex).checkpoint
}

export function planSourceSinkLinkage(
  sources: SourceEntry[],
  hypotheses: Hypothesis[],
  decisionIndex?: EvidenceDecisionIndex,
): ObserverActionPlan {
  if (hypotheses.length === 0) {
    return {
      checkpoint: { phase: "enriching", check: "source-sink-linkage", passed: false, detail: "no sink hypotheses to link with sources" },
      actions: [],
    }
  }

  const coverage = hypotheses.filter((h) => {
    const decision = decisionIndex?.byHypothesisId.get(h.id)
    return (h.sourceLinks?.length ?? 0) > 0 || h.sourceHint || decision?.hasGraphSource
  }).length
  const strong = hypotheses.filter((h) => {
    const decision = decisionIndex?.byHypothesisId.get(h.id)
    return (h.sourceLinks?.[0]?.score ?? 0) >= 70 || decision?.confidence === "high"
  }).length
  const ratio = coverage / hypotheses.length
  const actions: ObserverAction[] = []
  for (const h of hypotheses) {
    const decision = decisionIndex?.byHypothesisId.get(h.id)
    const score = h.sourceLinks?.[0]?.score ?? 0
    const passed = score >= 70 || Boolean(decision?.hasGraphSource)
    const reason = decision?.hasGraphSource
      ? `EvidenceGraph source decision ${decision.confidence}: ${decision.triggerSignature}`
      : score >= 70 ? `strong source handoff score=${score}` : score > 0 ? `weak source handoff score=${score}` : "no SourceAgent handoff"
    actions.push({
      kind: "record-source-linkage-verdict",
      hypothesisId: h.id,
      passed,
      reason,
    })
  }

  return {
    checkpoint: {
      phase: "enriching",
      check: "source-sink-linkage",
      passed: sources.length === 0 ? false : ratio >= 0.3,
      detail: sources.length === 0
        ? "SourceAgent did not produce sources; report should mark source-to-sink reachability as unproven"
        : `${coverage}/${hypotheses.length} sink hypothesis/hypotheses have SourceAgent handoff links (${strong} strong)`,
    },
    actions,
  }
}

export function checkLlmDrift(rawOutput: string, expectedFormat: "yaml" | "scala"): CheckpointResult {
  let passed = true
  let detail = ""

  if (expectedFormat === "yaml") {
    const hasMarkdownFences = /^```/.test(rawOutput.trim())
    const hasPreamble = /^(here|sure|ok|let me|below is|following)/im.test(rawOutput.trim().slice(0, 100))
    const hasRulesKeyword = /^rules\s*:/m.test(rawOutput)
    passed = !hasMarkdownFences && !hasPreamble && hasRulesKeyword
    detail = hasMarkdownFences ? "output contains markdown fences"
      : hasPreamble ? "output contains commentary preamble"
      : !hasRulesKeyword ? "output missing 'rules:' keyword"
      : "LLM output format valid"
  } else if (expectedFormat === "scala") {
    const hasMarkdownFences = /^```/.test(rawOutput.trim())
    const hasImport = /^import\s/m.test(rawOutput)
    passed = !hasMarkdownFences && hasImport
    detail = hasMarkdownFences ? "output contains markdown fences"
      : !hasImport ? "output missing scala imports"
      : "LLM output format valid"
  }

  return { phase: "scanning", check: "llm-drift", passed, detail }
}

export function checkStagnation(
  hypotheses: Hypothesis[],
  previousConfirmedCount: number,
): CheckpointResult {
  const currentConfirmed = hypotheses.filter((h) => h.status === "confirmed").length
  const stagnant = currentConfirmed === previousConfirmedCount

  return {
    phase: "reviewing",
    check: "stagnation",
    passed: !stagnant,
    detail: stagnant
      ? `no new findings since last check (still ${currentConfirmed} confirmed)`
      : `progress: ${currentConfirmed - previousConfirmedCount} new confirmed finding(s)`,
  }
}

// ─── Orchestration ───

export function runObserverChecks(
  phase: CheckpointPhase,
  hypotheses: Hypothesis[],
  coverageGrid: CoverageGrid,
  extra?: {
    sources?: SourceEntry[]
    profile?: ProjectProfile
    evidenceBundles?: EvidenceBundle[]
    rawLlmOutput?: string
    llmFormat?: "yaml" | "scala"
    previousConfirmed?: number
    report?: AuditReport
    pocOnly?: boolean
  },
): ObserverReport {
  const checkpoints: CheckpointResult[] = []
  const warnings: string[] = []
  const actions: ObserverAction[] = []

  const canonical = mapPhase(phase)
  const evidenceBundles = extra?.report?.evidenceBundles ?? extra?.evidenceBundles ?? []
  const decisionIndex = extra?.report
    ? evidenceDecisionIndexForReport(extra.report)
    : extra?.profile
      ? buildEvidenceDecisionIndex({
        profile: extra.profile,
        hypotheses,
        sources: extra.sources,
        evidenceBundles,
      })
      : undefined

  if (extra?.pocOnly) {
    if (extra.report) {
      const route = checkPocRouteAccuracy(extra.report)
      checkpoints.push(route)
      if (!route.passed) warnings.push(route.detail)

      const trigger = checkPocTriggerAccuracy(extra.report)
      checkpoints.push(trigger)
      if (!trigger.passed) warnings.push(trigger.detail)
    }
    return { checkpoints, warnings }
  }

  if (canonical === "bootstrap") {
    const dedup = planDeduplicateHypotheses(hypotheses)
    checkpoints.push(dedup.checkpoint)
    actions.push(...dedup.actions)
    if (!dedup.checkpoint.passed) warnings.push(dedup.checkpoint.detail)

    const sinkCov = checkSinkCoverage(hypotheses)
    checkpoints.push(sinkCov)
    if (!sinkCov.passed) warnings.push(sinkCov.detail)

    if (extra?.sources) {
      const srcCov = checkSourceCoverage(extra.sources, hypotheses)
      checkpoints.push(srcCov)
      if (!srcCov.passed) warnings.push(srcCov.detail)

      const linkage = planSourceSinkLinkage(extra.sources, hypotheses, decisionIndex)
      checkpoints.push(linkage.checkpoint)
      actions.push(...linkage.actions)
      if (!linkage.checkpoint.passed) warnings.push(linkage.checkpoint.detail)
    }

    if (extra?.rawLlmOutput && extra?.llmFormat) {
      const drift = checkLlmDrift(extra.rawLlmOutput, extra.llmFormat)
      checkpoints.push(drift)
      if (!drift.passed) warnings.push(drift.detail)
    }
  }

  if (canonical === "explore") {
    const drift = checkScopeDrift(hypotheses, coverageGrid)
    checkpoints.push(drift)
    if (!drift.passed) warnings.push(drift.detail)

    if (extra?.sources) {
      const srcCov = checkSourceCoverage(extra.sources, hypotheses)
      checkpoints.push(srcCov)
      if (!srcCov.passed) warnings.push(srcCov.detail)
    }
  }

  if (canonical === "reason") {
    const premature = checkPrematureEnd(hypotheses, coverageGrid)
    checkpoints.push(premature)
    if (!premature.passed) warnings.push(premature.detail)

    const evidence = checkEvidenceQuality(hypotheses, decisionIndex, evidenceBundles)
    checkpoints.push(evidence)
    if (!evidence.passed) warnings.push(evidence.detail)

    const graphCoverage = checkEvidenceGraphCoverage(hypotheses, decisionIndex)
    checkpoints.push(graphCoverage)
    if (!graphCoverage.passed) warnings.push(graphCoverage.detail)

    const verifierSource = checkVerifierSourceEvidence(hypotheses, decisionIndex, evidenceBundles)
    checkpoints.push(verifierSource)
    if (!verifierSource.passed) warnings.push(verifierSource.detail)

    const verifierIntegrity = checkVerifierIntegrity(hypotheses, decisionIndex, evidenceBundles)
    checkpoints.push(verifierIntegrity)
    if (!verifierIntegrity.passed) warnings.push(verifierIntegrity.detail)

    const coverage = checkCoverageGap(coverageGrid)
    checkpoints.push(coverage)
    if (!coverage.passed) warnings.push(coverage.detail)

    if (extra?.previousConfirmed !== undefined) {
      const stag = checkStagnation(hypotheses, extra.previousConfirmed)
      checkpoints.push(stag)
      if (!stag.passed) warnings.push(stag.detail)
    }

    if (extra?.report) {
      const route = checkPocRouteAccuracy(extra.report)
      checkpoints.push(route)
      if (!route.passed) warnings.push(route.detail)

      const trigger = checkPocTriggerAccuracy(extra.report)
      checkpoints.push(trigger)
      if (!trigger.passed) warnings.push(trigger.detail)
    }
  }

  return { checkpoints, warnings, actions: actions.length ? actions : undefined }
}

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

interface ParsedHttpPacket {
  method: string
  target: string
  headers: Map<string, string>
  body: string
}

function pocTargets(report: AuditReport): Hypothesis[] {
  return report.hypotheses.filter((hyp) => hyp.status === "confirmed" && HIGH_VALUE_POC_CATEGORIES.has(hyp.category))
}

function pocPacketsFor(report: AuditReport, hyp: Hypothesis): string[] {
  const bundle = report.evidenceBundles.find((item) => item.hypothesisId === hyp.id || item.id === hyp.evidenceBundleId)
  return bundle?.reportContext?.pocPackets?.length ? bundle.reportContext.pocPackets : buildHttpPoc(report, hyp)
}

function bundleFor(hyp: Hypothesis, evidenceBundles: EvidenceBundle[]): EvidenceBundle | undefined {
  return evidenceBundles.find((bundle) => bundle.hypothesisId === hyp.id || bundle.id === hyp.evidenceBundleId)
}

function parseHttpPacket(packet: string): ParsedHttpPacket | null {
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

function packetTriggersExpectation(packet: ParsedHttpPacket, expectation: PocExpectation): boolean {
  const encodedParam = encodeURIComponent(expectation.paramName)
  const encodedPayload = encodeURIComponent(expectation.payload)
  const target = packet.target
  const path = target.split("?")[0] ?? target
  const query = target.includes("?") ? target.slice(target.indexOf("?") + 1) : ""

  if (expectation.triggerLocation === "path") {
    return path === expectation.routePath && !query.includes(`${encodedParam}=`)
  }
  if (expectation.triggerLocation === "query") {
    return requestCarriesParameter(packet, query, encodedParam, encodedPayload, expectation)
  }
  if (expectation.triggerLocation === "form") {
    return requestCarriesParameter(packet, query, encodedParam, encodedPayload, expectation)
  }
  if (expectation.triggerLocation === "body") {
    return packet.body.trim().length > 0
      && (
        packet.body.includes(expectation.payload)
        || packet.body.includes(encodedPayload)
        || packet.body.includes(`"${expectation.paramName}"`)
        || packet.body.includes(expectation.paramName)
      )
  }
  if (expectation.triggerLocation === "header") {
    return (packet.headers.get(expectation.paramName.toLowerCase()) ?? "") === expectation.payload
  }
  if (expectation.triggerLocation === "cookie") {
    return (packet.headers.get("cookie") ?? "").includes(`${expectation.paramName}=${encodedPayload}`)
  }
  if (expectation.triggerLocation === "multipart") {
    const contentType = packet.headers.get("content-type") ?? ""
    return /multipart\/form-data/i.test(contentType)
      && packet.body.includes(`name="${expectation.paramName}"`)
      && packet.body.includes(expectation.payload)
  }
  return false
}

function requestCarriesParameter(packet: ParsedHttpPacket, query: string, encodedParam: string, encodedPayload: string, expectation: PocExpectation): boolean {
  if (query.includes(`${encodedParam}=${encodedPayload}`)) return true
  if (packet.body.includes(`${encodedParam}=${encodedPayload}`)) return true
  if (packet.body.includes(`"${expectation.paramName}"`)
    && (packet.body.includes(expectation.payload) || packet.body.includes(encodedPayload) || isStructuredRequestBody(packet))) return true
  return false
}

function isStructuredRequestBody(packet: ParsedHttpPacket): boolean {
  const contentType = packet.headers.get("content-type") ?? ""
  return /json|xml|text\/plain/i.test(contentType) && !/x-www-form-urlencoded|multipart\/form-data/i.test(contentType)
}
