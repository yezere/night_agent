import { relative } from "node:path"
import { buildEvidenceDecisionIndex, type EvidenceFlowDecision } from "../graph/evidence-decision.ts"
import type { DataflowEdge, EvidenceBundle, Hypothesis, ProjectProfile, SourceEntry, SourceLink } from "../types/index.ts"
import { compareSeverity, SEVERITY_ORDER } from "../types/index.ts"

export const VERIFIER_HIGH_VALUE_CATEGORIES = new Set([
  "cmdi",
  "sqli",
  "file-download",
  "file-upload",
  "path-traversal",
  "ssti",
  "spel",
  "ognl",
  "expression",
  "deser",
  "ssrf",
  "jndi",
])

export interface VerifierPriorityItem {
  hypothesis: Hypothesis
  score: number
  reasons: string[]
  identityKey: string
  representativeId?: string
  deferredReason?: string
}

export interface VerifierPriorityPlan {
  selected: VerifierPriorityItem[]
  deferred: VerifierPriorityItem[]
  items: VerifierPriorityItem[]
  maxSelected: number
  duplicateGroups: number
}

export interface VerifierPriorityInputs {
  profile: ProjectProfile
  candidates: Hypothesis[]
  sources: SourceEntry[]
  evidenceBundles: EvidenceBundle[]
  maxSelected?: number
  duplicateRepresentatives?: number
}

export function defaultVerifierMaxSelected(total: number): number {
  if (total <= 80) return total
  return Math.max(80, Math.ceil(total * 0.6))
}

export function buildVerifierPriorityPlan(inputs: VerifierPriorityInputs): VerifierPriorityPlan {
  const { profile, candidates, sources, evidenceBundles } = inputs
  const maxSelected = clampNumber(inputs.maxSelected, 1, Math.max(1, candidates.length), defaultVerifierMaxSelected(candidates.length))
  const duplicateRepresentatives = clampNumber(inputs.duplicateRepresentatives, 1, 4, 1)
  const bundleByHypothesis = new Map(evidenceBundles.map((bundle) => [bundle.hypothesisId, bundle]))
  const decisionIndex = buildEvidenceDecisionIndex({ profile, hypotheses: candidates, sources, evidenceBundles })
  const items: VerifierPriorityItem[] = candidates.map((hypothesis) => {
    const bundle = bundleByHypothesis.get(hypothesis.id)
    const decision = decisionIndex.byHypothesisId.get(hypothesis.id)
    const scored = scoreCandidate(hypothesis, bundle, decision)
    return {
      hypothesis,
      score: scored.score,
      reasons: scored.reasons,
      identityKey: decision?.identitySignature || fallbackIdentityKey(profile, hypothesis),
    }
  })

  const byIdentity = new Map<string, VerifierPriorityItem[]>()
  for (const item of items) {
    const group = byIdentity.get(item.identityKey) ?? []
    group.push(item)
    byIdentity.set(item.identityKey, group)
  }

  const selected = new Set<string>()
  const deferredReasons = new Map<string, string>()
  let duplicateGroups = 0

  const intermediateFlowDeferrals = planIntermediateFlowDeferrals(profile, items, bundleByHypothesis, decisionIndex.byHypothesisId)
  for (const [hypothesisId, deferral] of intermediateFlowDeferrals) {
    selected.add(deferral.representative.hypothesis.id)
    deferredReasons.set(hypothesisId, deferral.reason)
  }

  for (const group of byIdentity.values()) {
    group.sort(comparePriorityItems)
    if (group.length <= 1) continue
    duplicateGroups++
    const representatives = Math.min(duplicateRepresentatives, group.length)
    for (let idx = 0; idx < group.length; idx++) {
      const item = group[idx]!
      const representative = group[0]!
      if (deferredReasons.has(item.hypothesis.id)) continue
      item.representativeId = representative.hypothesis.id
      if (idx < representatives) {
        selected.add(item.hypothesis.id)
        continue
      }
      deferredReasons.set(
        item.hypothesis.id,
        `deferred duplicate candidate; verifier will review representative ${representative.hypothesis.id} for same evidence identity`,
      )
    }
  }

  const ranked = [...items].sort(comparePriorityItems)
  for (const item of ranked) {
    if (deferredReasons.has(item.hypothesis.id)) continue
    if (selected.has(item.hypothesis.id)) continue
    if (selected.size < maxSelected || mustVerify(item)) {
      selected.add(item.hypothesis.id)
      continue
    }
    deferredReasons.set(
      item.hypothesis.id,
      `deferred by verifier priority budget (${maxSelected}/${candidates.length}); score=${item.score}, reasons=${item.reasons.slice(0, 4).join(", ")}`,
    )
  }

  const selectedItems: VerifierPriorityItem[] = []
  const deferredItems: VerifierPriorityItem[] = []
  for (const item of ranked) {
    const deferredReason = deferredReasons.get(item.hypothesis.id)
    if (deferredReason) {
      item.deferredReason = deferredReason
      deferredItems.push(item)
    } else {
      selectedItems.push(item)
    }
  }

  return { selected: selectedItems, deferred: deferredItems, items: ranked, maxSelected, duplicateGroups }
}

interface IntermediateFlowProfile {
  item: VerifierPriorityItem
  sinkFile: string
  sinkLine: number
  intermediateEdges: DataflowEdge[]
  sourceKeys: Set<string>
  routeSignature: string
  triggerSignature: string
  hasReachableTrace: boolean
  edgeCount: number
}

function planIntermediateFlowDeferrals(
  profile: ProjectProfile,
  items: VerifierPriorityItem[],
  bundleByHypothesis: Map<string, EvidenceBundle>,
  decisions: Map<string, EvidenceFlowDecision>,
): Map<string, { representative: VerifierPriorityItem; reason: string }> {
  const profiles = items.map((item) => intermediateFlowProfile(profile, item, bundleByHypothesis.get(item.hypothesis.id), decisions.get(item.hypothesis.id)))
  const deferrals = new Map<string, { representative: VerifierPriorityItem; reason: string }>()

  for (const target of profiles) {
    const representatives = profiles
      .filter((candidate) => candidate.item.hypothesis.id !== target.item.hypothesis.id)
      .filter((candidate) => coversIntermediateSink(profile, candidate, target))
      .sort(compareFlowRepresentatives)
    const representative = representatives[0]
    if (!representative) continue
    if (!canDeferIntermediate(target, representative)) continue
    deferrals.set(target.item.hypothesis.id, {
      representative: representative.item,
      reason: `deferred intermediate-flow candidate; verifier will review downstream representative ${representative.item.hypothesis.id} whose source-to-final-sink evidence path already contains this sink as an intermediate hop`,
    })
    target.item.representativeId = representative.item.hypothesis.id
  }

  return deferrals
}

function intermediateFlowProfile(
  profile: ProjectProfile,
  item: VerifierPriorityItem,
  bundle: EvidenceBundle | undefined,
  decision: EvidenceFlowDecision | undefined,
): IntermediateFlowProfile {
  const hyp = item.hypothesis
  const dataflow = bundle?.dataflow ?? hyp.dataflowResult
  const intermediateEdges = (dataflow?.paths ?? [])
    .flatMap((path) => path.edges)
    .filter((edge) => edge.kind === "propagation" || edge.kind === "sanitizer")
    .filter((edge) => !sameLocation(profile, edge.file, edge.line, hyp.sinkFile, hyp.sinkLine, 0))
  const links = bundle?.sourceLinks ?? hyp.sourceLinks ?? []
  return {
    item,
    sinkFile: hyp.sinkFile,
    sinkLine: hyp.sinkLine,
    intermediateEdges,
    sourceKeys: sourceKeys(profile, links, bundle?.selectedSource ?? hyp.sourceHint),
    routeSignature: decision?.routeSignature ?? "",
    triggerSignature: decision?.triggerSignature ?? "",
    hasReachableTrace: Boolean(dataflow?.reachable),
    edgeCount: (dataflow?.paths ?? []).reduce((sum, path) => sum + path.edges.length, 0),
  }
}

function coversIntermediateSink(profile: ProjectProfile, candidate: IntermediateFlowProfile, target: IntermediateFlowProfile): boolean {
  if (candidate.intermediateEdges.length === 0) return false
  if (!compatibleIntermediateCategory(target.item.hypothesis.category, candidate.item.hypothesis.category)) return false
  if (!sameFlowTrigger(candidate, target)) return false
  return candidate.intermediateEdges.some((edge) => sameLocation(profile, edge.file, edge.line, target.sinkFile, target.sinkLine, 1))
}

function sameFlowTrigger(a: IntermediateFlowProfile, b: IntermediateFlowProfile): boolean {
  if (a.routeSignature && b.routeSignature && a.routeSignature === b.routeSignature) return true
  if (a.triggerSignature && b.triggerSignature && a.triggerSignature === b.triggerSignature) return true
  for (const key of a.sourceKeys) if (b.sourceKeys.has(key)) return true
  return false
}

function canDeferIntermediate(target: IntermediateFlowProfile, representative: IntermediateFlowProfile): boolean {
  if (!representative.hasReachableTrace) return false
  if (target.hasReachableTrace && target.edgeCount > representative.edgeCount) return false
  if (mustVerify(target.item) && representative.item.score + 80 < target.item.score) return false
  return true
}

function compareFlowRepresentatives(a: IntermediateFlowProfile, b: IntermediateFlowProfile): number {
  return Number(b.hasReachableTrace) - Number(a.hasReachableTrace)
    || b.edgeCount - a.edgeCount
    || comparePriorityItems(a.item, b.item)
}

function compatibleIntermediateCategory(targetCategory: string, representativeCategory: string): boolean {
  if (targetCategory === representativeCategory) return true
  if (targetCategory === "other") return true
  return categoryFamily(targetCategory) === categoryFamily(representativeCategory)
}

function categoryFamily(category: string): string {
  if (category === "file-download" || category === "path-traversal") return "file-read"
  if (category === "ssti" || category === "spel" || category === "ognl" || category === "expression") return "expression"
  return category
}

function sourceKeys(profile: ProjectProfile, links: SourceLink[], selectedSource?: SourceEntry): Set<string> {
  const keys = new Set<string>()
  if (selectedSource) keys.add(sourceKey(profile, selectedSource))
  for (const link of links.filter((item) => item.score >= 80).slice(0, 4)) {
    keys.add(sourceKey(profile, link.source))
  }
  if (keys.size === 0 && links[0] && links[0].score >= 60) {
    keys.add(sourceKey(profile, links[0].source))
  }
  return keys
}

function sourceKey(profile: ProjectProfile, source: SourceEntry): string {
  return [
    fileKey(profile, source.file),
    source.line,
    source.kind,
    normalizeToken(source.paramName || "unknown"),
  ].join(":")
}

function sameLocation(profile: ProjectProfile, leftFile: string, leftLine: number, rightFile: string, rightLine: number, tolerance: number): boolean {
  return fileKey(profile, leftFile) === fileKey(profile, rightFile)
    && Math.abs(Math.max(1, leftLine) - Math.max(1, rightLine)) <= tolerance
}

function fileKey(profile: ProjectProfile, file: string): string {
  const normalized = file.replace(/\\/g, "/")
  const root = profile.root.replace(/\\/g, "/").replace(/\/+$/, "")
  return (normalized.startsWith(`${root}/`) ? normalized.slice(root.length + 1) : normalized).replace(/^\/+/, "").toLowerCase()
}

function normalizeToken(value: string): string {
  return value.trim().toLowerCase().replace(/\s+/g, " ")
}

function scoreCandidate(
  hyp: Hypothesis,
  bundle: EvidenceBundle | undefined,
  decision: EvidenceFlowDecision | undefined,
): { score: number; reasons: string[] } {
  const reasons: string[] = []
  let score = 0

  const severityScore = severityPriority(hyp.severity)
  score += severityScore
  reasons.push(`severity:${hyp.severity}+${severityScore}`)

  if (VERIFIER_HIGH_VALUE_CATEGORIES.has(hyp.category)) {
    score += 90
    reasons.push(`high-value:${hyp.category}+90`)
  }

  if (hyp.origin === "joern" || hyp.origin === "joern-ai") {
    score += 80
    reasons.push(`origin:${hyp.origin}+80`)
  } else if (hyp.origin === "ai-first") {
    score += 35
    reasons.push("origin:ai-first+35")
  } else if (hyp.origin === "pre-scan") {
    score -= 15
    reasons.push("origin:pre-scan-15")
  }

  const sourceScore = Math.max(
    0,
    ...(bundle?.sourceLinks ?? hyp.sourceLinks ?? []).map((link) => link.score),
  )
  if (sourceScore > 0) {
    const delta = Math.min(120, Math.round(sourceScore * 1.2))
    score += delta
    reasons.push(`source-link:${sourceScore}+${delta}`)
  }

  if (bundle?.route || decision?.hasGraphRoute) {
    score += 35
    reasons.push("route+35")
  }
  if (bundle?.selectedSource || decision?.hasGraphSource) {
    score += 55
    reasons.push("source+55")
  }
  if (decision?.hasTrace || hyp.dataflowResult?.reachable) {
    score += 120
    reasons.push("trace+120")
  }
  if (decision?.confidence === "high") {
    score += 35
    reasons.push("graph-confidence:high+35")
  } else if (decision?.confidence === "medium") {
    score += 15
    reasons.push("graph-confidence:medium+15")
  }

  if (bundle?.observerVerdict?.passed) {
    score += 25
    reasons.push("observer-linkage-pass+25")
  } else if (bundle?.observerVerdict && !bundle.observerVerdict.passed) {
    score -= 25
    reasons.push("observer-linkage-weak-25")
  }

  if (!hyp.sinkCode.trim()) {
    score -= 50
    reasons.push("missing-sink-code-50")
  }

  if (hyp.category === "xss" || hyp.category === "file-download" || hyp.category === "deser") {
    score -= 15
    reasons.push(`noisy-bucket:${hyp.category}-15`)
  }

  return { score, reasons }
}

function severityPriority(severity: Hypothesis["severity"]): number {
  const rank = SEVERITY_ORDER[severity] ?? SEVERITY_ORDER.medium
  return 500 - rank * 110
}

function mustVerify(item: VerifierPriorityItem): boolean {
  const hyp = item.hypothesis
  if (hyp.severity === "critical" && item.score >= 580) return true
  if ((hyp.origin === "joern" || hyp.origin === "joern-ai") && compareSeverity(hyp.severity, "high") <= 0) return true
  if ((hyp.dataflowResult?.reachable || item.reasons.some((reason) => reason.startsWith("trace+"))) && compareSeverity(hyp.severity, "high") <= 0) return true
  return false
}

function comparePriorityItems(a: VerifierPriorityItem, b: VerifierPriorityItem): number {
  return b.score - a.score
    || compareSeverity(a.hypothesis.severity, b.hypothesis.severity)
    || a.hypothesis.sinkFile.localeCompare(b.hypothesis.sinkFile)
    || a.hypothesis.sinkLine - b.hypothesis.sinkLine
    || a.hypothesis.id.localeCompare(b.hypothesis.id)
}

function fallbackIdentityKey(profile: ProjectProfile, hyp: Hypothesis): string {
  const rel = hyp.sinkFile.startsWith(profile.root) ? relative(profile.root, hyp.sinkFile) : hyp.sinkFile
  const bucket = Math.floor(Math.max(0, hyp.sinkLine) / 40)
  return [
    hyp.category,
    rel,
    bucket,
    normalizeSinkSignature(hyp.sinkPattern || hyp.sinkCode),
  ].join("|")
}

function normalizeSinkSignature(value: string): string {
  return value
    .toLowerCase()
    .replace(/"[^"]*"|'[^']*'/g, "\"?\"")
    .replace(/\b[a-z_$][\w$]*\b/g, (token) => {
      if (/^(runtime|processbuilder|statement|preparedstatement|template|file|files|paths|json|objectmapper|resttemplate|url|httpurlconnection|groovyclassloader|scriptengine)$/i.test(token)) return token
      return "v"
    })
    .replace(/\s+/g, " ")
    .slice(0, 120)
}

function clampNumber(value: unknown, min: number, max: number, fallback: number): number {
  const parsed = typeof value === "number" ? value : Number.parseInt(String(value ?? ""), 10)
  if (!Number.isFinite(parsed)) return Math.max(min, Math.min(max, fallback))
  return Math.max(min, Math.min(max, parsed))
}
