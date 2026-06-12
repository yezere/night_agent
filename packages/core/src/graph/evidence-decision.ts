import { resolve } from "node:path"
import { buildEvidenceGraph, type EvidenceConfidence, type EvidenceGraphArtifact, type EvidenceNode, type TaintFlow } from "./evidence-graph.ts"
import type {
  AuditReport,
  DataflowEdge,
  DataflowTrace,
  EvidenceBundle,
  Finding,
  Hypothesis,
  ProjectProfile,
  RouteEntry,
  SourceEntry,
  SourceParamKind,
} from "../types/index.ts"

export interface EvidenceDecisionInput {
  profile: ProjectProfile
  hypotheses: Hypothesis[]
  sources?: SourceEntry[]
  evidenceBundles?: EvidenceBundle[]
  findings?: Finding[]
}

export interface EvidenceFlowDecision {
  hypothesisId: string
  flow?: TaintFlow
  status: TaintFlow["status"] | "none"
  confidence: EvidenceConfidence
  route?: RouteEntry
  source?: SourceEntry
  paramName?: string
  hasTrace: boolean
  hasGraphRoute: boolean
  hasGraphSource: boolean
  routeSignature: string
  triggerSignature: string
  identitySignature: string
  graphFacts: string[]
  graphEdges: DataflowEdge[]
}

export interface EvidenceDecisionIndex {
  graph: EvidenceGraphArtifact
  byHypothesisId: Map<string, EvidenceFlowDecision>
}

const reportDecisionCache = new WeakMap<AuditReport, EvidenceDecisionIndex>()

export function evidenceDecisionIndexForReport(report: AuditReport): EvidenceDecisionIndex {
  const cached = reportDecisionCache.get(report)
  if (cached) return cached
  const index = buildEvidenceDecisionIndex({
    profile: report.profile,
    hypotheses: report.hypotheses,
    sources: report.sources,
    evidenceBundles: report.evidenceBundles,
    findings: report.findings,
  })
  reportDecisionCache.set(report, index)
  return index
}

export function evidenceDecisionForReport(report: AuditReport, hyp: Hypothesis): EvidenceFlowDecision {
  const index = evidenceDecisionIndexForReport(report)
  return index.byHypothesisId.get(hyp.id) ?? emptyDecision(hyp)
}

export function buildEvidenceDecisionIndex(input: EvidenceDecisionInput): EvidenceDecisionIndex {
  const bundles = mergedBundles(input.evidenceBundles ?? [])
  const graph = buildEvidenceGraph({
    profile: input.profile,
    hypotheses: input.hypotheses,
    evidenceBundles: bundles,
    findings: input.findings ?? [],
    sources: input.sources ?? [],
  })
  const nodes = new Map(graph.nodes.map((node) => [node.id, node]))
  const flowsByHypothesis = new Map<string, TaintFlow[]>()
  for (const flow of graph.taintFlows) {
    const group = flowsByHypothesis.get(flow.hypothesisId) ?? []
    group.push(flow)
    flowsByHypothesis.set(flow.hypothesisId, group)
  }

  const byHypothesisId = new Map<string, EvidenceFlowDecision>()
  for (const hyp of input.hypotheses) {
    const bundle = bundles.find((item) => item.hypothesisId === hyp.id || item.id === hyp.evidenceBundleId)
    const flow = selectPrimaryFlow(flowsByHypothesis.get(hyp.id) ?? [])
    byHypothesisId.set(hyp.id, decisionFromFlow(input.profile, hyp, bundle, flow, nodes))
  }
  return { graph, byHypothesisId }
}

export function traceFromEvidenceDecision(
  decision: EvidenceFlowDecision | undefined,
  confidence: DataflowTrace["confidence"] = "medium",
): DataflowTrace | undefined {
  if (!decision?.graphEdges.length) return undefined
  return {
    reachable: true,
    confidence,
    sanitizers: decision.graphEdges
      .filter((edge) => edge.kind === "sanitizer")
      .map((edge) => ({ kind: "graph-sanitizer", file: edge.file, line: edge.line, code: edge.code })),
    paths: [{
      sourceLabel: decision.source
        ? `${decision.source.kind}:${decision.source.paramName || "(unnamed)"}`
        : "EvidenceGraph source",
      sinkLabel: "EvidenceGraph sink",
      edges: decision.graphEdges,
    }],
  }
}

export function evidenceDecisionText(decision: EvidenceFlowDecision | undefined): string {
  if (!decision) return ""
  return [
    decision.routeSignature,
    decision.source ? `${decision.source.kind}:${decision.source.paramName} ${decision.source.code}` : "",
    decision.paramName,
    ...decision.graphFacts,
    ...decision.graphEdges.map((edge) => `${edge.kind} ${edge.file}:${edge.line} ${edge.code}`),
  ].filter(Boolean).join("\n")
}

function decisionFromFlow(
  profile: ProjectProfile,
  hyp: Hypothesis,
  bundle: EvidenceBundle | undefined,
  flow: TaintFlow | undefined,
  nodes: Map<string, EvidenceNode>,
): EvidenceFlowDecision {
  const route = routeFromFlow(profile, flow, nodes) ?? bundle?.route
  const source = sourceFromFlow(profile, flow, nodes, bundle, hyp)
    ?? bundle?.selectedSource
    ?? bundle?.sourceLinks[0]?.source
    ?? hyp.sourceHint
    ?? hyp.sourceLinks?.[0]?.source
  const graphEdges = graphEdgesFromFlow(profile, hyp, flow, nodes)
  const graphFacts = graphFactsFromFlow(flow, nodes)
  const sourceParam = sourceParamName(source)
  const inferredParam = inferParamName(hyp, graphFacts.join("\n"))
  const paramName = preferredParamName(sourceParam, inferredParam)
  const triggerKind = triggerKindFor(source, sourceParam, paramName)
  const routeSignature = route ? `${route.method.toUpperCase()} ${normalizeRoutePath(route.path)}` : ""
  const triggerSignature = [
    routeSignature,
    source ? `${triggerKind}:${paramName || source.paramName || "unknown"}` : paramName ? `param:${paramName}` : "",
  ].filter(Boolean).join("|") || inferTriggerSignature(hyp, graphFacts.join("\n"))
  const sinkBucket = Math.floor(Math.max(0, hyp.sinkLine) / 80)
  const sinkSignature = `${relativeOrOriginal(profile, hyp.sinkFile)}:${sinkBucket}:${semanticSink(hyp)}`

  return {
    hypothesisId: hyp.id,
    flow,
    status: flow?.status ?? "none",
    confidence: flow?.confidence ?? "low",
    route,
    source,
    paramName,
    hasTrace: Boolean(flow?.hops.some((hop) => hop.role === "transform" || hop.role === "sanitizer") || graphEdges.length >= 2),
    hasGraphRoute: Boolean(flow?.routeNodeId || flow?.hops.some((hop) => hop.role === "route")),
    hasGraphSource: Boolean(flow?.sourceNodeId || flow?.hops.some((hop) => hop.role === "source") || source),
    routeSignature,
    triggerSignature,
    identitySignature: [
      hyp.category,
      routeSignature || relativeOrOriginal(profile, hyp.sinkFile),
      triggerSignature,
      sinkSignature,
    ].filter(Boolean).join("|"),
    graphFacts,
    graphEdges,
  }
}

function preferredParamName(sourceParam: string | undefined, inferredParam: string | undefined): string | undefined {
  if (!sourceParam) return inferredParam
  if (!inferredParam || sourceParam === inferredParam) return sourceParam
  const generic = new Set(["request", "requesturi", "paramname", "method", "path", "this", "self", "body"])
  return generic.has(sourceParam.toLowerCase()) ? inferredParam : sourceParam
}

function triggerKindFor(source: SourceEntry | undefined, sourceParam: string | undefined, paramName: string | undefined): string {
  if (!source) return "param"
  if (paramName && sourceParam && paramName !== sourceParam) {
    return source.kind === "body" || source.kind === "input-stream" ? "body" : "param"
  }
  return source.kind
}

function selectPrimaryFlow(flows: TaintFlow[]): TaintFlow | undefined {
  return [...flows].sort((a, b) => flowRank(b) - flowRank(a)
    || b.hops.length - a.hops.length
    || a.id.localeCompare(b.id))[0]
}

function flowRank(flow: TaintFlow): number {
  const statusRank: Record<TaintFlow["status"], number> = {
    confirmed: 60,
    verified: 50,
    traced: 40,
    candidate: 25,
    blocked: 15,
    unknown: 0,
  }
  const confidenceRank: Record<EvidenceConfidence, number> = { high: 8, medium: 4, low: 0 }
  return statusRank[flow.status]
    + confidenceRank[flow.confidence]
    + (flow.routeNodeId ? 6 : 0)
    + (flow.sourceNodeId ? 6 : 0)
}

function routeFromFlow(
  profile: ProjectProfile,
  flow: TaintFlow | undefined,
  nodes: Map<string, EvidenceNode>,
): RouteEntry | undefined {
  const node = flow?.routeNodeId ? nodes.get(flow.routeNodeId) : flow?.hops.map((hop) => nodes.get(hop.nodeId)).find((item) => item?.kind === "route")
  if (!node) return undefined
  const data = node.data ?? {}
  const method = stringData(data.method) ?? node.label.split(/\s+/)[0] ?? "GET"
  const path = stringData(data.path) ?? node.label.replace(/^[A-Z,\s|]+\s+/, "") ?? "/"
  return {
    method,
    path: normalizeRoutePath(path),
    sourceFile: node.location?.file ?? "",
    line: node.location?.line ?? 1,
    className: stringData(data.className),
    authHint: stringData(data.authHint),
  }
}

function sourceFromFlow(
  profile: ProjectProfile,
  flow: TaintFlow | undefined,
  nodes: Map<string, EvidenceNode>,
  bundle: EvidenceBundle | undefined,
  hyp: Hypothesis,
): SourceEntry | undefined {
  const node = flow?.sourceNodeId
    ? nodes.get(flow.sourceNodeId)
    : flow?.hops.map((hop) => nodes.get(hop.nodeId)).find((item) => item?.kind === "source")
  if (!node) return undefined
  const matched = matchSourceNode(profile, node, [
    ...(bundle?.selectedSource ? [bundle.selectedSource] : []),
    ...(bundle?.sourceLinks ?? []).map((link) => link.source),
    ...(hyp.sourceHint ? [hyp.sourceHint] : []),
    ...(hyp.sourceLinks ?? []).map((link) => link.source),
  ])
  if (matched) return matched
  const data = node.data ?? {}
  const explicitParam = stringData(data.paramName)
  if (!explicitParam && isUnhelpfulDataflowSource(node)) return undefined
  const kind = sourceKindData(data.kind) ?? "param"
  const paramName = explicitParam ?? inferParamName(hyp, `${node.label}\n${node.code ?? ""}\n${node.facts?.join("\n") ?? ""}`) ?? "unknown"
  return {
    id: stringData(data.sourceId) ?? node.id,
    kind,
    paramName,
    file: projectFile(profile, node.location?.file ?? hyp.sinkFile),
    line: node.location?.line ?? hyp.sinkLine,
    code: node.code ?? node.label,
    methodName: stringData(data.methodName) ?? "evidence-graph-source",
    className: stringData(data.className),
    origin: "joern",
  }
}

function isUnhelpfulDataflowSource(node: EvidenceNode): boolean {
  const text = `${node.label}\n${node.code ?? ""}\n${node.facts?.join("\n") ?? ""}`.toLowerCase()
  if (/^\s*(this|self)\s*$/.test(node.code ?? "")) return true
  return !/requestparam|requestbody|pathvariable|getparameter|getheader|getcookies?|multipartfile|getpart|getinputstream|getreader|param=|kind=param|kind=body|kind=pathvar|kind=header|kind=cookie/.test(text)
}

function matchSourceNode(profile: ProjectProfile, node: EvidenceNode, sources: SourceEntry[]): SourceEntry | undefined {
  const file = projectFile(profile, node.location?.file ?? "")
  const line = node.location?.line
  const param = stringData(node.data?.paramName)
  return sources.find((source) =>
    sameFile(profile, source.file, file)
      && (!line || source.line === line)
      && (!param || source.paramName === param)
  ) ?? sources.find((source) => sameFile(profile, source.file, file) && (!line || Math.abs(source.line - line) <= 3))
}

function graphEdgesFromFlow(
  profile: ProjectProfile,
  hyp: Hypothesis,
  flow: TaintFlow | undefined,
  nodes: Map<string, EvidenceNode>,
): DataflowEdge[] {
  const edges: DataflowEdge[] = []
  for (const hop of flow?.hops ?? []) {
    if (hop.role === "route" || hop.role === "verifier" || hop.role === "poc") continue
    const node = nodes.get(hop.nodeId)
    const location = hop.location ?? node?.location
    if (!location) continue
    edges.push({
      file: projectFile(profile, location.file),
      line: location.line,
      code: hop.code ?? node?.code ?? "",
      kind: hop.role === "sink" ? "sink"
        : hop.role === "source" ? "source"
        : hop.role === "sanitizer" ? "sanitizer"
        : "propagation",
    })
  }
  if (edges.length > 0) return dedupeEdges(edges)
  return [{
    file: projectFile(profile, hyp.sinkFile),
    line: hyp.sinkLine,
    code: hyp.sinkCode,
    kind: "sink",
  }]
}

function graphFactsFromFlow(flow: TaintFlow | undefined, nodes: Map<string, EvidenceNode>): string[] {
  const facts = new Set<string>()
  for (const fact of flow?.facts ?? []) if (fact.trim()) facts.add(fact.trim())
  for (const hop of flow?.hops ?? []) {
    if (hop.note?.trim()) facts.add(hop.note.trim())
    const node = nodes.get(hop.nodeId)
    for (const fact of node?.facts ?? []) if (fact.trim()) facts.add(fact.trim())
    if (node?.code?.trim()) facts.add(`${hop.role}: ${node.code.trim()}`)
  }
  return [...facts]
}

function mergedBundles(inputBundles: EvidenceBundle[]): EvidenceBundle[] {
  return [...new Map(inputBundles.map((bundle) => [bundle.id, bundle])).values()]
}

function emptyDecision(hyp: Hypothesis): EvidenceFlowDecision {
  const sinkSignature = semanticSink(hyp)
  return {
    hypothesisId: hyp.id,
    status: "none",
    confidence: "low",
    hasTrace: Boolean(hyp.dataflowResult?.paths.length),
    hasGraphRoute: false,
    hasGraphSource: Boolean(hyp.sourceHint || hyp.sourceLinks?.length),
    routeSignature: "",
    triggerSignature: "unknown-trigger",
    identitySignature: `${hyp.category}:${hyp.sinkFile}:${sinkSignature}`,
    graphFacts: [],
    graphEdges: [],
  }
}

function inferTriggerSignature(hyp: Hypothesis, text: string): string {
  const route = [...text.matchAll(/\b(GET|POST|PUT|DELETE|PATCH)\s+(\/[A-Za-z0-9_./{}:-]+)/gi)]
    .map((match) => `${match[1]!.toUpperCase()} ${normalizeRoutePath(match[2]!)}`)[0]
  const param = inferParamName(hyp, text)
  return [route, param ? `param:${param}` : ""].filter(Boolean).join("|") || "unknown-trigger"
}

function inferParamName(hyp: Hypothesis, text: string): string | undefined {
  const lower = `${hyp.category}\n${hyp.sinkPattern}\n${hyp.sinkCode}\n${hyp.description}\n${text}`.toLowerCase()
  const candidates = [
    "transformScript",
    "validationRules",
    "dynSentence",
    "caseResult",
    "sourceConfig",
    "apiUrl",
    "method",
    "reportCode",
    "rowDatas",
    "password",
    "oldPassword",
    "filename",
    "fileName",
    "filePath",
    "path",
    "file",
    "body",
  ]
  for (const candidate of candidates) {
    if (lower.includes(candidate.toLowerCase())) return candidate
  }
  const fieldMatch = text.match(/\b([A-Za-z_][A-Za-z0-9_]*)\s*(?:字段|参数|field|parameter|param)\b/i)
  return fieldMatch?.[1]
}

function sourceParamName(source: SourceEntry | undefined): string | undefined {
  const param = source?.paramName?.trim()
  if (param && param !== "unknown") return param
  if (source?.kind === "body" || source?.kind === "input-stream") return "body"
  return undefined
}

function sourceKindData(value: unknown): SourceParamKind | undefined {
  if (value === "param" || value === "body" || value === "header" || value === "cookie" || value === "pathvar" || value === "request-attr" || value === "input-stream") {
    return value
  }
  return undefined
}

function stringData(value: unknown): string | undefined {
  return typeof value === "string" && value.trim().length > 0 ? value : undefined
}

function normalizeRoutePath(path: string): string {
  const clean = path.replace(/[),.;，。；]+$/g, "")
  return clean.startsWith("/") ? clean : `/${clean}`
}

function projectFile(profile: ProjectProfile, file: string): string {
  if (!file) return file
  return file.startsWith("/") ? file : resolve(profile.root, file)
}

function relativeOrOriginal(profile: ProjectProfile, file: string): string {
  return file.startsWith(profile.root) ? file.slice(profile.root.length).replace(/^\/+/, "") : file
}

function sameFile(profile: ProjectProfile, left: string, right: string): boolean {
  const absLeft = projectFile(profile, left)
  const absRight = projectFile(profile, right)
  return absLeft === absRight || absLeft.endsWith(right) || absRight.endsWith(left)
}

function semanticSink(hyp: Hypothesis): string {
  return `${hyp.sinkPattern}\n${hyp.sinkCode}`
    .toLowerCase()
    .replace(/["'`]/g, "")
    .replace(/\s+/g, " ")
    .replace(/\bline\s+\d+\b/g, "line")
    .slice(0, 120)
}

function dedupeEdges(edges: DataflowEdge[]): DataflowEdge[] {
  const seen = new Set<string>()
  const out: DataflowEdge[] = []
  for (const edge of edges) {
    const key = `${edge.kind}:${edge.file}:${edge.line}:${edge.code}`
    if (seen.has(key)) continue
    seen.add(key)
    out.push(edge)
  }
  return out
}
