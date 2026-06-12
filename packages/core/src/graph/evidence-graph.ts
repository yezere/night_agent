import { createHash } from "node:crypto"
import { relative } from "node:path"
import type {
  DataflowEdge,
  EvidenceBundle,
  Finding,
  Hypothesis,
  ProjectProfile,
  RouteEntry,
  SourceEntry,
  SourceLink,
  VerifierVerdict,
} from "../types/index.ts"

export type EvidenceNodeKind =
  | "project"
  | "route"
  | "source"
  | "hypothesis"
  | "sink"
  | "dataflow-step"
  | "sanitizer"
  | "verifier"
  | "poc"
  | "finding"

export type EvidenceEdgeKind =
  | "project-exposes-route"
  | "route-binds-source"
  | "route-candidate-for-hypothesis"
  | "source-candidate-for-hypothesis"
  | "hypothesis-has-sink"
  | "dataflow-hop"
  | "passes-through-sanitizer"
  | "verified-by"
  | "confirmed-as"
  | "poc-targets"

export type EvidenceProducer =
  | "profile"
  | "source-agent"
  | "sink-agent"
  | "source-linker"
  | "joern"
  | "verifier"
  | "judge"
  | "poc-agent"
  | "reporting"

export type EvidenceConfidence = "high" | "medium" | "low"
export type TaintFlowStatus = "candidate" | "traced" | "verified" | "confirmed" | "blocked" | "unknown"

export interface EvidenceLocation {
  file: string
  line: number
  endLine?: number
}

export interface EvidenceNode {
  id: string
  kind: EvidenceNodeKind
  label: string
  location?: EvidenceLocation
  code?: string
  facts?: string[]
  producer: EvidenceProducer
  confidence: EvidenceConfidence
  data?: Record<string, unknown>
  contentHash?: string
}

export interface EvidenceEdge {
  id: string
  from: string
  to: string
  kind: EvidenceEdgeKind
  label: string
  producer: EvidenceProducer
  confidence: EvidenceConfidence
  reason?: string
  location?: EvidenceLocation
  code?: string
}

export interface TaintFlowHop {
  nodeId: string
  edgeId?: string
  role: "route" | "source" | "transform" | "sanitizer" | "sink" | "verifier" | "poc"
  label: string
  location?: EvidenceLocation
  code?: string
  note?: string
}

export interface TaintFlow {
  id: string
  hypothesisId: string
  status: TaintFlowStatus
  confidence: EvidenceConfidence
  producer: EvidenceProducer
  category: string
  severity: Hypothesis["severity"]
  sourceNodeId?: string
  sinkNodeId: string
  routeNodeId?: string
  verifierNodeId?: string
  findingNodeId?: string
  hops: TaintFlowHop[]
  facts: string[]
}

export interface EvidenceGraphArtifact {
  version: 1
  generatedAt: number
  project: {
    name: string
    root: string
    language: ProjectProfile["language"]
  }
  nodes: EvidenceNode[]
  edges: EvidenceEdge[]
  taintFlows: TaintFlow[]
  stats: {
    nodes: number
    edges: number
    taintFlows: number
    candidateFlows: number
    tracedFlows: number
    verifiedFlows: number
    confirmedFlows: number
    blockedFlows: number
  }
}

export interface VerifierEvidencePack {
  hypothesisId: string
  rich: boolean
  content: string
}

export interface EvidenceGraphInput {
  profile: ProjectProfile
  hypotheses: Hypothesis[]
  evidenceBundles: EvidenceBundle[]
  findings: Finding[]
  sources: SourceEntry[]
}

interface GraphBuilder {
  nodes: Map<string, EvidenceNode>
  edges: Map<string, EvidenceEdge>
  flows: TaintFlow[]
}

export function buildEvidenceGraph(report: EvidenceGraphInput): EvidenceGraphArtifact {
  const builder: GraphBuilder = { nodes: new Map(), edges: new Map(), flows: [] }
  const projectId = "project:root"
  addNode(builder, {
    id: projectId,
    kind: "project",
    label: report.profile.name,
    producer: "profile",
    confidence: "high",
    data: {
      root: report.profile.root,
      language: report.profile.language,
      dependencies: report.profile.dependencies.length,
      routes: report.profile.routes.length,
    },
  })

  const sourceByKey = new Map<string, SourceEntry>()
  for (const source of report.sources) {
    sourceByKey.set(sourceKey(source), source)
    const sourceNode = sourceNodeId(source)
    addSourceNode(builder, report.profile, source)
    const route = nearestRoute(report.profile, source.file, source.line)
    if (route) {
      const routeNode = addRouteNode(builder, report.profile, route)
      addEdge(builder, {
        id: edgeId(routeNode, sourceNode, "route-binds-source"),
        from: routeNode,
        to: sourceNode,
        kind: "route-binds-source",
        label: "route binds source",
        producer: "profile",
        confidence: "medium",
        reason: "nearest route in the same source file",
      })
    }
  }

  for (const route of report.profile.routes) {
    const routeNode = addRouteNode(builder, report.profile, route)
    addEdge(builder, {
      id: edgeId(projectId, routeNode, "project-exposes-route"),
      from: projectId,
      to: routeNode,
      kind: "project-exposes-route",
      label: "exposes",
      producer: "profile",
      confidence: "high",
      reason: `${route.method} ${route.path}`,
    })
  }

  for (const hyp of report.hypotheses) {
    const bundle = bundleFor(report, hyp)
    addHypothesisEvidence(builder, report, hyp, bundle, sourceByKey)
  }

  for (const finding of report.findings) {
    addFindingEvidence(builder, report, finding)
  }

  const flows = dedupeFlows(builder.flows)
  const stats = {
    nodes: builder.nodes.size,
    edges: builder.edges.size,
    taintFlows: flows.length,
    candidateFlows: flows.filter((flow) => flow.status === "candidate").length,
    tracedFlows: flows.filter((flow) => flow.status === "traced").length,
    verifiedFlows: flows.filter((flow) => flow.status === "verified").length,
    confirmedFlows: flows.filter((flow) => flow.status === "confirmed").length,
    blockedFlows: flows.filter((flow) => flow.status === "blocked").length,
  }

  return {
    version: 1,
    generatedAt: Date.now(),
    project: {
      name: report.profile.name,
      root: report.profile.root,
      language: report.profile.language,
    },
    nodes: [...builder.nodes.values()],
    edges: [...builder.edges.values()],
    taintFlows: flows,
    stats,
  }
}

export function buildVerifierEvidencePack(
  profile: ProjectProfile,
  hyp: Hypothesis,
  bundle?: EvidenceBundle,
): VerifierEvidencePack {
  const links = bundle?.sourceLinks ?? hyp.sourceLinks ?? []
  const dataflow = bundle?.dataflow ?? hyp.dataflowResult
  const verifier = bundle?.verifierVerdict ?? hyp.verifierVerdict
  const route = bundle?.route
  const rich = links.length > 0 && Boolean(dataflow?.paths.length || verifier)
  const rel = (file: string) => displayFile(profile, file)
  const lines: string[] = []

  lines.push(`# EvidenceGraph verifier pack for ${hyp.id}`)
  lines.push("")
  lines.push("Priority: read this structured evidence before requesting full files. Treat candidate links as hints, and require file:line-backed facts for confirmed/dismissed verdicts.")
  lines.push("")
  lines.push("## Hypothesis")
  lines.push(`- id: ${hyp.id}`)
  lines.push(`- status: ${hyp.status}`)
  lines.push(`- category/severity: ${hyp.category}/${hyp.severity}`)
  lines.push(`- sink: ${hyp.sinkPattern} @ ${rel(hyp.sinkFile)}:${hyp.sinkLine}`)
  lines.push(`- sink code: ${oneLine(hyp.sinkCode)}`)
  lines.push(`- origin: ${hyp.origin ?? "unknown"}`)
  if (hyp.resolutionNote) lines.push(`- prior note: ${hyp.resolutionNote}`)
  lines.push("")

  lines.push("## Route")
  if (route) {
    lines.push(`- selected: ${route.method} ${route.path} @ ${route.sourceFile}:${route.line}`)
    if (route.className) lines.push(`- class: ${route.className}`)
    if (route.authHint) lines.push(`- auth: ${route.authHint}`)
  } else {
    lines.push("- selected: (none)")
  }
  lines.push("")

  lines.push("## Source candidates")
  if (links.length === 0) {
    lines.push("- (none)")
  } else {
    links.slice(0, 8).forEach((link, index) => {
      const source = link.source
      lines.push(`${index + 1}. score=${link.score} ${source.kind}:${source.paramName || "(unnamed)"} @ ${rel(source.file)}:${source.line}`)
      lines.push(`   reason: ${link.reason}`)
      lines.push(`   code: ${oneLine(source.code)}`)
      if (source.methodName) lines.push(`   method: ${source.methodName}${source.className ? ` (${source.className})` : ""}`)
    })
  }
  lines.push("")

  lines.push("## Sink snippet")
  lines.push(`- ${rel(hyp.sinkFile)}:${hyp.sinkLine} ${oneLine(hyp.sinkCode)}`)
  lines.push("")

  lines.push("## Taint flow")
  if (!dataflow?.paths.length) {
    if (links.length > 0) {
      const top = links[0]!
      lines.push(`- candidate: ${top.source.kind}:${top.source.paramName || "(unnamed)"} @ ${rel(top.source.file)}:${top.source.line} -> ${hyp.sinkPattern} @ ${rel(hyp.sinkFile)}:${hyp.sinkLine}`)
      lines.push(`- confidence: ${scoreConfidence(top.score)} from source-linker`)
      lines.push(`- missing: no Joern/dataflow path recorded; verify transforms/helpers manually before confirming`)
    } else {
      lines.push("- unknown: no source candidate and no Joern/dataflow path recorded")
    }
  } else {
    dataflow.paths.slice(0, 2).forEach((path, pathIndex) => {
      lines.push(`path ${pathIndex + 1}: ${path.sourceLabel} -> ${path.sinkLabel}`)
      path.edges.slice(0, 16).forEach((edge, edgeIndex) => {
        lines.push(`  ${edgeIndex + 1}. ${edge.kind} @ ${rel(edge.file)}:${edge.line} ${oneLine(edge.code)}`)
      })
    })
  }
  lines.push("")

  lines.push("## Verifier/Judge prior")
  if (verifier) {
    lines.push(`- verdict: ${verifier.status}/${verifier.confidence}`)
    lines.push(`- reason: ${verifier.reason}`)
    for (const fact of (verifier.sourceSinkTrace ?? []).slice(0, 8)) lines.push(`- trace: ${fact}`)
    for (const barrier of (verifier.barrierAnalysis ?? verifier.sanitizerSummary ?? []).slice(0, 8)) lines.push(`- barrier: ${barrier}`)
    for (const missing of (verifier.missingEvidence ?? []).slice(0, 6)) lines.push(`- missing: ${missing}`)
  } else {
    lines.push("- (none)")
  }
  lines.push("")

  lines.push("## Required verifier action")
  lines.push("- Confirmed requires a concrete external source, transform/helper facts, sink fact, and barrier analysis with file:line evidence.")
  lines.push("- If this pack lacks helper/sanitizer/template/mapper/runtime details, use read_file/rg only for those missing pieces.")

  return {
    hypothesisId: hyp.id,
    rich,
    content: lines.join("\n"),
  }
}

function addHypothesisEvidence(
  builder: GraphBuilder,
  report: EvidenceGraphInput,
  hyp: Hypothesis,
  bundle: EvidenceBundle | undefined,
  sourceByKey: Map<string, SourceEntry>,
): void {
  const hypNode = hypothesisNodeId(hyp)
  addNode(builder, {
    id: hypNode,
    kind: "hypothesis",
    label: `${hyp.category}:${hyp.sinkPattern}`,
    location: location(report.profile, hyp.sinkFile, hyp.sinkLine),
    code: hyp.sinkCode,
    facts: [
      `status=${hyp.status}`,
      `severity=${hyp.severity}`,
      `origin=${hyp.origin ?? "unknown"}`,
      ...(hyp.resolutionNote ? [`resolution=${hyp.resolutionNote}`] : []),
    ],
    producer: "sink-agent",
    confidence: confidenceFromStatus(hyp.status),
    data: {
      hypothesisId: hyp.id,
      category: hyp.category,
      severity: hyp.severity,
      status: hyp.status,
      sinkPattern: hyp.sinkPattern,
    },
  })

  const sinkNode = sinkNodeId(hyp)
  addNode(builder, {
    id: sinkNode,
    kind: "sink",
    label: hyp.sinkPattern,
    location: location(report.profile, hyp.sinkFile, hyp.sinkLine),
    code: hyp.sinkCode,
    facts: [`category=${hyp.category}`, `severity=${hyp.severity}`],
    producer: "sink-agent",
    confidence: "high",
    data: {
      hypothesisId: hyp.id,
      sinkPattern: hyp.sinkPattern,
    },
  })
  addEdge(builder, {
    id: edgeId(hypNode, sinkNode, "hypothesis-has-sink"),
    from: hypNode,
    to: sinkNode,
    kind: "hypothesis-has-sink",
    label: "has sink",
    producer: "sink-agent",
    confidence: "high",
    location: location(report.profile, hyp.sinkFile, hyp.sinkLine),
    code: hyp.sinkCode,
  })

  const routeNode = bundle?.route ? addRouteNode(builder, report.profile, bundle.route) : undefined
  if (routeNode) {
    addEdge(builder, {
      id: edgeId(routeNode, hypNode, "route-candidate-for-hypothesis"),
      from: routeNode,
      to: hypNode,
      kind: "route-candidate-for-hypothesis",
      label: "route candidate",
      producer: "source-linker",
      confidence: "medium",
      reason: "route selected by source/sink linkage",
    })
  }

  const links = bundle?.sourceLinks ?? hyp.sourceLinks ?? []
  for (const link of links) {
    sourceByKey.set(sourceKey(link.source), link.source)
    const sourceNode = addSourceNode(builder, report.profile, link.source)
    addEdge(builder, {
      id: edgeId(sourceNode, hypNode, "source-candidate-for-hypothesis"),
      from: sourceNode,
      to: hypNode,
      kind: "source-candidate-for-hypothesis",
      label: "source candidate",
      producer: "source-linker",
      confidence: scoreConfidence(link.score),
      reason: `${link.reason}; score=${link.score}`,
      location: location(report.profile, link.source.file, link.source.line),
      code: link.source.code,
    })
  }

  const dataflow = bundle?.dataflow ?? hyp.dataflowResult
  if (dataflow?.paths.length) {
    dataflow.paths.forEach((path, pathIndex) => {
      const flow = flowFromDataflow(report, builder, hyp, path.edges, pathIndex, routeNode, bundle)
      builder.flows.push(flow)
    })
  } else {
    const flow = flowFromCandidates(report, hyp, links, routeNode, bundle)
    if (flow) builder.flows.push(flow)
  }

  const verifier = bundle?.verifierVerdict ?? hyp.verifierVerdict
  if (verifier) {
    const verifierNode = addVerifierNode(builder, hyp, verifier)
    addEdge(builder, {
      id: edgeId(hypNode, verifierNode, "verified-by"),
      from: hypNode,
      to: verifierNode,
      kind: "verified-by",
      label: `verifier ${verifier.status}`,
      producer: "verifier",
      confidence: verifier.confidence,
      reason: verifier.reason,
    })
  }

  if (bundle?.reportContext?.pocPackets.length) {
    const pocNode = `poc:${hyp.id}`
    addNode(builder, {
      id: pocNode,
      kind: "poc",
      label: `PoC ${hyp.id}`,
      facts: bundle.reportContext.pocPackets.slice(0, 3),
      producer: "poc-agent",
      confidence: hyp.status === "confirmed" ? "medium" : "low",
      data: {
        hypothesisId: hyp.id,
        packetCount: bundle.reportContext.pocPackets.length,
      },
    })
    addEdge(builder, {
      id: edgeId(pocNode, hypNode, "poc-targets"),
      from: pocNode,
      to: hypNode,
      kind: "poc-targets",
      label: "poc targets",
      producer: "poc-agent",
      confidence: hyp.status === "confirmed" ? "medium" : "low",
    })
  }
}

function flowFromDataflow(
  report: EvidenceGraphInput,
  builder: GraphBuilder,
  hyp: Hypothesis,
  edges: DataflowEdge[],
  pathIndex: number,
  routeNode: string | undefined,
  bundle: EvidenceBundle | undefined,
): TaintFlow {
  const sinkNode = sinkNodeId(hyp)
  const verifier = bundle?.verifierVerdict ?? hyp.verifierVerdict
  const finding = findingForHypothesis(report, hyp)
  const status = flowStatus(hyp, verifier, true, finding)
  const hops: TaintFlowHop[] = []
  let previousNode = routeNode
  let sourceNode: string | undefined

  if (routeNode) {
    const route = builder.nodes.get(routeNode)
    hops.push({ nodeId: routeNode, role: "route", label: route?.label ?? "route", location: route?.location, code: route?.code })
  }

  edges.forEach((edge, edgeIndex) => {
    const nodeId = edge.kind === "sink"
      ? sinkNode
      : `dataflow:${hyp.id}:${pathIndex}:${edgeIndex}:${edge.kind}`
    const nodeKind: EvidenceNodeKind = edge.kind === "source"
      ? "source"
      : edge.kind === "sink"
        ? "sink"
        : edge.kind === "sanitizer"
          ? "sanitizer"
          : "dataflow-step"
    addNode(builder, {
      id: nodeId,
      kind: nodeKind,
      label: `${edge.kind} ${displayFile(report.profile, edge.file)}:${edge.line}`,
      location: location(report.profile, edge.file, edge.line),
      code: edge.code,
      facts: [`dataflow kind=${edge.kind}`],
      producer: "joern",
      confidence: status === "confirmed" ? "high" : "medium",
      data: {
        hypothesisId: hyp.id,
        pathIndex,
        edgeIndex,
      },
    })
    if (edge.kind === "source" && !sourceNode) sourceNode = nodeId
    let hopEdgeId: string | undefined
    if (previousNode) {
      hopEdgeId = edgeId(previousNode, nodeId, edge.kind === "sanitizer" ? "passes-through-sanitizer" : "dataflow-hop")
      addEdge(builder, {
        id: hopEdgeId,
        from: previousNode,
        to: nodeId,
        kind: edge.kind === "sanitizer" ? "passes-through-sanitizer" : "dataflow-hop",
        label: edge.kind === "sanitizer" ? "passes through sanitizer" : "dataflow hop",
        producer: "joern",
        confidence: status === "confirmed" ? "high" : "medium",
        location: location(report.profile, edge.file, edge.line),
        code: edge.code,
      })
    }
    previousNode = nodeId
    hops.push({
      nodeId,
      edgeId: hopEdgeId,
      role: edge.kind === "source" ? "source" : edge.kind === "sink" ? "sink" : edge.kind === "sanitizer" ? "sanitizer" : "transform",
      label: edge.kind,
      location: location(report.profile, edge.file, edge.line),
      code: edge.code,
    })
  })

  const verifierNode = verifier ? addVerifierNode(builder, hyp, verifier) : undefined
  if (verifierNode) {
    hops.push({
      nodeId: verifierNode,
      role: "verifier",
      label: `verifier ${verifier!.status}`,
      note: verifier!.reason,
    })
  }

  return {
    id: `flow:${hyp.id}:dataflow:${pathIndex}`,
    hypothesisId: hyp.id,
    status,
    confidence: flowConfidence(status, verifier?.confidence),
    producer: "joern",
    category: hyp.category,
    severity: hyp.severity,
    sourceNodeId: sourceNode,
    sinkNodeId: sinkNode,
    routeNodeId: routeNode,
    verifierNodeId: verifierNode,
    findingNodeId: finding?.id ? `finding:${finding.id}` : undefined,
    hops,
    facts: [
      `reachable=${Boolean((bundle?.dataflow ?? hyp.dataflowResult)?.reachable)}`,
      ...(verifier ? [`verifier=${verifier.status}/${verifier.confidence}`, verifier.reason] : []),
    ],
  }
}

function flowFromCandidates(
  report: EvidenceGraphInput,
  hyp: Hypothesis,
  links: SourceLink[],
  routeNode: string | undefined,
  bundle: EvidenceBundle | undefined,
): TaintFlow | null {
  const sinkNode = sinkNodeId(hyp)
  const verifier = bundle?.verifierVerdict ?? hyp.verifierVerdict
  const topLink = links[0]
  if (!topLink && !verifier) return null

  const sourceNode = topLink ? sourceNodeId(topLink.source) : undefined
  const finding = findingForHypothesis(report, hyp)
  const status = flowStatus(hyp, verifier, false, finding)
  const hops: TaintFlowHop[] = []
  if (routeNode) {
    hops.push({ nodeId: routeNode, role: "route", label: "route candidate" })
  }
  if (topLink && sourceNode) {
    hops.push({
      nodeId: sourceNode,
      role: "source",
      label: `${topLink.source.kind}:${topLink.source.paramName}`,
      location: location(report.profile, topLink.source.file, topLink.source.line),
      code: topLink.source.code,
      note: topLink.reason,
    })
  }
  hops.push({
    nodeId: sinkNode,
    role: "sink",
    label: hyp.sinkPattern,
    location: location(report.profile, hyp.sinkFile, hyp.sinkLine),
    code: hyp.sinkCode,
  })

  const verifierNode = verifier ? `verifier:${hyp.id}` : undefined
  if (verifierNode && verifier) {
    hops.push({
      nodeId: verifierNode,
      role: "verifier",
      label: `verifier ${verifier.status}`,
      note: verifier.reason,
    })
  }

  return {
    id: `flow:${hyp.id}:candidate`,
    hypothesisId: hyp.id,
    status,
    confidence: flowConfidence(status, verifier?.confidence ?? scoreConfidence(topLink?.score ?? 0)),
    producer: verifier ? "verifier" : "source-linker",
    category: hyp.category,
    severity: hyp.severity,
    sourceNodeId: sourceNode,
    sinkNodeId: sinkNode,
    routeNodeId: routeNode,
    verifierNodeId: verifierNode,
    findingNodeId: finding?.id ? `finding:${finding.id}` : undefined,
    hops,
    facts: [
      topLink ? `sourceLink score=${topLink.score}: ${topLink.reason}` : "no source link",
      ...(verifier ? [`verifier=${verifier.status}/${verifier.confidence}`, verifier.reason] : []),
    ],
  }
}

function addFindingEvidence(builder: GraphBuilder, report: EvidenceGraphInput, finding: Finding): void {
  const findingNode = `finding:${finding.id}`
  addNode(builder, {
    id: findingNode,
    kind: "finding",
    label: finding.title,
    location: location(report.profile, finding.sink.file, finding.sink.line),
    code: finding.sink.snippet,
    facts: [
      `status=${finding.status}`,
      `severity=${finding.severity}`,
      `confidence=${finding.confidence}`,
    ],
    producer: "judge",
    confidence: finding.confidence,
    data: {
      findingId: finding.id,
      hypothesisId: finding.hypothesisId,
      category: finding.category,
    },
  })

  const hyp = finding.hypothesisId
    ? report.hypotheses.find((item) => item.id === finding.hypothesisId)
    : report.hypotheses.find((item) => item.sinkFile === finding.sink.file && item.sinkLine === finding.sink.line)
  if (!hyp) return
  addEdge(builder, {
    id: edgeId(hypothesisNodeId(hyp), findingNode, "confirmed-as"),
    from: hypothesisNodeId(hyp),
    to: findingNode,
    kind: "confirmed-as",
    label: "confirmed as finding",
    producer: "judge",
    confidence: finding.confidence,
    reason: finding.title,
  })
}

function addSourceNode(builder: GraphBuilder, profile: ProjectProfile, source: SourceEntry): string {
  const nodeId = sourceNodeId(source)
  addNode(builder, {
    id: nodeId,
    kind: "source",
    label: `${source.kind}:${source.paramName || "(unnamed)"}`,
    location: location(profile, source.file, source.line),
    code: source.code,
    facts: [
      `kind=${source.kind}`,
      `param=${source.paramName || "(none)"}`,
      `method=${source.methodName}`,
      ...(source.className ? [`class=${source.className}`] : []),
      `origin=${source.origin ?? "unknown"}`,
    ],
    producer: "source-agent",
    confidence: "high",
    data: {
      sourceId: source.id,
      kind: source.kind,
      paramName: source.paramName,
      methodName: source.methodName,
      className: source.className,
    },
  })
  return nodeId
}

function addRouteNode(builder: GraphBuilder, profile: ProjectProfile, route: RouteEntry): string {
  const nodeId = routeNodeId(route)
  addNode(builder, {
    id: nodeId,
    kind: "route",
    label: `${route.method} ${route.path}`,
    location: location(profile, route.sourceFile, route.line),
    code: `${route.method} ${route.path}`,
    facts: [
      ...(route.className ? [`class=${route.className}`] : []),
      ...(route.authHint ? [`auth=${route.authHint}`] : []),
    ],
    producer: "profile",
    confidence: "medium",
    data: {
      method: route.method,
      path: route.path,
      className: route.className,
      authHint: route.authHint,
    },
  })
  return nodeId
}

function addVerifierNode(builder: GraphBuilder, hyp: Hypothesis, verdict: VerifierVerdict): string {
  const nodeId = `verifier:${hyp.id}`
  addNode(builder, {
    id: nodeId,
    kind: "verifier",
    label: `verifier ${verdict.status}/${verdict.confidence}`,
    facts: [
      verdict.reason,
      ...(verdict.sourceSinkTrace ?? []),
      ...(verdict.barrierAnalysis ?? []),
      ...(verdict.sanitizerSummary ?? []),
      ...(verdict.missingEvidence ?? []).map((item) => `missing: ${item}`),
    ].filter(Boolean),
    producer: "verifier",
    confidence: verdict.confidence,
    data: {
      hypothesisId: hyp.id,
      status: verdict.status,
      checkedFiles: verdict.checkedFiles,
      toolCalls: verdict.toolCalls,
      evidence: verdict.evidence,
    },
  })
  return nodeId
}

function addNode(builder: GraphBuilder, node: EvidenceNode): void {
  if (!node.contentHash && node.code) node.contentHash = shortHash(node.code)
  const existing = builder.nodes.get(node.id)
  if (!existing) {
    builder.nodes.set(node.id, node)
    return
  }
  builder.nodes.set(node.id, mergeNode(existing, node))
}

function mergeNode(a: EvidenceNode, b: EvidenceNode): EvidenceNode {
  return {
    ...a,
    ...b,
    facts: [...new Set([...(a.facts ?? []), ...(b.facts ?? [])])],
    data: { ...(a.data ?? {}), ...(b.data ?? {}) },
    code: b.code ?? a.code,
    location: b.location ?? a.location,
    confidence: strongerConfidence(a.confidence, b.confidence),
    contentHash: b.contentHash ?? a.contentHash,
  }
}

function addEdge(builder: GraphBuilder, edge: EvidenceEdge): string {
  if (!builder.edges.has(edge.id)) builder.edges.set(edge.id, edge)
  return edge.id
}

function edgeId(from: string, to: string, kind: EvidenceEdgeKind): string {
  return `${kind}:${from}->${to}`
}

function sourceNodeId(source: SourceEntry): string {
  return `source:${source.id || shortHash(sourceKey(source))}`
}

function hypothesisNodeId(hyp: Hypothesis): string {
  return `hyp:${hyp.id}`
}

function sinkNodeId(hyp: Hypothesis): string {
  return `sink:${hyp.id}`
}

function routeNodeId(route: RouteEntry): string {
  return `route:${route.sourceFile}:${route.line}:${route.method}:${route.path}`
}

function sourceKey(source: SourceEntry): string {
  return `${source.file}:${source.line}:${source.kind}:${source.paramName}`
}

function bundleFor(report: EvidenceGraphInput, hyp: Hypothesis): EvidenceBundle | undefined {
  return report.evidenceBundles.find((bundle) => bundle.hypothesisId === hyp.id || bundle.id === hyp.evidenceBundleId)
}

function findingForHypothesis(report: EvidenceGraphInput, hyp: Hypothesis): Finding | undefined {
  return report.findings.find((finding) => finding.hypothesisId === hyp.id)
    ?? report.findings.find((finding) => finding.sink.file === hyp.sinkFile && finding.sink.line === hyp.sinkLine)
}

function nearestRoute(profile: ProjectProfile, file: string, line: number): RouteEntry | undefined {
  const rel = displayFile(profile, file)
  return profile.routes
    .filter((route) => route.sourceFile === rel || rel.endsWith(route.sourceFile) || route.sourceFile.endsWith(rel))
    .sort((a, b) => Math.abs(a.line - line) - Math.abs(b.line - line))[0]
}

function location(profile: ProjectProfile, file: string, line: number, endLine?: number): EvidenceLocation {
  return { file: displayFile(profile, file), line, ...(endLine ? { endLine } : {}) }
}

function displayFile(profile: ProjectProfile, file: string): string {
  if (!file) return file
  try {
    return file.startsWith("/") ? relative(profile.root, file) : file
  } catch {
    return file
  }
}

function flowStatus(hyp: Hypothesis, verifier: VerifierVerdict | undefined, hasTrace: boolean, finding?: Finding): TaintFlowStatus {
  const state = hyp.evidenceState
  if (finding?.status === "confirmed" || state?.finding === "confirmed" || hyp.status === "confirmed") return "confirmed"
  if (verifier?.status === "dismissed") return /sanitize|barrier|blocked|cut|校验|过滤|拦截/i.test([
    verifier.reason,
    ...(verifier.barrierAnalysis ?? []),
    ...(verifier.sanitizerSummary ?? []),
  ].join("\n")) ? "blocked" : "unknown"
  if (state?.trace === "blocked") return "blocked"
  if (verifier?.status === "confirmed" || state?.verification === "confirmed") return "verified"
  if (hasTrace || state?.trace === "reachable") return "traced"
  if (verifier) return "verified"
  return "candidate"
}

function flowConfidence(status: TaintFlowStatus, verifierConfidence?: EvidenceConfidence): EvidenceConfidence {
  if (status === "confirmed") return verifierConfidence ?? "high"
  if (status === "verified" || status === "traced") return verifierConfidence ?? "medium"
  if (status === "blocked") return verifierConfidence ?? "medium"
  return "low"
}

function confidenceFromStatus(status: Hypothesis["status"]): EvidenceConfidence {
  if (status === "confirmed") return "high"
  if (status === "dismissed") return "medium"
  return "low"
}

function scoreConfidence(score: number): EvidenceConfidence {
  if (score >= 70) return "high"
  if (score >= 45) return "medium"
  return "low"
}

function strongerConfidence(a: EvidenceConfidence, b: EvidenceConfidence): EvidenceConfidence {
  const rank: Record<EvidenceConfidence, number> = { high: 3, medium: 2, low: 1 }
  return rank[b] > rank[a] ? b : a
}

function shortHash(value: string): string {
  return createHash("sha1").update(value).digest("hex").slice(0, 12)
}

function oneLine(value: string): string {
  return value.replace(/\s+/g, " ").trim().slice(0, 1_200)
}

function dedupeFlows(flows: TaintFlow[]): TaintFlow[] {
  const seen = new Map<string, TaintFlow>()
  for (const flow of flows) {
    if (!seen.has(flow.id)) seen.set(flow.id, flow)
  }
  return [...seen.values()]
}
