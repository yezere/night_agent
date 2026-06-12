import { basename } from "node:path"
import type { AuditGraph, Finding, Hypothesis, Note, ProjectProfile } from "../types/index.ts"
import { isHighRiskDep } from "../types/index.ts"

function pushNode(graph: AuditGraph, node: AuditGraph["nodes"][number]) {
  if (!graph.nodes.some((n) => n.id === node.id)) graph.nodes.push(node)
}

function pushEdge(graph: AuditGraph, from: string, to: string, label: string) {
  if (!graph.edges.some((e) => e.from === from && e.to === to && e.label === label)) {
    graph.edges.push({ from, to, label })
  }
}

export function buildAuditGraph(
  profile: ProjectProfile,
  hypotheses: Hypothesis[],
  findings: Finding[],
  notes: Note[],
): AuditGraph {
  const graph: AuditGraph = { nodes: [], edges: [] }
  const projectId = `project:${profile.name}`

  pushNode(graph, { id: projectId, label: profile.name, kind: "project" })

  for (const dep of profile.dependencies.filter((d) => isHighRiskDep(d.name)).slice(0, 40)) {
    const depId = `dep:${dep.name}`
    pushNode(graph, { id: depId, label: `${dep.name}${dep.version ? ` ${dep.version}` : ""}`, kind: "dependency" })
    pushEdge(graph, projectId, depId, "depends")
  }

  for (const route of profile.routes.slice(0, 80)) {
    const routeId = `route:${route.sourceFile}:${route.line}`
    pushNode(graph, { id: routeId, label: `${route.method} ${route.path}`, kind: "route" })
    pushEdge(graph, projectId, routeId, "exposes")
  }

  for (const hyp of hypotheses.slice(0, 180)) {
    const hypId = `hyp:${hyp.id}`
    const fileId = `module:${hyp.sinkFile}`
    pushNode(graph, { id: fileId, label: basename(hyp.sinkFile), kind: "module" })
    pushNode(graph, {
      id: hypId,
      label: `${hyp.category}:${hyp.sinkPattern}`,
      kind: "hypothesis",
      severity: hyp.severity,
      status: hyp.status,
    })
    pushEdge(graph, projectId, fileId, "contains")
    pushEdge(graph, fileId, hypId, "raises")
  }

  for (const finding of findings) {
    const findingId = `finding:${finding.id}`
    const hyp = hypotheses.find((h) => h.sinkFile === finding.sink.file && h.sinkLine === finding.sink.line)
    pushNode(graph, {
      id: findingId,
      label: finding.title,
      kind: "finding",
      severity: finding.severity,
      status: finding.status,
    })
    if (hyp) pushEdge(graph, `hyp:${hyp.id}`, findingId, "confirms")
    else pushEdge(graph, projectId, findingId, "confirms")
  }

  for (const note of notes.slice(0, 80)) {
    const noteId = `note:${note.id}`
    pushNode(graph, { id: noteId, label: note.content.slice(0, 60), kind: "note" })
    if (note.relatedHypothesisIds.length === 0) pushEdge(graph, projectId, noteId, "notes")
    for (const hypId of note.relatedHypothesisIds) pushEdge(graph, noteId, `hyp:${hypId}`, "informs")
  }

  return graph
}
