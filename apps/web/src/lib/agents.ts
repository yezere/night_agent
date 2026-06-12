import type { AgentRunState, AuditEvent } from "../types"
import { eventDetail, eventTitle } from "./format"

const AGENTS = [
  { id: "manager", name: "Manager", label: "调度" },
  { id: "profile", name: "ProfilingAgent", label: "画像" },
  { id: "cpg", name: "CpgAgent", label: "CPG" },
  { id: "source", name: "SourceAgent", label: "输入源" },
  { id: "sink", name: "SinkAgent", label: "危险点" },
  { id: "discovery", name: "JoernDiscoveryAgent", label: "补充发现" },
  { id: "handoff", name: "EvidenceBundler", label: "交接" },
  { id: "query", name: "JoernQueryAgent", label: "查询" },
  { id: "trace", name: "TracerAgent", label: "追踪" },
  { id: "verify", name: "StaticVerifierAgent", label: "静态复核" },
  { id: "judge", name: "JudgeAgent", label: "判定" },
  { id: "observer", name: "Observer", label: "复核" },
  { id: "poc", name: "PocAgent", label: "PoC" },
  { id: "report", name: "ReportAgent", label: "报告" },
] as const

function normalizeAgent(event: AuditEvent): string | null {
  const source = event.source.toLowerCase()
  const p = event.payload && typeof event.payload === "object" ? event.payload as Record<string, unknown> : {}
  const task = String(p.task ?? p.kind ?? p.agent ?? p.title ?? "").toLowerCase()

  if (source.includes("handoff") || task.includes("handoff") || task.includes("evidencebundler") || task.includes("交接")) return "handoff"
  if (source.includes("profile")) return "profile"
  if (source.includes("source")) return "source"
  if (source.includes("sink")) return "sink"
  if (source.includes("cpg")) return "cpg"
  if (source.includes("discovery") || task.includes("discovery") || task.includes("补充发现")) return "discovery"
  if (source.includes("joern") || source.includes("query")) return "query"
  if (source.includes("trace")) return "trace"
  if (source.includes("verifier") || source.includes("verify")) return "verify"
  if (source.includes("judge")) return "judge"
  if (source.includes("observer")) return "observer"
  if (source.includes("poc")) return "poc"
  if (source.includes("report")) return "report"
  if (source.includes("manager") || source.includes("server") || source.includes("dispatcher")) return "manager"

  if (task.includes("profile")) return "profile"
  if (task.includes("source")) return "source"
  if (task.includes("sink")) return "sink"
  if (task.includes("cpg")) return "cpg"
  if (task.includes("handoff")) return "handoff"
  if (task.includes("discover") || task.includes("discovery") || task.includes("补充发现")) return "discovery"
  if (task.includes("joern") || task.includes("query")) return "query"
  if (task.includes("trace")) return "trace"
  if (task.includes("verifier") || task.includes("verify") || task.includes("复核")) return "verify"
  if (task.includes("judge") || task.includes("finding")) return "judge"
  if (task.includes("observer") || task.includes("observe")) return "observer"
  if (task.includes("poc")) return "poc"
  if (task.includes("report")) return "report"
  return null
}

export function buildAgentStates(events: AuditEvent[], active: boolean): AgentRunState[] {
  const states = new Map<string, AgentRunState>()
  for (const agent of AGENTS) {
    states.set(agent.id, {
      id: agent.id,
      name: agent.name,
      label: agent.label,
      status: "waiting",
      count: 0,
      lastTitle: "等待任务",
      lastDetail: "",
      lastAt: 0,
    })
  }

  for (const event of events) {
    const id = normalizeAgent(event)
    if (!id) continue
    const state = states.get(id)
    if (!state) continue
    state.count += 1
    state.lastAt = event.timestamp
    state.lastTitle = eventTitle(event)
    state.lastDetail = eventDetail(event)
    if (event.kind === "task:started" || event.kind === "state:enter") state.status = "running"
    if (event.kind === "task:failed" || event.kind === "audit:error") state.status = "failed"
    if (event.kind === "task:completed" || event.kind === "agent:submission" || event.kind === "agent:artifact") {
      if (state.status !== "failed") state.status = "done"
    }
  }

  if (!active) {
    for (const state of states.values()) {
      if (state.status === "running") state.status = "done"
    }
  }

  return [...states.values()]
}
