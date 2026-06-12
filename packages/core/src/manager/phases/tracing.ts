import { resolve } from "node:path"
import { SolverTracer } from "../../solver/solver-tracer.ts"
import { runObserverChecks } from "../../observer/supervisor.ts"
import { logObserverReport } from "./scanning.ts"
import { StateMachine } from "../../runtime/state-machine.ts"
import { submitAgentResult } from "../../runtime/agent-submission.ts"
import { AuditWorkspace } from "../../runtime/audit-workspace.ts"
import type { EventBus } from "../../runtime/event-bus.ts"
import type { AuditOptions, ProjectProfile, CoverageGrid, SourceEntry } from "../../types/index.ts"

export function runTracingPhase(
  sm: StateMachine,
  bus: EventBus,
  options: AuditOptions,
  profile: ProjectProfile,
  coverageGrid: CoverageGrid,
  workspace: AuditWorkspace,
  cpgPath: string | undefined,
  log: (msg: string) => void,
): SolverTracer {
  const result = sm.transition("tracing")
  if (!result.ok) {
    log(`state error: ${result.error}`)
    // Return a no-op tracer
    return null as unknown as SolverTracer
  }
  bus.emit("state:enter", { state: "tracing", from: result.from }, "manager")

  const ctx = {
    identity: { id: "tracer", role: "solver" as const, status: "idle" as const },
    bus,
    getState: () => ({
      currentState: "tracing" as const,
      profile: null,
      sources: [],
      stats: {} as any,
      iteration: 0,
      termination: {} as any,
      agentStatuses: {},
    }),
    log: (msg: string) => log(`[tracer] ${msg}`),
  }
  const tracer = new SolverTracer(ctx, profile, options, coverageGrid, workspace, cpgPath)
  return tracer
}

export function postTracingObserver(
  coverageGrid: CoverageGrid,
  bus?: EventBus,
  log?: (msg: string) => void,
  profile?: ProjectProfile,
  sources?: SourceEntry[],
  workspace?: AuditWorkspace,
): { warnings: string[] } {
  const hypotheses = workspace?.getHypotheses() ?? []
  const obsReport = runObserverChecks("explore", hypotheses, coverageGrid, profile ? { profile, sources, evidenceBundles: workspace?.getEvidenceBundles() ?? [] } : undefined)
  if (log) logObserverReport("post-trace", obsReport, (msg) => log(`[observer] ${msg}`))
  if (bus) {
    const reachable = hypotheses.filter((h) => h.evidenceState?.trace === "reachable").length
    const revisit = hypotheses.filter((h) => h.status === "maybe_revisit").length
    const dismissed = hypotheses.filter((h) => h.status === "dismissed").length
    submitAgentResult(bus, "tracer", {
      agent: "TracerAgent",
      kind: "trace",
      title: "TracerAgent 提交链路追踪结果",
      content: `我完成了 Joern/数据流追踪。当前可达 ${reachable} 个，排除 ${dismissed} 个，待复查 ${revisit} 个。Observer 已收到追踪后的状态用于复核。`,
      artifacts: { reachable, dismissed, revisit, warnings: obsReport.warnings.length },
    })
  }
  return obsReport
}
