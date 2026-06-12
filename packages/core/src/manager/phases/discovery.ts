import { JoernDiscoveryAgent, type JoernDiscoverySummary } from "../../solver/solver-joern-discovery.ts"
import { submitAgentResult } from "../../runtime/agent-submission.ts"
import { AuditWorkspace } from "../../runtime/audit-workspace.ts"
import type { EventBus } from "../../runtime/event-bus.ts"
import type { AuditOptions, ProjectProfile, SourceEntry } from "../../types/index.ts"

export async function runJoernDiscoveryPhase(
  bus: EventBus,
  options: AuditOptions,
  profile: ProjectProfile,
  workspace: AuditWorkspace,
  sources: SourceEntry[],
  cpgPath: string | undefined,
  log: (msg: string) => void,
): Promise<{ summary: JoernDiscoverySummary; sources: SourceEntry[] }> {
  const ctx = {
    identity: { id: "joern-discovery", role: "solver" as const, status: "idle" as const },
    bus,
    getState: () => ({
      currentState: "enriching" as const,
      profile: null,
      sources: [],
      stats: {} as any,
      iteration: 0,
      termination: {} as any,
      agentStatuses: {},
    }),
    log: (msg: string) => log(`[joern-discovery] ${msg}`),
  }
  const agent = new JoernDiscoveryAgent(ctx, options, profile, workspace, sources, cpgPath)
  await agent.start()
  const summary = agent.getSummary()
  const discoveredSources = agent.getSources()
  submitAgentResult(bus, "joern-discovery", {
    agent: "JoernDiscoveryAgent",
    kind: "discovery",
    title: "JoernDiscoveryAgent 提交 CPG 补充发现",
    content: `我完成了 CPG 视角补充发现：新增 ${summary.addedSources} 个输入源、${summary.addedSinks} 个危险点候选。新增候选仍会进入 EvidenceBundler、Tracer 和 StaticVerifierAgent 复核。`,
    artifacts: { ...summary },
  })
  return { summary, sources: discoveredSources }
}
