import { SolverVerifier, type VerificationSummary } from "../../solver/solver-verifier.ts"
import { submitAgentResult } from "../../runtime/agent-submission.ts"
import { AuditWorkspace } from "../../runtime/audit-workspace.ts"
import type { EventBus } from "../../runtime/event-bus.ts"
import type { AuditOptions, ProjectProfile } from "../../types/index.ts"

export async function runVerifyingPhase(
  bus: EventBus,
  options: AuditOptions,
  profile: ProjectProfile,
  workspace: AuditWorkspace,
  cpgPath: string | undefined,
  log: (msg: string) => void,
): Promise<VerificationSummary> {
  const ctx = {
    identity: { id: "verifier", role: "solver" as const, status: "idle" as const },
    bus,
    getState: () => ({
      currentState: "judging" as const,
      profile: null,
      sources: [],
      stats: {} as any,
      iteration: 0,
      termination: {} as any,
      agentStatuses: {},
    }),
    log: (msg: string) => log(`[verifier] ${msg}`),
  }
  const verifier = new SolverVerifier(ctx, options, profile, workspace, cpgPath)
  await verifier.start()
  const summary = verifier.getSummary()
  submitAgentResult(bus, "verifier", {
    agent: "StaticVerifierAgent",
    kind: "verification",
    title: "StaticVerifierAgent 提交静态复核结果",
    content: `我完成了候选漏洞静态复核：确认 ${summary.confirmed} 个，排除 ${summary.dismissed} 个，待复查 ${summary.revisit} 个，失败 ${summary.failed} 个。JudgeAgent 只会接收复核为 confirmed 的结果。`,
    artifacts: { ...summary },
  })
  return summary
}
