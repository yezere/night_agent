import { SolverJudge } from "../../solver/solver-judge.ts"
import { StateMachine } from "../../runtime/state-machine.ts"
import { submitAgentResult } from "../../runtime/agent-submission.ts"
import { AuditWorkspace } from "../../runtime/audit-workspace.ts"
import type { EventBus } from "../../runtime/event-bus.ts"
import type { AuditOptions, ProjectProfile, SourceEntry } from "../../types/index.ts"

/**
 * Run the judging phase: evaluate all traced hypotheses and produce findings.
 */
export async function runJudgingPhase(
  sm: StateMachine,
  bus: EventBus,
  options: AuditOptions,
  profile: ProjectProfile,
  workspace: AuditWorkspace,
  sources: SourceEntry[],
  log: (msg: string) => void,
): Promise<void> {
  const result = sm.transition("judging")
  if (!result.ok) { log(`state error: ${result.error}`); return }
  bus.emit("state:enter", { state: "judging", from: result.from }, "manager")

  const ctx = {
    identity: { id: "judge", role: "solver" as const, status: "idle" as const },
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
    log: (msg: string) => log(`[judge] ${msg}`),
  }
  const judge = new SolverJudge(ctx, workspace)

  // Build source map for lookups
  const sourceMap = new Map<string, SourceEntry>()
  for (const s of sources) {
    if (!sourceMap.has(s.file)) sourceMap.set(s.file, s)
  }

  await judge.judgeAll(sourceMap, { profile, sources })
  const findings = workspace.getFindings()
  const byCategory = findings.reduce<Record<string, number>>((acc, finding) => {
    acc[finding.category] = (acc[finding.category] ?? 0) + 1
    return acc
  }, {})

  // Add CVE hints
  for (const finding of findings) {
    const relatedDeps = profile.dependencies
      .filter((d) => {
        const cat = finding.category
        if (cat === "deser" && /fastjson|jackson/.test(d.name)) return true
        if (cat === "ssti" && /freemarker|velocity/.test(d.name)) return true
        if (cat === "sqli" && /mybatis/.test(d.name)) return true
        return false
      })
      .map((d) => d.name)
    if (relatedDeps.length > 0) {
      workspace.addNote(
        `[N-Day hint] ${finding.id} (${finding.category}) involves ${relatedDeps.join(", ")} — check CVE databases`,
        "cve",
        [finding.id],
      )
    }
  }

  submitAgentResult(bus, "judge", {
    agent: "JudgeAgent",
    kind: "finding",
    title: "JudgeAgent 提交判定结果",
    content: findings.length > 0
      ? `我完成了证据判定，提交 ${findings.length} 个确认发现。类别分布：${Object.entries(byCategory).map(([k, v]) => `${k} ${v} 个`).join("、") || "未分类"}。`
      : "我完成了证据判定，暂未提交确认发现；未确认的候选会继续保留为待复核或待复查。",
    artifacts: { findings: findings.length, byCategory },
  })
  bus.emit("state:leave", { state: "judging" }, "manager")
}
