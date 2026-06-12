import { resolve } from "node:path"
import { relative } from "node:path"
import { analyzeProject } from "../../analyzer/project-analyzer.ts"
import { createCoverageGrid, registerFile } from "../../context/coverage-grid.ts"
import { addEvent } from "../../runtime/event-log.ts"
import { submitAgentResult } from "../../runtime/agent-submission.ts"
import { StateMachine } from "../../runtime/state-machine.ts"
import type { EventBus } from "../../runtime/event-bus.ts"
import type { AuditOptions, ProjectProfile, CoverageGrid } from "../../types/index.ts"

function moduleNameFromPath(targetRoot: string, file: string): string {
  const rel = relative(targetRoot, file)
  const parts = rel.split("/")
  const srcIndex = parts.findIndex((p: string) => p === "main" || p === "src")
  if (srcIndex === -1) return parts[0] ?? "root"
  const after = parts.slice(srcIndex + 1).filter((p: string) => p !== "java")
  return after.slice(0, -1).join(".") || "root"
}

export interface ProfilingResult {
  profile: ProjectProfile | null
  coverageGrid: CoverageGrid | null
}

export async function runProfiling(
  sm: StateMachine,
  bus: EventBus,
  options: AuditOptions,
  log: (msg: string) => void,
): Promise<ProfilingResult> {
  const result = sm.transition("profiling")
  if (!result.ok) { log(`state error: ${result.error}`); return { profile: null, coverageGrid: null } }
  bus.emit("state:enter", { state: "profiling", from: result.from }, "manager")
  log("entering profiling")

  const profile = await analyzeProject(options.target, options.projectName)

  // Init coverage grid
  const grid = createCoverageGrid()
  for (const f of profile.highRiskFiles) {
    const mod = [moduleNameFromPath(resolve(options.target), f)]
    registerFile(grid, resolve(options.target, f), mod)
  }

  addEvent("bootstrap", "success", "Project profiled",
    `${profile.language}, ${profile.routes.length} route(s), ${profile.dependencies.length} dep(s)`)
  submitAgentResult(bus, "profile", {
    agent: "ProfilingAgent",
    kind: "profile",
    title: "ProfilingAgent 提交项目画像",
    content: `我完成了项目画像：语言 ${profile.language}，路由 ${profile.routes.length} 个，依赖 ${profile.dependencies.length} 个，高风险文件 ${profile.highRiskFiles.length} 个。后续 SourceAgent/SinkAgent 将基于该画像并行工作。`,
    artifacts: {
      language: profile.language,
      routes: profile.routes.length,
      dependencies: profile.dependencies.length,
      highRiskFiles: profile.highRiskFiles.length,
    },
  })

  bus.emit("state:leave", { state: "profiling" }, "manager")
  return { profile, coverageGrid: grid }
}
