import { relative, resolve } from "node:path"
import { addEvent } from "../../runtime/event-log.ts"
import { submitAgentResult } from "../../runtime/agent-submission.ts"
import { saveCheckpoint } from "../../runtime/checkpoint-store.ts"
import { markRescanAttempt, registerFile } from "../../context/coverage-grid.ts"
import { getCoverageGaps } from "../../context/coverage-grid.ts"
import { AuditWorkspace } from "../../runtime/audit-workspace.ts"
import { AgentDispatcher } from "../../agent/agent-dispatcher.ts"
import { planCoverageRescanTasks, summarizeCoverageRescan } from "../../observer/coverage-rescan.ts"
import { postScanProcessing, runSinkAgentPhase, runSourceAgentPhase } from "./scanning.ts"
import type {
  AuditOptions,
  CoverageGrid,
  CoverageRescanSummary,
  CoverageRescanTask,
  ProjectProfile,
  SourceEntry,
} from "../../types/index.ts"
import type { EventBus } from "../../runtime/event-bus.ts"

export interface CoverageRescanTaskResult {
  task: CoverageRescanTask
  sources: SourceEntry[]
  filesScanned: number
  newHypotheses: number
  totalHypotheses: number
}

export interface CoverageRescanLoopReport {
  checkpoints: Array<{ phase: string; check: string; passed: boolean; detail: string }>
  warnings: string[]
  rescan: CoverageRescanSummary
}

export interface CoverageRescanLoopInputs {
  bus: EventBus
  dispatcher: AgentDispatcher
  options: AuditOptions
  outputDir: string
  profile: ProjectProfile
  coverageGrid: CoverageGrid
  workspace: AuditWorkspace
  log: (msg: string) => void
  processWarnings: (report: { warnings: string[] }) => void
  checkPause: (snapshot: Parameters<typeof saveCheckpoint>[2]) => Promise<void>
}

export async function runCoverageRescanLoop(inputs: CoverageRescanLoopInputs): Promise<CoverageRescanLoopReport> {
  const { bus, dispatcher, outputDir, profile, coverageGrid, workspace, log, processWarnings, checkPause } = inputs
  const enabled = process.env.NIGHT_AGENT_COVERAGE_RESCAN !== "0"
  const maxRounds = envInt("NIGHT_AGENT_COVERAGE_RESCAN_ROUNDS", 2, 0, 6)
  const maxTasks = envInt("NIGHT_AGENT_COVERAGE_RESCAN_TASKS", 4, 1, 20)
  const maxFilesPerTask = envInt("NIGHT_AGENT_COVERAGE_RESCAN_FILES", 24, 1, 80)
  const unvisitedBefore = getCoverageGaps(coverageGrid).length
  let rounds = 0
  let tasksQueued = 0
  let filesQueued = 0
  let filesScanned = 0
  let newSources = 0
  let newHypotheses = 0

  if (enabled && maxRounds > 0 && unvisitedBefore > 0) {
    log(`[observer] coverage rescan loop starting: ${unvisitedBefore} unvisited high-risk file(s)`)
    for (let iteration = 1; iteration <= maxRounds; iteration++) {
      const tasks = planCoverageRescanTasks(profile, coverageGrid, {
        iteration,
        maxTasks,
        maxFilesPerTask,
      })
      if (tasks.length === 0) break
      rounds = iteration
      for (const task of tasks) {
        tasksQueued++
        filesQueued += task.files.length
        const result = await dispatcher.run<CoverageRescanTaskResult>({
          kind: "coverage-rescan",
          agent: "Observer",
          title: `Observer 覆盖率补扫 ${task.id}`,
          inputArtifacts: [
            ...workspace.getAgentArtifactsByKind("profile"),
            ...workspace.getAgentArtifactsByKind("source"),
            ...workspace.getAgentArtifactsByKind("sink"),
          ],
          data: { coverageTask: task },
        })
        const beforeSourceCount = workspace.getSources().length
        workspace.mergeSources(result.sources)
        newSources += Math.max(0, workspace.getSources().length - beforeSourceCount)
        filesScanned += result.filesScanned
        newHypotheses += result.newHypotheses

        const scanObserver = postScanProcessing(profile, coverageGrid, workspace.getSources(), workspace, bus)
        processWarnings(scanObserver)
        await saveCheckpoint(outputDir, "coverage-rescan", workspace.checkpointState(), {
          cursor: tasksQueued,
          total: unvisitedBefore,
          note: `coverage rescan ${tasksQueued} task(s), ${filesScanned} file(s) scanned`,
        })
        await checkPause(workspace.checkpointState())
      }
    }
  }

  const unvisitedAfter = getCoverageGaps(coverageGrid).length
  const summary = summarizeCoverageRescan({
    enabled,
    rounds,
    tasksQueued,
    filesQueued,
    filesScanned,
    newSources,
    newHypotheses,
    unvisitedBefore,
    unvisitedAfter,
    hypotheses: workspace.getHypotheses(),
    maxRounds,
  })
  const detail = enabled
    ? `coverage rescan queued ${tasksQueued} task(s), scanned ${filesScanned}/${filesQueued} file(s), +${newSources} source(s), +${newHypotheses} sink hypothesis/hypotheses, unvisited ${unvisitedBefore} -> ${unvisitedAfter}`
    : "coverage rescan disabled by NIGHT_AGENT_COVERAGE_RESCAN=0"
  const report: CoverageRescanLoopReport = {
    checkpoints: [{
      phase: "reviewing",
      check: "coverage-gap",
      passed: !enabled || unvisitedAfter === 0 || unvisitedAfter < unvisitedBefore,
      detail,
    }],
    warnings: summary.limitations,
    rescan: summary,
  }
  submitAgentResult(bus, "observer", {
    agent: "Observer",
    kind: "coverage",
    title: "Observer 提交覆盖率补扫总结",
    content: summary.limitations.length > 0
      ? `覆盖率补扫完成，但仍有限制：${summary.limitations.join("；")}。`
      : `覆盖率补扫完成：补扫 ${filesScanned} 个文件，新增 ${newSources} 个输入源、${newHypotheses} 个候选危险点。`,
    artifacts: summary as unknown as Record<string, unknown>,
  })
  bus.emit("observer:report", { report, trigger: "coverage-rescan" }, "observer")
  return report
}

export async function runCoverageRescanTask(
  bus: EventBus,
  options: AuditOptions,
  profile: ProjectProfile,
  coverageGrid: CoverageGrid,
  workspace: AuditWorkspace,
  task: CoverageRescanTask,
  log: (msg: string) => void,
): Promise<CoverageRescanTaskResult> {
  const beforeHypotheses = workspace.hypothesisCount()
  const files = task.files.map((file) => file.startsWith("/") ? file : resolve(profile.root, file))

  addEvent("bootstrap", "warn", "Observer coverage rescan queued", `${files.length} file(s): ${task.reason}`)
  bus.emit("coverage:rescan:started", {
    taskId: task.id,
    iteration: task.iteration,
    files,
    modules: task.modules,
    reason: task.reason,
  }, "observer")

  const [sources] = await Promise.all([
    runSourceAgentPhase(bus, options, profile, log, files),
    runSinkAgentPhase(bus, options, profile, workspace, log, files),
  ])

  for (const file of files) {
    if (!coverageGrid.units.has(file)) {
      registerFile(coverageGrid, file, [moduleNameFromPath(profile.root, file)])
    }
    markRescanAttempt(coverageGrid, file, task.reason)
  }

  const totalHypotheses = workspace.hypothesisCount()
  const newHypotheses = Math.max(0, totalHypotheses - beforeHypotheses)
  addEvent(
    "bootstrap",
    newHypotheses > 0 || sources.length > 0 ? "success" : "info",
    "Observer coverage rescan completed",
    `${files.length} file(s), +${sources.length} source(s), +${newHypotheses} sink hypothesis/hypotheses`,
  )
  bus.emit("coverage:rescan:completed", {
    taskId: task.id,
    iteration: task.iteration,
    files,
    modules: task.modules,
    sources: sources.length,
    newHypotheses,
    totalHypotheses,
  }, "observer")
  submitAgentResult(bus, "observer", {
    agent: "Observer",
    kind: "coverage",
    title: "Observer 提交覆盖率补扫任务结果",
    content: `补扫 ${files.length} 个未访问高危文件，SourceAgent 新提交 ${sources.length} 个输入源，SinkAgent 新增 ${newHypotheses} 个候选危险点。`,
    artifacts: {
      task,
      filesScanned: files.length,
      sources: sources.length,
      newHypotheses,
      totalHypotheses,
    },
  })

  return {
    task,
    sources,
    filesScanned: files.length,
    newHypotheses,
    totalHypotheses,
  }
}

function moduleNameFromPath(targetRoot: string, file: string): string {
  const rel = relative(targetRoot, file)
  const parts = rel.split("/")
  const srcIndex = parts.findIndex((part) => part === "main" || part === "src")
  if (srcIndex === -1) return parts[0] ?? "root"
  const after = parts.slice(srcIndex + 1).filter((part) => part !== "java")
  return after.slice(0, -1).join(".") || "root"
}

function envInt(name: string, fallback: number, min: number, max: number): number {
  const parsed = parseInt(process.env[name] ?? "", 10)
  if (!Number.isFinite(parsed)) return fallback
  return Math.min(max, Math.max(min, parsed))
}
