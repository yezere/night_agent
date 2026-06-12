import { relative } from "node:path"
import type {
  CoverageGrid,
  CoverageRescanSummary,
  CoverageRescanTask,
  CoverageUnit,
  Hypothesis,
  ProjectProfile,
} from "../types/index.ts"
import { sortJavaAuditFiles } from "../scanner/file-priority.ts"

export interface CoverageRescanPlanOptions {
  iteration: number
  maxTasks: number
  maxFilesPerTask: number
}

export function planCoverageRescanTasks(
  profile: ProjectProfile,
  grid: CoverageGrid,
  options: CoverageRescanPlanOptions,
): CoverageRescanTask[] {
  const unvisited = [...grid.units.values()].filter((unit) => unit.depth === "unvisited")
  if (unvisited.length === 0) return []

  const byModule = new Map<string, CoverageUnit[]>()
  for (const unit of unvisited) {
    const modules = unit.modules?.length ? unit.modules : [moduleNameFromPath(profile.root, unit.file)]
    for (const mod of modules) {
      const entries = byModule.get(mod) ?? []
      entries.push(unit)
      byModule.set(mod, entries)
    }
  }

  const modules = [...byModule.entries()].sort((a, b) => b[1].length - a[1].length || a[0].localeCompare(b[0]))
  const tasks: CoverageRescanTask[] = []
  for (const [mod, units] of modules) {
    const files = sortJavaAuditFiles(profile.root, new Set(units.map((unit) => unit.file)))
    for (let offset = 0; offset < files.length && tasks.length < options.maxTasks; offset += options.maxFilesPerTask) {
      const batch = files.slice(offset, offset + options.maxFilesPerTask)
      if (batch.length === 0) continue
      tasks.push({
        id: `coverage-rescan-${options.iteration}-${tasks.length + 1}`,
        iteration: options.iteration,
        trigger: "observer-coverage-gap",
        reason: `Observer coverage gap: ${batch.length} unvisited high-risk file(s) in module ${mod}`,
        files: batch,
        modules: [mod],
        unvisitedBefore: unvisited.length,
        createdAt: Date.now(),
      })
    }
    if (tasks.length >= options.maxTasks) break
  }
  return tasks
}

export function summarizeCoverageRescan(input: {
  enabled: boolean
  rounds: number
  tasksQueued: number
  filesQueued: number
  filesScanned: number
  newSources: number
  newHypotheses: number
  unvisitedBefore: number
  unvisitedAfter: number
  hypotheses: Hypothesis[]
  maxRounds: number
}): CoverageRescanSummary {
  const revisitHypotheses = input.hypotheses.filter((hyp) => hyp.status === "maybe_revisit").length
  const limitations: string[] = []
  if (!input.enabled) {
    limitations.push("coverage rescan disabled by NIGHT_AGENT_COVERAGE_RESCAN=0")
  }
  if (input.unvisitedAfter > 0) {
    limitations.push(`${input.unvisitedAfter} high-risk file(s) remain unvisited after ${input.rounds}/${input.maxRounds} rescan round(s)`)
  }
  if (input.tasksQueued > 0 && input.newHypotheses === 0) {
    limitations.push("coverage rescan produced no new sink hypotheses; report should keep uncovered modules explicit")
  }
  if (revisitHypotheses > 0) {
    limitations.push(`${revisitHypotheses} hypothesis/hypotheses remain in maybe_revisit queue`)
  }

  return {
    enabled: input.enabled,
    rounds: input.rounds,
    tasksQueued: input.tasksQueued,
    filesQueued: input.filesQueued,
    filesScanned: input.filesScanned,
    newSources: input.newSources,
    newHypotheses: input.newHypotheses,
    unvisitedBefore: input.unvisitedBefore,
    unvisitedAfter: input.unvisitedAfter,
    revisitHypotheses,
    limitations,
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
