import { resolve } from "node:path"
import type { AuditWorkspaceSnapshot } from "./audit-workspace.ts"
import type {
  AgentArtifact,
  AuditEvent,
  AuditState,
  CoverageGrid,
  EvidenceBundle,
  Finding,
  Hypothesis,
  Note,
  ProjectProfile,
  SourceEntry,
} from "../types/index.ts"

export type CheckpointPhase =
  | "profiling"
  | "scanning"
  | "enriching"
  | "handoff"
  | "coverage-rescan"
  | "joern-query"
  | "tracing"
  | "verifying"
  | "judging"
  | "reviewing"
  | "reporting"
  | "terminated"

export interface RunStateCheckpoint {
  version: 1
  phase: CheckpointPhase
  cursor?: number
  total?: number
  updatedAt: number
  profilePath?: string
  sourcesPath?: string
  hypothesesPath?: string
  evidenceBundlesPath?: string
  findingsPath?: string
  notesPath?: string
  agentArtifactsPath?: string
  eventsPath?: string
  coveragePath?: string
  note?: string
}

export type RuntimeCheckpointSnapshot = AuditWorkspaceSnapshot

interface JsonCoverageGrid {
  totalUnits: number
  units: Array<[string, CoverageGrid["units"] extends Map<string, infer T> ? T : never]>
  byModule: Array<[string, CoverageGrid["byModule"] extends Map<string, infer T> ? T : never]>
}

export function checkpointDir(outputDir: string): string {
  return resolve(outputDir, "checkpoints")
}

export async function saveCheckpoint(
  outputDir: string,
  phase: CheckpointPhase,
  snapshot: RuntimeCheckpointSnapshot,
  progress: { cursor?: number; total?: number; note?: string } = {},
): Promise<RunStateCheckpoint> {
  const dir = checkpointDir(outputDir)
  await Bun.$`mkdir -p ${dir}`
  const previous = await readJson<RunStateCheckpoint>(resolve(dir, "run-state.json"))
  const hypothesesPath = resolve(dir, "phase2-hypotheses.json")
  const evidenceBundlesPath = resolve(dir, "phase2-evidence-bundles.json")
  const findingsPath = resolve(dir, "phase2-findings.json")
  const notesPath = resolve(dir, "phase2-notes.json")
  const agentArtifactsPath = resolve(dir, "phase2-agent-artifacts.json")
  const eventsPath = resolve(dir, "audit-events.json")

  const state: RunStateCheckpoint = {
    version: 1,
    phase,
    cursor: progress.cursor,
    total: progress.total,
    updatedAt: Date.now(),
    profilePath: snapshot.profile ? resolve(dir, "phase0-profile.json") : previous?.profilePath,
    sourcesPath: resolve(dir, "phase1-sources.json"),
    hypothesesPath,
    evidenceBundlesPath,
    findingsPath,
    notesPath,
    agentArtifactsPath,
    eventsPath,
    coveragePath: snapshot.coverageGrid ? resolve(dir, "coverage-grid.json") : previous?.coveragePath,
    note: progress.note,
  }

  if (snapshot.profile) await writeJson(state.profilePath!, snapshot.profile)
  if (snapshot.coverageGrid) await writeJson(state.coveragePath!, serializeCoverageGrid(snapshot.coverageGrid))
  await writeJson(state.sourcesPath!, snapshot.sources)
  await writeJson(hypothesesPath, snapshot.hypotheses)
  await writeJson(evidenceBundlesPath, snapshot.evidenceBundles)
  await writeJson(findingsPath, snapshot.findings)
  await writeJson(notesPath, snapshot.notes)
  await writeJson(agentArtifactsPath, snapshot.agentArtifacts)
  await writeJson(eventsPath, snapshot.events)
  await writeJson(resolve(dir, "run-state.json"), state)
  return state
}

export async function loadCheckpoint(outputDir: string): Promise<{
  state: RunStateCheckpoint
  snapshot: AuditWorkspaceSnapshot
} | null> {
  const dir = checkpointDir(outputDir)
  const state = await readJson<RunStateCheckpoint>(resolve(dir, "run-state.json"))
  if (!state) return null
  const profile = state.profilePath ? await readJson<ProjectProfile>(state.profilePath) : null
  const coverageGrid = state.coveragePath ? deserializeCoverageGrid(await readJson<JsonCoverageGrid>(state.coveragePath)) : null

  return {
    state,
    snapshot: {
      profile,
      coverageGrid: coverageGrid ?? null,
      sources: state.sourcesPath ? await readJson<SourceEntry[]>(state.sourcesPath) ?? [] : [],
      hypotheses: await readJson<Hypothesis[]>(state.hypothesesPath ?? "") ?? [],
      evidenceBundles: await readJson<EvidenceBundle[]>(state.evidenceBundlesPath ?? "") ?? [],
      findings: await readJson<Finding[]>(state.findingsPath ?? "") ?? [],
      notes: await readJson<Note[]>(state.notesPath ?? "") ?? [],
      agentArtifacts: await readJson<AgentArtifact[]>(state.agentArtifactsPath ?? "") ?? [],
      events: await readJson<AuditEvent[]>(state.eventsPath ?? "") ?? [],
    },
  }
}

export async function restoreCheckpoint(outputDir: string): Promise<{
  state: RunStateCheckpoint
  snapshot: AuditWorkspaceSnapshot
} | null> {
  return loadCheckpoint(outputDir)
}

export function canResumeFromPhase(state: RunStateCheckpoint | null | undefined): boolean {
  if (!state) return false
  return ["profiling", "scanning", "enriching", "handoff", "coverage-rescan", "joern-query", "tracing", "verifying", "judging", "reviewing", "reporting"].includes(state.phase)
}

export function phaseToAuditState(phase: CheckpointPhase): AuditState {
  if (phase === "verifying") return "judging"
  if (phase === "handoff" || phase === "coverage-rescan" || phase === "joern-query") return "enriching"
  return phase === "terminated" ? "terminated" : phase
}

async function writeJson(path: string, value: unknown): Promise<void> {
  await Bun.write(path, JSON.stringify(value, null, 2))
}

async function readJson<T>(path: string): Promise<T | null> {
  if (!path) return null
  try {
    return JSON.parse(await Bun.file(path).text()) as T
  } catch {
    return null
  }
}

function serializeCoverageGrid(grid: CoverageGrid): JsonCoverageGrid {
  return {
    totalUnits: grid.totalUnits,
    units: [...grid.units.entries()],
    byModule: [...grid.byModule.entries()],
  }
}

function deserializeCoverageGrid(grid: JsonCoverageGrid | null): CoverageGrid | undefined {
  if (!grid) return undefined
  return {
    totalUnits: grid.totalUnits,
    units: new Map(grid.units),
    byModule: new Map(grid.byModule),
  }
}
