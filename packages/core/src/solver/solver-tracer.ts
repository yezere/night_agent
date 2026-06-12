import { relative, resolve } from "node:path"
import { BaseSolver, type SolverContext } from "./base-solver.ts"
import { runJoern, generateCpg } from "../tracer/joern-runner.ts"
import { traceDataflow, quickReachabilityCheck } from "../tracer/dataflow-tracer.ts"
import { detectJoernResourcePlan } from "../tracer/joern-resources.ts"
import { addEvent } from "../runtime/event-log.ts"
import { saveCheckpoint } from "../runtime/checkpoint-store.ts"
import { markTraced } from "../context/coverage-grid.ts"
import { AuditWorkspace } from "../runtime/audit-workspace.ts"
import type {
  ProjectProfile,
  Hypothesis,
  CoverageGrid,
  AuditOptions,
  DataflowTrace,
  JoernRunResult,
} from "../types/index.ts"
import { compareSeverity } from "../types/index.ts"

interface TraceRuntimeSettings {
  singleHypothesisTimeoutMs: number
  fallbackTimeoutMs: number
  fallbackEnabled: boolean
  autoLimitEnabled: boolean
  autoLimitThreshold: number
  autoLimitCount: number
  maxHypotheses: number | null
  perHypothesisTraceEnabled: boolean
}

export class SolverTracer extends BaseSolver {
  private profile: ProjectProfile
  private options: AuditOptions
  private coverageGrid: CoverageGrid
  private workspace: AuditWorkspace
  private cpgPath: string | null = null
  private joernResult: JoernRunResult = { ran: false, skippedReason: "not started", queryOutputs: [] }

  constructor(
    ctx: SolverContext,
    profile: ProjectProfile,
    options: AuditOptions,
    coverageGrid: CoverageGrid,
    workspace: AuditWorkspace,
    prebuiltCpgPath?: string,
  ) {
    super(ctx)
    this.profile = profile
    this.options = options
    this.coverageGrid = coverageGrid
    this.workspace = workspace
    this.cpgPath = prebuiltCpgPath ?? null
  }

  async start(): Promise<void> {
    this.setStatus("busy")

    if (this.options.runJoern === false) {
      this.joernResult = { ran: false, skippedReason: "--no-joern", queryOutputs: [] }
      this.log("joern disabled by --no-joern")
      this.setStatus("idle")
      return
    }

    // Generate CPG if not already provided
    if (!this.cpgPath) {
      const cpgResult = await generateCpg(this.profile, resolve(this.options.outputDir))
      if (!cpgResult.ok) {
        this.joernResult = { ran: false, skippedReason: cpgResult.skippedReason, queryOutputs: [] }
        this.log(`CPG generation failed: ${cpgResult.skippedReason}`)
        this.setStatus("idle")
        return
      }
      this.cpgPath = cpgResult.cpgPath
    }

    // Run bulk query scripts against CPG
    const outputDir = resolve(this.options.outputDir)
    const joern = await runJoern(this.profile, outputDir, this.options.runJoern ?? true, this.cpgPath, resolve(outputDir, "ai-joern-queries"))
    this.joernResult = joern
    addEvent("explore", joern.ran ? "success" : "warn", joern.ran ? "Joern completed" : "Joern skipped", joern.ran ? `${joern.queryOutputs.length} query script(s)` : joern.skippedReason)

    if (!joern.ran || !joern.cpgPath) {
      this.log(`joern skipped or failed: ${joern.skippedReason ?? "no CPG path"}`)
      this.setStatus("idle")
      return
    }

    this.cpgPath = joern.cpgPath

    // Trace each pending hypothesis
    const pending = this.workspace.getPendingTraceHypotheses()
    // Only trace Java sink files — Joern CPG can't resolve non-Java sinks
    const javaFiltered = pending.filter((h) => h.sinkFile.endsWith(".java") && h.sinkCode.length > 0)
    const sorted = [...javaFiltered].sort((a, b) => compareSeverity(a.severity, b.severity))

    // Track non-Java / empty-sink hypotheses as maybe_revisit
    for (const skipped of pending.filter((h) => !javaFiltered.includes(h))) {
      this.workspace.markTraceSkipped(skipped.id, "non-Java sink or empty sink code — can't trace with Joern")
    }

    const resourcePlan = detectJoernResourcePlan()
    const traceSettings = readTraceRuntimeSettings()
    const tracePlan = this.planTraceBudget(sorted.length, resourcePlan.totalMemoryMb, traceSettings)
    const limited = sorted.slice(0, tracePlan.limit)
    if (tracePlan.reason) {
      this.log(`trace budget: ${tracePlan.reason}; per-hypothesis trace ${limited.length}/${sorted.length}`)
      addEvent("explore", "warn", "TracerAgent memory guard", `${tracePlan.reason}; tracing ${limited.length}/${sorted.length} candidate(s)`)
    }
    for (const skipped of sorted.slice(limited.length)) {
      this.workspace.markTraceSkipped(skipped.id, tracePlan.reason
        ? `deferred by TracerAgent memory guard: ${tracePlan.reason}`
        : `deferred by --max-hypotheses=${this.options.maxHypotheses ?? 200}`)
    }

    const traceConcurrency = resourcePlan.traceConcurrency
    this.log(`trace settings: concurrency=${traceConcurrency}, timeout=${traceSettings.singleHypothesisTimeoutMs}ms, fallback=${traceSettings.fallbackEnabled ? `${traceSettings.fallbackTimeoutMs}ms` : "disabled"}, heap=${resourcePlan.heapMb}m, activeCpu=${resourcePlan.activeProcessorCount}, totalMem=${resourcePlan.totalMemoryMb}m, cpu=${resourcePlan.cpuCount}`)

    let done = 0
    for (let i = 0; i < limited.length; i += traceConcurrency) {
      const batch = limited.slice(i, i + traceConcurrency)
      await Promise.all(batch.map((hyp) => this.traceOne(hyp, traceSettings).then(() => {
        done++
        const updated = this.workspace.getHypothesis(hyp.id)
        if (updated) this.emit("hypothesis:updated", updated)
      })))
      this.log(`trace batch complete: ${done}/${limited.length}`)
      await saveCheckpoint(this.options.outputDir, "tracing", this.workspace.checkpointState(), {
        cursor: done,
        total: limited.length,
        note: `trace batch complete: ${done}/${limited.length}`,
      })
      const pauseReason = this.options.isPauseRequested?.()
      if (pauseReason) {
        addEvent("explore", "warn", "TracerAgent paused", pauseReason)
        throw new Error(`AUDIT_PAUSED:${pauseReason}`)
      }
    }

    this.setStatus("idle")
  }

  async stop(): Promise<void> {
    this.setStatus("idle")
  }

  private async traceOne(hyp: Hypothesis, settings: TraceRuntimeSettings): Promise<void> {
    const relSink = relative(this.profile.root, hyp.sinkFile)
    this.log(`tracing ${hyp.id}: ${hyp.category}/${hyp.severity} origin=${hyp.origin ?? "unknown"} sink=${relSink}:${hyp.sinkLine}`)
    this.workspace.markTraceStarted(hyp.id)
    addEvent("explore", "info", "Tracing hypothesis", hyp.description, [hyp.id])

    // ─── Primary trace ───
    let result = await this.traceWithTimeout(hyp, settings)

    // ─── Conclude fallback (30s quick reachability) ───
    if (!result && this.cpgPath && settings.fallbackEnabled) {
      this.log(`primary trace timed out for ${hyp.id}, attempting conclude fallback...`)
      addEvent("explore", "warn", "Primary trace timed out — trying conclude", hyp.description, [hyp.id])
      try {
        const concludeResult = await Promise.race([
          quickReachabilityCheck(hyp, this.cpgPath, resolve(this.options.outputDir), settings.fallbackTimeoutMs),
          new Promise<null>((resolve) => {
            setTimeout(() => resolve(null), settings.fallbackTimeoutMs + 5_000)
          }),
        ])
        if (concludeResult) {
          result = concludeResult
          this.log(`conclude fallback for ${hyp.id}: reachable=${concludeResult.reachable}, confidence=${concludeResult.confidence}`)
        }
      } catch {
        this.log(`conclude fallback failed for ${hyp.id}`)
      }
    }

    if (!result) {
      this.workspace.markTraceUnresolved(hyp.id, "dataflow trace timeout or error")
      addEvent("explore", "warn", "Trace timed out", hyp.description, [hyp.id])
      this.log(`trace result ${hyp.id}: maybe_revisit timeout-or-error`)
      return
    }

    const pathCount = result.paths.length
    const edgeCount = result.paths.reduce((sum, path) => sum + path.edges.length, 0)
    const sanitizerDesc = result.sanitizers.map((s) => s.kind).join(", ") || "none"
    if (result.reachable) {
      const note = result.confidence === "low" ? "low-confidence (conclude fallback)" : undefined
      this.workspace.recordTraceResult(hyp.id, result, note)
      markTraced(this.coverageGrid, resolve(this.profile.root, hyp.sinkFile))
      addEvent("explore", "success", "Dataflow confirmed", hyp.description, [hyp.id])
      this.log(`trace result ${hyp.id}: reachable=true confidence=${result.confidence} paths=${pathCount} edges=${edgeCount} sanitizers=${sanitizerDesc}`)
    } else if (result.sanitizers.length > 0) {
      this.workspace.recordTraceResult(hyp.id, result, `sanitizer: ${sanitizerDesc}`)
      markTraced(this.coverageGrid, resolve(this.profile.root, hyp.sinkFile))
      addEvent("explore", "info", "Dismissed by sanitizer", sanitizerDesc, [hyp.id])
      this.log(`trace result ${hyp.id}: dismissed reachable=false confidence=${result.confidence} paths=${pathCount} edges=${edgeCount} sanitizers=${sanitizerDesc}`)
    } else {
      this.workspace.recordTraceResult(hyp.id, result, "no path found but no sanitizer either")
      addEvent("explore", "warn", "No flow found", hyp.description, [hyp.id])
      this.log(`trace result ${hyp.id}: maybe_revisit reachable=false confidence=${result.confidence} paths=${pathCount} edges=${edgeCount} sanitizers=none`)
    }
  }

  private async traceWithTimeout(hyp: Hypothesis, settings: TraceRuntimeSettings): Promise<DataflowTrace | null> {
    if (!this.cpgPath) return null
    try {
      return await Promise.race([
        traceDataflow(hyp, this.cpgPath, resolve(this.options.outputDir), settings.singleHypothesisTimeoutMs),
        new Promise<null>((resolve) => {
          setTimeout(() => resolve(null), settings.singleHypothesisTimeoutMs + 5_000)
        }),
      ])
    } catch {
      return null
    }
  }

  getCpgPath(): string | null {
    return this.cpgPath
  }

  getJoernResult(): JoernRunResult {
    return this.joernResult
  }

  private planTraceBudget(totalCandidates: number, totalMemoryMb: number, settings: TraceRuntimeSettings): { limit: number; reason?: string } {
    const optionLimit = this.options.maxHypotheses ?? 200
    let limit = Math.min(totalCandidates, optionLimit)
    if (!settings.perHypothesisTraceEnabled) {
      return { limit: 0, reason: "per-hypothesis Joern trace disabled by NIGHT_AGENT_PER_HYPOTHESIS_TRACE=0" }
    }
    if (settings.maxHypotheses !== null) {
      return {
        limit: Math.min(limit, settings.maxHypotheses),
        reason: `limited by NIGHT_AGENT_TRACE_MAX_HYPOTHESES=${settings.maxHypotheses}`,
      }
    }
    if (settings.autoLimitEnabled && totalMemoryMb < 32_768 && totalCandidates > settings.autoLimitThreshold) {
      return {
        limit: Math.min(limit, settings.autoLimitCount),
        reason: `auto-limited on ${totalMemoryMb}MB memory with ${totalCandidates} trace candidates`,
      }
    }
    if (limit < totalCandidates) return { limit, reason: `limited by --max-hypotheses=${optionLimit}` }
    return { limit }
  }
}

function readIntEnv(name: string, fallback: number): number {
  const value = Number(process.env[name])
  return Number.isFinite(value) && value > 0 ? Math.floor(value) : fallback
}

function readTraceRuntimeSettings(): TraceRuntimeSettings {
  return {
    singleHypothesisTimeoutMs: readIntEnv("NIGHT_AGENT_TRACE_TIMEOUT_MS", 180_000),
    fallbackTimeoutMs: readIntEnv("NIGHT_AGENT_TRACE_FALLBACK_TIMEOUT_MS", 45_000),
    fallbackEnabled: process.env.NIGHT_AGENT_TRACE_FALLBACK !== "0",
    autoLimitEnabled: process.env.NIGHT_AGENT_TRACE_AUTO_LIMIT !== "0",
    autoLimitThreshold: readIntEnv("NIGHT_AGENT_TRACE_AUTO_LIMIT_THRESHOLD", 40),
    autoLimitCount: readNonNegativeIntEnv("NIGHT_AGENT_TRACE_AUTO_LIMIT_COUNT", 0),
    maxHypotheses: readOptionalIntEnv("NIGHT_AGENT_TRACE_MAX_HYPOTHESES"),
    perHypothesisTraceEnabled: process.env.NIGHT_AGENT_PER_HYPOTHESIS_TRACE !== "0",
  }
}

function readOptionalIntEnv(name: string): number | null {
  const raw = process.env[name]
  if (!raw) return null
  const value = Number(raw)
  return Number.isFinite(value) && value >= 0 ? Math.floor(value) : null
}

function readNonNegativeIntEnv(name: string, fallback: number): number {
  const raw = process.env[name]
  if (!raw) return fallback
  const value = Number(raw)
  return Number.isFinite(value) && value >= 0 ? Math.floor(value) : fallback
}
