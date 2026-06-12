import type { EventBus } from "../runtime/event-bus.ts"
import type { StateMachine } from "../runtime/state-machine.ts"
import type {
  AgentIdentity,
  AgentBusEvent,
  CheckpointResult,
  Hypothesis,
  CoverageGrid,
  ObserverReport,
  SharedAuditState,
} from "../types/index.ts"
import {
  deduplicateHypotheses,
  checkScopeDrift,
  checkEvidenceQuality,
  checkCoverageGap,
  checkStagnation,
} from "./supervisor.ts"
import { coveragePercent } from "../context/coverage-grid.ts"
import { snapshotCheckpoint, shouldTriggerReason, type ReasonCheckpoint } from "./checkpoint.ts"

const STAGNATION_AFTER_N_TRACES = 10

export interface ObserverDeps {
  bus: EventBus
  sm: StateMachine
  getState: () => SharedAuditState
  getHypotheses: () => Hypothesis[]
  getCoverageGrid: () => CoverageGrid | null
  log?: (msg: string) => void
}

export class ObserverAgent {
  readonly identity: AgentIdentity = { id: "observer", role: "observer", status: "idle" }
  private bus: EventBus
  private sm: StateMachine
  private getState: () => SharedAuditState
  private getHypotheses: () => Hypothesis[]
  private getCoverageGrid: () => CoverageGrid | null
  private unsubs: Array<() => void> = []
  private warningCount = 0
  private previousConfirmed = 0
  private tracedCount = 0
  private lastCoverageGapWarn = 0
  private lastStagnationWarn = 0
  private log: (msg: string) => void
  // Checkpoint-based trigger (Cairn pattern #4)
  private lastCheckpoint: ReasonCheckpoint | null = null

  constructor(deps: ObserverDeps) {
    this.bus = deps.bus
    this.sm = deps.sm
    this.getState = deps.getState
    this.getHypotheses = deps.getHypotheses
    this.getCoverageGrid = deps.getCoverageGrid
    this.log = deps.log ?? (() => {})
  }

  /** Start continuous monitoring — subscribe to relevant events. */
  start(): void {
    this.identity.status = "busy"
    this.log("started; monitoring state transitions, hypothesis updates, and findings")

    this.unsubs.push(
      this.bus.subscribe("hypothesis:updated", (event) => {
        this.onHypothesisUpdated(event)
      }),
    )

    this.unsubs.push(
      this.bus.subscribe("state:enter", (event) => {
        this.onStateEnter(event)
      }),
    )

    // Checkpoint-based Reason trigger (Cairn pattern #4)
    // Trigger review on: findings increased, notes increased, or pending→0
    this.unsubs.push(
      this.bus.subscribe("finding:confirmed", () => {
        const hyps = this.getHypotheses()
        const current = snapshotCheckpoint(
          hyps.filter((h) => h.status === "confirmed").length,
          hyps.filter((h) => h.dataflowResult).length, // note proxy: hypotheses with dataflow
          hyps.filter((h) => h.status === "pending").length,
          hyps.filter((h) => h.status === "dismissed").length,
        )
        const { trigger } = shouldTriggerReason(current, this.lastCheckpoint)
        if (trigger) {
          this.lastCheckpoint = current
          this.runReview("periodic")
        }
      }),
    )

    this.unsubs.push(
      this.bus.subscribe("hypothesis:updated", () => {
        const hyps = this.getHypotheses()
        const current = snapshotCheckpoint(
          hyps.filter((h) => h.status === "confirmed").length,
          hyps.filter((h) => h.dataflowResult).length,
          hyps.filter((h) => h.status === "pending").length,
          hyps.filter((h) => h.status === "dismissed").length,
        )
        const { trigger, changes } = shouldTriggerReason(current, this.lastCheckpoint)
        if (trigger && changes.some((c) => c === "open hypotheses exhausted")) {
          // Only trigger on "pending exhausted" from hypothesis updates
          // (findings increased is handled by finding:confirmed above)
          this.lastCheckpoint = current
          this.runReview("periodic")
        }
      }),
    )

    // Initialize checkpoint
    const hyps = this.getHypotheses()
    this.lastCheckpoint = snapshotCheckpoint(
      hyps.filter((h) => h.status === "confirmed").length,
      hyps.filter((h) => h.dataflowResult).length,
      hyps.filter((h) => h.status === "pending").length,
      hyps.filter((h) => h.status === "dismissed").length,
    )

    this.bus.emit("observer:started", { agent: "observer" }, "observer")
  }

  /** Stop monitoring — unsubscribe all. */
  stop(): void {
    this.identity.status = "idle"
    for (const unsub of this.unsubs) {
      unsub()
    }
    this.unsubs = []
    this.log(`stopped; warnings=${this.warningCount}, tracedConfirmed=${this.tracedCount}`)
    this.bus.emit("observer:stopped", { agent: "observer" }, "observer")
  }

  /** Get observer statistics. */
  stats(): { warningCount: number; previousConfirmed: number; tracedCount: number } {
    return {
      warningCount: this.warningCount,
      previousConfirmed: this.previousConfirmed,
      tracedCount: this.tracedCount,
    }
  }

  // ─── Event handlers ───

  private onHypothesisUpdated(event: AgentBusEvent): void {
    const hyp = event.payload as Hypothesis | undefined
    if (!hyp) return

    if (hyp.status === "confirmed") {
      this.tracedCount++
    }
  }

  private onStateEnter(event: AgentBusEvent): void {
    const p = event.payload as { state: string } | undefined
    if (!p) return

    if (p.state === "reviewing") {
      this.runReview("phase-boundary")
    }

    if (p.state === "reporting") {
      this.runReview("final")
    }

    if (p.state === "tracing") {
      this.tracedCount = 0
    }
  }

  // ─── Review orchestration ───

  runReview(trigger: "periodic" | "phase-boundary" | "final"): ObserverReport {
    const hyps = this.getHypotheses()
    const grid = this.getCoverageGrid()

    if (!grid || hyps.length === 0) {
      this.log(`review skipped (${trigger}); grid=${grid ? "yes" : "no"}, hypotheses=${hyps.length}`)
      return { checkpoints: [], warnings: [] }
    }

    const warnings: string[] = []
    const checkpoints: CheckpointResult[] = []

    // 1. Scope drift (periodic + phase-boundary)
    if (trigger !== "final") {
      const drift = checkScopeDrift(hyps, grid)
      checkpoints.push(drift)
      if (!drift.passed) {
        warnings.push(drift.detail)
        this.emitWarning("scope-drift", drift.detail)
      }
    }

    // 2. Stagnation (periodic, after enough traces)
    if (this.tracedCount >= STAGNATION_AFTER_N_TRACES) {
      const stag = checkStagnation(hyps, this.previousConfirmed)
      checkpoints.push(stag)
      if (!stag.passed && Date.now() - this.lastStagnationWarn > 60_000) {
        warnings.push(stag.detail)
        this.lastStagnationWarn = Date.now()
        this.emitWarning("stagnation", stag.detail)
        this.steer("stagnation detected — consider transitioning to review or expanding scope")
      }
      this.previousConfirmed = hyps.filter((h) => h.status === "confirmed").length
    }

    // 3. Coverage gap (periodic, throttle 30s)
    if (Date.now() - this.lastCoverageGapWarn > 30_000) {
      const gap = checkCoverageGap(grid)
      checkpoints.push(gap)
      if (!gap.passed) {
        warnings.push(gap.detail)
        this.lastCoverageGapWarn = Date.now()
        this.emitWarning("coverage-gap", gap.detail)
      }
    }

    // 4. Dedup (phase-boundary + final)
    if (trigger !== "periodic") {
      const dedup = deduplicateHypotheses(hyps)
      checkpoints.push(dedup)
      if (!dedup.passed) {
        warnings.push(dedup.detail)
        this.emitWarning("dedup", dedup.detail)
      }
    }

    // 5. Premature-end (phase-boundary)
    if (trigger === "phase-boundary") {
      const cov = coveragePercent(grid)
      const pending = hyps.filter((h) => h.status === "pending").length
      checkpoints.push({
        phase: "reviewing",
        check: "premature-end",
        passed: !(cov < 20 && pending > 5),
        detail: `coverage ${cov}%, ${pending} pending`,
      })
      if (cov < 20 && pending > 5) {
        const msg = `premature transition: ${cov}% coverage with ${pending} pending — consider re-scanning`
        warnings.push(msg)
        this.emitWarning("premature-end", msg)
        this.steer(msg)
      }
    }

    // 6. Evidence quality (final)
    if (trigger === "final") {
      const ev = checkEvidenceQuality(hyps)
      checkpoints.push(ev)
      if (!ev.passed) {
        warnings.push(ev.detail)
        this.emitWarning("evidence-quality", ev.detail)
      }
    }

    const report: ObserverReport = { checkpoints, warnings }
    this.log(`review ${trigger}: ${checkpoints.length} checkpoint(s), ${warnings.length} warning(s)`)
    for (const checkpoint of checkpoints) {
      this.log(`${checkpoint.passed ? "PASS" : "WARN"} ${checkpoint.phase}/${checkpoint.check}: ${checkpoint.detail}`)
    }
    this.bus.emit("observer:report", { report, trigger }, "observer")
    return report
  }

  // ─── Enforcement ───

  private emitWarning(check: string, detail: string): void {
    this.warningCount++
    this.log(`warning ${check}: ${detail}`)
    this.bus.emit("observer:warning", {
      check,
      detail,
      total: this.warningCount,
    }, "observer")
  }

  private steer(message: string): void {
    this.bus.emit("observer:steer", {
      message,
      warningCount: this.warningCount,
      timestamp: Date.now(),
    }, "observer")
  }

  /** Force a state transition — emergency override for critical issues. */
  forceTransition(to: string, reason: string): void {
    this.sm.forceTransition(to as Parameters<StateMachine["forceTransition"]>[0])
    this.bus.emit("observer:force-transition", { to, reason }, "observer")
  }
}
