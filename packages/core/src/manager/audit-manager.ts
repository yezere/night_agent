import { resolve } from "node:path"
import { EventBus } from "../runtime/event-bus.ts"
import { StateMachine } from "../runtime/state-machine.ts"
import { DEFAULT_TERMINATION } from "../runtime/termination.ts"
import { ObserverAgent } from "../observer/observer-agent.ts"
import { addEvent, clearEvents, getEvents } from "../runtime/event-log.ts"
import { submitAgentResult } from "../runtime/agent-submission.ts"
import { restoreCheckpoint, saveCheckpoint, type CheckpointPhase } from "../runtime/checkpoint-store.ts"
import { AuditWorkspace } from "../runtime/audit-workspace.ts"
import { AgentDispatcher } from "../agent/agent-dispatcher.ts"

// Phase modules
import { runProfiling, type ProfilingResult } from "./phases/profiling.ts"
import {
  runCpgAgentPhase,
  runSourceAgentPhase,
  runSinkAgentPhase,
  postScanProcessing,
  logObserverReport,
  type CpgResult,
} from "./phases/scanning.ts"
import { runTracingPhase, postTracingObserver } from "./phases/tracing.ts"
import { runJoernDiscoveryPhase } from "./phases/discovery.ts"
import { runVerifyingPhase } from "./phases/verifying.ts"
import { runJudgingPhase } from "./phases/judging.ts"
import { runReviewingPhase, runReportingPhase, createFailReport } from "./phases/reporting.ts"
import { JoernQueryAgent } from "../solver/solver-joern-query.ts"
import { runCoverageRescanLoop as runCoverageRescanLoopPhase, runCoverageRescanTask } from "./phases/coverage-rescan.ts"

import type {
  AuditOptions,
  AuditReport,
  CoverageRescanTask,
  ProjectProfile,
  SourceEntry,
  SharedAuditState,
  AuditStats,
  CoverageGrid,
  AgentBusEvent,
} from "../types/index.ts"

export type WsCallback = (event: AgentBusEvent) => void

export class AuditManager {
  private bus: EventBus
  private sm: StateMachine
  private options: AuditOptions
  private workspace: AuditWorkspace
  private startTime: number = 0
  private observerFailures: number = 0

  // State
  private wsCallback: WsCallback | null = null
  private observer: ObserverAgent | null = null
  private tracer: ReturnType<typeof runTracingPhase> = null as unknown as ReturnType<typeof runTracingPhase>
  private dispatcher: AgentDispatcher | null = null
  private pauseRequested: string | null = null

  constructor(options: AuditOptions, wsCallback?: WsCallback) {
    this.options = options
    this.workspace = new AuditWorkspace(options)
    this.bus = new EventBus()
    this.sm = new StateMachine()
    this.wsCallback = wsCallback ?? null

    // Forward all events to WebSocket
    this.bus.subscribe("*", (event) => {
      this.wsCallback?.(event)
    })
  }

  private log(msg: string): void {
    console.log(`  [manager] ${msg}`)
  }

  getState(): SharedAuditState {
    return this.workspace.runInScope(() => ({
      currentState: this.sm.state,
      profile: this.workspace.getProfile(),
      sources: this.workspace.getSources(),
      stats: this.buildStats(),
      iteration: this.sm.iterations(),
      termination: {
        maxTimeMinutes: this.options.timeoutMinutes ?? DEFAULT_TERMINATION.maxTimeMinutes,
        maxIterations: DEFAULT_TERMINATION.maxIterations,
        minCoveragePercent: DEFAULT_TERMINATION.minCoveragePercent,
        maxPendingHypotheses: DEFAULT_TERMINATION.maxPendingHypotheses,
        observerFailureLimit: DEFAULT_TERMINATION.observerFailureLimit,
      },
      agentStatuses: {
        manager: "busy",
        source: "idle",
        sink: "idle",
        joernDiscovery: "idle",
        joernQuery: "idle",
        tracer: "idle",
        verifier: "idle",
        judge: "idle",
        observer: this.observer?.identity.status ?? "idle",
      },
    }))
  }

  requestPause(reason = "paused by user"): void {
    this.pauseRequested = reason
    this.workspace.runInScope(() => {
      addEvent("bootstrap", "warn", "Pause requested", reason)
      this.bus.emit("audit:paused", { status: "requested", reason }, "manager")
    })
  }

  stop(): void {
    this.observer?.stop()
    this.observer = null
  }

  async run(): Promise<AuditReport> {
    this.workspace.enterScope()
    const outputDir = resolve(this.options.outputDir)
    this.startTime = Date.now()
    clearEvents()
    this.workspace.reset()
    await Bun.$`mkdir -p ${outputDir}`

    addEvent("bootstrap", "info", "Audit started", this.options.target)
    submitAgentResult(this.bus, "manager", {
      kind: "origin",
      agent: "Manager",
      title: "Manager 提交审计目标",
      content: `目标已进入 AgentBoard：${this.options.target}`,
      artifacts: {
        target: this.options.target,
        outputDir,
        runJoern: this.options.runJoern !== false,
        provider: this.options.llmConfig?.provider,
        model: this.options.llmConfig?.model,
      },
    })
    submitAgentResult(this.bus, "manager", {
      kind: "goal",
      agent: "Manager",
      title: "Manager 提交协作目标",
      content: "多 Agent 协作完成代码审计：画像、Source/Sink 提取、交接、Joern 追踪、AI 静态复核、判定、Observer 复核、PoC 和中文报告。",
      artifacts: {
        priorityCategories: ["cmdi", "sqli", "file-download", "file-upload", "ssti", "spel", "ognl", "expression"],
      },
    })
    this.bus.emit("state:changed", { state: "init" }, "manager")

    // ─── OBSERVER STARTUP ───
    this.startObserver()
    this.dispatcher = this.createDispatcher()

    // ─── AGENT WORKFLOW ───
    const restored = this.options.resumeFromCheckpoint ? await this.restoreCheckpointIfPresent(outputDir) : null
    let resumePhase: CheckpointPhase | null = restored?.phase ?? null
    let profile: ProjectProfile | null = restored?.profile ?? null
    let coverageGrid: CoverageGrid | null = restored?.coverageGrid ?? null

    if (restored) {
      this.log(`resuming from checkpoint phase=${restored.phase} cursor=${restored.cursor ?? "-"} total=${restored.total ?? "-"}`)
      this.bus.emit("state:enter", {
        state: "preparing",
        description: `从 checkpoint 继续：${restored.phase}`,
        checkpoint: restored,
      }, "manager")
      addEvent("bootstrap", "info", "Audit checkpoint restored", `${restored.phase} ${restored.cursor ?? ""}/${restored.total ?? ""}`.trim())
    }

    if (!profile || !coverageGrid || !isAfterOrAt(resumePhase, "profiling")) {
      const profiled = await this.dispatcher.run<ProfilingResult>({
        kind: "profile",
        agent: "ProfilingAgent",
        title: "项目画像 Agent",
        inputArtifacts: this.workspace.getAgentArtifactsByKind("origin"),
      })
      profile = profiled.profile
      coverageGrid = profiled.coverageGrid
      if (profile && coverageGrid) {
        this.workspace.setProfile(profile)
        this.workspace.setCoverageGrid(coverageGrid)
        await saveCheckpoint(outputDir, "profiling", this.workspace.checkpointState())
      }
      await this.checkPause("profiling", outputDir, this.workspace.checkpointState())
      resumePhase = null
    }
    if (!profile || !coverageGrid) {
      this.observer?.stop()
      return createFailReport(
        profile ?? this.dummyProfile(),
        coverageGrid ?? this.dummyGrid(),
        this.startTime,
        "profiling failed",
        this.workspace,
      )
    }
    this.workspace.setProfile(profile)
    this.workspace.setCoverageGrid(coverageGrid)

    let cpgResult: CpgResult = this.cpgFromCheckpoint(outputDir)
    if (isAfterOrAt(resumePhase, "scanning")) {
      this.log(`scan phase restored: SourceAgent=${this.workspace.getSources().length}, SinkAgent=${this.workspace.hypothesisCount()}, CPG=${cpgResult.ok ? "ready" : "unavailable"}`)
      this.sm.forceTransition("scanning")
      this.bus.emit("state:enter", { state: "scanning", from: "checkpoint", restored: true }, "manager")
      this.bus.emit("state:leave", { state: "scanning", restored: true }, "manager")
    } else {
      const scanningTransition = this.sm.transition("scanning")
      if (!scanningTransition.ok) {
        this.observer?.stop()
        return createFailReport(profile, coverageGrid, this.startTime, scanningTransition.error, this.workspace)
      }
      this.bus.emit("state:enter", { state: "scanning", from: scanningTransition.from }, "manager")
      this.log("dispatcher parallel phase: CPG + SourceAgent + SinkAgent")
      addEvent("bootstrap", "info", "Dispatcher parallel phase started", "CPG + SourceAgent + SinkAgent")

      const [sources, , generatedCpg] = await Promise.all([
        this.dispatcher.run<SourceEntry[]>({
          kind: "source",
          agent: "SourceAgent",
          title: "输入源提取 Agent",
          inputArtifacts: this.workspace.getAgentArtifactsByKind("profile"),
        }),
        this.dispatcher.run<void>({
          kind: "sink",
          agent: "SinkAgent",
          title: "危险点扫描 Agent",
          inputArtifacts: this.workspace.getAgentArtifactsByKind("profile"),
        }),
        this.dispatcher.run<CpgResult>({
          kind: "cpg",
          agent: "CpgAgent",
          title: "CPG 生成 Agent",
          inputArtifacts: this.workspace.getAgentArtifactsByKind("profile"),
        }),
      ])
      cpgResult = generatedCpg
      this.workspace.setSources(sources)
      this.log(`dispatcher parallel phase complete: SourceAgent=${sources.length}, SinkAgent=${this.workspace.hypothesisCount()}, CPG=${cpgResult.ok ? "ready" : "unavailable"}`)
      this.bus.emit("state:leave", { state: "scanning" }, "manager")
      await saveCheckpoint(outputDir, "scanning", this.workspace.checkpointState())
      await this.checkPause("scanning", outputDir, this.workspace.checkpointState())
    }

    if (isAfterOrAt(resumePhase, "enriching")) {
      this.sm.forceTransition("enriching")
      this.bus.emit("state:enter", { state: "enriching", from: "checkpoint", restored: true }, "manager")
      this.bus.emit("state:leave", { state: "enriching", restored: true }, "manager")
    } else {
      const enrichingTransition = this.sm.transition("enriching")
      if (enrichingTransition.ok) {
        this.bus.emit("state:enter", { state: "enriching", from: enrichingTransition.from }, "manager")
        await this.dispatcher.run<void>({
          kind: "discover",
          agent: "JoernDiscoveryAgent",
          title: "Joern/CPG 补充发现 Agent",
          inputArtifacts: [
            ...this.workspace.getAgentArtifactsByKind("source"),
            ...this.workspace.getAgentArtifactsByKind("sink"),
            ...this.workspace.getAgentArtifactsByKind("cpg"),
          ],
          data: { cpgPath: cpgResult.ok ? cpgResult.cpgPath : undefined },
        })
        this.bus.emit("state:leave", { state: "enriching" }, "manager")
        await saveCheckpoint(outputDir, "enriching", this.workspace.checkpointState())
        await this.checkPause("enriching", outputDir, this.workspace.checkpointState())
      } else {
        this.log(`enriching skipped: ${enrichingTransition.error}`)
      }
    }

    if (!isAfterOrAt(resumePhase, "handoff")) {
      const scanObserver = await this.dispatcher.run<{ warnings: string[] }>({
        kind: "handoff",
        agent: "EvidenceBundler",
        title: "Source/Sink 交接 Agent",
        inputArtifacts: [
          ...this.workspace.getAgentArtifactsByKind("source"),
          ...this.workspace.getAgentArtifactsByKind("sink"),
        ],
      })
      this.processWarningsFromReport(scanObserver)
      await saveCheckpoint(outputDir, "handoff", this.workspace.checkpointState())
      await this.checkPause("handoff", outputDir, this.workspace.checkpointState())
    }

    if (!isAfterOrAt(resumePhase, "coverage-rescan")) {
      const rescanObserver = await this.runCoverageRescanLoop(outputDir)
      this.processWarningsFromReport(rescanObserver)
      await saveCheckpoint(outputDir, "coverage-rescan", this.workspace.checkpointState())
      await this.checkPause("coverage-rescan", outputDir, this.workspace.checkpointState())
    }

    if (!isAfterOrAt(resumePhase, "joern-query")) {
      await this.dispatcher.run<void>({
        kind: "joern-query",
        agent: "JoernQueryAgent",
        title: "Joern 查询编写 Agent",
        inputArtifacts: [
          ...this.workspace.getAgentArtifactsByKind("source"),
          ...this.workspace.getAgentArtifactsByKind("sink"),
          ...this.workspace.getAgentArtifactsByKind("cpg"),
        ],
        data: { cpgPath: cpgResult.ok ? cpgResult.cpgPath : undefined },
      })
      await saveCheckpoint(outputDir, "joern-query", this.workspace.checkpointState())
      await this.checkPause("joern-query", outputDir, this.workspace.checkpointState())
    }

    if (!isAfterOrAt(resumePhase, "tracing") || this.workspace.hasTraceWorkRemaining()) {
      const traceReport = await this.dispatcher.run<{ warnings: string[] }>({
        kind: "trace",
        agent: "TracerAgent",
        title: "Joern/数据流追踪 Agent",
        inputArtifacts: [
          ...this.workspace.getAgentArtifactsByKind("handoff"),
          ...this.workspace.getAgentArtifactsByKind("query"),
        ],
        data: { cpgPath: cpgResult.ok ? cpgResult.cpgPath : undefined },
      })
      this.processWarningsFromReport(traceReport)
      await saveCheckpoint(outputDir, "tracing", this.workspace.checkpointState())
      await this.checkPause("tracing", outputDir, this.workspace.checkpointState())
    } else {
      this.sm.forceTransition("tracing")
    }

    if (!isAfterOrAt(resumePhase, "verifying") || this.workspace.hasVerifyWorkRemaining()) {
      await this.dispatcher.run<void>({
        kind: "verify",
        agent: "StaticVerifierAgent",
        title: "AI 静态复核 Agent",
        inputArtifacts: [
          ...this.workspace.getAgentArtifactsByKind("handoff"),
          ...this.workspace.getAgentArtifactsByKind("trace"),
          ...this.workspace.getAgentArtifactsByKind("query"),
        ],
      })
      await saveCheckpoint(outputDir, "verifying", this.workspace.checkpointState())
      await this.checkPause("verifying", outputDir, this.workspace.checkpointState())
    }

    await this.dispatcher.run<void>({
      kind: "judge",
      agent: "JudgeAgent",
      title: "证据判定 Agent",
      inputArtifacts: [
        ...this.workspace.getAgentArtifactsByKind("trace"),
        ...this.workspace.getAgentArtifactsByKind("verification"),
      ],
    })
    await saveCheckpoint(outputDir, "judging", this.workspace.checkpointState())
    await this.checkPause("judging", outputDir, this.workspace.checkpointState())

    const reviewWarnings = await this.dispatcher.run<{ warnings: string[] }>({
      kind: "observe",
      agent: "Observer",
      title: "全局复核 Agent",
      inputArtifacts: [
        ...this.workspace.getAgentArtifactsByKind("trace"),
        ...this.workspace.getAgentArtifactsByKind("finding"),
      ],
    })
    this.processWarningsFromReport(reviewWarnings)
    await saveCheckpoint(outputDir, "reviewing", this.workspace.checkpointState())
    await this.checkPause("reviewing", outputDir, this.workspace.checkpointState())

    const report = await this.dispatcher.run<AuditReport>({
      kind: "report",
      agent: "ReportAgent",
      title: "中文报告 Agent",
      inputArtifacts: this.workspace.getAgentArtifacts(),
      data: { outputDir },
    })

    // Clean up
    this.observer?.stop()
    this.workspace.reset()
    clearEvents()

    return report

  }

  private createDispatcher(): AgentDispatcher {
    const dispatcher = new AgentDispatcher(this.bus, (msg) => this.log(msg))
    dispatcher.register("profile", () => runProfiling(this.sm, this.bus, this.options, this.log))
    dispatcher.register("source", () => {
      const profile = this.workspace.requireProfile()
      return runSourceAgentPhase(this.bus, this.options, profile, this.log)
    })
    dispatcher.register("sink", async () => {
      const profile = this.workspace.requireProfile()
      await runSinkAgentPhase(this.bus, this.options, profile, this.workspace, this.log)
    })
    dispatcher.register("cpg", () => {
      const profile = this.workspace.requireProfile()
      return runCpgAgentPhase(this.bus, this.options, profile, this.log)
    })
    dispatcher.register("discover", async () => {
      const profile = this.workspace.requireProfile()
      const cpgArtifact = this.workspace.latestArtifactData<{ ok?: boolean; cpgPath?: string }>("cpg")
      const result = await runJoernDiscoveryPhase(
        this.bus,
        this.options,
        profile,
        this.workspace,
        this.workspace.getSources(),
        cpgArtifact?.ok ? cpgArtifact.cpgPath : undefined,
        this.log,
      )
      if (result.sources.length > 0) {
        const sources = this.workspace.mergeSources(result.sources)
        this.log(`[joern-discovery] source list merged: +${result.sources.length}, total=${sources.length}`)
      }
    })
    dispatcher.register("handoff", () => {
      return postScanProcessing(this.workspace.requireProfile(), this.workspace.requireCoverageGrid(), this.workspace.getSources(), this.workspace, this.bus)
    })
    dispatcher.register("coverage-rescan", (ctx) => {
      const task = ctx.task.data?.coverageTask as CoverageRescanTask | undefined
      if (!task) throw new Error("CoverageRescan missing coverage task payload")
      return runCoverageRescanTask(this.bus, this.options, this.workspace.requireProfile(), this.workspace.requireCoverageGrid(), this.workspace, task, this.log)
    })
    dispatcher.register("joern-query", async () => {
      const cpgArtifact = this.workspace.latestArtifactData<{ ok?: boolean; cpgPath?: string }>("cpg")
      await this.runJoernQueryAgent(this.workspace.requireProfile(), cpgArtifact?.ok ? cpgArtifact.cpgPath : undefined)
    })
    dispatcher.register("trace", async () => {
      const profile = this.workspace.requireProfile()
      const coverageGrid = this.workspace.requireCoverageGrid()
      const cpgArtifact = this.workspace.latestArtifactData<{ ok?: boolean; cpgPath?: string }>("cpg")
      this.tracer = runTracingPhase(
        this.sm,
        this.bus,
        this.options,
        profile,
        coverageGrid,
        this.workspace,
        cpgArtifact?.ok ? cpgArtifact.cpgPath : undefined,
        this.log,
      )
      if (this.tracer) await this.tracer.start()
      const traceReport = postTracingObserver(coverageGrid, this.bus, this.log, profile, this.workspace.getSources(), this.workspace)
      this.bus.emit("state:leave", { state: "tracing" }, "manager")
      return traceReport
    })
    dispatcher.register("verify", async () => {
      const cpgArtifact = this.workspace.latestArtifactData<{ ok?: boolean; cpgPath?: string }>("cpg")
      await runVerifyingPhase(
        this.bus,
        this.options,
        this.workspace.requireProfile(),
        this.workspace,
        cpgArtifact?.ok ? cpgArtifact.cpgPath : undefined,
        this.log,
      )
    })
    dispatcher.register("judge", async () => {
      await runJudgingPhase(this.sm, this.bus, this.options, this.workspace.requireProfile(), this.workspace, this.workspace.getSources(), this.log)
    })
    dispatcher.register("observe", () => {
      return runReviewingPhase(this.sm, this.bus, this.workspace.requireCoverageGrid(), this.workspace, this.log, { profile: this.workspace.requireProfile(), sources: this.workspace.getSources() })
    })
    dispatcher.register("report", () => {
      return runReportingPhase(this.sm, this.bus, {
        options: this.options,
        profile: this.workspace.requireProfile(),
        coverageGrid: this.workspace.requireCoverageGrid(),
        workspace: this.workspace,
        tracer: this.tracer,
        startTime: this.startTime,
        sources: this.workspace.getSources(),
        runPoc: async (report) => {
          const { runPocAgent } = await import("../report/poc-agent.ts")
          await runPocAgent(report, this.bus, this.options)
        },
      })
    })
    return dispatcher
  }

  // ─── Observer helper ───

  private startObserver(): void {
    this.log("[observer] starting continuous supervisor")
    this.observer = new ObserverAgent({
      bus: this.bus,
      sm: this.sm,
      getState: () => this.getState(),
      getHypotheses: () => this.workspace.runInScope(() => this.workspace.getHypotheses()),
      getCoverageGrid: () => this.workspace.getCoverageGrid(),
      log: (msg) => this.log(`[observer] ${msg}`),
    })
    this.observer.start()

    this.bus.subscribe("observer:steer", (event) => {
      const p = event.payload as { message: string; warningCount: number }
      this.log(`[observer steer] ${p.message} (warnings: ${p.warningCount})`)
      addEvent("reason", "warn", "Observer steer", p.message)
    })
  }

  // ─── Stats & helpers ───

  private buildStats(): AuditStats {
    return this.workspace.buildStats(this.startTime)
  }

  private processWarningsFromReport(report: { warnings: string[] }): { warnings: string[] } {
    if ("checkpoints" in report && Array.isArray(report.checkpoints)) {
      logObserverReport("manager-observer", report as { checkpoints: Array<{ phase: string; check: string; passed: boolean; detail: string }>; warnings: string[] }, (msg) => this.log(`[observer] ${msg}`))
    }
    for (const warning of report.warnings) {
      this.observerFailures++
      this.bus.emit("observer:warning", { warning, total: this.observerFailures }, "observer")
    }
    return report
  }

  private async runCoverageRescanLoop(outputDir: string): ReturnType<typeof runCoverageRescanLoopPhase> {
    if (!this.dispatcher) {
      throw new Error("CoverageRescan missing profile, coverage grid, or dispatcher")
    }
    const report = await runCoverageRescanLoopPhase({
      bus: this.bus,
      dispatcher: this.dispatcher,
      options: this.options,
      outputDir,
      profile: this.workspace.requireProfile(),
      coverageGrid: this.workspace.requireCoverageGrid(),
      workspace: this.workspace,
      log: this.log,
      processWarnings: (report) => this.processWarningsFromReport(report),
      checkPause: (snapshot) => this.checkPause("coverage-rescan", outputDir, snapshot),
    })
    return report
  }

  private async runJoernQueryAgent(profile: ProjectProfile, cpgPath?: string): Promise<void> {
    const ctx = {
      identity: { id: "joern-query", role: "solver" as const, status: "idle" as const },
      bus: this.bus,
      getState: () => this.getState(),
      log: (msg: string) => this.log(`[joern-query] ${msg}`),
    }
    const agent = new JoernQueryAgent(ctx, this.options, profile, this.workspace, this.workspace.getSources(), cpgPath)
    await agent.start()
    submitAgentResult(this.bus, "joern-query", {
      kind: "query",
      agent: "JoernQueryAgent",
      title: "JoernQueryAgent 提交查询准备结果",
      content: "Joern 查询脚本准备阶段已完成，后续 TracerAgent 可读取 Joern 输出和 EvidenceBundle 继续追踪。",
      artifacts: {
        sourceCount: this.workspace.getSources().length,
      },
    })
  }

  private dummyProfile(): ProjectProfile {
    return {
      name: this.options.projectName ?? "unknown",
      root: this.options.target,
      language: "unknown",
      buildFiles: [],
      directories: [],
      fileStats: [],
      dependencies: [],
      routes: [],
      securityMechanisms: [],
      dataFlowSummary: [],
      highRiskFiles: [],
    }
  }

  private dummyGrid(): CoverageGrid {
    return { totalUnits: 0, units: new Map(), byModule: new Map() }
  }

  private async restoreCheckpointIfPresent(outputDir: string): Promise<{
    phase: CheckpointPhase
    cursor?: number
    total?: number
    profile?: ProjectProfile
    coverageGrid?: CoverageGrid
  } | null> {
    const restored = await restoreCheckpoint(outputDir)
    if (!restored) return null
    this.workspace.restoreSnapshot(restored.snapshot)
    return {
      phase: restored.state.phase,
      cursor: restored.state.cursor,
      total: restored.state.total,
      profile: restored.snapshot.profile ?? undefined,
      coverageGrid: restored.snapshot.coverageGrid ?? undefined,
    }
  }

  private cpgFromCheckpoint(outputDir: string): CpgResult {
    const cpgPath = resolve(outputDir, "project-cpg.bin")
    if (Bun.file(cpgPath).size > 0) return { ok: true, cpgPath }
    return { ok: false, cpgPath: "", skippedReason: "checkpoint has no CPG" }
  }

  private async checkPause(
    phase: CheckpointPhase,
    outputDir: string,
    snapshot: Parameters<typeof saveCheckpoint>[2],
  ): Promise<void> {
    if (!this.pauseRequested) return
    await saveCheckpoint(outputDir, phase, snapshot, { note: this.pauseRequested })
    this.bus.emit("audit:paused", { status: "paused", reason: this.pauseRequested, phase }, "manager")
    this.stop()
    throw new AuditPausedError(this.pauseRequested, phase)
  }
}

const PHASE_ORDER: CheckpointPhase[] = [
  "profiling",
  "scanning",
  "enriching",
  "handoff",
  "coverage-rescan",
  "joern-query",
  "tracing",
  "verifying",
  "judging",
  "reviewing",
  "reporting",
  "terminated",
]

function isAfterOrAt(current: CheckpointPhase | null, target: CheckpointPhase): boolean {
  if (!current) return false
  return PHASE_ORDER.indexOf(current) >= PHASE_ORDER.indexOf(target)
}

export class AuditPausedError extends Error {
  phase: CheckpointPhase

  constructor(reason: string, phase: CheckpointPhase) {
    super(reason)
    this.name = "AuditPausedError"
    this.phase = phase
  }
}
