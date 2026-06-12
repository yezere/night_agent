import * as AgentBoard from "../graph/agent-board.ts"
import * as EvidenceBundleStore from "../graph/evidence-bundle-store.ts"
import * as FactStore from "../graph/fact-store.ts"
import * as HintStore from "../graph/hint-store.ts"
import * as IntentStore from "../graph/intent-store.ts"
import { createGraphStoreScope, enforceGraphStoreScope, enterGraphStoreScope, runWithGraphStoreScope, type GraphStoreScope } from "../graph/store-scope.ts"
import { clearEvents, getEvents, restoreEvents } from "./event-log.ts"
import type {
  AgentArtifact,
  AgentArtifactKind,
  AuditEvent,
  AuditOptions,
  AuditReport,
  AuditStats,
  CoverageGrid,
  DataflowTrace,
  EvidenceBundle,
  Finding,
  Hypothesis,
  HypothesisEvidenceState,
  ObserverReport,
  ProjectProfile,
  SourceEntry,
  SourceHypothesisLinkage,
  VerifierVerdict,
} from "../types/index.ts"

export interface AuditWorkspaceSnapshot {
  profile: ProjectProfile | null
  coverageGrid: CoverageGrid | null
  sources: SourceEntry[]
  hypotheses: Hypothesis[]
  evidenceBundles: EvidenceBundle[]
  findings: Finding[]
  notes: ReturnType<typeof HintStore.getAllNotes>
  agentArtifacts: AgentArtifact[]
  events: AuditEvent[]
}

export class AuditWorkspace {
  readonly runId: string
  readonly options: AuditOptions
  private readonly scope: GraphStoreScope
  private profile: ProjectProfile | null = null
  private coverageGrid: CoverageGrid | null = null
  private sources: SourceEntry[] = []

  constructor(options: AuditOptions, runId = `run-${Date.now().toString(36)}-${crypto.randomUUID().slice(0, 8)}`) {
    this.options = options
    this.runId = runId
    this.scope = createGraphStoreScope()
  }

  enterScope(): void {
    enforceGraphStoreScope(true)
    enterGraphStoreScope(this.scope)
  }

  runInScope<T>(fn: () => T): T {
    return runWithGraphStoreScope(this.scope, fn)
  }

  reset(): void {
    this.enterScope()
    this.profile = null
    this.coverageGrid = null
    this.sources = []
    IntentStore.clear()
    FactStore.clear()
    HintStore.clear()
    EvidenceBundleStore.clear()
    AgentBoard.clear()
    clearEvents()
  }

  setProfile(profile: ProjectProfile | null): void {
    this.profile = profile
  }

  getProfile(): ProjectProfile | null {
    return this.profile
  }

  requireProfile(): ProjectProfile {
    if (!this.profile) throw new Error("AuditWorkspace missing project profile")
    return this.profile
  }

  setCoverageGrid(coverageGrid: CoverageGrid | null): void {
    this.coverageGrid = coverageGrid
  }

  getCoverageGrid(): CoverageGrid | null {
    return this.coverageGrid
  }

  requireCoverageGrid(): CoverageGrid {
    if (!this.coverageGrid) throw new Error("AuditWorkspace missing coverage grid")
    return this.coverageGrid
  }

  restoreSnapshot(snapshot: AuditWorkspaceSnapshot): void {
    this.enterScope()
    this.profile = snapshot.profile
    this.coverageGrid = snapshot.coverageGrid
    this.sources = clone(snapshot.sources)
    IntentStore.restore(clone(snapshot.hypotheses))
    EvidenceBundleStore.restore(clone(snapshot.evidenceBundles))
    FactStore.restore(clone(snapshot.findings))
    HintStore.restore(clone(snapshot.notes))
    AgentBoard.restore(clone(snapshot.agentArtifacts))
    restoreEvents(clone(snapshot.events))
  }

  checkpointState(): AuditWorkspaceSnapshot {
    return this.snapshot()
  }

  setSources(sources: SourceEntry[]): void {
    this.sources = [...sources]
  }

  getSources(): SourceEntry[] {
    return [...this.sources]
  }

  getSourcesSnapshot(): SourceEntry[] {
    return clone(this.sources)
  }

  mergeSources(additions: SourceEntry[]): SourceEntry[] {
    const byKey = new Map<string, SourceEntry>()
    for (const source of [...this.sources, ...additions]) {
      byKey.set(`${source.file}:${source.kind}:${source.paramName}:${source.line}`, source)
    }
    this.sources = [...byKey.values()].map((source, index) => ({ ...source, id: `src-${index}` }))
    return this.getSources()
  }

  getHypothesis(id: string): Hypothesis | undefined {
    return IntentStore.getHypothesis(id)
  }

  getHypotheses(): Hypothesis[] {
    return IntentStore.getAllHypotheses()
  }

  getHypothesesSnapshot(): Hypothesis[] {
    return clone(this.getHypotheses())
  }

  addHypothesis(input: Parameters<typeof IntentStore.addHypothesis>[0]): Hypothesis {
    return IntentStore.addHypothesis(input)
  }

  getPendingTraceHypotheses(): Hypothesis[] {
    return this.getHypotheses().filter((hyp) => {
      const state = evidenceState(hyp)
      return (hyp.status === "pending" || hyp.status === "tracing") && (state.trace === "not_started" || state.trace === "running")
    })
  }

  hypothesisCount(): number {
    return IntentStore.size()
  }

  countHypothesesByStatus(): Record<Hypothesis["status"], number> {
    return IntentStore.countByStatus()
  }

  hasTraceWorkRemaining(): boolean {
    return this.getHypotheses().some((hyp) => {
      const state = evidenceState(hyp)
      return (hyp.status === "pending" || hyp.status === "tracing") && (state.trace === "not_started" || state.trace === "running")
    })
  }

  hasVerifyWorkRemaining(): boolean {
    return this.getHypotheses().some((hyp) => {
      const state = evidenceState(hyp)
      if (hyp.status === "dismissed" || hyp.status === "confirmed") return false
      return state.verification === "not_started" || !hyp.verifierVerdict
    })
  }

  markTraceStarted(hypothesisId: string): Hypothesis | undefined {
    const hyp = IntentStore.getHypothesis(hypothesisId)
    if (!hyp) return undefined
    setEvidenceState(hyp, { trace: "running" })
    IntentStore.updateStatus(hyp.id, "tracing")
    return IntentStore.getHypothesis(hypothesisId)
  }

  markTraceSkipped(hypothesisId: string, reason: string): Hypothesis | undefined {
    const hyp = IntentStore.getHypothesis(hypothesisId)
    if (!hyp) return undefined
    setEvidenceState(hyp, { trace: "skipped", traceReason: reason })
    IntentStore.updateStatus(hyp.id, "maybe_revisit", hyp.dataflowResult, reason)
    return IntentStore.getHypothesis(hypothesisId)
  }

  markCandidateDeferred(hypothesisId: string, reason: string): Hypothesis | undefined {
    const hyp = IntentStore.getHypothesis(hypothesisId)
    if (!hyp) return undefined
    setEvidenceState(hyp, { finding: "needs_review", findingReason: reason })
    IntentStore.updateStatus(hyp.id, "maybe_revisit", hyp.dataflowResult, reason)
    return IntentStore.getHypothesis(hypothesisId)
  }

  markTraceUnresolved(hypothesisId: string, reason: string, dataflow?: DataflowTrace): Hypothesis | undefined {
    const hyp = IntentStore.getHypothesis(hypothesisId)
    if (!hyp) return undefined
    setEvidenceState(hyp, { trace: "unresolved", traceReason: reason })
    IntentStore.updateStatus(hyp.id, "maybe_revisit", dataflow ?? hyp.dataflowResult, reason)
    if (dataflow) EvidenceBundleStore.updateDataflow(hyp.id, dataflow)
    return IntentStore.getHypothesis(hypothesisId)
  }

  recordTraceResult(hypothesisId: string, dataflow: DataflowTrace, reason?: string): Hypothesis | undefined {
    const hyp = IntentStore.getHypothesis(hypothesisId)
    if (!hyp) return undefined
    const traceStatus = dataflow.reachable ? "reachable" : dataflow.sanitizers.length > 0 ? "blocked" : "unresolved"
    setEvidenceState(hyp, { trace: traceStatus, traceReason: reason })
    const lifecycleStatus: Hypothesis["status"] = dataflow.reachable
      ? "pending"
      : dataflow.sanitizers.length > 0
        ? "dismissed"
        : "maybe_revisit"
    IntentStore.updateStatus(hyp.id, lifecycleStatus, dataflow, reason)
    EvidenceBundleStore.updateDataflow(hyp.id, dataflow)
    return IntentStore.getHypothesis(hypothesisId)
  }

  recordVerifierVerdict(hypothesisId: string, verdict: VerifierVerdict, reasonPrefix = "StaticVerifierAgent"): Hypothesis | undefined {
    const hyp = IntentStore.getHypothesis(hypothesisId)
    if (!hyp) return undefined
    hyp.verifierVerdict = verdict
    setEvidenceState(hyp, { verification: verdict.status, verificationReason: verdict.reason })
    EvidenceBundleStore.updateVerifierVerdict(hyp.id, verdict)
    const lifecycleStatus: Hypothesis["status"] = verdict.status === "confirmed"
      ? "pending"
      : verdict.status
    IntentStore.updateStatus(hyp.id, lifecycleStatus, hyp.dataflowResult, `${reasonPrefix}: ${verdict.reason}`)
    const updated = IntentStore.getHypothesis(hyp.id) ?? hyp
    updated.verifierVerdict = verdict
    return updated
  }

  markJudgeNeedsReview(hypothesisId: string, reason: string, dataflow?: DataflowTrace): Hypothesis | undefined {
    const hyp = IntentStore.getHypothesis(hypothesisId)
    if (!hyp) return undefined
    setEvidenceState(hyp, { finding: "needs_review", findingReason: reason })
    IntentStore.updateStatus(hyp.id, "maybe_revisit", dataflow ?? hyp.dataflowResult, reason)
    return IntentStore.getHypothesis(hypothesisId)
  }

  markJudgeRejected(hypothesisId: string, status: Exclude<VerifierVerdict["status"], "confirmed">, reason: string, dataflow?: DataflowTrace): Hypothesis | undefined {
    const hyp = IntentStore.getHypothesis(hypothesisId)
    if (!hyp) return undefined
    setEvidenceState(hyp, { finding: status === "dismissed" ? "rejected" : "needs_review", findingReason: reason })
    IntentStore.updateStatus(hyp.id, status, dataflow ?? hyp.dataflowResult, reason)
    return IntentStore.getHypothesis(hypothesisId)
  }

  markJudgeDuplicate(hypothesisId: string, primaryHypothesisId: string, dataflow?: DataflowTrace): Hypothesis | undefined {
    const reason = `semantic duplicate — merged into ${primaryHypothesisId}`
    const hyp = IntentStore.getHypothesis(hypothesisId)
    if (!hyp) return undefined
    setEvidenceState(hyp, { finding: "duplicate", findingReason: reason })
    IntentStore.updateStatus(hyp.id, "dismissed", dataflow ?? hyp.dataflowResult, reason)
    return IntentStore.getHypothesis(hypothesisId)
  }

  addFinding(finding: Omit<Finding, "id" | "createdAt">): Finding {
    return FactStore.addFinding(finding)
  }

  markFindingConfirmed(hypothesisId: string, dataflow: DataflowTrace, reason: string): Hypothesis | undefined {
    const hyp = IntentStore.getHypothesis(hypothesisId)
    if (!hyp) return undefined
    setEvidenceState(hyp, { finding: "confirmed", findingReason: reason })
    IntentStore.updateStatus(hyp.id, "confirmed", dataflow, reason)
    return IntentStore.getHypothesis(hypothesisId)
  }

  updateSelectedSource(hypothesisId: string, source: SourceEntry): void {
    const hyp = IntentStore.getHypothesis(hypothesisId)
    if (hyp) hyp.sourceHint = source
    EvidenceBundleStore.updateSelectedSource(hypothesisId, source)
  }

  linkSourcesToHypotheses(linkages: SourceHypothesisLinkage[]): EvidenceBundle[] {
    const bundles: EvidenceBundle[] = []
    for (const linkage of linkages) {
      const hyp = IntentStore.getHypothesis(linkage.hypothesisId)
      if (!hyp) continue
      bundles.push(EvidenceBundleStore.upsertFromHypothesis(hyp, linkage.sourceLinks, linkage.route))
    }
    return bundles
  }

  getEvidenceBundle(hypothesisId: string): EvidenceBundle | undefined {
    return EvidenceBundleStore.getByHypothesisId(hypothesisId)
  }

  getEvidenceBundles(): EvidenceBundle[] {
    return EvidenceBundleStore.getAll()
  }

  getEvidenceBundlesSnapshot(): EvidenceBundle[] {
    return clone(this.getEvidenceBundles())
  }

  getFindings(): Finding[] {
    return FactStore.getAllFindings()
  }

  getFindingsSnapshot(): Finding[] {
    return clone(this.getFindings())
  }

  getNotes(): ReturnType<typeof HintStore.getAllNotes> {
    return HintStore.getAllNotes()
  }

  getNotesSnapshot(): ReturnType<typeof HintStore.getAllNotes> {
    return clone(this.getNotes())
  }

  addNote(content: string, source: Parameters<typeof HintStore.addNote>[1], relatedIds: string[] = []): void {
    HintStore.addNote(content, source, relatedIds)
  }

  getAgentArtifacts(): AgentArtifact[] {
    return AgentBoard.getAll()
  }

  getAgentArtifactsSnapshot(): AgentArtifact[] {
    return clone(this.getAgentArtifacts())
  }

  getAgentArtifactsByKind(kind: AgentArtifactKind): AgentArtifact[] {
    return AgentBoard.getByKind(kind)
  }

  latestArtifactData<T extends Record<string, unknown>>(kind: AgentArtifactKind): T | undefined {
    return AgentBoard.getByKind(kind).at(-1)?.data as T | undefined
  }

  applyObserverActions(report: ObserverReport): { applied: number; skipped: number } {
    let applied = 0
    let skipped = 0
    for (const action of report.actions ?? []) {
      if (action.kind === "dismiss-duplicate-hypothesis") {
        const hyp = IntentStore.getHypothesis(action.hypothesisId)
        if (!hyp || hyp.status === "dismissed") {
          skipped++
          continue
        }
        setEvidenceState(hyp, { finding: "duplicate", findingReason: action.reason })
        if (IntentStore.updateStatus(hyp.id, "dismissed", hyp.dataflowResult, action.reason)) applied++
        else skipped++
      } else if (action.kind === "record-source-linkage-verdict") {
        EvidenceBundleStore.updateObserverVerdict(action.hypothesisId, Boolean(action.passed), action.reason)
        applied++
      }
    }
    return { applied, skipped }
  }

  snapshot(): AuditWorkspaceSnapshot {
    return {
      profile: this.profile,
      coverageGrid: this.coverageGrid,
      sources: this.getSourcesSnapshot(),
      hypotheses: this.getHypothesesSnapshot(),
      evidenceBundles: this.getEvidenceBundlesSnapshot(),
      findings: this.getFindingsSnapshot(),
      notes: this.getNotesSnapshot(),
      agentArtifacts: this.getAgentArtifactsSnapshot(),
      events: getEvents(),
    }
  }

  refreshReportSnapshot(report: AuditReport): void {
    report.hypotheses = this.getHypotheses()
    report.evidenceBundles = this.getEvidenceBundles()
    report.findings = this.getFindings()
    report.notes = this.getNotes()
    report.agentArtifacts = this.getAgentArtifacts()
    report.sources = this.getSources()
    report.events = getEvents()
  }

  buildStats(startTime: number): AuditStats {
    const confirmed = this.getFindings().length
    const byStatus = this.countHypothesesByStatus()
    let visited = 0
    if (this.coverageGrid) {
      for (const [, unit] of this.coverageGrid.units) {
        if (unit.depth !== "unvisited") visited++
      }
    }
    const coveragePercent = this.coverageGrid?.totalUnits
      ? Math.round((visited / this.coverageGrid.totalUnits) * 100)
      : 0
    return {
      totalHypotheses: this.hypothesisCount(),
      confirmedFindings: confirmed,
      dismissedHypotheses: byStatus.dismissed ?? 0,
      pendingHypotheses: byStatus.pending ?? 0,
      revisitHypotheses: byStatus.maybe_revisit ?? 0,
      coveragePercent,
      elapsedSeconds: (Date.now() - startTime) / 1000,
    }
  }
}

function clone<T>(value: T): T {
  return structuredClone(value)
}

function evidenceState(hyp: Hypothesis): HypothesisEvidenceState {
  if (!hyp.evidenceState) {
    hyp.evidenceState = {
      trace: "not_started",
      verification: "not_started",
      finding: "not_started",
      updatedAt: hyp.updatedAt ?? Date.now(),
    }
  }
  return hyp.evidenceState
}

function setEvidenceState(hyp: Hypothesis, patch: Partial<Omit<HypothesisEvidenceState, "updatedAt">>): void {
  hyp.evidenceState = {
    ...evidenceState(hyp),
    ...patch,
    updatedAt: Date.now(),
  }
  hyp.updatedAt = Date.now()
}
