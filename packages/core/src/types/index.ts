// ─── Graph Protocol Types (Cairn-inspired) ───

/** Confirmed vulnerability finding */
export interface Finding {
  id: string
  hypothesisId: string
  title: string
  severity: Severity
  category: string // cmdi, sqli, ssrf, deser, ssti, jndi, path-traversal, upload, ...
  source: SourceRef
  sink: SinkRef
  evidenceChain: EvidenceLink[]
  cveHint?: string
  status: FindingStatus
  confidence: "high" | "medium" | "low"
  createdAt: number
}

export type Severity = "critical" | "high" | "medium" | "low" | "info"
export type FindingStatus = "confirmed" | "dismissed" | "maybe_revisit"

/** Numeric rank for severity — lower = more severe. Single source of truth. */
export const SEVERITY_ORDER: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }

export function compareSeverity(a: Severity, b: Severity): number {
  return (SEVERITY_ORDER[a] ?? 2) - (SEVERITY_ORDER[b] ?? 2)
}

/** Patterns identifying high-risk Java dependencies */
export const HIGH_RISK_DEP_PATTERNS = [
  "fastjson", "shiro", "log4j", "struts", "spring-web", "jackson",
  "freemarker", "velocity", "druid", "tomcat", "activemq", "axis",
  "xstream", "ognl", "groovy", "snakeyaml", "mybatis",
]

export function isHighRiskDep(name: string): boolean {
  const lower = name.toLowerCase()
  return HIGH_RISK_DEP_PATTERNS.some((p) => lower.includes(p))
}

export interface SourceRef {
  kind: string // controller-param, request-body, file-upload, header, cookie, config, ...
  file: string
  line: number
  snippet: string
}

export interface SinkRef {
  kind: string // Runtime.exec, ProcessBuilder, readObject, execute, lookup, process, ...
  file: string
  line: number
  snippet: string
}

export interface EvidenceLink {
  step: number
  file: string
  line: number
  code: string
  role: "source" | "transform" | "sink" | "sanitizer" | "barrier"
  note?: string
}

export interface SourceLink {
  source: SourceEntry
  score: number
  reason: string
}

export interface SourceHypothesisLinkage {
  hypothesisId: string
  sourceLinks: SourceLink[]
  route?: RouteEntry
}

export type EvidenceOrigin = "ai-first" | "ai-refine" | "pre-scan" | "joern" | "joern-ai" | "verifier" | "unknown"

export interface VerifierVerdict {
  status: "confirmed" | "maybe_revisit" | "dismissed"
  confidence: "high" | "medium" | "low"
  reason: string
  sourceSinkTrace?: string[]
  barrierAnalysis?: string[]
  evidence: string[]
  checkedFiles: string[]
  toolCalls: string[]
  sanitizerSummary?: string[]
  missingEvidence?: string[]
  recommendedStatus?: HypothesisStatus
  createdAt: number
}

export interface EvidenceBundle {
  id: string
  hypothesisId: string
  sourceLinks: SourceLink[]
  selectedSource?: SourceEntry
  sink: SinkRef
  route?: RouteEntry
  dataflow?: DataflowTrace
  observerVerdict?: {
    passed: boolean
    reason: string
    checkedAt: number
  }
  verifierVerdict?: VerifierVerdict
  reportContext?: {
    codeContext: string
    chainText: string
    pocPackets: string[]
  }
  createdAt: number
  updatedAt: number
}

export type AgentArtifactKind =
  | "origin"
  | "goal"
  | "profile"
  | "source"
  | "sink"
  | "cpg"
  | "discovery"
  | "query"
  | "handoff"
  | "trace"
  | "verification"
  | "finding"
  | "observer"
  | "coverage"
  | "poc"
  | "report"
  | "hint"
  | "failure"

export interface AgentArtifact {
  id: string
  kind: AgentArtifactKind
  agent: string
  title: string
  content: string
  refs?: string[]
  data?: Record<string, unknown>
  createdAt: number
}

export type AgentWorkflowTaskKind =
  | "profile"
  | "source"
  | "sink"
  | "cpg"
  | "discover"
  | "coverage-rescan"
  | "handoff"
  | "joern-query"
  | "trace"
  | "verify"
  | "judge"
  | "observe"
  | "poc"
  | "report"

export interface AgentWorkflowTask {
  id: string
  kind: AgentWorkflowTaskKind
  agent: string
  title: string
  status: "queued" | "running" | "done" | "failed"
  inputArtifactIds: string[]
  outputArtifactIds: string[]
  data?: Record<string, unknown>
  error?: string
  createdAt: number
  startedAt?: number
  completedAt?: number
}

// ─── Hypothesis (Intent) ───

/** Hypothesis to verify — the core work unit of the audit */
export interface Hypothesis {
  id: string
  description: string
  severity: Severity
  category: string
  sinkFile: string
  sinkLine: number
  sinkPattern: string
  sinkCode: string
  /**
   * Backward-compatible lifecycle field.
   * Only Judge should write `confirmed`; reachability and verifier decisions live
   * in `evidenceState` and verifier/dataflow fields.
   */
  status: HypothesisStatus
  evidenceState?: HypothesisEvidenceState
  dataflowResult?: DataflowTrace
  createdAt: number
  updatedAt: number
  resolutionNote?: string // why dismissed / needs revisit
  sourceHint?: SourceEntry // associated user-controlled input point
  sourceLinks?: SourceLink[] // SourceAgent -> SinkAgent handoff candidates
  evidenceBundleId?: string
  origin?: EvidenceOrigin
  verifierVerdict?: VerifierVerdict
}

export type HypothesisStatus = "pending" | "tracing" | "confirmed" | "dismissed" | "maybe_revisit"

export type HypothesisTraceStatus = "not_started" | "running" | "reachable" | "blocked" | "unresolved" | "skipped"
export type HypothesisVerificationStatus = "not_started" | "confirmed" | "dismissed" | "maybe_revisit" | "failed"
export type HypothesisFindingStatus = "not_started" | "confirmed" | "rejected" | "duplicate" | "needs_review"

export interface HypothesisEvidenceState {
  trace: HypothesisTraceStatus
  verification: HypothesisVerificationStatus
  finding: HypothesisFindingStatus
  traceReason?: string
  verificationReason?: string
  findingReason?: string
  updatedAt: number
}

// ─── Note / Hint ───

/** External knowledge that informs the audit */
export interface Note {
  id: string
  content: string
  source: "cve" | "best-practice" | "pattern" | "observer" | "dependency-fingerprint"
  relatedHypothesisIds: string[]
}

// ─── Dataflow Trace (Joern) ───

export interface DataflowTrace {
  reachable: boolean
  paths: DataflowPath[]
  sanitizers: SanitizerRef[]
  confidence: "high" | "medium" | "low"
}

export interface DataflowPath {
  edges: DataflowEdge[]
  sourceLabel: string
  sinkLabel: string
}

export interface DataflowEdge {
  file: string
  line: number
  code: string
  kind: "source" | "propagation" | "sink" | "sanitizer"
}

export interface SanitizerRef {
  kind: string // auth-check, input-validation, param-binding, whitelist, ...
  file: string
  line: number
  code: string
}

// ─── Coverage Grid ───

export interface CoverageGrid {
  totalUnits: number
  units: Map<string, CoverageUnit>
  byModule: Map<string, CoverageStats>
}

export interface CoverageUnit {
  file: string
  depth: CoverageDepth
  hypothesisCount: number
  confirmedCount: number
  modules?: string[]
  rescanCount?: number
  lastRescanAt?: number
  lastRescanReason?: string
}

export type CoverageDepth = "unvisited" | "scanned" | "traced" | "verified"

export interface CoverageStats {
  total: number
  unvisited: number
  scanned: number
  traced: number
  verified: number
}

export interface CoverageRescanTask {
  id: string
  iteration: number
  trigger: "observer-coverage-gap"
  reason: string
  files: string[]
  modules: string[]
  unvisitedBefore: number
  createdAt: number
}

export interface CoverageRescanSummary {
  enabled: boolean
  rounds: number
  tasksQueued: number
  filesQueued: number
  filesScanned: number
  newSources: number
  newHypotheses: number
  unvisitedBefore: number
  unvisitedAfter: number
  revisitHypotheses: number
  limitations: string[]
}

// ─── Project Profile ───

export interface ProjectProfile {
  name: string
  root: string
  language: ProjectLanguage
  buildFiles: string[]
  directories: string[]
  fileStats: FileStat[]
  dependencies: DependencyFingerprint[]
  routes: RouteEntry[]
  securityMechanisms: SecurityMechanism[]
  dataFlowSummary: string[]
  highRiskFiles: string[]
}

export type ProjectLanguage = "java" | "python" | "javascript" | "go" | "unknown"

export interface FileStat {
  extension: string
  count: number
}

export interface DependencyFingerprint {
  ecosystem: string
  name: string
  version?: string
  sourceFile: string
}

export interface RouteEntry {
  method: string
  path: string
  className?: string
  sourceFile: string
  line: number
  authHint?: string
}

export interface SecurityMechanism {
  kind: string
  name: string
  sourceFile: string
  line: number
  detail: string
}

// ─── Joern Types ───

export interface JoernRunResult {
  ran: boolean
  skippedReason?: string
  cpgPath?: string
  customQueryFile?: string
  queryOutputs: QueryOutput[]
}

export interface QueryOutput {
  name: string
  outputFile: string
  exitCode: number
}

export interface JoernDataflowQuery {
  sourceFile: string
  sourceLine: number
  sourcePattern: string
  sinkFile: string
  sinkLine: number
  sinkPattern: string
}

// ─── Observer Reports ───

export interface ObserverReport {
  checkpoints: CheckpointResult[]
  warnings: string[]
  actions?: ObserverAction[]
  rescan?: CoverageRescanSummary
}

export interface ObserverAction {
  kind: "dismiss-duplicate-hypothesis" | "record-source-linkage-verdict"
  hypothesisId: string
  reason: string
  primaryHypothesisId?: string
  passed?: boolean
}

export type CheckpointPhase = "bootstrap" | "explore" | "reason" | "scanning" | "enriching" | "tracing" | "judging" | "reviewing"
export type CheckKind = "dedup" | "scope-drift" | "premature-end" | "timeout" | "evidence-quality" | "evidence-graph" | "verifier-source-evidence" | "verifier-integrity" | "poc-route" | "poc-trigger" | "coverage-gap" | "source-coverage" | "sink-coverage" | "source-sink-linkage" | "llm-drift" | "stagnation"

export interface CheckpointResult {
  phase: CheckpointPhase
  check: CheckKind
  passed: boolean
  detail: string
  mergedIds?: string[][] // merged hypothesis IDs (for dedup)
}

// ─── Runtime Events / Visualization ───

export type AuditEventPhase = "bootstrap" | "explore" | "reason" | "report"
export type AuditEventLevel = "info" | "warn" | "error" | "success"

export interface AuditEvent {
  id: string
  phase: AuditEventPhase
  level: AuditEventLevel
  title: string
  detail?: string
  relatedHypothesisIds: string[]
  timestamp: number
}

export interface AuditGraphNode {
  id: string
  label: string
  kind: "project" | "module" | "route" | "hypothesis" | "finding" | "dependency" | "note"
  severity?: Severity
  status?: HypothesisStatus | FindingStatus
}

export interface AuditGraphEdge {
  from: string
  to: string
  label: string
}

export interface AuditGraph {
  nodes: AuditGraphNode[]
  edges: AuditGraphEdge[]
}

// ─── LLM Config ───

export type LLMProvider = "anthropic" | "openai" | "deepseek" | "glm"

export interface LLMConfig {
  provider: LLMProvider
  apiKey: string
  model?: string
  baseUrl?: string
}

// ─── Audit Options & Report ───

export interface AuditOptions {
  target: string
  outputDir: string
  projectName?: string
  runJoern?: boolean
  resumeFromCheckpoint?: boolean
  timeoutMinutes?: number
  llmConfig?: LLMConfig
  maxHypotheses?: number
  maxReportDetails?: number
  isPauseRequested?: () => string | null
}

export interface AuditReport {
  profile: ProjectProfile
  hypotheses: Hypothesis[]
  evidenceBundles: EvidenceBundle[]
  agentArtifacts: AgentArtifact[]
  markdownReport?: string
  findings: Finding[]
  notes: Note[]
  sources: SourceEntry[]
  coverageGrid: CoverageGrid
  joern: JoernRunResult
  observer: ObserverReport
  events: AuditEvent[]
  graph: AuditGraph
  generatedFiles: string[]
  stats: AuditStats
}

export interface AuditStats {
  totalHypotheses: number
  confirmedFindings: number
  dismissedHypotheses: number
  pendingHypotheses: number
  revisitHypotheses: number
  coveragePercent: number
  elapsedSeconds: number
}

// ─── Multi-Agent Architecture Types ───

/** Agent identity and status */
export interface AgentIdentity {
  id: string // "scanner" | "reader" | "tracer" | "judge" | "observer"
  role: "manager" | "solver" | "observer"
  status: "idle" | "busy" | "error" | "terminated"
}

/** Audit state machine states */
export type AuditState =
  | "init"
  | "profiling"
  | "scanning"
  | "enriching"
  | "tracing"
  | "judging"
  | "reviewing"
  | "reporting"
  | "terminated"

/** Task kinds dispatched by Manager to Solvers */
export type TaskKind = "scan" | "extract_sources" | "trace_dataflow" | "judge_evidence" | "generate_report"

/** Union type for task payloads */
export type TaskPayload =
  | ScanPayload
  | ExtractSourcesPayload
  | TraceDataflowPayload
  | JudgeEvidencePayload
  | GenerateReportPayload

export interface ScanPayload {
  profile: ProjectProfile
  target: string
  outputDir: string
}

export interface ExtractSourcesPayload {
  profile: ProjectProfile
  hypothesisIds: string[]
}

export interface TraceDataflowPayload {
  hypothesisId: string
  sourceHint?: SourceEntry
  cpgPath: string
}

export interface JudgeEvidencePayload {
  hypothesisId: string
  dataflowResult: DataflowTrace
  sourceEntry?: SourceEntry
}

export interface GenerateReportPayload {
  outputDir: string
  profile: ProjectProfile
}

/** A task in the Manager→Solver queue */
export interface AuditTask {
  id: string
  kind: TaskKind
  payload: TaskPayload
  assignedTo: string
  status: "queued" | "running" | "done" | "failed"
  error?: string
  createdAt: number
  completedAt?: number
}

/** User-controllable input point extracted by ripgrep */
export interface SourceEntry {
  id: string
  kind: SourceParamKind
  paramName: string
  file: string
  line: number
  code: string
  methodName: string
  className?: string
  origin?: EvidenceOrigin
}

export type SourceParamKind = "param" | "body" | "header" | "cookie" | "pathvar" | "request-attr" | "input-stream"

/** A code snippet read from a file */
export interface CodeSnippet {
  file: string
  targetLine: number
  startLine: number
  endLine: number
  lines: string[] // each element is "lineNum|code"
  methodContext?: string
}

/** EventBus event types */
export type AuditEventKind =
  | "state:changed"
  | "state:enter"
  | "state:leave"
  | "task:queued"
  | "task:started"
  | "task:completed"
  | "task:failed"
  | "hypothesis:created"
  | "hypothesis:updated"
  | "finding:confirmed"
  | "finding:dismissed"
  | "source:extracted"
  | "observer:warning"
  | "observer:error"
  | "observer:started"
  | "observer:stopped"
  | "observer:report"
  | "observer:steer"
  | "observer:force-transition"
  | "coverage:rescan:started"
  | "coverage:rescan:completed"
  | "agent:submission"
  | "agent:artifact"
  | "audit:completed"
  | "audit:paused"
  | "audit:error"

/** Typed event emitted on the EventBus */
export interface AgentBusEvent {
  kind: AuditEventKind
  payload: unknown
  timestamp: number
  source: string // agent id that emitted the event
}

/** Event handler callback */
export type EventHandler = (event: AgentBusEvent) => void | Promise<void>

/** Externalized termination conditions */
export interface TerminationConditions {
  maxTimeMinutes: number
  maxIterations: number
  minCoveragePercent: number
  maxPendingHypotheses: number
  observerFailureLimit: number
}

/** Result of checking termination conditions */
export interface TerminationCheck {
  shouldStop: boolean
  reason?: string
  details: Record<string, string | number | boolean>
}

/** Shared audit snapshot for observability */
export interface SharedAuditState {
  currentState: AuditState
  profile: ProjectProfile | null
  sources: SourceEntry[]
  stats: AuditStats
  iteration: number
  termination: TerminationConditions
  agentStatuses: Record<string, AgentIdentity["status"]>
}

/** Ripgrep match result */
export interface RipgrepMatch {
  file: string
  line: number
  column: number
  endLine: number
  endColumn: number
  match: string
  context: string // surrounding line content
}

/** Compressed state for LLM context */
export interface CompressedSnapshot {
  summary: string
  stats: AuditStats
  topFindings: string[]
  pendingCount: number
  pendingPreview: string[]
  tokenEstimate: number
}
