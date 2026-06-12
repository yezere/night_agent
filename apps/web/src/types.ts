export interface Stats {
  totalHypotheses: number
  confirmedFindings: number
  dismissedHypotheses: number
  pendingHypotheses: number
  revisitHypotheses: number
  coveragePercent: number
  elapsedSeconds: number
}

export interface SourceEntry {
  id: string
  kind: string
  paramName: string
  file: string
  line: number
  code: string
  methodName: string
  className?: string
  origin?: string
}

export interface SourceLink {
  source: SourceEntry
  score: number
  reason: string
}

export interface VerifierVerdict {
  status: "confirmed" | "maybe_revisit" | "dismissed"
  confidence: "high" | "medium" | "low"
  reason: string
  sourceSinkTrace?: string[]
  barrierAnalysis?: string[]
  evidence: string[]
  checkedFiles: string[]
  sanitizerSummary?: string[]
  missingEvidence?: string[]
}

export interface DataflowTrace {
  reachable: boolean
  paths: Array<{ edges: Array<{ file: string; line: number; code: string; kind: string }> }>
  sanitizers: Array<{ kind: string; file: string; line: number; code: string }>
  confidence: "high" | "medium" | "low"
}

export interface Hypothesis {
  id: string
  description: string
  severity: string
  category: string
  sinkFile: string
  sinkLine: number
  sinkPattern: string
  sinkCode: string
  status: string
  dataflowResult?: DataflowTrace
  resolutionNote?: string
  sourceHint?: SourceEntry
  sourceLinks?: SourceLink[]
  origin?: string
  verifierVerdict?: VerifierVerdict
}

export interface EvidenceBundle {
  id: string
  hypothesisId: string
  sourceLinks: SourceLink[]
  selectedSource?: SourceEntry
  sink: {
    kind: string
    file: string
    line: number
    snippet: string
  }
  verifierVerdict?: VerifierVerdict
  dataflow?: DataflowTrace
}

export interface Finding {
  id: string
  title: string
  severity: string
  category: string
  source: {
    kind: string
    file: string
    line: number
    snippet: string
  }
  sink: {
    kind: string
    file: string
    line: number
    snippet: string
  }
  status: string
  confidence: "high" | "medium" | "low"
}

export interface ObserverReport {
  checkpoints: Array<{ phase: string; check: string; passed: boolean; detail: string }>
  warnings: string[]
  rescan?: {
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
}

export interface AuditStatus {
  state: string
  currentState?: string
  stats: Stats | null
  profile?: { name?: string; root?: string; language?: string }
  observer?: ObserverReport | null
  generatedFiles?: string[]
  sources?: SourceEntry[]
  run?: {
    input: string
    target: string
    outputDir: string
    runId: string
    cloned: boolean
  } | null
}

export interface HistoryEntry {
  runId: string
  input: string
  target: string
  outputDir: string
  cloned: boolean
  provider: string | null
  model: string | null
  mode: "quick" | "full"
  status: "preparing" | "running" | "completed" | "error" | "interrupted"
  projectName: string | null
  startedAt: number
  completedAt: number | null
  stats: Stats | null
  observer?: ObserverReport | null
  generatedFiles: string[]
  error: string | null
}

export interface AuditEvent {
  kind: string
  source: string
  timestamp: number
  payload?: unknown
  title?: string
  detail?: string
  level?: "info" | "warn" | "error" | "success"
  phase?: string
  relatedHypothesisIds?: string[]
}

export interface RunDetail extends HistoryEntry {
  report: AuditReport | null
  events: AuditEvent[]
  sources: SourceEntry[]
}

export interface AuditReport {
  profile?: { name?: string; root?: string; language?: string }
  stats?: Stats
  observer?: ObserverReport
  generatedFiles?: string[]
  markdownReport?: string
  hypotheses?: Hypothesis[]
  findings?: Finding[]
  evidenceBundles?: EvidenceBundle[]
  sources?: SourceEntry[]
}

export interface ModelSettings {
  provider: "glm" | "deepseek" | "openai" | "anthropic"
  model: string
  baseUrl: string
  apiKey: string
  updatedAt: number | null
}

export interface JoernRuntimeConfig {
  memorySafe: boolean
  traceConcurrency: number
  joernXmxMb: number
  joernActiveProcessors: number
  traceTimeoutMs: number
  fallbackTimeoutMs: number
  traceFallback: boolean
  traceAutoLimit: boolean
  traceAutoLimitThreshold: number
  traceAutoLimitCount: number
  traceMaxHypotheses: number
  perHypothesisTrace: boolean
}

export interface VerifierRuntimeConfig {
  triageEnabled: boolean
  maxCandidates: number
  duplicateRepresentatives: number
  recheckDeferred: boolean
  concurrency: number
}

export interface BatchEntry {
  id: string
  input: string
  runId: string
  outputDir: string
  target?: string
  cloned?: boolean
  status: "pending" | "running" | "interrupted" | "completed" | "failed"
  startedAt?: number
  completedAt?: number
  updatedAt?: number
  error?: string
  reportFiles?: string[]
  generatedFiles?: string[]
  stats?: Stats
  observerWarnings?: string[]
}

export interface BatchState {
  version: 1
  reportsDir: string
  outRoot: string
  running?: boolean
  stopOnError?: boolean
  currentIndex?: number
  createdAt: number
  updatedAt: number
  entries: BatchEntry[]
}

export interface AgentRunState {
  id: string
  name: string
  label: string
  status: "waiting" | "running" | "done" | "failed"
  count: number
  lastTitle: string
  lastDetail: string
  lastAt: number
}
