import { useCallback, useEffect, useMemo, useRef, useState } from "react"
import {
  deleteRun as deleteRunApi,
  fetchBatchStatus,
  fetchHistory,
  fetchMarkdown,
  fetchModelSettings,
  fetchRun,
  fetchStatus,
  pauseAudit,
  resumeRun,
  saveModelSettings,
  startAudit,
  startBatch,
} from "./api"
import { useWebSocket } from "./hooks/useWebSocket"
import type { AuditEvent, AuditStatus, BatchState, HistoryEntry, JoernRuntimeConfig, ModelSettings, RunDetail, SourceEntry, VerifierRuntimeConfig } from "./types"
import { buildAgentStates } from "./lib/agents"
import { compactPath, eventDetail, eventRunId, eventTitle, eventTone, formatDate, formatTime, isActiveState, runTitle, statusLabel } from "./lib/format"
import { renderMarkdown } from "./lib/markdown"

const WS_URL = `${window.location.protocol === "https" ? "wss" : "ws"}://${window.location.host}/ws`

type ModelPresetId = ModelSettings["provider"] | "mimo"

const MODEL_PRESETS: Array<{ id: ModelPresetId; provider: ModelSettings["provider"]; label: string; model: string; baseUrl: string }> = [
  { id: "glm", provider: "glm", label: "GLM Coding Plan", model: "GLM-5.1", baseUrl: "https://open.bigmodel.cn/api/coding/paas/v4" },
  { id: "mimo", provider: "openai", label: "MiMo Coding Plan", model: "mimo-v2.5-pro", baseUrl: "https://token-plan-cn.xiaomimimo.com/v1" },
  { id: "deepseek", provider: "deepseek", label: "DeepSeek", model: "deepseek-chat", baseUrl: "https://api.deepseek.com" },
  { id: "openai", provider: "openai", label: "OpenAI", model: "gpt-4o", baseUrl: "https://api.openai.com" },
  { id: "anthropic", provider: "anthropic", label: "Claude", model: "claude-sonnet-4-6", baseUrl: "https://api.anthropic.com" },
]

const DEFAULT_SETTINGS: ModelSettings = {
  provider: "glm",
  model: "GLM-5.1",
  baseUrl: "https://open.bigmodel.cn/api/coding/paas/v4",
  apiKey: "",
  updatedAt: null,
}

const DEFAULT_JOERN_RUNTIME: JoernRuntimeConfig = {
  memorySafe: true,
  traceConcurrency: 1,
  joernXmxMb: 2048,
  joernActiveProcessors: 2,
  traceTimeoutMs: 180_000,
  fallbackTimeoutMs: 45_000,
  traceFallback: true,
  traceAutoLimit: true,
  traceAutoLimitThreshold: 40,
  traceAutoLimitCount: 0,
  traceMaxHypotheses: 0,
  perHypothesisTrace: true,
}

const DEFAULT_VERIFIER_RUNTIME: VerifierRuntimeConfig = {
  triageEnabled: true,
  maxCandidates: 0,
  duplicateRepresentatives: 1,
  recheckDeferred: false,
  concurrency: 3,
}

function loadJoernRuntime(): JoernRuntimeConfig {
  try {
    const raw = window.localStorage.getItem("night_agent_joern_runtime")
    if (!raw) return DEFAULT_JOERN_RUNTIME
    const parsed = JSON.parse(raw) as Partial<JoernRuntimeConfig>
    return { ...DEFAULT_JOERN_RUNTIME, ...parsed }
  } catch {
    return DEFAULT_JOERN_RUNTIME
  }
}

function loadVerifierRuntime(): VerifierRuntimeConfig {
  try {
    const raw = window.localStorage.getItem("night_agent_verifier_runtime")
    if (!raw) return DEFAULT_VERIFIER_RUNTIME
    const parsed = JSON.parse(raw) as Partial<VerifierRuntimeConfig>
    return { ...DEFAULT_VERIFIER_RUNTIME, ...parsed }
  } catch {
    return DEFAULT_VERIFIER_RUNTIME
  }
}

function clampRuntimeNumber(value: unknown, fallback: number, min: number, max: number): number {
  const parsed = typeof value === "number" ? value : Number(value)
  if (!Number.isFinite(parsed)) return fallback
  return Math.min(max, Math.max(min, Math.floor(parsed)))
}

function payloadRecord(event: AuditEvent): Record<string, unknown> {
  return event.payload && typeof event.payload === "object" ? event.payload as Record<string, unknown> : {}
}

function hasMarkdown(run?: { runId: string } | null, files?: string[]): boolean {
  return Boolean(run && files?.some((file) => file.endsWith(".md") && file.includes("审计报告")))
}

function hasCompleteMarkdown(run?: { runId: string } | null, files?: string[]): boolean {
  return Boolean(run && files?.some((file) => file.endsWith(".md") && file.includes("完整结果")))
}

function reportFailure(events: AuditEvent[]): string {
  const event = [...events].reverse().find((item) => {
    const payload = payloadRecord(item)
    const title = String(payload.title ?? "")
    const agent = String(payload.agent ?? item.source)
    const kind = String(payload.kind ?? item.kind)
    return /ReportAgent|report/i.test(agent) && (kind === "failure" || title.includes("未生成报告") || item.kind === "task:failed")
  })
  if (!event) return ""
  const payload = payloadRecord(event)
  return String(payload.content ?? payload.error ?? payload.title ?? "ReportAgent 未生成 Markdown 报告")
}

function statusFromDetail(detail: RunDetail): AuditStatus {
  return {
    state: detail.status === "completed" ? "terminated" : detail.status,
    stats: detail.stats,
    observer: detail.observer,
    generatedFiles: detail.generatedFiles,
    sources: detail.sources,
    profile: detail.report && typeof detail.report === "object"
      ? (detail.report as { profile?: AuditStatus["profile"] }).profile
      : undefined,
    run: {
      input: detail.input,
      target: detail.target,
      outputDir: detail.outputDir,
      runId: detail.runId,
      cloned: detail.cloned,
    },
  }
}

function shortValue(value: string): string {
  if (!value) return "未配置"
  if (value.length <= 12) return value
  return `${value.slice(0, 6)}...${value.slice(-4)}`
}

function modelPresetId(settings: ModelSettings): ModelPresetId {
  const text = `${settings.model} ${settings.baseUrl}`.toLowerCase()
  if (/mimo|xiaomimimo|token-plan/.test(text)) return "mimo"
  return settings.provider
}

function safeDownloadName(value: string, suffix = "审计报告"): string {
  const trimmed = value.trim() || "night-agent-report"
  return `${trimmed.replace(/[\\/:*?"<>|]+/g, "_").slice(0, 80)}-${suffix}.md`
}

function parseTargetsText(value: string): string[] {
  return value.split(/\r?\n/).map((line) => line.trim()).filter((line) => line && !line.startsWith("#"))
}

type ActivityGroupId = "sources" | "sinks" | "hypotheses" | "findings" | "system"
type DashboardView = "project" | "tasks" | "report"

interface ActivityItem {
  key: string
  title: string
  detail: string
  time: number
  tone: "info" | "success" | "warn" | "error"
}

interface ActivityGroup {
  id: ActivityGroupId
  title: string
  subtitle: string
  count: number
  lastAt: number
  items: ActivityItem[]
}

function eventPayload(event: AuditEvent): Record<string, unknown> {
  return event.payload && typeof event.payload === "object" ? event.payload as Record<string, unknown> : {}
}

function activityGroupMeta(id: ActivityGroupId): Pick<ActivityGroup, "id" | "title" | "subtitle"> {
  switch (id) {
    case "sources":
      return { id, title: "输入源", subtitle: "SourceAgent 发现" }
    case "sinks":
      return { id, title: "危险点", subtitle: "SinkAgent 候选" }
    case "hypotheses":
      return { id, title: "假设状态", subtitle: "Tracer/Judge 更新" }
    case "findings":
      return { id, title: "确认发现", subtitle: "Judge 输出" }
    default:
      return { id, title: "流程状态", subtitle: "运行阶段" }
  }
}

function activityItemForEvent(event: AuditEvent, index: number): { group: ActivityGroupId; item: ActivityItem } | null {
  const p = eventPayload(event)
  if (event.kind === "source:extracted") {
    const kind = String(p.kind ?? "")
    const name = String(p.paramName ?? "")
    const file = String(p.file ?? "")
    const line = String(p.line ?? "")
    return {
      group: "sources",
      item: {
        key: `${event.kind}:${file}:${line}:${kind}:${name}:${index}`,
        title: `发现输入源 ${kind}${name ? `:${name}` : ""}`,
        detail: `${compactPath(file)}:${line} ${String(p.code ?? "")}`.trim(),
        time: event.timestamp,
        tone: "info",
      },
    }
  }

  if (event.kind === "hypothesis:created") {
    const category = String(p.category ?? "")
    const file = String(p.sinkFile ?? "")
    const line = String(p.sinkLine ?? "")
    return {
      group: "sinks",
      item: {
        key: `${event.kind}:${file}:${line}:${String(p.sinkPattern ?? "")}:${index}`,
        title: `发现候选 ${category}`,
        detail: `${String(p.severity ?? "").toUpperCase()} ${String(p.sinkPattern ?? p.description ?? "")} @ ${compactPath(file)}:${line}`.trim(),
        time: event.timestamp,
        tone: eventTone(event),
      },
    }
  }

  if (event.kind === "hypothesis:updated") {
    const status = String(p.status ?? "")
    const category = String(p.category ?? "")
    const file = String(p.sinkFile ?? "")
    const line = String(p.sinkLine ?? "")
    return {
      group: "hypotheses",
      item: {
        key: `${event.kind}:${String(p.id ?? "")}:${status}:${index}`,
        title: `更新假设 ${status || "unknown"}`,
        detail: `${category} ${String(p.sinkPattern ?? p.description ?? "")} @ ${compactPath(file)}:${line}`.trim(),
        time: event.timestamp,
        tone: status === "confirmed" ? "success" : status === "dismissed" || status === "maybe_revisit" ? "warn" : "info",
      },
    }
  }

  if (event.kind === "finding:confirmed") {
    const category = String(p.category ?? "")
    return {
      group: "findings",
      item: {
        key: `${event.kind}:${String(p.id ?? "")}:${index}`,
        title: `确认漏洞 ${category}`,
        detail: `${String(p.title ?? "")} ${String(p.confidence ?? "")}`.trim(),
        time: event.timestamp,
        tone: "success",
      },
    }
  }

  if (event.kind === "state:enter" || event.kind === "audit:completed" || event.kind === "audit:error") {
    return {
      group: "system",
      item: {
        key: `${event.kind}:${event.timestamp}:${index}`,
        title: eventTitle(event),
        detail: eventDetail(event),
        time: event.timestamp,
        tone: eventTone(event),
      },
    }
  }

  if (event.kind === "coverage:rescan:started" || event.kind === "coverage:rescan:completed") {
    const files = Array.isArray(p.files) ? p.files.length : Number(p.files ?? 0)
    const newHypotheses = Number(p.newHypotheses ?? 0)
    return {
      group: "system",
      item: {
        key: `${event.kind}:${String(p.taskId ?? "")}:${index}`,
        title: event.kind.endsWith("started") ? "覆盖率补扫开始" : "覆盖率补扫完成",
        detail: event.kind.endsWith("started")
          ? `${files} 个文件 · ${String(p.reason ?? "")}`
          : `${files} 个文件 · 新增 ${newHypotheses} 个候选危险点`,
        time: event.timestamp,
        tone: event.kind.endsWith("completed") && newHypotheses > 0 ? "success" : "info",
      },
    }
  }

  return null
}

function buildActivityGroups(events: AuditEvent[]): ActivityGroup[] {
  const groups = new Map<ActivityGroupId, ActivityGroup>()
  for (const id of ["sources", "sinks", "hypotheses", "findings", "system"] as ActivityGroupId[]) {
    groups.set(id, { ...activityGroupMeta(id), count: 0, lastAt: 0, items: [] })
  }

  events.forEach((event, index) => {
    const activity = activityItemForEvent(event, index)
    if (!activity) return
    const group = groups.get(activity.group)
    if (!group) return
    group.count += 1
    group.lastAt = Math.max(group.lastAt, activity.item.time)
    group.items.push(activity.item)
  })

  return [...groups.values()]
    .filter((group) => group.count > 0)
    .map((group) => ({
      ...group,
      items: group.items.slice(-60).reverse(),
    }))
    .sort((a, b) => {
      const order: ActivityGroupId[] = ["sources", "sinks", "hypotheses", "findings", "system"]
      return order.indexOf(a.id) - order.indexOf(b.id)
    })
}

export default function App() {
  const { connected, messages, clearMessages, replaceMessages } = useWebSocket(WS_URL)
  const [settings, setSettings] = useState<ModelSettings>(DEFAULT_SETTINGS)
  const [settingsDirty, setSettingsDirty] = useState(false)
  const [settingsSaving, setSettingsSaving] = useState(false)
  const [history, setHistory] = useState<HistoryEntry[]>([])
  const [liveStatus, setLiveStatus] = useState<AuditStatus | null>(null)
  const [viewedRunDetail, setViewedRunDetail] = useState<RunDetail | null>(null)
  const [selectedRunId, setSelectedRunId] = useState<string | null>(null)
  const [selectedEvents, setSelectedEvents] = useState<AuditEvent[]>([])
  const [target, setTarget] = useState("")
  const [runJoern, setRunJoern] = useState(true)
  const [joernRuntime, setJoernRuntime] = useState<JoernRuntimeConfig>(() => loadJoernRuntime())
  const [verifierRuntime, setVerifierRuntime] = useState<VerifierRuntimeConfig>(() => loadVerifierRuntime())
  const [starting, setStarting] = useState(false)
  const [batchTargets, setBatchTargets] = useState("")
  const [batchReportsDir, setBatchReportsDir] = useState(() => window.localStorage.getItem("night_agent_batch_reports_dir") ?? "/tmp/night_agent_reports")
  const [batchOutRoot, setBatchOutRoot] = useState("")
  const [batchRunning, setBatchRunning] = useState(false)
  const [batchRerun, setBatchRerun] = useState(false)
  const [batchReset, setBatchReset] = useState(false)
  const [batchStopOnError, setBatchStopOnError] = useState(false)
  const [batchState, setBatchState] = useState<BatchState | null>(null)
  const [loadingRunId, setLoadingRunId] = useState<string | null>(null)
  const [markdown, setMarkdown] = useState("")
  const [markdownLoading, setMarkdownLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [sidebarOpen, setSidebarOpen] = useState(() => window.matchMedia("(min-width: 821px)").matches)
  const [activeView, setActiveView] = useState<DashboardView>("project")
  const [expandedActivityGroups, setExpandedActivityGroups] = useState<Set<ActivityGroupId>>(() => new Set())
  const [markdownFullscreen, setMarkdownFullscreen] = useState(false)
  const liveRunRef = useRef<string | null>(null)
  const batchTargetsDirtyRef = useRef(false)
  const batchHydratedRef = useRef(false)
  const markdownRequestRef = useRef(0)
  const hasConnectedRef = useRef(false)

  const displayStatus = viewedRunDetail ? statusFromDetail(viewedRunDetail) : liveStatus
  const active = starting || isActiveState(liveStatus?.state)
  const batchActive = batchRunning || Boolean(batchState?.running)
  const currentRun = liveStatus?.run ?? null
  const displayedRun = displayStatus?.run ?? null
  const visibleEvents = selectedRunId ? selectedEvents : messages
  const displayActive = selectedRunId ? isActiveState(displayStatus?.state) : active
  const agentStates = useMemo(() => buildAgentStates(visibleEvents, displayActive), [visibleEvents, displayActive])
  const activityGroups = useMemo(() => buildActivityGroups(visibleEvents), [visibleEvents])
  const recentEvents = useMemo(() => [...visibleEvents].slice(-180).reverse(), [visibleEvents])
  const reportReady = hasMarkdown(displayedRun, displayStatus?.generatedFiles)
  const completeReportReady = hasCompleteMarkdown(displayedRun, displayStatus?.generatedFiles)
  const reportFailureText = useMemo(() => reportFailure(visibleEvents), [visibleEvents])
  const batchTargetCount = parseTargetsText(batchTargets).length
  const batchCompleted = batchState?.entries.filter((entry) => entry.status === "completed").length ?? 0
  const batchFailed = batchState?.entries.filter((entry) => entry.status === "failed").length ?? 0
  const selectedModelPresetId = useMemo(() => modelPresetId(settings), [settings.provider, settings.model, settings.baseUrl])
  const joernRuntimePayload = useMemo<JoernRuntimeConfig>(() => {
    const normalized: JoernRuntimeConfig = {
      ...joernRuntime,
      traceConcurrency: clampRuntimeNumber(joernRuntime.traceConcurrency, DEFAULT_JOERN_RUNTIME.traceConcurrency, 1, 5),
      joernXmxMb: clampRuntimeNumber(joernRuntime.joernXmxMb, DEFAULT_JOERN_RUNTIME.joernXmxMb, 1024, 8192),
      joernActiveProcessors: clampRuntimeNumber(joernRuntime.joernActiveProcessors, DEFAULT_JOERN_RUNTIME.joernActiveProcessors, 1, 8),
      traceTimeoutMs: clampRuntimeNumber(joernRuntime.traceTimeoutMs, DEFAULT_JOERN_RUNTIME.traceTimeoutMs, 30_000, 600_000),
      fallbackTimeoutMs: clampRuntimeNumber(joernRuntime.fallbackTimeoutMs, DEFAULT_JOERN_RUNTIME.fallbackTimeoutMs, 10_000, 180_000),
      traceAutoLimitThreshold: clampRuntimeNumber(joernRuntime.traceAutoLimitThreshold, DEFAULT_JOERN_RUNTIME.traceAutoLimitThreshold, 1, 500),
      traceAutoLimitCount: clampRuntimeNumber(joernRuntime.traceAutoLimitCount, DEFAULT_JOERN_RUNTIME.traceAutoLimitCount, 0, 200),
      traceMaxHypotheses: clampRuntimeNumber(joernRuntime.traceMaxHypotheses, DEFAULT_JOERN_RUNTIME.traceMaxHypotheses, 0, 500),
    }
    return normalized.memorySafe
      ? { ...normalized, traceConcurrency: 1, traceAutoLimit: true, traceAutoLimitCount: 0, traceMaxHypotheses: 0 }
      : normalized
  }, [joernRuntime])
  const verifierRuntimePayload = useMemo<VerifierRuntimeConfig>(() => ({
    ...verifierRuntime,
    maxCandidates: clampRuntimeNumber(verifierRuntime.maxCandidates, DEFAULT_VERIFIER_RUNTIME.maxCandidates, 0, 500),
    duplicateRepresentatives: clampRuntimeNumber(verifierRuntime.duplicateRepresentatives, DEFAULT_VERIFIER_RUNTIME.duplicateRepresentatives, 1, 4),
    concurrency: clampRuntimeNumber(verifierRuntime.concurrency, DEFAULT_VERIFIER_RUNTIME.concurrency, 1, 6),
  }), [verifierRuntime])

  const refreshHistory = useCallback(async () => {
    try {
      setHistory(await fetchHistory())
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    }
  }, [])

  const refreshStatus = useCallback(async () => {
    try {
      const next = await fetchStatus()
      setLiveStatus(next)
      if (next.run?.runId && isActiveState(next.state)) liveRunRef.current = next.run.runId
      if (!isActiveState(next.state)) refreshHistory()
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    }
  }, [refreshHistory])

  const refreshBatch = useCallback(async () => {
    const dir = batchReportsDir.trim()
    try {
      const next = await fetchBatchStatus(dir || undefined)
      setBatchState(next)
      setBatchRunning(Boolean(next.running))
      if (!batchTargetsDirtyRef.current && next.entries.length > 0 && next.reportsDir && next.reportsDir !== batchReportsDir) {
        setBatchReportsDir(next.reportsDir)
        window.localStorage.setItem("night_agent_batch_reports_dir", next.reportsDir)
      }
      if (!batchTargetsDirtyRef.current && !batchHydratedRef.current && next.entries.length > 0) {
        setBatchTargets(next.entries.map((entry) => entry.input).join("\n"))
        batchHydratedRef.current = true
      }
      if (!next.running) refreshHistory()
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    }
  }, [batchReportsDir, refreshHistory])

  const loadSettings = useCallback(async () => {
    try {
      setSettings(await fetchModelSettings())
      setSettingsDirty(false)
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    }
  }, [])

  useEffect(() => {
    loadSettings()
    refreshHistory()
    refreshStatus()
  }, [loadSettings, refreshHistory, refreshStatus])

  useEffect(() => {
    if (!active) return
    const timer = setInterval(refreshStatus, 1800)
    return () => clearInterval(timer)
  }, [active, refreshStatus])

  useEffect(() => {
    refreshBatch()
  }, [refreshBatch])

  useEffect(() => {
    if (!batchActive) return
    const timer = setInterval(() => {
      refreshBatch()
      refreshStatus()
      refreshHistory()
    }, 2600)
    return () => clearInterval(timer)
  }, [batchActive, refreshBatch, refreshHistory, refreshStatus])

  useEffect(() => {
    const terminal = messages.find((msg) => msg.kind === "audit:completed" || msg.kind === "audit:error")
    if (!terminal) return
    setStarting(false)
    refreshStatus()
    refreshHistory()
  }, [messages, refreshHistory, refreshStatus])

  useEffect(() => {
    const requestId = markdownRequestRef.current + 1
    markdownRequestRef.current = requestId
    if (!displayedRun?.runId || !reportReady) {
      setMarkdown("")
      setMarkdownFullscreen(false)
      return
    }
    setMarkdownLoading(true)
    fetchMarkdown(displayedRun.runId)
      .then((text) => {
        if (markdownRequestRef.current === requestId) setMarkdown(text)
      })
      .catch((err) => {
        if (markdownRequestRef.current !== requestId) return
        setMarkdown("")
        setError(err instanceof Error ? err.message : String(err))
      })
      .finally(() => {
        if (markdownRequestRef.current === requestId) setMarkdownLoading(false)
      })
  }, [displayedRun?.runId, reportReady])

  useEffect(() => {
    if (!connected) return
    const reconnected = hasConnectedRef.current
    hasConnectedRef.current = true
    if (!reconnected || !liveRunRef.current) return
    refreshStatus()
    fetchRun(liveRunRef.current)
      .then((detail) => {
        if (detail.runId === liveRunRef.current) replaceMessages(detail.events)
      })
      .catch(() => {
        // Status polling still recovers the control state if event backfill fails.
      })
  }, [connected, refreshStatus, replaceMessages])

  async function persistSettings(): Promise<void> {
    setSettingsSaving(true)
    setError(null)
    try {
      const saved = await saveModelSettings(settings)
      setSettings(saved)
      setSettingsDirty(false)
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setSettingsSaving(false)
    }
  }

  async function runAudit(): Promise<void> {
    const input = target.trim()
    if (!input || starting || active || batchActive) return
    setError(null)
    setStarting(true)
    setSelectedRunId(null)
    setSelectedEvents([])
    setViewedRunDetail(null)
    setMarkdown("")
    setActiveView("tasks")
    clearMessages()
    try {
      if (settingsDirty) await persistSettings()
      const run = await startAudit({
        repoUrl: input,
        runJoern,
        provider: settings.provider,
        model: settings.model,
        baseUrl: settings.baseUrl,
        apiKey: settings.apiKey,
        joernRuntime: joernRuntimePayload,
        verifierRuntime: verifierRuntimePayload,
      })
      liveRunRef.current = run.runId
      setLiveStatus({
        state: "preparing",
        stats: null,
        run,
        generatedFiles: [],
        sources: [],
      })
      setTarget("")
      refreshHistory()
    } catch (err) {
      setStarting(false)
      setError(err instanceof Error ? err.message : String(err))
    }
  }

  async function runBatch(): Promise<void> {
    const reportsDir = batchReportsDir.trim()
    const targetsText = batchTargets.trim()
    if (!reportsDir || !targetsText || active || batchActive) return
    setError(null)
    setBatchRunning(true)
    try {
      if (settingsDirty) await persistSettings()
      window.localStorage.setItem("night_agent_batch_reports_dir", reportsDir)
      const next = await startBatch({
        targetsText,
        reportsDir,
        outRoot: batchOutRoot.trim() || undefined,
        runJoern,
        provider: settings.provider,
        model: settings.model,
        baseUrl: settings.baseUrl,
        apiKey: settings.apiKey,
        joernRuntime: joernRuntimePayload,
        verifierRuntime: verifierRuntimePayload,
        rerun: batchRerun,
        reset: batchReset,
        stopOnError: batchStopOnError,
      })
      batchHydratedRef.current = true
      setBatchState(next)
      setBatchRunning(Boolean(next.running))
      refreshHistory()
    } catch (err) {
      setBatchRunning(false)
      setError(err instanceof Error ? err.message : String(err))
    }
  }

  async function loadRun(runId: string): Promise<void> {
    setLoadingRunId(runId)
    setError(null)
    try {
      const detail = await fetchRun(runId)
      setSelectedRunId(runId)
      setSelectedEvents(detail.events)
      setViewedRunDetail(detail)
      setActiveView("tasks")
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setLoadingRunId(null)
    }
  }

  async function continueRun(entry: HistoryEntry, event?: React.MouseEvent): Promise<void> {
    event?.stopPropagation()
    if (starting || active) return
    setError(null)
    setStarting(true)
    setSelectedRunId(null)
    setSelectedEvents([])
    setViewedRunDetail(null)
    setMarkdown("")
    setActiveView("tasks")
    clearMessages()
    try {
      if (settingsDirty) await persistSettings()
      const run = await resumeRun(entry.runId, {
        provider: settings.provider,
        model: settings.model,
        baseUrl: settings.baseUrl,
        apiKey: settings.apiKey,
        joernRuntime: joernRuntimePayload,
        verifierRuntime: verifierRuntimePayload,
      })
      liveRunRef.current = run.runId
      setLiveStatus({
        state: "preparing",
        stats: entry.stats,
        observer: entry.observer,
        generatedFiles: entry.generatedFiles,
        run,
        sources: [],
      })
      refreshHistory()
    } catch (err) {
      setStarting(false)
      setError(err instanceof Error ? err.message : String(err))
    }
  }

  async function continueCurrentRun(): Promise<void> {
    if (!displayedRun || active || starting) return
    const entry = history.find((item) => item.runId === displayedRun.runId)
    if (entry) {
      await continueRun(entry)
      return
    }
    setError("当前 run 不在历史记录中，刷新历史后再继续")
  }

  async function pauseCurrentRun(): Promise<void> {
    if (!active || !currentRun) return
    setError(null)
    try {
      await pauseAudit()
      setLiveStatus((prev) => prev ? { ...prev, state: "pausing" } : prev)
      refreshHistory()
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    }
  }

  async function removeRun(runId: string, event: React.MouseEvent): Promise<void> {
    event.stopPropagation()
    setError(null)
    try {
      await deleteRunApi(runId)
      setHistory((prev) => prev.filter((item) => item.runId !== runId))
      if (selectedRunId === runId) {
        setSelectedRunId(null)
        setSelectedEvents([])
        setViewedRunDetail(null)
        setMarkdown("")
      }
      if (currentRun?.runId === runId) setLiveStatus(null)
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    }
  }

  function updateSettings(patch: Partial<ModelSettings>): void {
    setSettings((prev) => ({ ...prev, ...patch }))
    setSettingsDirty(true)
  }

  function updateJoernRuntime(patch: Partial<JoernRuntimeConfig>): void {
    setJoernRuntime((prev) => {
      const next = { ...prev, ...patch }
      window.localStorage.setItem("night_agent_joern_runtime", JSON.stringify(next))
      return next
    })
  }

  function updateVerifierRuntime(patch: Partial<VerifierRuntimeConfig>): void {
    setVerifierRuntime((prev) => {
      const next = { ...prev, ...patch }
      window.localStorage.setItem("night_agent_verifier_runtime", JSON.stringify(next))
      return next
    })
  }

  function toggleMemorySafe(enabled: boolean): void {
    updateJoernRuntime(enabled
      ? {
          memorySafe: true,
          traceConcurrency: 1,
          joernXmxMb: 2048,
          joernActiveProcessors: 2,
          traceAutoLimit: true,
          traceAutoLimitCount: 0,
          traceMaxHypotheses: 0,
        }
      : {
          memorySafe: false,
          traceAutoLimit: false,
          traceAutoLimitCount: 2,
          traceMaxHypotheses: 200,
        })
  }

  function changeModelPreset(presetId: ModelPresetId): void {
    const preset = MODEL_PRESETS.find((item) => item.id === presetId)
    if (!preset) return
    updateSettings({
      provider: preset.provider,
      model: preset.model,
      baseUrl: preset.baseUrl,
      apiKey: preset.provider === settings.provider && presetId === selectedModelPresetId ? settings.apiKey : "",
    })
  }

  function toggleActivityGroup(groupId: ActivityGroupId): void {
    setExpandedActivityGroups((prev) => {
      const next = new Set(prev)
      if (next.has(groupId)) next.delete(groupId)
      else next.add(groupId)
      return next
    })
  }

  function closeSidebarOnMobile(): void {
    if (window.matchMedia("(max-width: 820px)").matches) setSidebarOpen(false)
  }

  const completedAgents = agentStates.filter((agent) => agent.status === "done").length
  const activeAgent = agentStates.find((agent) => agent.status === "running")
  const checkpoints = displayStatus?.observer?.checkpoints ?? []
  const rescanSummary = displayStatus?.observer?.rescan
  const visibleCheckpoints = [
    ...checkpoints.filter((check) => check.check === "verifier-integrity"),
    ...checkpoints.filter((check) => check.check !== "verifier-integrity").slice(-8).reverse(),
  ].slice(0, 9)
  const sources = displayStatus?.sources ?? []
  const canResumeCurrent = !active && Boolean(displayedRun && ["interrupted", "error"].includes(displayStatus?.state ?? ""))
  const currentViewTitle = activeView === "project" ? "项目"
    : activeView === "tasks" ? "任务状态"
      : "漏洞报告"
  const navItems: Array<{ id: DashboardView; title: string; detail: string; metric: string }> = [
    {
      id: "project",
      title: "项目",
      detail: displayStatus?.profile?.name ?? displayedRun?.input ?? "配置和启动",
      metric: statusLabel(displayStatus?.state),
    },
    {
      id: "tasks",
      title: "任务状态",
      detail: activeAgent ? `${activeAgent.name} 运行中` : `${completedAgents}/${agentStates.length} Agent`,
      metric: `${displayStatus?.stats?.coveragePercent ?? 0}%`,
    },
    {
      id: "report",
      title: "漏洞报告",
      detail: reportReady ? "Markdown 已生成" : reportFailureText ? "报告失败" : "等待结果",
      metric: `${displayStatus?.stats?.confirmedFindings ?? 0} 确认`,
    },
  ]

  return (
    <div className={`app-shell ${sidebarOpen ? "" : "sidebar-collapsed"}`}>
      <aside className="sidebar">
        <div className="brand-row">
          <button className="icon-button" type="button" onClick={() => setSidebarOpen(false)} title="收起侧栏">☰</button>
          <div>
            <strong>night_agent</strong>
            <span>{connected ? "已连接" : "未连接"} · {statusLabel(liveStatus?.state)}</span>
          </div>
        </div>

        <nav className="dashboard-nav" aria-label="审计数据视图">
          {navItems.map((item) => (
            <button
              key={item.id}
              className={`dashboard-nav-item ${activeView === item.id ? "active" : ""}`}
              type="button"
              onClick={() => {
                setActiveView(item.id)
                closeSidebarOnMobile()
              }}
            >
              <span>{item.title}</span>
              <strong>{item.metric}</strong>
              <em>{item.detail}</em>
            </button>
          ))}
        </nav>

        <button className="new-run" type="button" onClick={() => { setSelectedRunId(null); setSelectedEvents([]); setViewedRunDetail(null); if (!active) setLiveStatus(null); setMarkdown(""); setActiveView("project"); clearMessages(); closeSidebarOnMobile(); }}>
          新建审计
        </button>

        <div className="history-head">
          <span>历史记录</span>
          <button type="button" onClick={refreshHistory}>刷新</button>
        </div>
        <div className="history-list">
          {history.length === 0 && <div className="empty-state">暂无历史记录</div>}
          {history.map((entry) => (
            <button
              key={entry.runId}
              className={`history-item ${selectedRunId === entry.runId ? "active" : ""}`}
              type="button"
              onClick={() => {
                loadRun(entry.runId)
                closeSidebarOnMobile()
              }}
            >
              <span className={`status-dot ${entry.status}`} />
              <span className="history-copy">
                <strong>{loadingRunId === entry.runId ? "加载中..." : runTitle(entry)}</strong>
                <em>{entry.mode === "full" ? "完整 Joern" : "快速"} · {entry.stats?.confirmedFindings ?? 0} 确认 · {formatDate(entry.startedAt)}</em>
              </span>
              {["interrupted", "error"].includes(entry.status) && (
                <span className="resume-run" title="从 checkpoint 继续" onClick={(event) => continueRun(entry, event)}>继续</span>
              )}
              <span className="delete-run" title="删除历史" onClick={(event) => removeRun(entry.runId, event)}>×</span>
            </button>
          ))}
        </div>
      </aside>

      <main className={`workspace view-${activeView}`}>
        <header className="topbar">
          <div className="view-heading">
            {!sidebarOpen && <button className="icon-button" type="button" onClick={() => setSidebarOpen(true)} title="展开侧栏">☰</button>}
            <div>
              <span>当前视图</span>
              <strong>{currentViewTitle}</strong>
            </div>
          </div>
          <div className="target-box">
            <textarea
              value={target}
              onChange={(event) => setTarget(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "Enter" && !event.shiftKey) {
                  event.preventDefault()
                  runAudit()
                }
              }}
              placeholder="输入项目路径或 Git URL"
              disabled={starting || active || batchActive}
            />
            <button type="button" onClick={runAudit} disabled={!target.trim() || starting || active || batchActive}>
              {starting || active ? "运行中" : "启动"}
            </button>
          </div>
          {active && currentRun && (
            <button className="run-control pause" type="button" onClick={pauseCurrentRun}>
              暂停
            </button>
          )}
          {canResumeCurrent && (
            <button className="run-control resume" type="button" onClick={continueCurrentRun}>
              继续
            </button>
          )}
          <label className="switch">
            <input type="checkbox" checked={runJoern} onChange={(event) => setRunJoern(event.target.checked)} />
            <span>Joern</span>
          </label>
        </header>

        {error && (
          <div className="error-banner">
            <strong>错误</strong>
            <span>{error}</span>
            <button type="button" onClick={() => setError(null)}>×</button>
          </div>
        )}

        <section className="summary-grid">
          <div className="summary-card wide">
            <span>当前项目</span>
            <strong>{displayStatus?.profile?.name ?? displayedRun?.input ?? "未选择"}</strong>
            <em>{displayedRun ? compactPath(displayedRun.target) : "等待输入路径或 Git URL"}</em>
          </div>
          <div className="summary-card">
            <span>假设</span>
            <strong>{displayStatus?.stats?.totalHypotheses ?? 0}</strong>
          </div>
          <div className="summary-card">
            <span>确认</span>
            <strong>{displayStatus?.stats?.confirmedFindings ?? 0}</strong>
          </div>
          <div className="summary-card">
            <span>待复核</span>
            <strong>{displayStatus?.stats?.pendingHypotheses ?? 0}</strong>
          </div>
          <div className="summary-card">
            <span>覆盖率</span>
            <strong>{displayStatus?.stats?.coveragePercent ?? 0}%</strong>
          </div>
        </section>

        <section className="work-grid">
          <div className="panel agent-panel">
            <div className="panel-title">
              <div>
                <h2>Agent 协作</h2>
                <p>{activeAgent ? `${activeAgent.name} 正在处理` : `${completedAgents}/${agentStates.length} 已完成`}</p>
              </div>
              <span className={`connection ${connected ? "ok" : ""}`} />
            </div>
            <div className="agent-grid">
              {agentStates.map((agent) => (
                <div key={agent.id} className={`agent-card ${agent.status}`}>
                  <div className="agent-card-head">
                    <strong>{agent.name}</strong>
                    <span>{agent.label}</span>
                  </div>
                  <p>{agent.lastDetail || agent.lastTitle}</p>
                  <em>{agent.count} 条事件</em>
                </div>
              ))}
            </div>
          </div>

          <div className="panel activity-panel">
            <div className="panel-title">
              <div>
                <h2>审计动态</h2>
                <p>Source、Sink 和假设状态在这里合并更新</p>
              </div>
            </div>
            <div className="activity-grid">
              {activityGroups.length === 0 && <div className="empty-state">等待 SourceAgent / SinkAgent 输出</div>}
              {activityGroups.map((group) => (
                <div className={`activity-card ${group.id} ${expandedActivityGroups.has(group.id) ? "expanded" : ""}`} key={group.id}>
                  <button className="activity-card-head" type="button" onClick={() => toggleActivityGroup(group.id)}>
                    <div>
                      <strong>{group.title}</strong>
                      <span>{group.subtitle}</span>
                    </div>
                    <em>{expandedActivityGroups.has(group.id) ? "收起" : group.count > 4 ? `展开 ${group.count}` : String(group.count)}</em>
                  </button>
                  <div className="activity-items">
                    {(expandedActivityGroups.has(group.id) ? group.items : group.items.slice(0, 4)).map((item) => (
                      <div className={`activity-item ${item.tone}`} key={item.key}>
                        <span>{formatTime(item.time)}</span>
                        <div>
                          <strong>{item.title}</strong>
                          <p>{item.detail}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="panel event-panel">
            <div className="panel-title">
              <div>
                <h2>实时事件</h2>
                <p>{selectedRunId ? "历史事件" : "WebSocket 实时流"}</p>
              </div>
              <button type="button" onClick={() => selectedRunId ? setSelectedEvents([]) : clearMessages()}>清空视图</button>
            </div>
            <div className="event-list">
              {recentEvents.length === 0 && <div className="empty-state">等待后台消息</div>}
              {recentEvents.map((event, index) => (
                <div key={`${event.timestamp}-${event.kind}-${index}`} className={`event-row ${eventTone(event)}`}>
                  <span>{formatTime(event.timestamp)}</span>
                  <div>
                    <strong>{eventTitle(event)}</strong>
                    <p>{eventDetail(event)}</p>
                    <em>{event.source}{eventRunId(event) ? ` · ${eventRunId(event)}` : ""}</em>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </section>
        <div className="workspace-secondary">
        <section className="panel settings-panel">
          <div className="panel-title">
            <div>
              <h2>模型设置</h2>
              <p>{settingsDirty ? "有未保存修改" : settings.updatedAt ? `已保存 ${formatDate(settings.updatedAt)}` : "保存在 SQLite"}</p>
            </div>
            <button type="button" onClick={persistSettings} disabled={settingsSaving || !settingsDirty}>{settingsSaving ? "保存中" : "保存"}</button>
          </div>
          <label>
            <span>Provider</span>
            <select value={selectedModelPresetId} onChange={(event) => changeModelPreset(event.target.value as ModelPresetId)}>
              {MODEL_PRESETS.map((preset) => <option key={preset.id} value={preset.id}>{preset.label}</option>)}
            </select>
          </label>
          <label>
            <span>Model</span>
            <input value={settings.model} onChange={(event) => updateSettings({ model: event.target.value })} />
          </label>
          <label>
            <span>Base URL</span>
            <input value={settings.baseUrl} onChange={(event) => updateSettings({ baseUrl: event.target.value })} />
          </label>
          <label>
            <span>API Key</span>
            <input value={settings.apiKey} onChange={(event) => updateSettings({ apiKey: event.target.value })} type="password" />
          </label>
          <div className="settings-foot">
            <span>{settings.provider}</span>
            <span>{settings.model || "default"}</span>
            <span>{shortValue(settings.apiKey)}</span>
          </div>
          <div className="joern-runtime">
            <div className="settings-subhead">
              <strong>Joern 资源</strong>
              <span>{joernRuntime.memorySafe ? "内存安全" : "完整追踪"}</span>
            </div>
            <label className="check-row">
              <input type="checkbox" checked={joernRuntime.memorySafe} onChange={(event) => toggleMemorySafe(event.target.checked)} disabled={!runJoern} />
              <span>内存安全</span>
            </label>
            <div className="joern-runtime-grid">
              <label>
                <span>Trace 并发</span>
                <input type="number" min={1} max={5} value={joernRuntime.traceConcurrency} onChange={(event) => updateJoernRuntime({ traceConcurrency: Number(event.target.value) })} disabled={!runJoern} />
              </label>
              <label>
                <span>Xmx MB</span>
                <input type="number" min={1024} max={8192} step={256} value={joernRuntime.joernXmxMb} onChange={(event) => updateJoernRuntime({ joernXmxMb: Number(event.target.value) })} disabled={!runJoern} />
              </label>
              <label>
                <span>CPU</span>
                <input type="number" min={1} max={8} value={joernRuntime.joernActiveProcessors} onChange={(event) => updateJoernRuntime({ joernActiveProcessors: Number(event.target.value) })} disabled={!runJoern} />
              </label>
              <label>
                <span>逐条上限</span>
                <input type="number" min={0} max={500} value={joernRuntime.traceMaxHypotheses} onChange={(event) => updateJoernRuntime({ traceMaxHypotheses: Number(event.target.value) })} disabled={!runJoern} />
              </label>
              <label>
                <span>单条超时 ms</span>
                <input type="number" min={30000} max={600000} step={10000} value={joernRuntime.traceTimeoutMs} onChange={(event) => updateJoernRuntime({ traceTimeoutMs: Number(event.target.value) })} disabled={!runJoern} />
              </label>
              <label>
                <span>Fallback ms</span>
                <input type="number" min={10000} max={180000} step={5000} value={joernRuntime.fallbackTimeoutMs} onChange={(event) => updateJoernRuntime({ fallbackTimeoutMs: Number(event.target.value) })} disabled={!runJoern || !joernRuntime.traceFallback} />
              </label>
            </div>
            <div className="joern-runtime-toggles">
              <label className="check-row">
                <input type="checkbox" checked={joernRuntime.traceFallback} onChange={(event) => updateJoernRuntime({ traceFallback: event.target.checked })} disabled={!runJoern} />
                <span>Fallback</span>
              </label>
              <label className="check-row">
                <input type="checkbox" checked={joernRuntime.traceAutoLimit} onChange={(event) => updateJoernRuntime({ traceAutoLimit: event.target.checked })} disabled={!runJoern} />
                <span>自动限流</span>
              </label>
              <label className="check-row">
                <input type="checkbox" checked={joernRuntime.perHypothesisTrace} onChange={(event) => updateJoernRuntime({ perHypothesisTrace: event.target.checked })} disabled={!runJoern} />
                <span>逐条 Trace</span>
              </label>
            </div>
          </div>
          <div className="joern-runtime verifier-runtime">
            <div className="settings-subhead">
              <strong>Verifier 复核</strong>
              <span>{verifierRuntimePayload.triageEnabled ? verifierRuntimePayload.maxCandidates > 0 ? `${verifierRuntimePayload.maxCandidates} 条` : "自动预算" : "完整复核"}</span>
            </div>
            <div className="joern-runtime-grid">
              <label>
                <span>候选预算</span>
                <input type="number" min={0} max={500} value={verifierRuntime.maxCandidates} onChange={(event) => updateVerifierRuntime({ maxCandidates: Number(event.target.value) })} disabled={!verifierRuntime.triageEnabled} />
              </label>
              <label>
                <span>重复代表</span>
                <input type="number" min={1} max={4} value={verifierRuntime.duplicateRepresentatives} onChange={(event) => updateVerifierRuntime({ duplicateRepresentatives: Number(event.target.value) })} disabled={!verifierRuntime.triageEnabled} />
              </label>
              <label>
                <span>Verifier 并发</span>
                <input type="number" min={1} max={6} value={verifierRuntime.concurrency} onChange={(event) => updateVerifierRuntime({ concurrency: Number(event.target.value) })} />
              </label>
            </div>
            <div className="joern-runtime-toggles">
              <label className="check-row">
                <input type="checkbox" checked={verifierRuntime.triageEnabled} onChange={(event) => updateVerifierRuntime({ triageEnabled: event.target.checked })} />
                <span>Triage</span>
              </label>
              <label className="check-row">
                <input type="checkbox" checked={verifierRuntime.recheckDeferred} onChange={(event) => updateVerifierRuntime({ recheckDeferred: event.target.checked })} disabled={!verifierRuntime.triageEnabled} />
                <span>重查 deferred</span>
              </label>
            </div>
          </div>
        </section>

        <section className="panel batch-panel">
          <div className="panel-title">
            <div>
              <h2>批量审计</h2>
              <p>{batchActive ? "串行执行中" : batchState?.entries.length ? `${batchCompleted}/${batchState.entries.length} 已完成，${batchFailed} 失败` : `${batchTargetCount} 个待提交目标`}</p>
            </div>
            <button type="button" onClick={runBatch} disabled={!batchReportsDir.trim() || !batchTargets.trim() || active || batchActive}>
              {batchActive ? "运行中" : batchState?.entries.some((entry) => entry.status !== "completed") ? "继续批量" : "启动批量"}
            </button>
          </div>
          <label>
            <span>目标列表</span>
            <textarea
              value={batchTargets}
              onChange={(event) => {
                batchTargetsDirtyRef.current = true
                setBatchTargets(event.target.value)
              }}
              placeholder="每行一个项目路径或 Git URL，# 开头会忽略"
              disabled={batchActive}
            />
          </label>
          <label>
            <span>报告目录</span>
            <input
              value={batchReportsDir}
              onChange={(event) => {
                setBatchReportsDir(event.target.value)
                window.localStorage.setItem("night_agent_batch_reports_dir", event.target.value)
              }}
              disabled={batchActive}
              placeholder="/tmp/night_agent_reports"
            />
          </label>
          <label>
            <span>原始产物目录</span>
            <input
              value={batchOutRoot}
              onChange={(event) => setBatchOutRoot(event.target.value)}
              disabled={batchActive}
              placeholder="默认 <报告目录>/.runs"
            />
          </label>
          <div className="batch-options">
            <label><input type="checkbox" checked={batchRerun} onChange={(event) => setBatchRerun(event.target.checked)} disabled={batchActive} />重跑已完成</label>
            <label><input type="checkbox" checked={batchReset} onChange={(event) => setBatchReset(event.target.checked)} disabled={batchActive} />重建批次</label>
            <label><input type="checkbox" checked={batchStopOnError} onChange={(event) => setBatchStopOnError(event.target.checked)} disabled={batchActive} />失败即停</label>
          </div>
          <div className="batch-summary-line">
            <span>状态文件</span>
            <strong>{batchState?.reportsDir ? `${batchState.reportsDir}/batch-state.json` : "等待启动"}</strong>
          </div>
          <div className="batch-list">
            {(!batchState || batchState.entries.length === 0) && <div className="empty-state">提交后这里显示每个项目的进度。</div>}
            {batchState?.entries.map((entry, index) => {
              const reports = (entry.reportFiles ?? []).filter((file) => file.endsWith(".md")).map((file) => file.split(/[\\/]/).pop()).filter(Boolean)
              return (
                <div className={`batch-item ${entry.status}`} key={entry.id}>
                  <div className="batch-item-head">
                    <strong>{index + 1}. {entry.input.split(/[\\/]/).pop() || entry.input}</strong>
                    <span>{entry.status}</span>
                  </div>
                  <p title={entry.input}>{compactPath(entry.input)}</p>
                  <div className="batch-metrics">
                    <span>确认 {entry.stats?.confirmedFindings ?? "-"}</span>
                    <span>覆盖 {entry.stats?.coveragePercent ?? "-"}%</span>
                    <span>报告 {reports.length || "-"}</span>
                  </div>
                  {reports.length > 0 && <em>{reports.join(" · ")}</em>}
                  {entry.error && <em className="batch-error">{entry.error}</em>}
                </div>
              )
            })}
          </div>
        </section>

        <section className="panel report-panel">
          <div className="panel-title">
            <div>
              <h2>Markdown 报告</h2>
              <p>{reportReady ? "报告已生成" : reportFailureText ? "报告未生成" : "等待 ReportAgent"}</p>
            </div>
            <div className="report-actions">
              {markdown && <button type="button" onClick={() => setMarkdownFullscreen(true)}>全屏</button>}
              {reportReady && displayedRun && (
                <>
                  <a
                    href={`/api/audit/runs/${displayedRun.runId}/report/markdown`}
                    download={safeDownloadName(displayStatus?.profile?.name ?? displayedRun.input ?? "night-agent-report")}
                  >
                    下载报告
                  </a>
                </>
              )}
              {completeReportReady && displayedRun && (
                <>
                  <a
                    href={`/api/audit/runs/${displayedRun.runId}/report/complete-markdown`}
                    download={safeDownloadName(displayStatus?.profile?.name ?? displayedRun.input ?? "night-agent-report", "完整结果")}
                  >
                    下载全部
                  </a>
                </>
              )}
              {reportReady && displayedRun && (
                <>
                  <a href={`/api/audit/runs/${displayedRun.runId}/report/markdown`} target="_blank" rel="noreferrer">原文</a>
                </>
              )}
            </div>
          </div>
          <div className="markdown-preview">
            {markdownLoading && <p className="muted">正在加载 Markdown...</p>}
            {!markdownLoading && markdown && renderMarkdown(markdown)}
            {!markdownLoading && !markdown && reportFailureText && (
              <div className="report-empty failed">
                <strong>ReportAgent 未生成 Markdown</strong>
                <p>{reportFailureText}</p>
                <span>当前假设 {displayStatus?.stats?.totalHypotheses ?? 0} 个，确认 {displayStatus?.stats?.confirmedFindings ?? 0} 个，待复核 {displayStatus?.stats?.pendingHypotheses ?? 0} 个。</span>
              </div>
            )}
            {!markdownLoading && !markdown && !reportFailureText && <p className="muted">AI 报告生成后会显示在这里。</p>}
          </div>
        </section>

        <section className="panel task-observer-panel">
          <div className="panel-title">
            <div>
              <h2>Observer</h2>
              <p>{rescanSummary ? `补扫 ${rescanSummary.filesScanned} 文件，剩余 ${rescanSummary.unvisitedAfter}` : `${checkpoints.length} 个检查点`}</p>
            </div>
          </div>
          {rescanSummary && (
            <div className="rescan-summary">
              <div><span>补扫任务</span><strong>{rescanSummary.tasksQueued}</strong></div>
              <div><span>新增 Source</span><strong>{rescanSummary.newSources}</strong></div>
              <div><span>新增 Sink</span><strong>{rescanSummary.newHypotheses}</strong></div>
              <div><span>未访问</span><strong>{rescanSummary.unvisitedAfter}</strong></div>
            </div>
          )}
          <div className="check-list">
            {checkpoints.length === 0 && <span className="muted">等待检查结果</span>}
            {visibleCheckpoints.map((check, index) => (
              <div className="check-item" key={`${check.phase}-${check.check}-${index}`}>
                <span className={check.passed ? "pass" : "warn"}>{check.passed ? "PASS" : "WARN"}</span>
                <div>
                  <strong>{check.check}</strong>
                  <p>{check.detail}</p>
                </div>
              </div>
            ))}
          </div>
        </section>

        <section className="panel task-source-panel">
          <div className="panel-title">
            <div>
              <h2>输入源</h2>
              <p>{sources.length} 个 SourceAgent 结果</p>
            </div>
          </div>
          <div className="source-list">
            {sources.length === 0 && <span className="muted">等待输入源</span>}
            {sources.slice(0, 12).map((source) => (
              <div className="source-item" key={`${source.id}-${source.file}-${source.line}`}>
                <strong>{source.kind}:{source.paramName}</strong>
                <span>{compactPath(source.file)}:{source.line}</span>
              </div>
            ))}
          </div>
        </section>
        </div>
      </main>

      {markdownFullscreen && (
        <div className="markdown-fullscreen" role="dialog" aria-modal="true" aria-label="Markdown 报告全屏预览">
          <div className="markdown-fullscreen-head">
            <div>
              <strong>Markdown 报告</strong>
              <span>{displayStatus?.profile?.name ?? displayedRun?.input ?? "审计报告"}</span>
            </div>
            <button type="button" onClick={() => setMarkdownFullscreen(false)}>关闭</button>
          </div>
          <div className="markdown-fullscreen-body">
            {renderMarkdown(markdown)}
          </div>
        </div>
      )}
    </div>
  )
}
