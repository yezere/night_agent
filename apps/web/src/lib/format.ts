import type { AuditEvent, HistoryEntry } from "../types"

export function compactPath(path: string): string {
  const src = path.lastIndexOf("/src/")
  if (src !== -1) return path.slice(src + 1)
  const parts = path.split("/").filter(Boolean)
  return parts.length > 4 ? `.../${parts.slice(-4).join("/")}` : path
}

export function formatTime(ts: number): string {
  return new Date(ts).toLocaleTimeString("zh-CN", { hour: "2-digit", minute: "2-digit" })
}

export function formatDate(ts: number): string {
  return new Date(ts).toLocaleString("zh-CN", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  })
}

export function runTitle(entry: HistoryEntry): string {
  return entry.projectName || entry.input.split("/").filter(Boolean).pop() || entry.input || "未命名审计"
}

export function statusLabel(status?: string): string {
  switch (status) {
    case "running": return "运行中"
    case "pausing": return "暂停中"
    case "preparing": return "准备中"
    case "completed":
    case "terminated": return "已完成"
    case "interrupted": return "已中断"
    case "error": return "失败"
    case "idle": return "空闲"
    case "profiling": return "识别项目"
    case "scanning": return "扫描 Source/Sink"
    case "tracing": return "Joern 追踪"
    case "judging": return "判定证据"
    case "reviewing": return "Observer 复核"
    case "reporting": return "编写报告"
    default: return status || "空闲"
  }
}

export function isActiveState(state?: string): boolean {
  return Boolean(state && !["idle", "terminated", "completed", "error", "interrupted"].includes(state))
}

export function eventRunId(event: AuditEvent): string | null {
  if (!event.payload || typeof event.payload !== "object") return null
  const payload = event.payload as Record<string, unknown>
  return typeof payload.runId === "string" ? payload.runId : null
}

export function payloadText(payload: unknown): string {
  if (!payload || typeof payload !== "object") return ""
  const p = payload as Record<string, unknown>
  const parts = [
    p.description,
    p.title,
    p.content,
    p.error,
    p.warning,
    p.state,
    p.task,
    p.kind,
  ].filter((v) => typeof v === "string" && v)
  return parts.length > 0 ? String(parts[0]) : ""
}

export function eventTitle(event: AuditEvent): string {
  const p = event.payload && typeof event.payload === "object" ? event.payload as Record<string, unknown> : {}
  const title = typeof event.title === "string" ? event.title : typeof p.title === "string" ? p.title : ""
  if (title === "Observer challenged verifier verdict") return "Observer 要求重判"
  if (title === "StaticVerifierAgent recheck queued") return "Verifier 重判排队"
  if (title === "StaticVerifierAgent recheck completed") return "Verifier 重判完成"
  if (event.kind === "agent:submission" && typeof p.title === "string") return p.title
  if (event.kind === "agent:artifact" && typeof p.title === "string") return p.title
  if (event.kind === "task:started") return `${String(p.task ?? event.source)} 开始`
  if (event.kind === "task:completed") return `${String(p.task ?? event.source)} 完成`
  if (event.kind === "task:failed") return `${String(p.task ?? event.source)} 失败`
  if (event.kind === "source:extracted") return `发现输入源 ${String(p.kind ?? "")}:${String(p.paramName ?? "")}`
  if (event.kind === "hypothesis:created") return `发现候选 ${String(p.category ?? "")}`
  if (event.kind === "hypothesis:updated") return `更新假设 ${String(p.status ?? "")}`
  if (event.kind === "finding:confirmed") return `确认漏洞 ${String(p.category ?? "")}`
  if (event.kind === "observer:report") return "Observer 复核"
  if (event.kind === "observer:warning") return "Observer 警告"
  if (event.kind === "audit:completed") return "审计完成"
  if (event.kind === "audit:paused") return "审计已暂停"
  if (event.kind === "audit:error") return "审计失败"
  if (event.kind === "state:enter") return `进入 ${statusLabel(String(p.state ?? ""))}`
  return event.kind
}

export function eventDetail(event: AuditEvent): string {
  const p = event.payload && typeof event.payload === "object" ? event.payload as Record<string, unknown> : {}
  if (event.detail) return event.detail
  if (event.kind === "agent:submission") return String(p.content ?? "")
  if (event.kind === "agent:artifact") return String(p.content ?? "")
  if (event.kind === "task:completed") {
    const fields = ["sources", "hypotheses", "findings", "bundles", "confirmed", "dismissed", "revisit", "warnings"]
    return fields
      .filter((key) => typeof p[key] === "number" || typeof p[key] === "string")
      .map((key) => `${key}=${String(p[key])}`)
      .join(", ")
  }
  if (event.kind === "source:extracted") return `${String(p.file ?? "")}:${String(p.line ?? "")} ${String(p.code ?? "")}`
  if (event.kind === "hypothesis:created" || event.kind === "hypothesis:updated") {
    return `${String(p.severity ?? "")} ${String(p.sinkPattern ?? p.description ?? "")} @ ${compactPath(String(p.sinkFile ?? ""))}:${String(p.sinkLine ?? "")}`
  }
  if (event.kind === "finding:confirmed") return `${String(p.title ?? "")} ${String(p.confidence ?? "")}`
  if (event.kind === "observer:report") {
    const report = p.report && typeof p.report === "object" ? p.report as Record<string, unknown> : {}
    const checkpoints = Array.isArray(report.checkpoints) ? report.checkpoints.length : 0
    const warnings = Array.isArray(report.warnings) ? report.warnings.length : 0
    return `${checkpoints} 个检查点，${warnings} 个警告`
  }
  return payloadText(event.payload)
}

export function eventTone(event: AuditEvent): "info" | "success" | "warn" | "error" {
  if (event.level === "warn" || event.title === "Observer challenged verifier verdict") return "warn"
  if (event.level === "error") return "error"
  if (event.level === "success") return "success"
  if (event.kind.includes("failed") || event.kind.includes("error")) return "error"
  if (event.kind.includes("warning")) return "warn"
  if (event.kind.includes("completed") || event.kind === "finding:confirmed") return "success"
  return "info"
}
