import type { AuditReport, AuditStatus, BatchState, HistoryEntry, JoernRuntimeConfig, ModelSettings, RunDetail, VerifierRuntimeConfig } from "./types"

async function readJson<T>(resp: Response): Promise<T> {
  if (!resp.ok) {
    const text = await resp.text().catch(() => resp.statusText)
    throw new Error(text)
  }
  return resp.json() as Promise<T>
}

export async function fetchModelSettings(): Promise<ModelSettings> {
  return readJson<ModelSettings>(await fetch("/api/settings/model"))
}

export async function saveModelSettings(settings: ModelSettings): Promise<ModelSettings> {
  return readJson<ModelSettings>(await fetch("/api/settings/model", {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(settings),
  }))
}

export async function fetchHistory(): Promise<HistoryEntry[]> {
  return readJson<HistoryEntry[]>(await fetch("/api/audit/history"))
}

export async function fetchStatus(): Promise<AuditStatus> {
  return readJson<AuditStatus>(await fetch("/api/audit/status"))
}

export async function fetchRun(runId: string): Promise<RunDetail> {
  return readJson<RunDetail>(await fetch(`/api/audit/runs/${runId}`))
}

export async function fetchCurrentReport(): Promise<AuditReport> {
  return readJson<AuditReport>(await fetch("/api/audit/report"))
}

export async function deleteRun(runId: string): Promise<void> {
  await readJson<{ ok: boolean }>(await fetch(`/api/audit/runs/${runId}`, { method: "DELETE" }))
}

export async function resumeRun(runId: string, input: {
  provider: string
  model: string
  baseUrl: string
  apiKey: string
  joernRuntime?: JoernRuntimeConfig
  verifierRuntime?: VerifierRuntimeConfig
}): Promise<{ runId: string; input: string; target: string; outputDir: string; cloned: boolean; resumed: boolean }> {
  return readJson(await fetch(`/api/audit/runs/${runId}/resume`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(input),
  }))
}

export async function pauseAudit(): Promise<{ ok: boolean; runId: string }> {
  return readJson(await fetch("/api/audit/pause", { method: "POST" }))
}

export async function fetchMarkdown(runId: string): Promise<string> {
  const resp = await fetch(`/api/audit/runs/${runId}/report/markdown`)
  if (!resp.ok) throw new Error(await resp.text())
  return resp.text()
}

export async function startAudit(input: {
  repoUrl: string
  runJoern: boolean
  provider: string
  model: string
  baseUrl: string
  apiKey: string
  joernRuntime?: JoernRuntimeConfig
  verifierRuntime?: VerifierRuntimeConfig
}): Promise<{ runId: string; input: string; target: string; outputDir: string; cloned: boolean }> {
  return readJson(await fetch("/api/audit/start", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(input),
  }))
}

export async function startBatch(input: {
  targetsText: string
  reportsDir: string
  outRoot?: string
  runJoern: boolean
  provider: string
  model: string
  baseUrl: string
  apiKey: string
  joernRuntime?: JoernRuntimeConfig
  verifierRuntime?: VerifierRuntimeConfig
  rerun?: boolean
  reset?: boolean
  stopOnError?: boolean
  timeoutMinutes?: number
  maxHypotheses?: number
}): Promise<BatchState> {
  return readJson<BatchState>(await fetch("/api/batch/start", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(input),
  }))
}

export async function fetchBatchStatus(reportsDir?: string): Promise<BatchState> {
  const qs = reportsDir ? `?reportsDir=${encodeURIComponent(reportsDir)}` : ""
  return readJson<BatchState>(await fetch(`/api/batch/status${qs}`))
}
