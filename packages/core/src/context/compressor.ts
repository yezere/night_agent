import type { Hypothesis, AuditStats } from "../types/index.ts"
import { compareSeverity } from "../types/index.ts"

const CHARS_PER_TOKEN = 4

interface CompressedSnapshot {
  summary: string
  stats: AuditStats
  topFindings: string[]
  pendingCount: number
  pendingPreview: string[]
  tokenEstimate: number
}

function estimateTokens(text: string): number {
  return Math.ceil(text.length / CHARS_PER_TOKEN)
}

export function compressState(hypotheses: Hypothesis[], stats: AuditStats): CompressedSnapshot {
  const confirmed = hypotheses
    .filter((h) => h.status === "confirmed")
    .sort((a, b) => compareSeverity(a.severity, b.severity))

  const pending = hypotheses.filter((h) => h.status === "pending")

  // Adaptive sizing: cap at 10 each, but reduce if total chars would be huge
  const maxItems = confirmed.length + pending.length > 200 ? 5 : 10

  const topFindings = confirmed.slice(0, maxItems).map((h) =>
    `[${h.severity}] ${h.category}: ${h.sinkFile}:${h.sinkLine}`
  )
  const pendingPreview = pending.slice(0, maxItems).map((h) =>
    `[${h.severity}] ${h.category}: ${h.sinkFile}:${h.sinkLine}`
  )

  const summary = `${confirmed.length} confirmed findings, ${stats.dismissedHypotheses} dismissed, ${pending.length} pending — ${stats.coveragePercent}% coverage`

  // Estimate tokens from the full snapshot content
  const serialized = summary + topFindings.join(" ") + pendingPreview.join(" ")
  const tokenEstimate = estimateTokens(serialized)

  return {
    summary,
    stats,
    topFindings,
    pendingCount: pending.length,
    pendingPreview,
    tokenEstimate,
  }
}
