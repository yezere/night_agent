import type { Hypothesis, HypothesisEvidenceState } from "../types/index.ts"
import { graphStoreScopeOrDefault } from "./store-scope.ts"

const defaultHypotheses = new Map<string, Hypothesis>()

function hypotheses(): Map<string, Hypothesis> {
  return graphStoreScopeOrDefault("intent-store")?.intent.hypotheses ?? defaultHypotheses
}

function id(): string {
  return `hyp-${crypto.randomUUID().slice(0, 8)}`
}

export function addHypothesis(h: Omit<Hypothesis, "id" | "status" | "createdAt" | "updatedAt">): Hypothesis {
  const now = Date.now()
  const hyp: Hypothesis = { ...h, id: id(), status: "pending", evidenceState: initialEvidenceState(now), createdAt: now, updatedAt: now }
  hypotheses().set(hyp.id, hyp)
  return hyp
}

export function getHypothesis(id: string): Hypothesis | undefined {
  return hypotheses().get(id)
}

export function getAllHypotheses(): Hypothesis[] {
  return [...hypotheses().values()]
}

export function getPending(): Hypothesis[] {
  return [...hypotheses().values()].filter((h) => h.status === "pending")
}

export function getTracing(): Hypothesis[] {
  return [...hypotheses().values()].filter((h) => h.status === "tracing")
}

export function getConfirmed(): Hypothesis[] {
  return [...hypotheses().values()].filter((h) => h.status === "confirmed")
}

export function getDismissed(): Hypothesis[] {
  return [...hypotheses().values()].filter((h) => h.status === "dismissed")
}

export function updateStatus(
  id: string,
  status: Hypothesis["status"],
  dataflowResult?: Hypothesis["dataflowResult"],
  resolutionNote?: string,
): boolean {
  const hyp = hypotheses().get(id)
  if (!hyp) return false
  hyp.status = status
  hyp.updatedAt = Date.now()
  if (dataflowResult) hyp.dataflowResult = dataflowResult
  if (resolutionNote !== undefined) hyp.resolutionNote = resolutionNote
  return true
}

export function countByStatus(): Record<Hypothesis["status"], number> {
  const result: Record<Hypothesis["status"], number> = {
    pending: 0,
    tracing: 0,
    confirmed: 0,
    dismissed: 0,
    maybe_revisit: 0,
  }
  for (const [, h] of hypotheses()) result[h.status]++
  return result
}

export function size(): number {
  return hypotheses().size
}

export function clear() {
  hypotheses().clear()
}

export function restore(items: Hypothesis[]): void {
  const store = hypotheses()
  store.clear()
  for (const item of items) {
    if (!item.evidenceState) item.evidenceState = initialEvidenceState(item.updatedAt ?? Date.now())
    if (item.status === "tracing" && item.evidenceState.trace === "not_started") {
      item.evidenceState.trace = "running"
      item.evidenceState.updatedAt = item.updatedAt ?? Date.now()
    }
    store.set(item.id, item)
  }
}

function initialEvidenceState(now: number): HypothesisEvidenceState {
  return {
    trace: "not_started",
    verification: "not_started",
    finding: "not_started",
    updatedAt: now,
  }
}
