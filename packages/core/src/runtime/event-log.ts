import type { AuditEvent, AuditEventLevel, AuditEventPhase } from "../types/index.ts"
import { graphStoreScopeOrDefault } from "../graph/store-scope.ts"

const MAX_EVENTS = 500
const DEDUP_WINDOW = 50 // check last N events for duplicates

// ─── Log state dedup (Cairn pattern #8) ───
// Track suppressed counts for "state change only" logging philosophy.
// Stable state (repeated sends) is suppressed; only state changes are emitted.
const defaultState = {
  events: [] as AuditEvent[],
  suppressedCounts: new Map<string, number>(),
  suppressedTotal: 0,
}

function state(): typeof defaultState {
  return graphStoreScopeOrDefault("event-log")?.events ?? defaultState
}

function makeId(): string {
  return `evt-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`
}

/** Build a dedup key from event fields — identical phase+level+title within window = suppressed. */
function dedupKey(phase: AuditEventPhase, level: AuditEventLevel, title: string): string {
  return `${phase}::${level}::${title}`
}

export function addEvent(
  phase: AuditEventPhase,
  level: AuditEventLevel,
  title: string,
  detail?: string,
  relatedHypothesisIds: string[] = [],
): AuditEvent {
  const current = state()
  // Dedup: check if an identical event exists in the last DEDUP_WINDOW events
  const key = dedupKey(phase, level, title)
  const recent = current.events.slice(-DEDUP_WINDOW)
  for (let i = recent.length - 1; i >= 0; i--) {
    if (dedupKey(recent[i]!.phase, recent[i]!.level, recent[i]!.title) === key) {
      // Update the existing event's relatedHypothesisIds instead of creating a duplicate
      if (relatedHypothesisIds.length > 0) {
        const existing = recent[i]!
        for (const id of relatedHypothesisIds) {
          if (!existing.relatedHypothesisIds.includes(id)) {
            existing.relatedHypothesisIds.push(id)
          }
        }
      }
      // Track suppressed count
      current.suppressedCounts.set(key, (current.suppressedCounts.get(key) ?? 0) + 1)
      current.suppressedTotal++
      return recent[i]!
    }
  }

  // Suppressed count tracking: if we transition from suppressed → emitted,
  // attach the count to the detail so it's visible
  const suppressed = current.suppressedCounts.get(key)
  current.suppressedCounts.delete(key)

  const event: AuditEvent = {
    id: makeId(),
    phase,
    level,
    title,
    detail: suppressed ? `${detail ?? ""}${detail ? " | " : ""}${suppressed} similar suppressed` : detail,
    relatedHypothesisIds,
    timestamp: Date.now(),
  }
  current.events.push(event)

  // Cap: maintain ring buffer
  if (current.events.length > MAX_EVENTS) {
    current.events.splice(0, current.events.length - MAX_EVENTS)
  }

  return event
}

export function getEvents(): AuditEvent[] {
  return [...state().events]
}

export function getRecentEvents(n: number = 20): AuditEvent[] {
  return state().events.slice(-n)
}

export function eventCount(): number {
  return state().events.length
}

/** Returns the total number of suppressed events (both pending and flushed). */
export function suppressedEventCount(): number {
  const current = state()
  let pending = 0
  for (const [, count] of current.suppressedCounts) {
    pending += count
  }
  return current.suppressedTotal + pending
}

export function clearEvents() {
  const current = state()
  current.events.length = 0
  current.suppressedCounts.clear()
  current.suppressedTotal = 0
}

export function restoreEvents(items: AuditEvent[]) {
  const current = state()
  current.events.length = 0
  current.events.push(...items.slice(-MAX_EVENTS))
  current.suppressedCounts.clear()
  current.suppressedTotal = 0
}
