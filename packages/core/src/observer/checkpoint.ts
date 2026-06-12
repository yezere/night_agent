/**
 * ReasonCheckpoint — Cairn pattern #4: Reason trigger deduplication.
 *
 * Rather than firing Observer reviews on every N events (noisy),
 * we snapshot the graph state and only trigger review when:
 * 1. Finding count increased (new confirmed facts)
 * 2. Note count increased (new hints)
 * 3. Open (pending) hypotheses went from non-zero to zero (all paths exhausted)
 *
 * Explicitly NOT triggering on:
 * - Hypothesis count change alone (noise from scanning)
 * - Tracer failures (handled by observer independently)
 * - Transient status changes
 */

export interface ReasonCheckpoint {
  findingCount: number
  noteCount: number
  pendingCount: number
  dismissedCount: number
}

export function snapshotCheckpoint(
  findingCount: number,
  noteCount: number,
  pendingCount: number,
  dismissedCount: number,
): ReasonCheckpoint {
  return { findingCount, noteCount, pendingCount, dismissedCount }
}

/**
 * Returns true if the current state differs from the last checkpoint
 * in a way that warrants a Reason (global review) trigger.
 */
export function shouldTriggerReason(
  current: ReasonCheckpoint,
  previous: ReasonCheckpoint | null,
): { trigger: boolean; changes: string[] } {
  if (!previous) return { trigger: true, changes: ["initial checkpoint"] }

  const changes: string[] = []

  if (current.findingCount > previous.findingCount) {
    changes.push(`findings increased: ${previous.findingCount} → ${current.findingCount}`)
  }
  if (current.noteCount > previous.noteCount) {
    changes.push(`notes increased: ${previous.noteCount} → ${current.noteCount}`)
  }
  if (previous.pendingCount > 0 && current.pendingCount === 0) {
    changes.push("open hypotheses exhausted")
  }
  if (current.dismissedCount > previous.dismissedCount) {
    changes.push(`dismissed increased: ${previous.dismissedCount} → ${current.dismissedCount}`)
  }

  return { trigger: changes.length > 0, changes }
}

/** Log-friendly checkpoint diff string for debugging. */
export function checkpointDiff(prev: ReasonCheckpoint, curr: ReasonCheckpoint): string {
  const parts: string[] = []
  if (curr.findingCount !== prev.findingCount) parts.push(`findings: ${prev.findingCount}→${curr.findingCount}`)
  if (curr.noteCount !== prev.noteCount) parts.push(`notes: ${prev.noteCount}→${curr.noteCount}`)
  if (curr.pendingCount !== prev.pendingCount) parts.push(`pending: ${prev.pendingCount}→${curr.pendingCount}`)
  if (curr.dismissedCount !== prev.dismissedCount) parts.push(`dismissed: ${prev.dismissedCount}→${curr.dismissedCount}`)
  return parts.length > 0 ? parts.join(" | ") : "no changes"
}
