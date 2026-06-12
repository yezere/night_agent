import type { TerminationConditions, TerminationCheck } from "../types/index.ts"

export const DEFAULT_TERMINATION: TerminationConditions = {
  maxTimeMinutes: 30,
  maxIterations: 50,
  minCoveragePercent: 60,
  maxPendingHypotheses: 0,
  observerFailureLimit: 3,
}

export function shouldTerminate(
  conditions: TerminationConditions,
  elapsedMs: number,
  iterations: number,
  coveragePercent: number,
  pendingHypotheses: number,
  observerFailures: number,
): TerminationCheck {
  const details: Record<string, string | number | boolean> = {}

  if (elapsedMs >= conditions.maxTimeMinutes * 60_000) {
    details.elapsedMinutes = Math.round(elapsedMs / 60_000)
    details.limitMinutes = conditions.maxTimeMinutes
    return { shouldStop: true, reason: `time limit reached (${details.elapsedMinutes}/${details.limitMinutes} min)`, details }
  }

  if (iterations >= conditions.maxIterations) {
    details.iterations = iterations
    details.limitIterations = conditions.maxIterations
    return { shouldStop: true, reason: `max iterations reached (${iterations}/${conditions.maxIterations})`, details }
  }

  if (coveragePercent >= conditions.minCoveragePercent && pendingHypotheses <= conditions.maxPendingHypotheses) {
    details.coveragePercent = coveragePercent
    details.pendingHypotheses = pendingHypotheses
    return { shouldStop: true, reason: "coverage target met with no pending hypotheses", details }
  }

  if (observerFailures >= conditions.observerFailureLimit) {
    details.observerFailures = observerFailures
    details.limitFailures = conditions.observerFailureLimit
    return { shouldStop: true, reason: `observer failure limit reached (${observerFailures}/${conditions.observerFailureLimit})`, details }
  }

  details.elapsedMinutes = Math.round(elapsedMs / 60_000)
  details.iterations = iterations
  details.coveragePercent = coveragePercent
  details.pendingHypotheses = pendingHypotheses
  return { shouldStop: false, details }
}
