import type { AuditState } from "../types/index.ts"

const VALID_TRANSITIONS: Record<AuditState, AuditState[]> = {
  init: ["profiling", "terminated"],
  profiling: ["scanning", "terminated"],
  scanning: ["enriching", "tracing", "judging", "reviewing", "terminated"],
  enriching: ["tracing", "judging", "reviewing", "terminated"],
  tracing: ["judging", "reviewing", "terminated"],
  judging: ["reviewing", "terminated"],
  reviewing: ["scanning", "enriching", "tracing", "judging", "reporting", "terminated"],
  reporting: ["terminated"],
  terminated: [],
}

export class StateMachine {
  private current: AuditState = "init"
  private history: AuditState[] = []
  private transitionCount = 0

  get state(): AuditState {
    return this.current
  }

  canTransition(to: AuditState): boolean {
    return VALID_TRANSITIONS[this.current]?.includes(to) ?? false
  }

  transition(to: AuditState): { ok: true; from: AuditState } | { ok: false; error: string } {
    if (!this.canTransition(to)) {
      return {
        ok: false,
        error: `Invalid transition: ${this.current} → ${to}. Valid targets: ${VALID_TRANSITIONS[this.current].join(", ") || "(none)"}`,
      }
    }
    const from = this.current
    this.history.push(from)
    this.current = to
    this.transitionCount++
    return { ok: true, from }
  }

  /** Force transition — bypasses validation. Use only for error recovery. */
  forceTransition(to: AuditState): AuditState {
    const from = this.current
    this.history.push(from)
    this.current = to
    this.transitionCount++
    return from
  }

  isTerminal(): boolean {
    return this.current === "terminated"
  }

  getHistory(): AuditState[] {
    return [...this.history]
  }

  iterations(): number {
    return this.transitionCount
  }

  reset(): void {
    this.current = "init"
    this.history = []
    this.transitionCount = 0
  }
}
