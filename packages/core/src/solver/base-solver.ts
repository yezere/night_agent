import type { AgentIdentity, AgentBusEvent, SharedAuditState } from "../types/index.ts"
import type { EventBus } from "../runtime/event-bus.ts"

export interface SolverContext {
  identity: AgentIdentity
  bus: EventBus
  getState: () => SharedAuditState
  log: (msg: string) => void
}

export abstract class BaseSolver {
  readonly identity: AgentIdentity
  protected bus: EventBus
  protected getSharedState: () => SharedAuditState
  protected log: (msg: string) => void
  private unsubs: Array<() => void> = []

  constructor(ctx: SolverContext) {
    this.identity = ctx.identity
    this.bus = ctx.bus
    this.getSharedState = ctx.getState
    this.log = ctx.log
  }

  abstract start(): Promise<void>
  abstract stop(): Promise<void>

  /**
   * Handle an event from the EventBus. Override to react to specific events.
   * Default: no-op.
   */
  async onEvent(_event: AgentBusEvent): Promise<void> {
    // Override in subclasses
  }

  protected subscribe(pattern: string, handler: (event: AgentBusEvent) => Promise<void>): void {
    const unsub = this.bus.subscribe(pattern, handler)
    this.unsubs.push(unsub)
  }

  protected emit(kind: AgentBusEvent["kind"], payload: unknown): void {
    this.bus.emit(kind, payload, this.identity.id)
  }

  protected setStatus(status: AgentIdentity["status"]): void {
    this.identity.status = status
    this.log(`[${this.identity.id}] status → ${status}`)
  }

  async destroy(): Promise<void> {
    await this.stop()
    for (const unsub of this.unsubs) {
      unsub()
    }
    this.unsubs = []
  }
}
