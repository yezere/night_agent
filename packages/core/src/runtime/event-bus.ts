import { randomUUID } from "node:crypto"
import type { AgentBusEvent, AuditEventKind, EventHandler } from "../types/index.ts"

interface Subscription {
  id: string
  pattern: string | AuditEventKind
  handler: EventHandler
}

export class EventBus {
  private subs: Subscription[] = []

  subscribe(pattern: AuditEventKind | string, handler: EventHandler): () => void {
    const id = randomUUID()
    this.subs.push({ id, pattern, handler })
    return () => {
      this.subs = this.subs.filter((s) => s.id !== id)
    }
  }

  async publish(kind: AuditEventKind, payload: unknown, source: string): Promise<void> {
    const event: AgentBusEvent = { kind, payload, timestamp: Date.now(), source }
    const matching = this.subs.filter((s) => this.matches(s.pattern, kind))
    for (const sub of matching) {
      try {
        await sub.handler(event)
      } catch (err) {
        console.error(`[event-bus] handler error for ${kind}:`, err instanceof Error ? err.message : String(err))
      }
    }
  }

  /** Emit synchronously — fire-and-forget, errors logged */
  emit(kind: AuditEventKind, payload: unknown, source: string): void {
    const event: AgentBusEvent = { kind, payload, timestamp: Date.now(), source }
    const matching = this.subs.filter((s) => this.matches(s.pattern, kind))
    for (const sub of matching) {
      try {
        const result = sub.handler(event)
        if (result instanceof Promise) {
          result.catch((err) =>
            console.error(`[event-bus] async handler error for ${kind}:`, err instanceof Error ? err.message : String(err))
          )
        }
      } catch (err) {
        console.error(`[event-bus] handler error for ${kind}:`, err instanceof Error ? err.message : String(err))
      }
    }
  }

  private matches(pattern: string, kind: string): boolean {
    if (pattern === "*") return true
    if (pattern.endsWith(":*")) {
      const prefix = pattern.slice(0, -2)
      return kind.startsWith(prefix + ":")
    }
    return pattern === kind
  }

  subscriberCount(): number {
    return this.subs.length
  }

  clear(): void {
    this.subs = []
  }
}
