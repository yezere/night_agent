import { randomUUID } from "node:crypto"
import type { AuditTask, TaskKind, TaskPayload } from "../types/index.ts"
import { SEVERITY_ORDER } from "../types/index.ts"

export class TaskQueue {
  private items: AuditTask[] = []
  private history: AuditTask[] = []

  enqueue(kind: TaskKind, payload: TaskPayload, assignedTo: string, priority?: number): AuditTask {
    const task: AuditTask = {
      id: randomUUID(),
      kind,
      payload,
      assignedTo,
      status: "queued",
      createdAt: Date.now(),
    }
    if (priority !== undefined) {
      // Insert at position based on priority (lower = higher priority)
      let i = 0
      for (; i < this.items.length; i++) {
        const existingPrio = SEVERITY_ORDER[this.items[i]!.kind as keyof typeof SEVERITY_ORDER] ?? 2
        if (priority < existingPrio) break
      }
      this.items.splice(i, 0, task)
    } else {
      this.items.push(task)
    }
    return task
  }

  next(assignedTo?: string): AuditTask | undefined {
    const idx = assignedTo
      ? this.items.findIndex((t) => t.assignedTo === assignedTo && t.status === "queued")
      : this.items.findIndex((t) => t.status === "queued")
    if (idx === -1) return undefined
    const task = this.items[idx]!
    task.status = "running"
    return task
  }

  markDone(taskId: string): void {
    const task = this.items.find((t) => t.id === taskId)
    if (task) {
      task.status = "done"
      task.completedAt = Date.now()
      this.history.push(task)
      this.items = this.items.filter((t) => t.id !== taskId)
    }
  }

  markFailed(taskId: string, error: string): void {
    const task = this.items.find((t) => t.id === taskId)
    if (task) {
      task.status = "failed"
      task.error = error
      task.completedAt = Date.now()
      this.history.push(task)
      this.items = this.items.filter((t) => t.id !== taskId)
    }
  }

  pendingCount(assignedTo?: string): number {
    return assignedTo
      ? this.items.filter((t) => t.assignedTo === assignedTo && t.status === "queued").length
      : this.items.filter((t) => t.status === "queued").length
  }

  runningCount(): number {
    return this.items.filter((t) => t.status === "running").length
  }

  allQueued(): AuditTask[] {
    return this.items.filter((t) => t.status === "queued")
  }

  allRunning(): AuditTask[] {
    return this.items.filter((t) => t.status === "running")
  }

  getHistory(): AuditTask[] {
    return [...this.history]
  }

  clear(): void {
    this.items = []
    this.history = []
  }
}
