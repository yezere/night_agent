import type { EventBus } from "../runtime/event-bus.ts"
import { submitAgentResult } from "../runtime/agent-submission.ts"
import * as AgentBoard from "../graph/agent-board.ts"
import type { AgentArtifact, AgentWorkflowTask, AgentWorkflowTaskKind } from "../types/index.ts"

export interface AgentTaskContext {
  bus: EventBus
  task: AgentWorkflowTask
  inputArtifacts: AgentArtifact[]
  log: (msg: string) => void
}

export type AgentWorker<T = unknown> = (ctx: AgentTaskContext) => Promise<T> | T

export class AgentDispatcher {
  private bus: EventBus
  private log: (msg: string) => void
  private workers = new Map<AgentWorkflowTaskKind, AgentWorker>()
  private tasks: AgentWorkflowTask[] = []
  private sequence = 0

  constructor(bus: EventBus, log: (msg: string) => void) {
    this.bus = bus
    this.log = log
  }

  register(kind: AgentWorkflowTaskKind, worker: AgentWorker): void {
    this.workers.set(kind, worker)
  }

  async run<T = unknown>(input: {
    kind: AgentWorkflowTaskKind
    agent: string
    title: string
    inputArtifacts?: AgentArtifact[]
    data?: Record<string, unknown>
  }): Promise<T> {
    const worker = this.workers.get(input.kind)
    if (!worker) throw new Error(`No worker registered for ${input.kind}`)

    const task: AgentWorkflowTask = {
      id: this.nextTaskId(input.kind),
      kind: input.kind,
      agent: input.agent,
      title: input.title,
      status: "queued",
      inputArtifactIds: input.inputArtifacts?.map((artifact) => artifact.id) ?? [],
      outputArtifactIds: [],
      data: input.data,
      createdAt: Date.now(),
    }
    this.tasks.push(task)
    this.bus.emit("task:queued", task, "dispatcher")
    this.log(`[dispatcher] queued ${task.agent}/${task.kind}`)

    task.status = "running"
    task.startedAt = Date.now()
    this.bus.emit("task:started", { task: task.agent, kind: task.kind, title: task.title }, task.agent)

    try {
      const before = this.snapshotArtifactIds()
      const result = await worker({
        bus: this.bus,
        task,
        inputArtifacts: input.inputArtifacts ?? [],
        log: (msg) => this.log(`[${task.agent}] ${msg}`),
      })
      const after = this.snapshotArtifactIds()
      task.outputArtifactIds = [...after].filter((id) => !before.has(id))
      task.status = "done"
      task.completedAt = Date.now()
      this.bus.emit("task:completed", {
        task: task.agent,
        kind: task.kind,
        outputs: task.outputArtifactIds.length,
      }, task.agent)
      return result as T
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err)
      task.status = "failed"
      task.error = message
      task.completedAt = Date.now()
      submitAgentResult(this.bus, task.agent, {
        agent: task.agent,
        kind: "failure",
        title: `${task.agent} 执行失败`,
        content: message,
        artifacts: { taskId: task.id, kind: task.kind },
      })
      this.bus.emit("task:failed", { task: task.agent, kind: task.kind, error: message }, task.agent)
      throw err
    }
  }

  history(): AgentWorkflowTask[] {
    return this.tasks.map((task) => ({ ...task }))
  }

  private nextTaskId(kind: AgentWorkflowTaskKind): string {
    this.sequence += 1
    return `task-${kind}-${Date.now().toString(36)}-${this.sequence.toString(36)}`
  }

  private snapshotArtifactIds(): Set<string> {
    return new Set(AgentBoard.getAll().map((artifact) => artifact.id))
  }
}
