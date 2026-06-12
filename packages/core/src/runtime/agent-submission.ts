import * as AgentBoard from "../graph/agent-board.ts"
import type { AgentArtifactKind, AgentBusEvent } from "../types/index.ts"
import type { EventBus } from "./event-bus.ts"

export interface AgentSubmission {
  agent: string
  title: string
  content: string
  kind?: AgentArtifactKind
  refs?: string[]
  artifacts?: Record<string, unknown>
}

export function submitAgentResult(bus: EventBus, source: string, submission: AgentSubmission): void {
  let payload: AgentSubmission = submission
  if (submission.kind) {
    const artifact = AgentBoard.addArtifact({
      kind: submission.kind,
      agent: submission.agent,
      title: submission.title,
      content: submission.content,
      refs: submission.refs,
      data: submission.artifacts,
    })
    bus.emit("agent:artifact" as AgentBusEvent["kind"], artifact, source)
    payload = {
      ...submission,
      artifacts: {
        artifactId: artifact.id,
        kind: artifact.kind,
        ...(submission.artifacts ?? {}),
      },
    }
  }
  bus.emit("agent:submission" as AgentBusEvent["kind"], payload, source)
}
