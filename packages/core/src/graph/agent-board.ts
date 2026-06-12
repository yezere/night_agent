import type { AgentArtifact, AgentArtifactKind } from "../types/index.ts"
import { graphStoreScopeOrDefault } from "./store-scope.ts"

const defaultBoard: { artifacts: AgentArtifact[]; sequence: number } = { artifacts: [], sequence: 0 }

function board(): typeof defaultBoard {
  return graphStoreScopeOrDefault("agent-board")?.agentBoard ?? defaultBoard
}

function nextId(kind: AgentArtifactKind, current = board()): string {
  current.sequence += 1
  return `artifact-${kind}-${Date.now().toString(36)}-${current.sequence.toString(36)}`
}

export function addArtifact(input: {
  kind: AgentArtifactKind
  agent: string
  title: string
  content: string
  refs?: string[]
  data?: Record<string, unknown>
}): AgentArtifact {
  const current = board()
  const artifact: AgentArtifact = {
    id: nextId(input.kind, current),
    kind: input.kind,
    agent: input.agent,
    title: input.title,
    content: input.content,
    refs: input.refs,
    data: input.data,
    createdAt: Date.now(),
  }
  current.artifacts.push(artifact)
  return artifact
}

export function getAll(): AgentArtifact[] {
  return [...board().artifacts]
}

export function getByKind(kind: AgentArtifactKind): AgentArtifact[] {
  return board().artifacts.filter((artifact) => artifact.kind === kind)
}

export function clear(): void {
  const current = board()
  current.artifacts.length = 0
  current.sequence = 0
}

export function restore(items: AgentArtifact[]): void {
  const current = board()
  current.artifacts.length = 0
  current.artifacts.push(...items)
  current.sequence = items.length
}
