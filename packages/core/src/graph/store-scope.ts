import { AsyncLocalStorage } from "node:async_hooks"
import type { AgentArtifact, AuditEvent, EvidenceBundle, Finding, Hypothesis, Note } from "../types/index.ts"

export interface GraphStoreScope {
  intent: {
    hypotheses: Map<string, Hypothesis>
  }
  facts: {
    facts: Map<string, Finding>
    byCategory: Map<string, Finding[]>
    bySeverity: Map<string, Finding[]>
    byFile: Map<string, Finding[]>
  }
  notes: {
    notes: Map<string, Note>
  }
  agentBoard: {
    artifacts: AgentArtifact[]
    sequence: number
  }
  evidenceBundles: {
    bundles: Map<string, EvidenceBundle>
  }
  events: {
    events: AuditEvent[]
    suppressedCounts: Map<string, number>
    suppressedTotal: number
  }
}

const storage = new AsyncLocalStorage<GraphStoreScope>()
let strictScopeAccess = false

export function createGraphStoreScope(): GraphStoreScope {
  return {
    intent: { hypotheses: new Map() },
    facts: {
      facts: new Map(),
      byCategory: new Map(),
      bySeverity: new Map(),
      byFile: new Map(),
    },
    notes: { notes: new Map() },
    agentBoard: { artifacts: [], sequence: 0 },
    evidenceBundles: { bundles: new Map() },
    events: { events: [], suppressedCounts: new Map(), suppressedTotal: 0 },
  }
}

export function currentGraphStoreScope(): GraphStoreScope | undefined {
  return storage.getStore()
}

export function graphStoreScopeOrDefault(owner: string): GraphStoreScope | undefined {
  const scope = storage.getStore()
  if (!scope && strictScopeAccess) {
    throw new Error(`${owner} accessed graph store without active AuditWorkspace scope`)
  }
  return scope
}

export function enforceGraphStoreScope(enabled = true): void {
  strictScopeAccess = enabled
}

export function enterGraphStoreScope(scope: GraphStoreScope): void {
  storage.enterWith(scope)
}

export function runWithGraphStoreScope<T>(scope: GraphStoreScope, fn: () => T): T {
  return storage.run(scope, fn)
}
