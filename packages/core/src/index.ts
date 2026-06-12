export { CodeAuditAgent } from "./agent/audit-agent.ts"
export { AuditManager } from "./manager/audit-manager.ts"
export type { AuditOptions, AuditReport, LLMConfig, LLMProvider, AgentBusEvent, EvidenceBundle, SourceLink, HypothesisEvidenceState } from "./types/index.ts"
export { SEVERITY_ORDER, compareSeverity, HIGH_RISK_DEP_PATTERNS, isHighRiskDep } from "./types/index.ts"
export { generateJoernQueries, generateJoernQueriesWithTools, extractSourceEntriesWithLLM, generateMarkdownReportWithLLM, checkLlmHealth, assertLlmReady, llmAvailable } from "./llm/llm-runner.ts"
export type { LLMHealthResult } from "./llm/llm-runner.ts"

// Runtime
export { EventBus } from "./runtime/event-bus.ts"
export { TaskQueue } from "./runtime/task-queue.ts"
export { StateMachine } from "./runtime/state-machine.ts"
export { shouldTerminate, DEFAULT_TERMINATION } from "./runtime/termination.ts"
export { TaskCancellation } from "./runtime/cancellation.ts"
export { AuditWorkspace } from "./runtime/audit-workspace.ts"
export type { AuditWorkspaceSnapshot } from "./runtime/audit-workspace.ts"
export { buildEvidenceGraph } from "./graph/evidence-graph.ts"
export type { EvidenceGraphArtifact, EvidenceNode, EvidenceEdge, TaintFlow } from "./graph/evidence-graph.ts"
export { buildEvidenceDecisionIndex, evidenceDecisionForReport, evidenceDecisionIndexForReport } from "./graph/evidence-decision.ts"
export type { EvidenceDecisionIndex, EvidenceFlowDecision } from "./graph/evidence-decision.ts"

// Solvers
export { BaseSolver, type SolverContext } from "./solver/base-solver.ts"
export { SolverScanner } from "./solver/solver-scanner.ts"
export { SinkAgent } from "./solver/solver-sink.ts"
export { SolverReader } from "./solver/solver-reader.ts"
export { JoernQueryAgent } from "./solver/solver-joern-query.ts"
export { SolverTracer } from "./solver/solver-tracer.ts"
export { SolverJudge } from "./solver/solver-judge.ts"

// Tools
export { ripgrepSearch, rgAvailable } from "./tools/ripgrep-wrapper.ts"
export { readSnippet, readMultipleSnippets, formatSnippetForLLM } from "./tools/file-reader.ts"
export { tryLoadPrompt } from "./llm/prompt-loader.ts"
