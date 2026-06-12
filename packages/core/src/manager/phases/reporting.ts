import { resolve } from "node:path"
import { writeCompleteFindingsReport, writeReport } from "../../report/report-writer.ts"
import { enrichReportDetails } from "../../report/report-agent.ts"
import { buildAuditGraph } from "../../graph/audit-graph.ts"
import { buildEvidenceGraph } from "../../graph/evidence-graph.ts"
import { compressState } from "../../context/compressor.ts"
import { addEvent, getEvents } from "../../runtime/event-log.ts"
import { saveCheckpoint } from "../../runtime/checkpoint-store.ts"
import { submitAgentResult } from "../../runtime/agent-submission.ts"
import { runObserverChecks } from "../../observer/supervisor.ts"
import { logObserverReport } from "./scanning.ts"
import { AuditWorkspace } from "../../runtime/audit-workspace.ts"
import { StateMachine } from "../../runtime/state-machine.ts"
import type { EventBus } from "../../runtime/event-bus.ts"
import { SolverTracer } from "../../solver/solver-tracer.ts"
import type {
  AuditOptions,
  AuditReport,
  ProjectProfile,
  CoverageGrid,
  CoverageRescanSummary,
  AuditStats,
  SourceEntry,
} from "../../types/index.ts"

export function runReviewingPhase(
  sm: StateMachine,
  bus: EventBus,
  coverageGrid: CoverageGrid,
  workspace: AuditWorkspace,
  log: (msg: string) => void,
  graphContext?: { profile: ProjectProfile; sources: SourceEntry[] },
): { warnings: string[] } {
  const result = sm.transition("reviewing")
  if (!result.ok) { log(`state error: ${result.error}`); return { warnings: [] } }
  bus.emit("state:enter", { state: "reviewing", from: result.from }, "manager")

  const hypotheses = workspace.getHypotheses()
  const obsReport = runObserverChecks("reason", hypotheses, coverageGrid, graphContext ? { ...graphContext, evidenceBundles: workspace.getEvidenceBundles() } : undefined)
  workspace.applyObserverActions(obsReport)
  logObserverReport("reviewing", obsReport, (msg) => log(`[observer] ${msg}`))
  bus.emit("observer:report", { report: obsReport, trigger: "reviewing" }, "observer")
  submitAgentResult(bus, "observer", {
    agent: "Observer",
    kind: "observer",
    title: "Observer 提交复核结果",
    content: obsReport.warnings.length > 0
      ? `我完成了复核，提交 ${obsReport.checkpoints.length} 个检查点，其中 ${obsReport.warnings.length} 个需要关注。`
      : `我完成了复核，提交 ${obsReport.checkpoints.length} 个检查点，未发现流程级异常。`,
    artifacts: { checkpoints: obsReport.checkpoints.length, warnings: obsReport.warnings.length },
  })

  bus.emit("state:leave", { state: "reviewing" }, "manager")
  return obsReport
}

export interface ReportingInputs {
  options: AuditOptions
  profile: ProjectProfile
  coverageGrid: CoverageGrid
  workspace: AuditWorkspace
  tracer: SolverTracer | null
  startTime: number
  sources: SourceEntry[]
  runPoc?: (report: AuditReport) => Promise<void> | void
}

export async function runReportingPhase(
  sm: StateMachine,
  bus: EventBus,
  inputs: ReportingInputs,
): Promise<AuditReport> {
  const { options, profile, coverageGrid, workspace, tracer, startTime, sources, runPoc } = inputs

  const result = sm.transition("reporting")
  if (!result.ok) return createFailReport(profile, coverageGrid, startTime, result.error, workspace)

  bus.emit("state:enter", { state: "reporting", from: result.from }, "manager")

  let hypotheses = workspace.getHypotheses()
  const joernInfo = tracer?.getJoernResult?.() ?? { ran: false, skippedReason: "not started", queryOutputs: [] }
  const bootstrapObserver = runObserverChecks("bootstrap", hypotheses, coverageGrid, { profile, sources, evidenceBundles: workspace.getEvidenceBundles() })
  workspace.applyObserverActions(bootstrapObserver)
  hypotheses = workspace.getHypotheses()
  const reasonObserver = runObserverChecks("reason", hypotheses, coverageGrid, { profile, sources, evidenceBundles: workspace.getEvidenceBundles() })
  workspace.applyObserverActions(reasonObserver)
  hypotheses = workspace.getHypotheses()
  let obsReport = attachCoverageRescanSummary(mergeObserverReports(bootstrapObserver, reasonObserver), workspace)
  logObserverReport("final-report", obsReport, (msg) => console.log(`  [observer] ${msg}`))
  bus.emit("observer:report", { report: obsReport, trigger: "final-report" }, "observer")
  let stats = workspace.buildStats(startTime)

  addEvent("reason", "success", "Reason phase completed",
    `${stats.confirmedFindings} confirmed, ${stats.revisitHypotheses} revisit`)

  const report: AuditReport = {
    profile,
    hypotheses: workspace.getHypothesesSnapshot(),
    evidenceBundles: workspace.getEvidenceBundlesSnapshot(),
    agentArtifacts: workspace.getAgentArtifactsSnapshot(),
    findings: workspace.getFindingsSnapshot(),
    notes: workspace.getNotesSnapshot(),
    sources: workspace.getSourcesSnapshot(),
    coverageGrid,
    joern: joernInfo,
    observer: obsReport,
    events: getEvents(),
    graph: { nodes: [], edges: [] },
    generatedFiles: [],
    stats,
  }

  await runPoc?.(report)
  report.events = getEvents()
  report.agentArtifacts = workspace.getAgentArtifactsSnapshot()
  const pocObserver = runObserverChecks("reviewing", hypotheses, coverageGrid, { sources, report, pocOnly: true })
  if (pocObserver.checkpoints.length > 0) {
    logObserverReport("poc-report", pocObserver, (msg) => console.log(`  [observer] ${msg}`))
    bus.emit("observer:report", { report: pocObserver, trigger: "poc-report" }, "observer")
    obsReport = attachCoverageRescanSummary(mergeObserverReports(obsReport, pocObserver), workspace)
    report.observer = obsReport
  }
  stats = workspace.buildStats(startTime)
  report.stats = stats

  const graph = buildAuditGraph(profile, report.hypotheses, report.findings, report.notes)
  const evidenceGraph = buildEvidenceGraph(report)
  const snapshot = compressState(report.hypotheses, stats)
  report.graph = graph

  const outputDir = resolve(options.outputDir)
  await saveCheckpoint(outputDir, "reporting", workspace.checkpointState())

  // Write intermediate artifacts
  await Bun.write(resolve(outputDir, "phase0-profile.json"), JSON.stringify(profile, null, 2))
  await Bun.write(resolve(outputDir, "phase2-hypotheses.json"), JSON.stringify(report.hypotheses, null, 2))
  await Bun.write(resolve(outputDir, "phase2-evidence-bundles.json"), JSON.stringify(report.evidenceBundles, null, 2))
  await Bun.write(resolve(outputDir, "phase2-agent-artifacts.json"), JSON.stringify(report.agentArtifacts, null, 2))
  await Bun.write(resolve(outputDir, "phase2-findings.json"), JSON.stringify(report.findings, null, 2))
  await Bun.write(resolve(outputDir, "evidence-graph.json"), JSON.stringify(evidenceGraph, null, 2))
  await Bun.write(resolve(outputDir, "taint-flows.json"), JSON.stringify(evidenceGraph.taintFlows, null, 2))
  await Bun.write(resolve(outputDir, "phase3-coverage.json"), JSON.stringify({ coveragePercent: stats.coveragePercent, snapshot }, null, 2))
  await Bun.write(resolve(outputDir, "phase3-stats.json"), JSON.stringify(stats, null, 2))

  let reportPath: string | null = null
  let completeReportPath: string | null = null
  reportPath = await writeReport(report, outputDir)
  completeReportPath = await writeCompleteFindingsReport(report, outputDir)

  report.generatedFiles = [
    resolve(outputDir, "phase0-profile.json"),
    resolve(outputDir, "phase2-hypotheses.json"),
    resolve(outputDir, "phase2-evidence-bundles.json"),
    resolve(outputDir, "phase2-agent-artifacts.json"),
    resolve(outputDir, "phase2-findings.json"),
    resolve(outputDir, "evidence-graph.json"),
    resolve(outputDir, "taint-flows.json"),
    resolve(outputDir, "phase3-coverage.json"),
    resolve(outputDir, "phase3-stats.json"),
    resolve(outputDir, "audit-events.json"),
    resolve(outputDir, "audit-graph.json"),
    resolve(outputDir, "audit-summary.json"),
    ...(reportPath ? [reportPath] : []),
    ...(completeReportPath ? [completeReportPath] : []),
  ]

  await Bun.write(resolve(outputDir, "audit-summary.json"), JSON.stringify(report, null, 2))
  await Bun.write(resolve(outputDir, "audit-events.json"), JSON.stringify(report.events, null, 2))
  await Bun.write(resolve(outputDir, "audit-graph.json"), JSON.stringify(report.graph, null, 2))

  try {
    await enrichReportDetails(report, options, (msg) => console.log(`  [report-agent] ${msg}`))
    report.events = getEvents()
    report.agentArtifacts = workspace.getAgentArtifactsSnapshot()
    await Bun.write(resolve(outputDir, "phase2-evidence-bundles.json"), JSON.stringify(report.evidenceBundles, null, 2))
    reportPath = await writeReport(report, outputDir)
    completeReportPath = await writeCompleteFindingsReport(report, outputDir)
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err)
    console.log(`  [report-agent] markdown generation skipped: ${msg}`)
    addEvent("report", "warn", "ReportAgent markdown generation skipped", msg)
    submitAgentResult(bus, "report", {
      agent: "ReportAgent",
      kind: "failure",
      title: "ReportAgent Markdown 生成失败",
      content: `${msg}。结构化 JSON 和完整结果 Markdown 已先行落盘，可继续下载全部结果。`,
      artifacts: { generatedFiles: report.generatedFiles.length },
    })
    report.events = getEvents()
    report.agentArtifacts = workspace.getAgentArtifactsSnapshot()
  }

  sm.transition("terminated")
  if (reportPath) {
    submitAgentResult(bus, "report", {
      agent: "ReportAgent",
      kind: "report",
      title: "ReportAgent 提交报告结果",
      content: `我完成了中文 Markdown 审计报告，并生成了完整结果 Markdown，可用于下载全部候选和确认结果。`,
      artifacts: { markdown: reportPath, completeMarkdown: completeReportPath, generatedFiles: report.generatedFiles.length },
    })
    report.agentArtifacts = workspace.getAgentArtifactsSnapshot()
    await writeReport(report, outputDir)
    await writeCompleteFindingsReport(report, outputDir)
  } else {
    submitAgentResult(bus, "report", {
      agent: "ReportAgent",
      kind: "failure",
      title: "ReportAgent 未生成报告",
      content: "没有 AI Markdown 产物，已按要求跳过模板报告输出。",
      artifacts: { generatedFiles: report.generatedFiles.length },
    })
    report.agentArtifacts = workspace.getAgentArtifactsSnapshot()
  }
  await Bun.write(resolve(outputDir, "phase2-agent-artifacts.json"), JSON.stringify(report.agentArtifacts, null, 2))
  report.generatedFiles = buildGeneratedFiles(outputDir, reportPath, completeReportPath)
  await Bun.write(resolve(outputDir, "audit-summary.json"), JSON.stringify(report, null, 2))
  await saveCheckpoint(outputDir, "terminated", workspace.checkpointState(), { note: "audit completed" })
  bus.emit("audit:completed", { stats, generatedFiles: report.generatedFiles }, "manager")
  return report
}

function buildGeneratedFiles(outputDir: string, reportPath: string | null, completeReportPath: string | null): string[] {
  return [
    resolve(outputDir, "phase0-profile.json"),
    resolve(outputDir, "phase2-hypotheses.json"),
    resolve(outputDir, "phase2-evidence-bundles.json"),
    resolve(outputDir, "phase2-agent-artifacts.json"),
    resolve(outputDir, "phase2-findings.json"),
    resolve(outputDir, "evidence-graph.json"),
    resolve(outputDir, "taint-flows.json"),
    resolve(outputDir, "phase3-coverage.json"),
    resolve(outputDir, "phase3-stats.json"),
    resolve(outputDir, "audit-events.json"),
    resolve(outputDir, "audit-graph.json"),
    resolve(outputDir, "audit-summary.json"),
    ...(reportPath ? [reportPath] : []),
    ...(completeReportPath ? [completeReportPath] : []),
  ]
}

function mergeObserverReports(...reports: AuditReport["observer"][]): AuditReport["observer"] {
  const checkpoints = reports.flatMap((r) => r.checkpoints)
  const warnings = [...new Set(reports.flatMap((r) => r.warnings))]
  const actions = reports.flatMap((r) => r.actions ?? [])
  return { checkpoints, warnings, actions: actions.length ? actions : undefined }
}

function attachCoverageRescanSummary(report: AuditReport["observer"], workspace: AuditWorkspace): AuditReport["observer"] {
  const coverageArtifact = [...workspace.getAgentArtifactsByKind("coverage")].reverse()
    .find((artifact) => artifact.data && "unvisitedAfter" in artifact.data)
  const rescan = coverageArtifact?.data as CoverageRescanSummary | undefined
  if (!rescan) return report
  const revisitHypotheses = workspace.getHypotheses().filter((hyp) => hyp.status === "maybe_revisit").length
  const limitations = new Set(rescan.limitations)
  if (revisitHypotheses > 0) limitations.add(`${revisitHypotheses} hypothesis/hypotheses remain in maybe_revisit queue`)
  const refreshed: CoverageRescanSummary = {
    ...rescan,
    revisitHypotheses,
    limitations: [...limitations],
  }
  return {
    checkpoints: report.checkpoints,
    warnings: [...new Set([...report.warnings, ...refreshed.limitations])],
    actions: report.actions,
    rescan: refreshed,
  }
}

export function createFailReport(
  profile: ProjectProfile,
  coverageGrid: CoverageGrid,
  startTime: number,
  reason: string,
  workspace?: AuditWorkspace,
): AuditReport {
  return {
    profile,
    hypotheses: workspace?.getHypotheses() ?? [],
    evidenceBundles: workspace?.getEvidenceBundles() ?? [],
    agentArtifacts: workspace?.getAgentArtifacts() ?? [],
    findings: workspace?.getFindings() ?? [],
    notes: workspace?.getNotes() ?? [],
    sources: workspace?.getSources() ?? [],
    coverageGrid,
    joern: { ran: false, skippedReason: reason, queryOutputs: [] },
    observer: { checkpoints: [], warnings: [reason] },
    events: getEvents(),
    graph: { nodes: [], edges: [] },
    generatedFiles: [],
    stats: workspace?.buildStats(startTime) ?? fallbackStats(coverageGrid, startTime),
  }
}

function fallbackStats(coverageGrid: CoverageGrid, startTime: number): AuditStats {
  let visited = 0
  for (const [, unit] of coverageGrid.units) {
    if (unit.depth !== "unvisited") visited++
  }
  const coveragePercent = coverageGrid.totalUnits === 0
    ? 0
    : Math.round((visited / coverageGrid.totalUnits) * 100)
  return {
    totalHypotheses: 0,
    confirmedFindings: 0,
    dismissedHypotheses: 0,
    pendingHypotheses: 0,
    revisitHypotheses: 0,
    coveragePercent,
    elapsedSeconds: (Date.now() - startTime) / 1000,
  }
}
