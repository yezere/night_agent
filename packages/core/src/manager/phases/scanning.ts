import { resolve } from "node:path"
import { relative } from "node:path"
import { SinkAgent } from "../../solver/solver-sink.ts"
import { SolverReader } from "../../solver/solver-reader.ts"
import { generateCpg } from "../../tracer/joern-runner.ts"
import { addEvent } from "../../runtime/event-log.ts"
import { submitAgentResult } from "../../runtime/agent-submission.ts"
import { linkSourcesToHypotheses } from "../../graph/source-linker.ts"
import { registerFile, markScanned } from "../../context/coverage-grid.ts"
import { runObserverChecks } from "../../observer/supervisor.ts"
import { StateMachine } from "../../runtime/state-machine.ts"
import { AuditWorkspace } from "../../runtime/audit-workspace.ts"
import type { EventBus } from "../../runtime/event-bus.ts"
import type { AuditOptions, ProjectProfile, CoverageGrid, SourceEntry } from "../../types/index.ts"
import { isHighRiskDep } from "../../types/index.ts"

function moduleNameFromPath(targetRoot: string, file: string): string {
  const rel = relative(targetRoot, file)
  const parts = rel.split("/")
  const srcIndex = parts.findIndex((p: string) => p === "main" || p === "src")
  if (srcIndex === -1) return parts[0] ?? "root"
  const after = parts.slice(srcIndex + 1).filter((p: string) => p !== "java")
  return after.slice(0, -1).join(".") || "root"
}

export interface CpgResult {
  cpgPath: string
  ok: boolean
  skippedReason?: string
}

export interface ScanningResult {
  sources: SourceEntry[]
  cpg: CpgResult
}

export async function runCpgAgentPhase(
  bus: EventBus,
  options: AuditOptions,
  profile: ProjectProfile,
  log: (msg: string) => void,
): Promise<CpgResult> {
  if (options.runJoern === false) {
    const result = { cpgPath: "", ok: false, skippedReason: "--no-joern" }
    submitAgentResult(bus, "cpg", {
      agent: "CpgAgent",
      kind: "cpg",
      title: "CpgAgent 跳过 CPG 生成",
      content: "当前运行关闭了 Joern，CPG 生成已跳过。",
      artifacts: result,
    })
    return result
  }

  try {
    const result = await generateCpg(profile, resolve(options.outputDir))
    submitAgentResult(bus, "cpg", {
      agent: "CpgAgent",
      kind: "cpg",
      title: "CpgAgent 提交 CPG 结果",
      content: result.ok
        ? `CPG 已生成：${result.cpgPath}。TracerAgent 和 JoernQueryAgent 可继续读取。`
        : `CPG 未生成：${result.skippedReason ?? "未知原因"}。`,
      artifacts: result,
    })
    return result
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err)
    log(`CPG generation error: ${msg}`)
    addEvent("explore", "error", "CPG generation failed", msg)
    const result = { cpgPath: "", ok: false, skippedReason: msg }
    submitAgentResult(bus, "cpg", {
      agent: "CpgAgent",
      kind: "failure",
      title: "CpgAgent 生成失败",
      content: msg,
      artifacts: result,
    })
    return result
  }
}

/**
 * Run parallel scanning phase: CPG generation + SourceAgent + SinkAgent.
 * These are independent and run concurrently.
 */
export async function runScanning(
  sm: StateMachine,
  bus: EventBus,
  options: AuditOptions,
  profile: ProjectProfile,
  workspace: AuditWorkspace,
  log: (msg: string) => void,
): Promise<ScanningResult> {
  sm.transition("scanning")
  bus.emit("state:enter", { state: "scanning", from: "profiling" }, "manager")
  log("parallel phase: CPG generation + SourceAgent + SinkAgent")
  bus.emit("task:started", { task: "parallel-scan", agents: ["SourceAgent", "SinkAgent"], joern: options.runJoern !== false }, "manager")
  addEvent("bootstrap", "info", "Parallel phase started", "CPG + SourceAgent + SinkAgent")

  const cpgTask: Promise<CpgResult> = runCpgAgentPhase(bus, options, profile, log)

  const [sources, , cpgResult] = await Promise.all([
    runSourceAgentPhase(bus, options, profile, log),
    runSinkAgentPhase(bus, options, profile, workspace, log),
    cpgTask,
  ])
  const hypotheses = workspace.getHypotheses()
  log(`parallel phase complete: SourceAgent=${sources.length} source(s), SinkAgent=${hypotheses.length} sink hypothesis/hypotheses, CPG=${cpgResult.ok ? "ready" : "unavailable"}`)
  bus.emit("task:completed", {
    task: "parallel-scan",
    sources: sources.length,
    sinkHypotheses: hypotheses.length,
    cpg: cpgResult.ok ? "ready" : "unavailable",
    cpgPath: cpgResult.ok ? cpgResult.cpgPath : undefined,
    skippedReason: cpgResult.skippedReason,
  }, "manager")

  bus.emit("state:leave", { state: "scanning" }, "manager")

  if (cpgResult.ok) {
    log(`CPG ready at ${cpgResult.cpgPath}`)
  } else {
    log(`CPG unavailable: ${cpgResult.skippedReason} — tracing will attempt on-demand generation`)
  }

  return { sources, cpg: cpgResult }
}

export async function runSinkAgentPhase(
  bus: EventBus,
  options: AuditOptions,
  profile: ProjectProfile,
  workspace: AuditWorkspace,
  log: (msg: string) => void,
  focusFiles: string[] = [],
): Promise<void> {
  const ctx = {
    identity: { id: "sink", role: "solver" as const, status: "idle" as const },
    bus,
    getState: () => ({ currentState: "scanning" as const, profile: null, sources: [], stats: {} as any, iteration: 0, termination: {} as any, agentStatuses: {} }),
    log: (msg: string) => log(`[sink] ${msg}`),
  }
  const sinkAgent = new SinkAgent(ctx, options, profile, workspace, focusFiles)
  bus.emit("task:started", { task: "SinkAgent", ruleLanguage: profile.language }, "sink")
  await sinkAgent.start()
  const hypotheses = workspace.getHypotheses()
  const byCategory = hypotheses.reduce<Record<string, number>>((acc, hyp) => {
    acc[hyp.category] = (acc[hyp.category] ?? 0) + 1
    return acc
  }, {})
  log(`[sink] completed with ${hypotheses.length} active sink hypothesis/hypotheses (${Object.entries(byCategory).map(([k, v]) => `${k}:${v}`).join(", ") || "none"})`)
  bus.emit("task:completed", { task: "SinkAgent", hypotheses: hypotheses.length, byCategory }, "sink")
  submitAgentResult(bus, "sink", {
    agent: "SinkAgent",
    kind: "sink",
    title: "SinkAgent 提交危险点扫描结果",
    content: hypotheses.length > 0
      ? `我完成了危险调用扫描，提交 ${hypotheses.length} 个候选 Sink。主要类别：${Object.entries(byCategory).map(([k, v]) => `${k} ${v} 个`).join("、") || "未分类"}。后续可以由追踪和报告 agent 自行选择重点链路。`
      : "我完成了危险调用扫描，没有提交候选 Sink。",
    artifacts: { hypotheses: hypotheses.length, byCategory },
  })
}

export async function runSourceAgentPhase(
  bus: EventBus,
  options: AuditOptions,
  profile: ProjectProfile,
  log: (msg: string) => void,
  focusFiles: string[] = [],
): Promise<SourceEntry[]> {
  const ctx = {
    identity: { id: "source", role: "solver" as const, status: "idle" as const },
    bus,
    getState: () => ({ currentState: "scanning" as const, profile: null, sources: [], stats: {} as any, iteration: 0, termination: {} as any, agentStatuses: {} }),
    log: (msg: string) => log(`[source] ${msg}`),
  }
  const reader = new SolverReader(ctx, options.target, profile, options, focusFiles)

  const sources: SourceEntry[] = []
  const unsub = bus.subscribe("source:extracted", (event) => {
    sources.push(event.payload as SourceEntry)
  })

  bus.emit("task:started", { task: "SourceAgent", target: options.target }, "source")
  await reader.start()
  unsub()
  const byKind = sources.reduce<Record<string, number>>((acc, source) => {
    acc[source.kind] = (acc[source.kind] ?? 0) + 1
    return acc
  }, {})
  log(`[source] completed with ${sources.length} source(s) (${Object.entries(byKind).map(([k, v]) => `${k}:${v}`).join(", ") || "none"})`)
  bus.emit("task:completed", { task: "SourceAgent", sources: sources.length, byKind }, "source")
  submitAgentResult(bus, "source", {
    agent: "SourceAgent",
    kind: "source",
    title: "SourceAgent 提交输入源提取结果",
    content: sources.length > 0
      ? `我完成了输入源提取，提交 ${sources.length} 个外部可控入口。类型分布：${Object.entries(byKind).map(([k, v]) => `${k} ${v} 个`).join("、") || "未分类"}。`
      : "我完成了输入源提取，没有识别到外部可控入口。",
    artifacts: { sources: sources.length, byKind },
  })
  return sources
}

/** Post-scan: register coverage + dependency hints + observer dedup. */
export function postScanProcessing(
  profile: ProjectProfile,
  coverageGrid: CoverageGrid,
  sources: SourceEntry[] = [],
  workspace: AuditWorkspace,
  bus?: EventBus,
): { warnings: string[] } {
  const hyps = workspace.getHypotheses()
  const linkages = linkSourcesToHypotheses(profile, sources, hyps)
  workspace.linkSourcesToHypotheses(linkages)
  const bundled = hyps.filter((h) => h.evidenceBundleId).length
  const linked = hyps.filter((h) => (h.sourceLinks?.length ?? 0) > 0).length
  const strong = hyps.filter((h) => (h.sourceLinks?.[0]?.score ?? 0) >= 70).length
  addEvent("bootstrap", "info", "EvidenceBundle handoff created", `${bundled} bundle(s), ${linked} linked, ${strong} strong`)
  bus?.emit("task:completed", { task: "EvidenceBundler", bundles: bundled, linked, strong }, "observer")
  if (bus) {
    submitAgentResult(bus, "observer", {
      agent: "EvidenceBundler",
      kind: "handoff",
      title: "EvidenceBundler 提交 Source/Sink 交接结果",
      content: `我把 SourceAgent 和 SinkAgent 的产物合并成 ${bundled} 个交接包，其中 ${linked} 个带输入源关联，${strong} 个为强关联。后续 Tracer/Judge/ReportAgent 可以直接读取这些交接包，也可以按模型判断重新组织证据。`,
      artifacts: { bundles: bundled, linked, strong },
    })
  }

  for (const h of hyps) {
    const absFile = resolve(profile.root, h.sinkFile)
    if (!coverageGrid.units.has(absFile)) {
      const mod = [moduleNameFromPath(profile.root, h.sinkFile)]
      registerFile(coverageGrid, absFile, mod)
    }
    const unit = coverageGrid.units.get(absFile)
    if (unit) {
      unit.hypothesisCount++
      markScanned(coverageGrid, absFile)
    }
  }

  // Dependency hints
  for (const dep of profile.dependencies) {
    if (isHighRiskDep(dep.name)) {
      workspace.addNote(
        `danger dep: ${dep.name} ${dep.version ?? "?"} (${dep.sourceFile}) — suggest N-Day search`,
        "dependency-fingerprint",
        hyps.map((h) => h.id),
      )
    }
  }

  // Observer: dedup
  const obsReport = runObserverChecks("bootstrap", hyps, coverageGrid, { profile, sources, evidenceBundles: workspace.getEvidenceBundles() })
  const applied = workspace.applyObserverActions(obsReport)
  if (applied.applied > 0) console.log(`  [observer] applied ${applied.applied} post-scan action(s)`)
  logObserverReport("post-scan", obsReport, (msg) => console.log(`  [observer] ${msg}`))
  bus?.emit("observer:report", { report: obsReport, trigger: "post-scan" }, "observer")
  return obsReport
}

export function logObserverReport(trigger: string, report: { checkpoints: Array<{ phase: string; check: string; passed: boolean; detail: string }>; warnings: string[] }, log: (msg: string) => void): void {
  log(`${trigger}: ${report.checkpoints.length} checkpoint(s), ${report.warnings.length} warning(s)`)
  for (const checkpoint of report.checkpoints) {
    log(`${checkpoint.passed ? "PASS" : "WARN"} ${checkpoint.phase}/${checkpoint.check}: ${checkpoint.detail}`)
  }
  for (const warning of report.warnings) {
    log(`warning: ${warning}`)
  }
}
