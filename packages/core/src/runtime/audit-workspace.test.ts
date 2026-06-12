import { afterEach, expect, test } from "bun:test"
import { mkdtemp, rm } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { linkSourcesToHypotheses } from "../graph/source-linker.ts"
import { enforceGraphStoreScope } from "../graph/store-scope.ts"
import { buildEvidenceGraph } from "../graph/evidence-graph.ts"
import { addEvent, getEvents } from "./event-log.ts"
import { restoreCheckpoint, saveCheckpoint } from "./checkpoint-store.ts"
import { AuditWorkspace } from "./audit-workspace.ts"
import type {
  AuditOptions,
  CoverageGrid,
  Finding,
  Hypothesis,
  ProjectProfile,
  SourceEntry,
  VerifierVerdict,
} from "../types/index.ts"

afterEach(() => {
  enforceGraphStoreScope(false)
})

test("AuditWorkspace keeps graph state isolated per run scope", () => {
  const first = workspace("one")
  const second = workspace("two")

  first.runInScope(() => {
    first.reset()
    first.addHypothesis(hypothesisInput("A.java", 10))
  })
  second.runInScope(() => {
    second.reset()
    second.addHypothesis(hypothesisInput("B.java", 20))
  })

  expect(first.runInScope(() => first.getHypotheses().map((hyp) => hyp.sinkFile))).toEqual(["A.java"])
  expect(second.runInScope(() => second.getHypotheses().map((hyp) => hyp.sinkFile))).toEqual(["B.java"])
})

test("checkpoint restore hydrates workspace snapshot without direct store writes", async () => {
  const dir = await mkdtemp(join(tmpdir(), "night-agent-checkpoint-"))
  try {
    const source = sourceEntry("src/main/java/app/A.java", 8)
    const original = workspace("checkpoint", dir)
    original.runInScope(() => {
      original.reset()
      original.setProfile(profile())
      original.setCoverageGrid(coverageGrid("src/main/java/app/A.java"))
      original.setSources([source])
      original.addHypothesis(hypothesisInput("src/main/java/app/A.java", 30))
      addEvent("bootstrap", "info", "saved")
    })

    await original.runInScope(() => saveCheckpoint(dir, "scanning", original.checkpointState()))
    const loaded = await restoreCheckpoint(dir)
    expect(loaded).not.toBeNull()

    const restored = workspace("restored", dir)
    restored.runInScope(() => {
      restored.reset()
      restored.restoreSnapshot(loaded!.snapshot)
    })

    expect(restored.runInScope(() => restored.getProfile()?.name)).toBe("demo")
    expect(restored.runInScope(() => restored.getSources())).toHaveLength(1)
    expect(restored.runInScope(() => restored.hypothesisCount())).toBe(1)
    expect(restored.runInScope(() => getEvents().map((event) => event.title))).toEqual(["saved"])
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test("workspace owns source linkage, verification state, and observer actions", () => {
  const ws = workspace("state")
  const src = sourceEntry("src/main/java/app/A.java", 8)
  const verdict: VerifierVerdict = {
    status: "confirmed",
    confidence: "high",
    reason: "source reaches sink",
    evidence: ["A.java:30"],
    checkedFiles: ["A.java"],
    toolCalls: ["read_file A.java"],
    createdAt: Date.now(),
  }

  ws.runInScope(() => {
    ws.reset()
    ws.setProfile(profile())
    ws.setSources([src])
    const hyp = ws.addHypothesis(hypothesisInput("src/main/java/app/A.java", 30))

    const linkages = linkSourcesToHypotheses(profile(), [src], [hyp])
    const bundles = ws.linkSourcesToHypotheses(linkages)
    expect(bundles).toHaveLength(1)
    expect(ws.getEvidenceBundle(hyp.id)?.selectedSource?.id).toBe(src.id)

    ws.markTraceStarted(hyp.id)
    expect(ws.getHypothesis(hyp.id)?.evidenceState?.trace).toBe("running")
    expect(ws.getHypothesis(hyp.id)?.status).toBe("tracing")

    ws.recordVerifierVerdict(hyp.id, verdict)
    expect(ws.getHypothesis(hyp.id)?.evidenceState?.verification).toBe("confirmed")
    expect(ws.getHypothesis(hyp.id)?.status).toBe("pending")

    ws.applyObserverActions({
      checkpoints: [],
      warnings: [],
      actions: [{ kind: "record-source-linkage-verdict", hypothesisId: hyp.id, passed: false, reason: "weak source match" }],
    })
    expect(ws.getEvidenceBundle(hyp.id)?.observerVerdict?.passed).toBe(false)

    ws.applyObserverActions({
      checkpoints: [],
      warnings: [],
      actions: [{ kind: "dismiss-duplicate-hypothesis", hypothesisId: hyp.id, primaryHypothesisId: "hyp-primary", reason: "duplicate" }],
    })
    expect(ws.getHypothesis(hyp.id)?.status).toBe("dismissed")
    expect(ws.getHypothesis(hyp.id)?.evidenceState?.finding).toBe("duplicate")
  })
})

test("EvidenceGraph links findings by explicit hypothesisId before sink location fallback", () => {
  const first = hypothesis("hyp-one", "src/main/java/app/A.java", 40)
  const second = hypothesis("hyp-two", "src/main/java/app/A.java", 40)
  const finding: Finding = {
    id: "finding-two",
    hypothesisId: second.id,
    title: "SQLI via Statement.execute",
    severity: "high",
    category: "sqli",
    source: { kind: "param", file: "src/main/java/app/A.java", line: 8, snippet: "name" },
    sink: { kind: "Statement.execute", file: "src/main/java/app/A.java", line: 40, snippet: "stmt.execute(sql)" },
    evidenceChain: [],
    status: "confirmed",
    confidence: "high",
    createdAt: Date.now(),
  }

  const graph = buildEvidenceGraph({
    profile: profile(),
    hypotheses: [first, second],
    evidenceBundles: [],
    findings: [finding],
    sources: [],
  })

  expect(graph.edges.some((edge) =>
    edge.kind === "confirmed-as"
    && edge.from === `hyp:${second.id}`
    && edge.to === `finding:${finding.id}`
  )).toBe(true)
  expect(graph.edges.some((edge) =>
    edge.kind === "confirmed-as"
    && edge.from === `hyp:${first.id}`
    && edge.to === `finding:${finding.id}`
  )).toBe(false)
})

function workspace(name: string, outputDir = join(tmpdir(), `night-agent-${name}`)): AuditWorkspace {
  const options: AuditOptions = { target: "/repo/demo", outputDir, projectName: name }
  return new AuditWorkspace(options, `run-${name}`)
}

function profile(): ProjectProfile {
  return {
    name: "demo",
    root: "/repo/demo",
    language: "java",
    buildFiles: [],
    directories: [],
    fileStats: [],
    dependencies: [],
    routes: [{ method: "GET", path: "/a", sourceFile: "src/main/java/app/A.java", line: 8 }],
    securityMechanisms: [],
    dataFlowSummary: [],
    highRiskFiles: [],
  }
}

function coverageGrid(file: string): CoverageGrid {
  return {
    totalUnits: 1,
    units: new Map([[file, { file, depth: "scanned", hypothesisCount: 1, confirmedCount: 0 }]]),
    byModule: new Map([["app", { total: 1, unvisited: 0, scanned: 1, traced: 0, verified: 0 }]]),
  }
}

function sourceEntry(file: string, line: number): SourceEntry {
  return {
    id: `src-${line}`,
    kind: "param",
    paramName: "name",
    file,
    line,
    code: "String name = request.getParameter(\"name\")",
    methodName: "doGet",
    className: "A",
    origin: "pre-scan",
  }
}

function hypothesisInput(file: string, line: number): Parameters<AuditWorkspace["addHypothesis"]>[0] {
  return {
    description: "user input reaches sink",
    severity: "high",
    category: "sqli",
    sinkFile: file,
    sinkLine: line,
    sinkPattern: "Statement.execute",
    sinkCode: "stmt.execute(sql)",
    origin: "pre-scan",
  }
}

function hypothesis(id: string, file: string, line: number): Hypothesis {
  const now = Date.now()
  return {
    ...hypothesisInput(file, line),
    id,
    status: "pending",
    evidenceState: {
      trace: "not_started",
      verification: "not_started",
      finding: "not_started",
      updatedAt: now,
    },
    createdAt: now,
    updatedAt: now,
  }
}
