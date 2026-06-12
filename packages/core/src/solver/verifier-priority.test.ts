import { expect, test } from "bun:test"
import { buildVerifierPriorityPlan, defaultVerifierMaxSelected } from "./verifier-priority.ts"
import type { EvidenceBundle, Hypothesis, ProjectProfile, SourceEntry, SourceLink } from "../types/index.ts"

test("verifier priority defers duplicate evidence identities to representative review", () => {
  const src = source("src-1", "name")
  const link: SourceLink = { source: src, score: 90, reason: "same route source" }
  const candidates = [
    hypothesis("hyp-3", { sourceLinks: [link] }),
    hypothesis("hyp-1", { sourceLinks: [link] }),
    hypothesis("hyp-2", { sourceLinks: [link] }),
  ]

  const plan = buildVerifierPriorityPlan({
    profile: profile(),
    candidates,
    sources: [src],
    evidenceBundles: [],
    maxSelected: 10,
    duplicateRepresentatives: 1,
  })

  expect(plan.duplicateGroups).toBe(1)
  expect(plan.selected.map((item) => item.hypothesis.id)).toEqual(["hyp-1"])
  expect(plan.deferred.map((item) => item.hypothesis.id).sort()).toEqual(["hyp-2", "hyp-3"])
  expect(plan.deferred.every((item) => item.deferredReason?.includes("deferred duplicate candidate"))).toBe(true)
})

test("verifier priority budget keeps high-evidence candidate before low-signal candidate", () => {
  const src = source("src-1", "query")
  const high = hypothesis("hyp-high", {
    category: "sqli",
    severity: "critical",
    origin: "joern-ai",
    sourceLinks: [{ source: src, score: 95, reason: "strong source handoff" }],
  })
  const low = hypothesis("hyp-low", {
    category: "xss",
    severity: "low",
    origin: "pre-scan",
    sinkFile: "/repo/demo/src/main/java/app/View.java",
    sinkLine: 90,
    sinkPattern: "response.getWriter",
    sinkCode: "",
  })

  const plan = buildVerifierPriorityPlan({
    profile: profile(),
    candidates: [low, high],
    sources: [src],
    evidenceBundles: [],
    maxSelected: 1,
  })

  expect(plan.selected.map((item) => item.hypothesis.id)).toEqual(["hyp-high"])
  expect(plan.deferred.map((item) => item.hypothesis.id)).toEqual(["hyp-low"])
  expect(plan.deferred[0]?.deferredReason).toContain("priority budget")
})

test("verifier priority defers intermediate-flow sink when downstream flow covers it", () => {
  const src = source("src-flow", "body")
  const link: SourceLink = { source: src, score: 95, reason: "same route source" }
  const intermediate = hypothesis("hyp-middle", {
    severity: "high",
    sinkFile: "/repo/demo/src/main/java/app/TransformService.java",
    sinkLine: 20,
    sinkPattern: "intermediate call",
    sinkCode: "transform(value)",
    sourceLinks: [link],
  })
  const downstream = hypothesis("hyp-final", {
    severity: "critical",
    sinkFile: "/repo/demo/src/main/java/app/DangerousSink.java",
    sinkLine: 40,
    sinkPattern: "Statement.execute",
    sinkCode: "stmt.execute(sql)",
    sourceLinks: [link],
  })

  const plan = buildVerifierPriorityPlan({
    profile: profile(),
    candidates: [intermediate, downstream],
    sources: [src],
    evidenceBundles: [
      evidenceBundle(intermediate, [link]),
      evidenceBundle(downstream, [link], {
        reachable: true,
        confidence: "high",
        sanitizers: [],
        paths: [{
          sourceLabel: "HTTP Entry",
          sinkLabel: "Statement.execute",
          edges: [
            { kind: "source", file: src.file, line: src.line, code: src.code },
            { kind: "propagation", file: intermediate.sinkFile, line: intermediate.sinkLine, code: intermediate.sinkCode },
            { kind: "sink", file: downstream.sinkFile, line: downstream.sinkLine, code: downstream.sinkCode },
          ],
        }],
      }),
    ],
    maxSelected: 10,
  })

  expect(plan.selected.map((item) => item.hypothesis.id)).toEqual(["hyp-final"])
  expect(plan.deferred.map((item) => item.hypothesis.id)).toEqual(["hyp-middle"])
  expect(plan.deferred[0]?.representativeId).toBe("hyp-final")
  expect(plan.deferred[0]?.deferredReason).toContain("intermediate-flow")
})

test("default verifier budget trims large queues but leaves small queues intact", () => {
  expect(defaultVerifierMaxSelected(40)).toBe(40)
  expect(defaultVerifierMaxSelected(161)).toBe(97)
})

function profile(): ProjectProfile {
  return {
    name: "demo",
    root: "/repo/demo",
    language: "java",
    buildFiles: [],
    directories: [],
    fileStats: [],
    dependencies: [],
    routes: [{ method: "POST", path: "/dataSet/testTransform", sourceFile: "src/main/java/app/DataSetController.java", line: 30 }],
    securityMechanisms: [],
    dataFlowSummary: [],
    highRiskFiles: [],
  }
}

function evidenceBundle(
  hyp: Hypothesis,
  links: SourceLink[],
  dataflow?: EvidenceBundle["dataflow"],
): EvidenceBundle {
  return {
    id: `bundle-${hyp.id}`,
    hypothesisId: hyp.id,
    sourceLinks: links,
    selectedSource: links[0]?.source,
    sink: {
      kind: hyp.sinkPattern,
      file: hyp.sinkFile,
      line: hyp.sinkLine,
      snippet: hyp.sinkCode,
    },
    dataflow,
    createdAt: 1,
    updatedAt: 1,
  }
}

function source(id: string, paramName: string): SourceEntry {
  return {
    id,
    kind: "body",
    paramName,
    file: "/repo/demo/src/main/java/app/DataSetController.java",
    line: 35,
    code: "param.getDataSetTransformDtoList()",
    methodName: "testTransform",
    className: "DataSetController",
    origin: "ai-first",
  }
}

function hypothesis(id: string, overrides: Partial<Hypothesis> = {}): Hypothesis {
  return {
    id,
    description: "user script reaches dynamic execution",
    severity: "critical",
    category: "ssti",
    sinkFile: "/repo/demo/src/main/java/app/GroovyTransformServiceImpl.java",
    sinkLine: 46,
    sinkPattern: "GroovyClassLoader.parseClass",
    sinkCode: "groovyClassLoader.parseClass(transformScript)",
    status: "pending",
    createdAt: 1,
    updatedAt: 1,
    origin: "ai-first",
    ...overrides,
  }
}
