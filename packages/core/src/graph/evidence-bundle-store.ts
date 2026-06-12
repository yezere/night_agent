import type { DataflowTrace, EvidenceBundle, Hypothesis, RouteEntry, SourceEntry, SourceLink, VerifierVerdict } from "../types/index.ts"
import { graphStoreScopeOrDefault } from "./store-scope.ts"

const defaultBundles = new Map<string, EvidenceBundle>()

function bundles(): Map<string, EvidenceBundle> {
  return graphStoreScopeOrDefault("evidence-bundle-store")?.evidenceBundles.bundles ?? defaultBundles
}

function bundleId(hypothesisId: string): string {
  return `bundle-${hypothesisId.replace(/^hyp-/, "")}`
}

export function upsertFromHypothesis(
  hyp: Hypothesis,
  sourceLinks: SourceLink[],
  route?: RouteEntry,
): EvidenceBundle {
  const id = hyp.evidenceBundleId ?? bundleId(hyp.id)
  const now = Date.now()
  const selectedSource = sourceLinks[0]?.source
  const store = bundles()
  const existing = store.get(id)
  const bundle: EvidenceBundle = {
    id,
    hypothesisId: hyp.id,
    sourceLinks,
    selectedSource,
    sink: {
      kind: hyp.sinkPattern,
      file: hyp.sinkFile,
      line: hyp.sinkLine,
      snippet: hyp.sinkCode,
    },
    route: route ?? existing?.route,
    dataflow: existing?.dataflow,
    observerVerdict: existing?.observerVerdict,
    verifierVerdict: existing?.verifierVerdict,
    createdAt: existing?.createdAt ?? now,
    updatedAt: now,
  }
  hyp.evidenceBundleId = id
  hyp.sourceLinks = sourceLinks
  hyp.sourceHint = selectedSource
  store.set(id, bundle)
  return bundle
}

export function updateDataflow(hypothesisId: string, dataflow: DataflowTrace): void {
  const bundle = getByHypothesisId(hypothesisId)
  if (!bundle) return
  bundle.dataflow = dataflow
  bundle.updatedAt = Date.now()
}

export function updateObserverVerdict(hypothesisId: string, passed: boolean, reason: string): void {
  const bundle = getByHypothesisId(hypothesisId)
  if (!bundle) return
  bundle.observerVerdict = { passed, reason, checkedAt: Date.now() }
  bundle.updatedAt = Date.now()
}

export function updateVerifierVerdict(hypothesisId: string, verdict: VerifierVerdict): void {
  const bundle = getByHypothesisId(hypothesisId)
  if (!bundle) return
  bundle.verifierVerdict = verdict
  bundle.updatedAt = Date.now()
}

export function updateSelectedSource(hypothesisId: string, source: SourceEntry): void {
  const bundle = getByHypothesisId(hypothesisId)
  if (!bundle) return
  bundle.selectedSource = source
  const selectedIndex = bundle.sourceLinks.findIndex((link) =>
    link.source.id === source.id
      || (link.source.file === source.file && link.source.line === source.line && link.source.paramName === source.paramName)
  )
  if (selectedIndex > 0) {
    const [selected] = bundle.sourceLinks.splice(selectedIndex, 1)
    if (selected) bundle.sourceLinks.unshift(selected)
  }
  bundle.updatedAt = Date.now()
}

export function getByHypothesisId(hypothesisId: string): EvidenceBundle | undefined {
  return [...bundles().values()].find((bundle) => bundle.hypothesisId === hypothesisId)
}

export function selectedSourceFor(hypothesisId: string): SourceEntry | undefined {
  return getByHypothesisId(hypothesisId)?.selectedSource
}

export function getAll(): EvidenceBundle[] {
  return [...bundles().values()]
}

export function clear(): void {
  bundles().clear()
}

export function restore(items: EvidenceBundle[]): void {
  const store = bundles()
  store.clear()
  for (const item of items) {
    const { reportContext: _reportContext, ...coreBundle } = item
    store.set(coreBundle.id, coreBundle)
  }
}
