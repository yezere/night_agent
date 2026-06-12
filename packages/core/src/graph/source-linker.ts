import { relative } from "node:path"
import type { Hypothesis, ProjectProfile, SourceEntry, SourceHypothesisLinkage, SourceLink } from "../types/index.ts"

function classNameFromFile(file: string): string {
  return file.replace(/\.(java|jsp|jspx)$/i, "").split("/").pop() ?? file
}

function modulePrefix(profile: ProjectProfile, file: string): string {
  const rel = relative(profile.root, file)
  const parts = rel.split("/")
  const javaIdx = parts.lastIndexOf("java")
  if (javaIdx !== -1) return parts.slice(0, javaIdx + 2).join("/")
  return parts.slice(0, 3).join("/")
}

function scoreSource(profile: ProjectProfile, source: SourceEntry, hyp: Hypothesis): SourceLink | null {
  const sourceClass = classNameFromFile(source.file)
  const sinkClass = classNameFromFile(hyp.sinkFile)
  const sameFile = source.file === hyp.sinkFile || hyp.sinkFile.endsWith(source.file) || source.file.endsWith(hyp.sinkFile)
  const sameClass = sourceClass.length > 0 && sinkClass.length > 0
    && (sourceClass.includes(sinkClass) || sinkClass.includes(sourceClass))
  const sameDeclaredClass = Boolean(source.className && sinkClass.length > 0
    && (source.className.includes(sinkClass) || sinkClass.includes(source.className)))
  const sameModule = modulePrefix(profile, source.file) === modulePrefix(profile, hyp.sinkFile)
  const lineDistance = sameFile ? Math.abs(source.line - hyp.sinkLine) : Number.MAX_SAFE_INTEGER

  if (sameFile) {
    const sourceBeforeSink = source.line <= hyp.sinkLine
    const likelySameMethod = sourceBeforeSink && lineDistance <= 80
    const base = lineDistance <= 80 ? 100 : lineDistance <= 220 ? 90 : 80
    const sourceBias = sourceBeforeSink ? 8 : -12
    const methodBias = likelySameMethod ? 18 : 0
    const score = base + sourceBias + methodBias
    const reason = likelySameMethod
      ? `same-file likely-same-method distance=${lineDistance}`
      : `same-file distance=${lineDistance}${sourceBeforeSink ? " before-sink" : " after-sink"}`
    return { source, score, reason }
  }
  if (sameClass || sameDeclaredClass) {
    return { source, score: sameDeclaredClass ? 76 : 70, reason: `same-class ${source.className ?? sourceClass}/${sinkClass}` }
  }
  if (sameModule) {
    const webEntry = /_jspservice|doget|dopost|doput|dodelete|dopatch|service/i.test(source.methodName)
      || /\.(jsp|jspx)$/i.test(source.file)
      || /servlet|filter|listener/i.test(`${source.file} ${source.className ?? ""}`)
    return { source, score: webEntry ? 58 : 45, reason: `same-module ${modulePrefix(profile, source.file)}${webEntry ? " web-entry" : ""}` }
  }
  return null
}

function sourceKindRank(kind: SourceEntry["kind"]): number {
  if (kind === "param" || kind === "pathvar" || kind === "body" || kind === "input-stream") return 4
  if (kind === "request-attr") return 3
  if (kind === "cookie") return 2
  if (kind === "header") return 1
  return 0
}

export function linkSourcesToHypotheses(profile: ProjectProfile, sources: SourceEntry[], hypotheses: Hypothesis[]): SourceHypothesisLinkage[] {
  const results: SourceHypothesisLinkage[] = []
  for (const hyp of hypotheses) {
    const links = sources
      .map((source) => scoreSource(profile, source, hyp))
      .filter((link): link is SourceLink => link != null)
      .sort((a, b) => b.score - a.score
        || sourceKindRank(b.source.kind) - sourceKindRank(a.source.kind)
        || sourceDirectionRank(b.source, hyp) - sourceDirectionRank(a.source, hyp)
        || Math.abs(a.source.line - hyp.sinkLine) - Math.abs(b.source.line - hyp.sinkLine))
      .slice(0, 5)

    const sinkRoute = profile.routes
      .filter((candidate) => {
        const routeFile = `${profile.root}/${candidate.sourceFile}`.replace(/\/+/g, "/")
        return hyp.sinkFile === routeFile || hyp.sinkFile.endsWith(candidate.sourceFile)
      })
      .sort((a, b) => Math.abs(a.line - hyp.sinkLine) - Math.abs(b.line - hyp.sinkLine))[0]
    const sourceRoute = !sinkRoute && links[0]?.source
      ? profile.routes
        .filter((candidate) => {
          const source = links[0]!.source
          const routeFile = `${profile.root}/${candidate.sourceFile}`.replace(/\/+/g, "/")
          return source.file === routeFile || source.file.endsWith(candidate.sourceFile)
        })
        .sort((a, b) => Math.abs(a.line - links[0]!.source.line) - Math.abs(b.line - links[0]!.source.line))[0]
      : undefined
    const route = sinkRoute ?? sourceRoute
    results.push({ hypothesisId: hyp.id, sourceLinks: links, route })
  }
  return results
}

function sourceDirectionRank(source: SourceEntry, hyp: Hypothesis): number {
  if (source.file !== hyp.sinkFile) return 0
  return source.line <= hyp.sinkLine ? 1 : -1
}
