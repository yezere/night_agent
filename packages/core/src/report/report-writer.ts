import { isAbsolute, resolve } from "node:path"
import { readFileSync } from "node:fs"
import type {
  AuditReport,
  DataflowEdge,
  EvidenceBundle,
  Hypothesis,
  SourceLink,
  ProjectProfile,
  RouteEntry,
  SourceEntry,
} from "../types/index.ts"
import { compareSeverity } from "../types/index.ts"
import { evidenceDecisionForReport, evidenceDecisionText } from "../graph/evidence-decision.ts"

export function relativeFile(profile: ProjectProfile, file: string): string {
  return file.startsWith(profile.root) ? file.slice(profile.root.length).replace(/^\/+/, "") : file
}

function projectFile(profile: ProjectProfile, file: string): string {
  if (isAbsolute(file)) return file
  return resolve(profile.root, file)
}

export function readCodeContext(file: string, line: number, radius: number = 3): string {
  try {
    const lines = readFileSync(file, "utf-8").split("\n")
    const start = Math.max(1, line - radius)
    const end = Math.min(lines.length, line + radius)
    const width = String(end).length
    const out: string[] = []
    for (let current = start; current <= end; current++) {
      const marker = current === line ? ">>" : "  "
      out.push(`${marker} ${String(current).padStart(width, " ")} | ${lines[current - 1] ?? ""}`)
    }
    return out.join("\n")
  } catch {
    return `>> ${line} | 代码读取失败：${file}`
  }
}

function classNameFromFile(file: string): string {
  return file.replace(/\.java$/, "").split("/").pop() ?? file
}

function routeMatchesFile(route: RouteEntry, profile: ProjectProfile, file: string): boolean {
  const routeFile = resolve(profile.root, route.sourceFile)
  return routeFile === file || file.endsWith(route.sourceFile)
}

export function nearestRoute(profile: ProjectProfile, hyp: Hypothesis, evidenceBundles: EvidenceBundle[] = []): RouteEntry | undefined {
  const bundleRoute = evidenceBundles.find((bundle) => bundle.hypothesisId === hyp.id || bundle.id === hyp.evidenceBundleId)?.route
  if (bundleRoute) return bundleRoute
  const routes = profile.routes.filter((route) => routeMatchesFile(route, profile, hyp.sinkFile))
  if (routes.length === 0) return undefined
  return routes.sort((a, b) => Math.abs(a.line - hyp.sinkLine) - Math.abs(b.line - hyp.sinkLine))[0]
}

export function relatedSources(report: AuditReport, hyp: Hypothesis): SourceEntry[] {
  const bundle = bundleFor(report, hyp)
  const decisionSource = evidenceDecisionForReport(report, hyp).source
  const bundleSources = bundle?.sourceLinks.map((link) => link.source) ?? hyp.sourceLinks?.map((link) => link.source)
  if (decisionSource && bundleSources?.length) {
    return [
      decisionSource,
      ...bundleSources.filter((source) =>
        source.id !== decisionSource.id
          && !(source.file === decisionSource.file && source.line === decisionSource.line && source.paramName === decisionSource.paramName)
      ),
    ]
  }
  if (decisionSource) return [decisionSource]
  if (bundle?.selectedSource && bundleSources?.length) {
    return [
      bundle.selectedSource,
      ...bundleSources.filter((source) =>
        source.id !== bundle.selectedSource?.id
          && !(source.file === bundle.selectedSource?.file && source.line === bundle.selectedSource?.line && source.paramName === bundle.selectedSource?.paramName)
      ),
    ]
  }
  if (bundleSources && bundleSources.length > 0) return bundleSources
  const sameFile = report.sources.filter((s) => s.file === hyp.sinkFile || hyp.sinkFile.endsWith(s.file))
  if (sameFile.length > 0) return sameFile.sort((a, b) => Math.abs(a.line - hyp.sinkLine) - Math.abs(b.line - hyp.sinkLine)).slice(0, 4)
  const sinkClass = classNameFromFile(hyp.sinkFile)
  return report.sources.filter((s) => s.methodName.includes(sinkClass) || s.file.includes(sinkClass)).slice(0, 4)
}

export type PocTriggerLocation = "path" | "query" | "form" | "body" | "header" | "cookie" | "multipart"

export interface PocExpectation {
  route: RouteEntry
  source: SourceEntry
  method: string
  routePath: string
  requestTarget: string
  paramName: string
  payload: string
  triggerLocation: PocTriggerLocation
}

function payloadForCategory(hyp: Hypothesis): string {
  switch (hyp.category) {
    case "cmdi": return "id"
    case "ssrf": return "http://127.0.0.1:8080/internal"
    case "sqli": return "' OR '1'='1"
    case "file-download": return "../../etc/passwd"
    case "path-traversal": return "../../etc/passwd"
    case "file-upload": return "night_agent_probe"
    case "upload": return "night_agent_probe"
    case "deser": return '{"@type":"java.lang.AutoCloseable"}'
    case "ssti": return "${7*7}"
    case "spel": return "#{7*7}"
    case "ognl": return "%{7*7}"
    case "expression": return "${7*7}"
    case "template-injection": return "${7*7}"
    case "jndi": return "ldap://127.0.0.1:1389/Exploit"
    case "xxe": return "<!DOCTYPE x [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><x>&xxe;</x>"
    case "redirect": return "https://attacker.example/callback"
    default: return "night_agent_probe"
  }
}

export function pocSourceFor(report: AuditReport, hyp: Hypothesis): SourceEntry | undefined {
  const decisionSource = evidenceDecisionForReport(report, hyp).source
  if (decisionSource && isDirectHttpSource(decisionSource)) return decisionSource
  return relatedSources(report, hyp).find(isDirectHttpSource)
}

export function pocRouteFor(report: AuditReport, hyp: Hypothesis, source: SourceEntry | undefined = pocSourceFor(report, hyp)): RouteEntry | undefined {
  const decisionRoute = evidenceDecisionForReport(report, hyp).route
  if (decisionRoute) return decisionRoute
  const sourceRoute = source ? nearestRouteForSource(report.profile, source) : undefined
  if (sourceRoute) return sourceRoute
  return nearestRoute(report.profile, hyp, report.evidenceBundles)
}

export function buildHttpPocExpectation(report: AuditReport, hyp: Hypothesis): PocExpectation | null {
  const verifierExpectation = verifierHttpPocExpectation(report, hyp)
  const graphExpectation = graphHttpPocExpectation(report, hyp)
  if (graphExpectation) {
    if (verifierExpectation && shouldPreferVerifierExpectation(graphExpectation, verifierExpectation)) return verifierExpectation
    return graphExpectation
  }
  const source = pocSourceFor(report, hyp)
  if (!source) return verifierExpectation
  const route = pocRouteFor(report, hyp, source)
  if (!route) return verifierExpectation

  const payload = payloadForCategory(hyp)
  const paramName = sourceParamName(source)
  if (!paramName) return verifierExpectation

  const method = methodForRoute(route, source)
  const routePath = concreteRoutePath(route, source, payload)
  if (!routePath) return verifierExpectation

  let requestTarget = routePath
  let triggerLocation: PocTriggerLocation = "query"
  if (source.kind === "pathvar") {
    triggerLocation = "path"
  } else if (source.kind === "header") {
    triggerLocation = "header"
  } else if (source.kind === "cookie") {
    triggerLocation = "cookie"
  } else if (isMultipartSource(source, hyp)) {
    triggerLocation = "multipart"
  } else if (source.kind === "body" || source.kind === "input-stream") {
    triggerLocation = "body"
  } else if (methodAllowsBody(method)) {
    triggerLocation = "form"
  } else {
    requestTarget = appendQuery(routePath, paramName, payload)
  }

  const sourceExpectation = {
    route,
    source,
    method,
    routePath,
    requestTarget,
    paramName,
    payload,
    triggerLocation,
  }
  if (verifierExpectation && shouldPreferVerifierExpectation(sourceExpectation, verifierExpectation)) return verifierExpectation
  return sourceExpectation
}

function graphHttpPocExpectation(report: AuditReport, hyp: Hypothesis): PocExpectation | null {
  const decision = evidenceDecisionForReport(report, hyp)
  const route = decision.route
  if (!route) return null
  const source = decision.source && isDirectHttpSource(decision.source)
    ? decision.source
    : graphDecisionSource(report, hyp, route)
  if (!source || !isDirectHttpSource(source)) return null

  const payload = payloadForCategory(hyp)
  const paramName = sourceParamName(source)
  if (!paramName) return null
  const method = methodForRoute(route, source)
  const routePath = concreteRoutePath(route, source, payload)
  if (!routePath) return null

  let requestTarget = routePath
  let triggerLocation: PocTriggerLocation = "query"
  if (source.kind === "pathvar") {
    triggerLocation = "path"
  } else if (source.kind === "header") {
    triggerLocation = "header"
  } else if (source.kind === "cookie") {
    triggerLocation = "cookie"
  } else if (isMultipartSource(source, hyp)) {
    triggerLocation = "multipart"
  } else if (source.kind === "body" || source.kind === "input-stream") {
    triggerLocation = "body"
  } else if (methodAllowsBody(method)) {
    triggerLocation = "form"
  } else {
    requestTarget = appendQuery(routePath, paramName, payload)
  }

  return {
    route,
    source,
    method,
    routePath,
    requestTarget,
    paramName,
    payload,
    triggerLocation,
  }
}

function graphDecisionSource(report: AuditReport, hyp: Hypothesis, route: RouteEntry): SourceEntry | undefined {
  const decision = evidenceDecisionForReport(report, hyp)
  const paramName = decision.paramName
  if (!paramName) return undefined
  const kind: SourceEntry["kind"] = route.path.includes(`{${paramName}`) ? "pathvar" : methodAllowsBody(route.method.toUpperCase()) ? "body" : "param"
  return {
    id: `evidence-graph-source:${hyp.id}`,
    kind,
    paramName,
    file: projectFile(report.profile, route.sourceFile),
    line: route.line,
    code: `EvidenceGraph trigger ${decision.triggerSignature}\n${evidenceDecisionText(decision).slice(0, 600)}`,
    methodName: "evidence-graph-source",
    className: route.className,
    origin: "verifier",
  }
}

function verifierHttpPocExpectation(report: AuditReport, hyp: Hypothesis): PocExpectation | null {
  const verifier = bundleFor(report, hyp)?.verifierVerdict ?? hyp.verifierVerdict
  if (!verifier) return null
  const text = [
    verifier.reason,
    ...(verifier.sourceSinkTrace ?? []),
    ...(verifier.evidence ?? []),
  ].join("\n")
  const route = routeFromVerifierTrace(report.profile, hyp, text)
  if (!route) return null
  const paramName = paramNameFromVerifierTrace(hyp, text)
  if (!paramName) return null
  const payload = payloadForCategory(hyp)
  const sourceKind = route.path.includes(`{${paramName}`) ? "pathvar" : "body"
  const source: SourceEntry = {
    id: `verifier-source:${hyp.id}`,
    kind: sourceKind,
    paramName,
    file: projectFile(report.profile, route.sourceFile),
    line: route.line,
    code: `${route.method} ${route.path} @ verifier sourceSinkTrace\n${text.slice(0, 600)}`,
    methodName: "verifier-source",
    className: route.className,
    origin: "verifier",
  }
  const method = methodForRoute(route, source)
  const routePath = concreteRoutePath(route, source, payload)
  if (!routePath) return null
  const triggerLocation: PocTriggerLocation = source.kind === "pathvar"
    ? "path"
    : isMultipartSource(source, hyp) ? "multipart" : "body"
  return {
    route,
    source,
    method,
    routePath,
    requestTarget: routePath,
    paramName,
    payload,
    triggerLocation,
  }
}

function routeFromVerifierTrace(profile: ProjectProfile, hyp: Hypothesis, text: string): RouteEntry | null {
  const matches = [...text.matchAll(/\b(GET|POST|PUT|DELETE|PATCH)\s+(\/[A-Za-z0-9_./{}:-]+)/gi)]
  let fallback: RouteEntry | null = null
  for (const match of matches) {
    const method = match[1]!.toUpperCase()
    const path = normalizeRoutePath(match[2]!)
    const route = profile.routes.find((candidate) =>
      routeMethodMatches(candidate.method, method) && normalizeRoutePath(candidate.path) === path
    )
    if (route) return route
    fallback ??= {
      method,
      path,
      sourceFile: relativeFile(profile, hyp.sinkFile),
      line: hyp.sinkLine,
    }
  }
  return fallback
}

function routeMethodMatches(routeMethod: string, method: string): boolean {
  const upper = routeMethod.toUpperCase()
  return upper === method || upper === "REQUEST" || upper === "ANY" || upper.split(/[,\s|]+/).includes(method)
}

function normalizeRoutePath(path: string): string {
  const clean = path.replace(/[),.;，。；]+$/g, "")
  return clean.startsWith("/") ? clean : `/${clean}`
}

function paramNameFromVerifierTrace(hyp: Hypothesis, text: string): string | null {
  const lower = `${hyp.category}\n${hyp.sinkPattern}\n${hyp.sinkCode}\n${text}`.toLowerCase()
  const candidates = [
    "transformScript",
    "validationRules",
    "dynSentence",
    "caseResult",
    "sourceConfig",
    "apiUrl",
    "method",
    "reportCode",
    "file",
    "rowDatas",
    "password",
    "oldPassword",
    "body",
  ]
  for (const candidate of candidates) {
    if (lower.includes(candidate.toLowerCase())) return candidate
  }
  const fieldMatch = text.match(/\b([A-Za-z_][A-Za-z0-9_]*)\s*(?:字段|参数|field|parameter|param)\b/i)
  if (fieldMatch?.[1]) return fieldMatch[1]
  return null
}

function shouldPreferVerifierExpectation(sourceExpectation: PocExpectation, verifierExpectation: PocExpectation): boolean {
  if (sourceExpectation.source.origin !== "verifier" && verifierExpectation.source.origin === "verifier") {
    if (verifierExpectation.paramName !== "body" && sourceExpectation.paramName !== verifierExpectation.paramName) return true
    if (sourceExpectation.paramName === "body" && verifierExpectation.paramName !== "body") return true
    if (!sourceExpectation.source.file.endsWith(sourceExpectation.route.sourceFile)) return true
  }
  return false
}

export function buildHttpPoc(report: AuditReport, hyp: Hypothesis): string[] {
  const expectation = buildHttpPocExpectation(report, hyp)
  if (!expectation) return []

  const host = "target.example"
  const headers = [
    `${expectation.method} ${expectation.requestTarget} HTTP/1.1`,
    `Host: ${host}`,
  ]
  let body = ""

  if (expectation.triggerLocation === "header") {
    headers.push(`${expectation.paramName}: ${expectation.payload}`)
  } else if (expectation.triggerLocation === "cookie") {
    headers.push(`Cookie: ${expectation.paramName}=${encodeURIComponent(expectation.payload)}`)
  } else if (expectation.triggerLocation === "form") {
    body = `${encodeURIComponent(expectation.paramName)}=${encodeURIComponent(expectation.payload)}`
    headers.push("Content-Type: application/x-www-form-urlencoded")
  } else if (expectation.triggerLocation === "multipart") {
    const boundary = "----night-agent-boundary"
    body = [
      `--${boundary}`,
      `Content-Disposition: form-data; name="${expectation.paramName}"; filename="night-agent.txt"`,
      "Content-Type: text/plain",
      "",
      multipartPayload(hyp, expectation.payload),
      `--${boundary}--`,
      "",
    ].join("\n")
    headers.push(`Content-Type: multipart/form-data; boundary=${boundary}`)
  } else if (expectation.triggerLocation === "body") {
    const requestBody = bodyPayload(hyp, expectation.source, expectation.paramName, expectation.payload)
    body = requestBody.body
    headers.push(`Content-Type: ${requestBody.contentType}`)
  }

  if (body.length > 0) headers.push(`Content-Length: ${body.length}`)
  return [`${headers.join("\n")}\n\n${body}`]
}

function nearestRouteForSource(profile: ProjectProfile, source: SourceEntry): RouteEntry | undefined {
  const routes = profile.routes.filter((route) => routeMatchesFile(route, profile, source.file))
  if (routes.length === 0) return undefined
  return routes.sort((a, b) => routeDistance(a, source.line) - routeDistance(b, source.line))[0]
}

function routeDistance(route: RouteEntry, line: number): number {
  const distance = Math.abs(route.line - line)
  return route.line <= line ? distance : distance + 10_000
}

function isDirectHttpSource(source: SourceEntry): boolean {
  if (source.kind === "request-attr") return false
  if (source.kind === "body" || source.kind === "input-stream") return true
  return Boolean(sourceParamName(source))
}

function sourceParamName(source: SourceEntry): string | null {
  const param = source.paramName?.trim()
  if (param && param !== "unknown") return param
  if (source.kind === "body" || source.kind === "input-stream") return "body"
  return null
}

function methodForRoute(route: RouteEntry, source: SourceEntry): string {
  const preferred = source.kind === "body" || source.kind === "input-stream" ? "POST" : "GET"
  const method = route.method.toUpperCase()
  if (method === "REQUEST" || method === "ANY") return preferred
  const methods = method.split(/[,\s|]+/).filter(Boolean)
  if (methods.length > 1) return methods.includes(preferred) ? preferred : methods[0]!
  return methods[0] ?? preferred
}

function methodAllowsBody(method: string): boolean {
  return method === "POST" || method === "PUT" || method === "PATCH"
}

function concreteRoutePath(route: RouteEntry, source: SourceEntry, payload: string): string | null {
  let path = route.path || "/"
  if (!path.startsWith("/")) path = `/${path}`

  const encodedPayload = encodeURIComponent(payload)
  if (source.kind === "pathvar") {
    const param = sourceParamName(source)
    let replaced = false
    if (param) {
      const exact = new RegExp(`\\{${escapeRegExp(param)}(?::[^}]*)?\\}`, "g")
      path = path.replace(exact, () => {
        replaced = true
        return encodedPayload
      })
    }
    if (!replaced) {
      path = path.replace(/\{[^}]+}/, () => {
        replaced = true
        return encodedPayload
      })
    }
    if (!replaced) return null
  }

  return path.replace(/\{[^}]+}/g, "night_agent_probe")
}

function appendQuery(path: string, paramName: string, payload: string): string {
  const sep = path.includes("?") ? "&" : "?"
  return `${path}${sep}${encodeURIComponent(paramName)}=${encodeURIComponent(payload)}`
}

function isMultipartSource(source: SourceEntry, hyp: Hypothesis): boolean {
  const sourceText = `${source.kind} ${source.paramName} ${source.code}`.toLowerCase()
  const sinkText = `${hyp.sinkPattern} ${hyp.sinkCode}`.toLowerCase()
  const multipartSource = /multipartfile|getpart|getparts|part\.|fileitem|getoriginalfilename|getsubmittedfilename/.test(sourceText)
  const multipartSink = /multipartfile|getpart|getparts|part\.write|getoriginalfilename|getsubmittedfilename/.test(sinkText)
  return multipartSource || ((hyp.category === "file-upload" || hyp.category === "upload") && multipartSink)
}

function multipartPayload(hyp: Hypothesis, payload: string): string {
  if (hyp.category === "file-upload" || hyp.category === "upload") return "night_agent_probe"
  return payload
}

function bodyPayload(hyp: Hypothesis, source: SourceEntry, paramName: string, payload: string): { body: string; contentType: string } {
  if (hyp.category === "xxe") return { body: payload, contentType: "application/xml" }
  if (hyp.category === "deser") return { body: payload, contentType: "application/json" }
  if (source.kind === "input-stream" || /\bstring\b|byte\[\]|inputstream/i.test(source.code)) {
    return { body: payload, contentType: "text/plain" }
  }
  return { body: JSON.stringify({ [paramName === "body" ? "value" : paramName]: payload }), contentType: "application/json" }
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
}

function chainEdges(report: AuditReport, hyp: Hypothesis): DataflowEdge[] {
  const bundle = bundleFor(report, hyp)
  const decisionEdges = evidenceDecisionForReport(report, hyp).graphEdges
  if (decisionEdges.length > 0) return decisionEdges
  const flowEdges = bundle?.dataflow?.paths?.[0]?.edges ?? hyp.dataflowResult?.paths?.[0]?.edges
  if (flowEdges && flowEdges.length > 0) return flowEdges
  const sources = relatedSources(report, hyp)
  const edges: DataflowEdge[] = []
  for (const source of sources.slice(0, 2)) {
    edges.push({ file: projectFile(report.profile, source.file), line: source.line, code: source.code, kind: "source" })
  }
  edges.push({
    file: projectFile(report.profile, hyp.sinkFile),
    line: hyp.sinkLine,
    code: hyp.sinkCode || readCodeContext(projectFile(report.profile, hyp.sinkFile), hyp.sinkLine, 0).replace(/^>>\s*\d+\s*\|\s*/, ""),
    kind: "sink",
  })
  return edges
}

export function formatChainMd(report: AuditReport, hyp: Hypothesis): string {
  const edges = chainEdges(report, hyp)
  return edges.map((edge, index) => {
    const role = edge.kind === "source" ? "入口" : edge.kind === "sink" ? "危险点" : edge.kind === "sanitizer" ? "过滤/屏障" : "传播"
    return `${index}. [${role}] ${relativeFile(report.profile, edge.file)}:${edge.line}\n   ${edge.code}`
  }).join("\n")
}

const IMPORTANT_REPORT_CATEGORIES = new Set([
  "cmdi",
  "sqli",
  "path-traversal",
  "file-download",
  "file-upload",
  "upload",
  "ssti",
  "spel",
  "ognl",
  "expression",
  "template-injection",
])

const DETAILED_SOURCE_LIMIT = 3
const SOURCE_SUMMARY_LIMIT = 8

const STATUS_LABEL: Record<string, string> = {
  confirmed: "已确认",
  pending: "待确认",
  tracing: "追踪中",
  maybe_revisit: "待复查",
  dismissed: "已排除",
}

const STATUS_ORDER: Record<string, number> = {
  confirmed: 0,
  pending: 1,
  tracing: 2,
  maybe_revisit: 3,
  dismissed: 4,
}

function bundleFor(report: AuditReport, hyp: Hypothesis): EvidenceBundle | undefined {
  return report.evidenceBundles.find((bundle) => bundle.hypothesisId === hyp.id || bundle.id === hyp.evidenceBundleId)
}

function routeFor(report: AuditReport, hyp: Hypothesis): RouteEntry | undefined {
  return bundleFor(report, hyp)?.route ?? nearestRoute(report.profile, hyp, report.evidenceBundles)
}

function sourceLinksFor(report: AuditReport, hyp: Hypothesis): SourceLink[] {
  const bundle = bundleFor(report, hyp)
  const bundleLinks = bundle?.sourceLinks
  if (bundleLinks?.length) {
    const selectedSource = bundle?.selectedSource
    if (!selectedSource) return bundleLinks
    const selectedIndex = bundleLinks.findIndex((link) =>
      link.source.id === selectedSource.id
        || (link.source.file === selectedSource.file && link.source.line === selectedSource.line && link.source.paramName === selectedSource.paramName)
    )
    if (selectedIndex <= 0) return bundleLinks
    const selected = bundleLinks[selectedIndex]!
    return [selected, ...bundleLinks.filter((_, index) => index !== selectedIndex)]
  }
  if (hyp.sourceLinks?.length) return hyp.sourceLinks
  return relatedSources(report, hyp).map((source) => ({
    source,
    score: 0,
    reason: "report fallback: nearest source candidate",
  }))
}

function categoryWeight(category: string): number {
  return IMPORTANT_REPORT_CATEGORIES.has(category) ? 0 : 1
}

function sortedHypotheses(report: AuditReport): Hypothesis[] {
  return [...report.hypotheses].sort((a, b) => {
    return (STATUS_ORDER[a.status] ?? 9) - (STATUS_ORDER[b.status] ?? 9)
      || compareSeverity(a.severity, b.severity)
      || categoryWeight(a.category) - categoryWeight(b.category)
      || a.category.localeCompare(b.category)
      || relativeFile(report.profile, a.sinkFile).localeCompare(relativeFile(report.profile, b.sinkFile))
      || a.sinkLine - b.sinkLine
  })
}

function mdCell(value: unknown): string {
  return String(value ?? "-")
    .replace(/\|/g, "\\|")
    .replace(/\r?\n/g, "<br>")
    .trim() || "-"
}

function oneLine(value: unknown, max = 180): string {
  const text = String(value ?? "").replace(/\s+/g, " ").trim()
  return text.length > max ? `${text.slice(0, max - 1)}…` : text
}

function codeLanguage(file: string): string {
  if (/\.java$/i.test(file)) return "java"
  if (/\.jsp$/i.test(file)) return "jsp"
  if (/\.xml$/i.test(file)) return "xml"
  if (/\.ya?ml$/i.test(file)) return "yaml"
  if (/\.properties$/i.test(file)) return "properties"
  return "text"
}

function routeText(route: RouteEntry | undefined): string {
  if (!route) return "未识别到直接 HTTP 路由"
  return `${route.method} ${route.path} (${route.sourceFile}:${route.line})`
}

function hypothesisTitle(hyp: Hypothesis): string {
  return oneLine(hyp.description || `${hyp.category} via ${hyp.sinkPattern}`, 140)
}

function sourceLine(report: AuditReport, link: SourceLink): string {
  const source = link.source
  const name = source.paramName && source.paramName !== "unknown" ? `${source.kind}:${source.paramName}` : source.kind
  const score = link.score ? `，score=${link.score}` : ""
  const reason = link.reason ? `，${oneLine(link.reason, 80)}` : ""
  return `- ${name} @ \`${relativeFile(report.profile, source.file)}:${source.line}\`${score}${reason}\n  - \`${oneLine(source.code, 220)}\``
}

function sourceSummary(report: AuditReport, links: SourceLink[]): string {
  return links.slice(0, SOURCE_SUMMARY_LIMIT).map((link) => {
    const source = link.source
    const name = source.paramName && source.paramName !== "unknown" ? `${source.kind}:${source.paramName}` : source.kind
    const score = link.score ? ` score=${link.score}` : ""
    return `${name} @ ${relativeFile(report.profile, source.file)}:${source.line}${score}`
  }).join("；")
}

function pocSection(report: AuditReport, hyp: Hypothesis): string {
  if (hyp.status !== "confirmed") return "仅已确认漏洞生成 HTTP PoC 草案。\n"
  const bundle = bundleFor(report, hyp)
  const packets = bundle?.reportContext?.pocPackets?.length ? bundle.reportContext.pocPackets : buildHttpPoc(report, hyp)
  if (packets.length === 0) return "未生成 HTTP PoC 草案。\n"
  return packets.map((packet, index) => `#### 数据包 ${index}\n\n\`\`\`http\n${packet.trim()}\n\`\`\``).join("\n\n")
}

function statusSummary(report: AuditReport): string {
  const byStatus = new Map<string, number>()
  const byCategory = new Map<string, number>()
  for (const hyp of report.hypotheses) {
    byStatus.set(hyp.status, (byStatus.get(hyp.status) ?? 0) + 1)
    byCategory.set(hyp.category, (byCategory.get(hyp.category) ?? 0) + 1)
  }
  const statusText = [...byStatus.entries()]
    .sort((a, b) => (STATUS_ORDER[a[0]] ?? 9) - (STATUS_ORDER[b[0]] ?? 9))
    .map(([status, count]) => `${STATUS_LABEL[status] ?? status} ${count}`)
    .join("，") || "无"
  const categoryText = [...byCategory.entries()]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .map(([category, count]) => `${category} ${count}`)
    .join("，") || "无"
  return `- 按状态：${statusText}\n- 按类别：${categoryText}`
}

function indexTable(report: AuditReport, hypotheses: Hypothesis[]): string {
  const rows = [
    "| # | 状态 | 风险 | 类别 | 位置 | 入口关联 | 标题 |",
    "| --- | --- | --- | --- | --- | --- | --- |",
  ]
  hypotheses.forEach((hyp, index) => {
    const links = sourceLinksFor(report, hyp)
    const strongest = links[0]
    const sourceText = strongest
      ? `${strongest.source.kind}:${strongest.source.paramName} score=${strongest.score}`
      : "无"
    rows.push(`| ${index + 1} | ${mdCell(STATUS_LABEL[hyp.status] ?? hyp.status)} | ${mdCell(hyp.severity)} | ${mdCell(hyp.category)} | ${mdCell(`${relativeFile(report.profile, hyp.sinkFile)}:${hyp.sinkLine}`)} | ${mdCell(sourceText)} | ${mdCell(hypothesisTitle(hyp))} |`)
  })
  return rows.join("\n")
}

function detailSection(report: AuditReport, hyp: Hypothesis, index: number): string {
  const bundle = bundleFor(report, hyp)
  const links = sourceLinksFor(report, hyp)
  const route = routeFor(report, hyp)
  const sinkFile = projectFile(report.profile, hyp.sinkFile)
  const sinkRel = relativeFile(report.profile, hyp.sinkFile)
  const observer = bundle?.observerVerdict
    ? `${bundle.observerVerdict.passed ? "通过" : "未通过"}：${bundle.observerVerdict.reason}`
    : "无 Observer 单项结论"
  const verifier = bundle?.verifierVerdict ?? hyp.verifierVerdict
  const verifierLine = verifier
    ? `${STATUS_LABEL[verifier.status] ?? verifier.status} / ${verifier.confidence}：${verifier.reason}`
    : "无 StaticVerifierAgent 复核结论"
  const verifierEvidence = verifier
    ? `\n- **Verifier 证据**：${verifier.evidence.length ? mdCell(verifier.evidence.slice(0, 5).join("；")) : "无"}`
      + `\n- **Verifier 已读文件**：${verifier.checkedFiles.length ? mdCell(verifier.checkedFiles.slice(0, 8).join("；")) : "无"}`
      + (verifier.sanitizerSummary?.length ? `\n- **安全屏障检查**：${mdCell(verifier.sanitizerSummary.slice(0, 5).join("；"))}` : "")
      + (verifier.missingEvidence?.length ? `\n- **缺失证据**：${mdCell(verifier.missingEvidence.slice(0, 5).join("；"))}` : "")
    : ""
  const dataflow = bundle?.dataflow ?? hyp.dataflowResult
  const flowText = dataflow
    ? `reachable=${dataflow.reachable}，confidence=${dataflow.confidence}，paths=${dataflow.paths.length}，sanitizers=${dataflow.sanitizers.length}`
    : "无 Joern 数据流结果"
  const routeLine = routeText(route)
  const sourceList = links.length
    ? links.slice(0, DETAILED_SOURCE_LIMIT).map((link) => sourceLine(report, link)).join("\n")
    : "- 未关联到 SourceAgent 输入源"
  const remainingLinks = links.slice(DETAILED_SOURCE_LIMIT)
  const moreSources = remainingLinks.length > 0
    ? `\n- 还有 ${remainingLinks.length} 个 SourceAgent 关联未详细展开。摘要：${sourceSummary(report, remainingLinks)}${remainingLinks.length > SOURCE_SUMMARY_LIMIT ? `；另有 ${remainingLinks.length - SOURCE_SUMMARY_LIMIT} 个未列出` : ""}`
    : ""
  const note = hyp.resolutionNote ? `\n- **判定备注**：${hyp.resolutionNote}` : ""

  return `### ${index + 1}. [${STATUS_LABEL[hyp.status] ?? hyp.status}] ${hyp.severity.toUpperCase()} / ${hyp.category} - ${hypothesisTitle(hyp)}

- **Hypothesis ID**：\`${hyp.id}\`
- **危险点**：\`${hyp.sinkPattern}\` @ \`${sinkRel}:${hyp.sinkLine}\`
- **关联路由**：${routeLine}
- **Observer**：${observer}
- **StaticVerifierAgent**：${verifierLine}${verifierEvidence}
- **Joern/追踪**：${flowText}${note}

**危险点代码上下文**

\`\`\`${codeLanguage(hyp.sinkFile)}
${readCodeContext(sinkFile, hyp.sinkLine, 5)}
\`\`\`

**SourceAgent 关联入口**

${sourceList}${moreSources}

**入口到 Sink 链路**

\`\`\`text
${formatChainMd(report, hyp)}
\`\`\`

**HTTP PoC 草案**

${pocSection(report, hyp)}
`
}

export function buildCompleteFindingsAppendix(report: AuditReport): string {
  const hypotheses = sortedHypotheses(report)
  if (hypotheses.length === 0) {
    return `## 附录：完整审计结果\n\n本次没有生成漏洞假设。`
  }

  const sections: string[] = []
  let currentStatus = ""
  for (const hyp of hypotheses) {
    if (hyp.status !== currentStatus) {
      currentStatus = hyp.status
      sections.push(`## ${STATUS_LABEL[currentStatus] ?? currentStatus}结果`)
    }
    sections.push(detailSection(report, hyp, hypotheses.indexOf(hyp)))
  }

  return `---

## 附录：完整审计结果

> 本附录由后端根据 Agent 产物稳定生成，保证所有候选、确认、待复查和排除结果都进入 Markdown。前文由 ReportAgent 自由组织重点，本附录按“已确认优先、严重程度优先、高影响类别优先”排序，便于逐项复核。

${statusSummary(report)}

### 全部结果索引

${indexTable(report, hypotheses)}

${sections.join("\n\n")}`
}

export function buildCompleteFindingsMarkdown(report: AuditReport): string {
  const appendix = buildCompleteFindingsAppendix(report)
    .replace(/^---\n\n/, "")
    .replace(/^## 附录：完整审计结果/, "## 完整审计结果")
  return `# ${report.profile.name} 完整审计结果

${appendix}`
}

function buildConfirmedFindingsAppendix(report: AuditReport, hypotheses: Hypothesis[]): string {
  if (hypotheses.length === 0) return ""
  const sorted = [...hypotheses].sort((a, b) => {
    return compareSeverity(a.severity, b.severity)
      || categoryWeight(a.category) - categoryWeight(b.category)
      || relativeFile(report.profile, a.sinkFile).localeCompare(relativeFile(report.profile, b.sinkFile))
      || a.sinkLine - b.sinkLine
  })
  return `---

## 附录：AI 报告遗漏的已确认结果

> 本附录只补充已确认 confirmed 结果。未确认、待复查、追踪中和已排除结果不会进入 AI 报告，请使用“下载全部”查看完整结果。

${indexTable(report, sorted)}

${sorted.map((hyp, index) => detailSection(report, hyp, index)).join("\n\n")}`
}

export function appendCompleteFindingsAppendix(markdown: string, report: AuditReport): string {
  const marker = "## 附录：完整审计结果"
  const body = markdown.trim()
  if (body.includes(marker)) return body
  const reportable = report.hypotheses.filter((hyp) => hyp.status === "confirmed")
  const missing = reportable.filter((hyp) => !body.includes(hyp.id))
  if (missing.length === 0) return body
  return `${body}\n\n${buildConfirmedFindingsAppendix(report, missing)}`
}

export async function writeCompleteFindingsReport(report: AuditReport, outputDir: string): Promise<string | null> {
  if (report.hypotheses.length === 0) return null
  const reportPath = resolve(outputDir, `${report.profile.name}-完整结果.md`)
  await Bun.write(reportPath, `${buildCompleteFindingsMarkdown(report).trim()}\n`)
  return reportPath
}

export async function writeReport(report: AuditReport, outputDir: string): Promise<string | null> {
  const content = report.markdownReport?.trim()
  if (!content) return null

  const reportPath = resolve(outputDir, `${report.profile.name}-审计报告.md`)
  await Bun.write(reportPath, `${content}\n`)
  return reportPath
}
