import { basename, relative, resolve } from "node:path"
import type {
  ProjectProfile,
  FileStat,
  DependencyFingerprint,
  RouteEntry,
  SecurityMechanism,
  ProjectLanguage,
} from "../types/index.ts"
import { isHighRiskDep } from "../types/index.ts"
import { javaAuditFileScore, sortJavaAuditFiles } from "../scanner/file-priority.ts"

const IGNORED_DIRS = new Set([
  ".git", ".night-agent", ".night_agent", "node_modules", "dist", "build", "target", ".next",
  "coverage", "output-audit", "__pycache__", ".idea", ".vscode",
])

const BUILD_FILE_NAMES = new Set([
  "pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle",
  "package.json", "requirements.txt", "setup.py", "pyproject.toml",
  "go.mod", "Makefile", "Dockerfile",
])

const JAVA_ROUTE_PATTERNS = [
  /@(Get|Post|Put|Delete|Patch)Mapping\s*\(\s*["']([^"']+)["']/g,
  /@RequestMapping\s*\(\s*["']([^"']+)["']/g,
  /@RequestMapping\s*\(\s*value\s*=\s*["']([^"']+)["']/g,
  /@RequestMapping\s*\(\s*method\s*=\s*[^)]+,\s*value\s*=\s*["']([^"']+)["']/g,
]

const SERVLET_METHODS = ["doGet", "doPost", "doPut", "doDelete", "doPatch", "doHead", "doOptions", "service"]

interface AuthPattern {
  kind: string
  pattern: RegExp
  detail?: string
}

const JAVA_AUTH_PATTERNS: AuthPattern[] = [
  { kind: "annotation", pattern: /@(Secured|PreAuthorize|PostAuthorize|RolesAllowed)\s*\(/ },
  { kind: "filter", pattern: /extends\s+(OncePerRequestFilter|GenericFilterBean|AbstractAuthenticationFilter)/ },
  { kind: "config", pattern: /\.antMatchers\s*\(/, detail: "Spring Security chain config" },
  { kind: "shiro", pattern: /SecurityUtils\.getSubject|Subject\.(login|isAuthenticated|hasRole)/ },
]

async function walkFiles(root: string): Promise<string[]> {
  const files: string[] = []

  async function visit(dir: string) {
    for await (const entry of new Bun.Glob("*").scan({ cwd: dir, onlyFiles: false, dot: true })) {
      if (IGNORED_DIRS.has(entry)) continue
      const fullPath = resolve(dir, entry)
      const stat = await Bun.file(fullPath).stat().catch(() => undefined)
      if (!stat) continue
      if (stat.isDirectory()) await visit(fullPath)
      else files.push(fullPath)
    }
  }

  await visit(root)
  return files
}

function detectLanguage(files: string[]): ProjectLanguage {
  const counts: Record<string, number> = {}
  for (const f of files) {
    const ext = f.split(".").pop()?.toLowerCase() ?? ""
    counts[ext] = (counts[ext] ?? 0) + 1
  }
  if ((counts["java"] ?? 0) + (counts["xml"] ?? 0) + (counts["jsp"] ?? 0) + (counts["jspx"] ?? 0) > 0) return "java"
  if (counts["py"] ?? 0 > 0) return "python"
  if ((counts["js"] ?? 0) + (counts["ts"] ?? 0) > 0) return "javascript"
  if (counts["go"] ?? 0 > 0) return "go"
  return "unknown"
}

function buildFileStats(files: string[]): FileStat[] {
  const counts = new Map<string, number>()
  for (const f of files) {
    const ext = f.split(".").pop()?.toLowerCase() ?? "none"
    counts.set(ext, (counts.get(ext) ?? 0) + 1)
  }
  return [...counts.entries()]
    .map(([extension, count]) => ({ extension, count }))
    .sort((a, b) => b.count - a.count)
}

function detectBuildFiles(files: string[], root: string): string[] {
  return files
    .filter((f) => {
      const name = basename(f).toLowerCase()
      return BUILD_FILE_NAMES.has(name) || BUILD_FILE_NAMES.has(basename(f))
    })
    .map((f) => relative(root, f))
}

function detectDirectories(files: string[], root: string): string[] {
  const dirs = new Set<string>()
  for (const f of files) {
    const rel = relative(root, f)
    const topDir = rel.split("/")[0]
    if (topDir && !topDir.startsWith(".")) dirs.add(topDir)
  }
  return [...dirs].sort()
}

async function parseMavenDeps(file: string, root: string): Promise<DependencyFingerprint[]> {
  const deps: DependencyFingerprint[] = []
  try {
    const text = await Bun.file(file).text()
    // Extract groupId:artifactId:version from <dependency> blocks
    const depRegex = /<dependency>\s*<groupId>([^<]+)<\/groupId>\s*<artifactId>([^<]+)<\/artifactId>\s*(?:<version>([^<]+)<\/version>)?/g
    for (const m of text.matchAll(depRegex)) {
      deps.push({
        ecosystem: "maven",
        name: `${m[1]}:${m[2]}`,
        version: m[3],
        sourceFile: relative(root, file),
      })
    }
    // Also extract properties-referenced versions
    const propRegex = /<([^>]+\.version)>\s*([^<]+)\s*<\//
    const props = new Map<string, string>()
    for (const m of text.matchAll(new RegExp(propRegex, "g"))) {
      props.set(m[1]!, m[2]!)
    }
    const varDepRegex = /<version>\$\{([^}]+)\}<\/version>/
    for (const dep of deps) {
      if (dep.version?.startsWith("${")) {
        const propName = dep.version.slice(2, -1)
        dep.version = props.get(propName) ?? dep.version
      }
    }
  } catch {
    // ignore parse errors
  }
  return deps
}

interface ServletMapping {
  servletName: string
  className?: string
  jspFile?: string
  urlPatterns: Array<{ path: string; line: number }>
  sourceFile: string
}

async function extractRoutes(root: string, allFiles: string[]): Promise<RouteEntry[]> {
  const routes: RouteEntry[] = []
  const webXmlMappings = await extractWebXmlServletMappings(root, allFiles)
  const mappingByClass = new Map<string, ServletMapping[]>()
  const mappingByJsp = new Map<string, ServletMapping[]>()
  for (const mapping of webXmlMappings) {
    if (mapping.className) {
      const simple = mapping.className.split(".").pop() ?? mapping.className
      for (const key of [mapping.className, simple]) {
        const list = mappingByClass.get(key) ?? []
        list.push(mapping)
        mappingByClass.set(key, list)
      }
    }
    if (mapping.jspFile) {
      const normalized = normalizeRoutePath(mapping.jspFile)
      mappingByJsp.set(normalized, [...(mappingByJsp.get(normalized) ?? []), mapping])
    }
  }

  async function scanJava(files: string[]) {
    for (const fullPath of files.filter((f) => f.endsWith(".java"))) {
      const entry = relative(root, fullPath)
      try {
        const text = await Bun.file(fullPath).text()
        // Detect controller classes
        const hasController = /@(RestController|Controller)\b/.test(text)
        const className = javaClassName(text) ?? entry.replace(/\.java$/, "")
        const servletMappings = mappingByClass.get(className) ?? []
        const hasWebServlet = /@WebServlet\b/.test(text)
        const hasServletClass = /\bextends\s+(?:HttpServlet|GenericServlet)\b|\bimplements\s+Servlet\b/.test(text)

        if (hasController) {
          const classPrefix = classRoutePrefix(text)
          for (const pattern of JAVA_ROUTE_PATTERNS) {
            for (const m of text.matchAll(pattern)) {
              if (isClassLevelRoute(text, m.index ?? 0)) continue
              const path = joinRoutePaths(classPrefix, m[2] || m[1] || "/")
              routes.push({
                method: extractHttpMethod(m[0]),
                path,
                className,
                sourceFile: entry,
                line: lineNumberAt(text, m.index ?? 0),
                authHint: extractAuthHint(text),
              })
            }
          }
        }

        if (hasWebServlet) {
          for (const route of extractWebServletRoutes(text, entry, className)) {
            routes.push(route)
          }
        }

        if (hasServletClass || servletMappings.length > 0 || hasWebServlet) {
          const methods = extractServletMethodRoutes(text, entry, className, servletMappings)
          routes.push(...methods)
        }
      } catch {
        // skip unreadable files
      }
    }
  }

  async function scanJsp(files: string[]) {
    for (const fullPath of files.filter((f) => /\.(jsp|jspx)$/i.test(f))) {
      const rel = relative(root, fullPath)
      const jspPath = jspRoutePath(root, fullPath)
      const webMappings = mappingByJsp.get(jspPath) ?? mappingByJsp.get(normalizeRoutePath(`/${rel}`)) ?? []
      if (webMappings.length > 0) {
        for (const mapping of webMappings) {
          for (const url of mapping.urlPatterns) {
            routes.push({
              method: "JSP",
              path: normalizeRoutePath(url.path),
              className: jspClassName(rel),
              sourceFile: rel,
              line: 1,
              authHint: rel.includes("/WEB-INF/") ? "JSP under WEB-INF; requires forward/include route" : undefined,
            })
          }
        }
        continue
      }
      routes.push({
        method: rel.includes("/WEB-INF/") ? "JSP-INTERNAL" : "JSP",
        path: jspPath,
        className: jspClassName(rel),
        sourceFile: rel,
        line: 1,
        authHint: rel.includes("/WEB-INF/") ? "JSP under WEB-INF; requires forward/include route" : undefined,
      })
    }
  }

  try {
    await scanJava(allFiles)
    await scanJsp(allFiles)
  } catch {
    // ignore
  }
  return deduplicateRoutes(routes).slice(0, 800)
}

function classRoutePrefix(text: string): string {
  const classMatch = /\b(?:class|interface|enum)\s+[A-Za-z_$][\w$]*/.exec(text)
  if (!classMatch) return ""
  const beforeClass = text.slice(0, classMatch.index)
  const matches = [...beforeClass.matchAll(/@RequestMapping\s*\(\s*(?:value\s*=\s*)?["']([^"']+)["']/g)]
  return matches.at(-1)?.[1] ?? ""
}

function isClassLevelRoute(text: string, annotationIndex: number): boolean {
  const after = text.slice(annotationIndex).split("\n").slice(1, 8)
  for (const line of after) {
    const trimmed = line.trim()
    if (!trimmed || trimmed.startsWith("*") || trimmed.startsWith("//")) continue
    if (trimmed.startsWith("@")) continue
    return /\b(?:class|interface|enum)\s+[A-Za-z_$][\w$]*/.test(trimmed)
  }
  return false
}

function joinRoutePaths(prefix: string, path: string): string {
  const normalizedPrefix = normalizeRoutePath(prefix)
  const normalizedPath = normalizeRoutePath(path)
  if (!normalizedPrefix || normalizedPrefix === "/") return normalizedPath || "/"
  if (!normalizedPath || normalizedPath === "/") return normalizedPrefix
  return normalizeRoutePath(`${normalizedPrefix}/${normalizedPath}`)
}

function normalizeRoutePath(path: string): string {
  if (!path) return ""
  const normalized = `/${path}`.replace(/\/+/g, "/")
  return normalized.length > 1 ? normalized.replace(/\/$/, "") : normalized
}

async function extractWebXmlServletMappings(root: string, allFiles: string[]): Promise<ServletMapping[]> {
  const mappings: ServletMapping[] = []
  for (const webXml of allFiles.filter((file) => /(^|\/)WEB-INF\/web\.xml$/i.test(file) || /(^|\/)web\.xml$/i.test(file))) {
    try {
      const text = await Bun.file(webXml).text()
      const sourceFile = relative(root, webXml)
      const servletByName = new Map<string, { className?: string; jspFile?: string }>()

      for (const block of xmlBlocks(text, "servlet")) {
        const servletName = xmlTagValues(block.text, "servlet-name")[0]
        if (!servletName) continue
        const className = xmlTagValues(block.text, "servlet-class")[0]?.trim()
        const jspFile = xmlTagValues(block.text, "jsp-file")[0]?.trim()
        servletByName.set(servletName.trim(), { className, jspFile })
      }

      for (const block of xmlBlocks(text, "servlet-mapping")) {
        const servletName = xmlTagValues(block.text, "servlet-name")[0]?.trim()
        if (!servletName) continue
        const target = servletByName.get(servletName)
        const urlPatterns = xmlTagMatches(block.text, "url-pattern").map((match) => ({
          path: normalizeRoutePath(match.value.trim()),
          line: lineNumberAt(text, block.index + match.index),
        })).filter((item) => item.path)
        if (urlPatterns.length === 0) continue
        mappings.push({
          servletName,
          className: target?.className,
          jspFile: target?.jspFile,
          urlPatterns,
          sourceFile,
        })
      }
    } catch {
      // ignore unreadable web.xml
    }
  }
  return mappings
}

function xmlBlocks(text: string, tag: string): Array<{ text: string; index: number }> {
  const blocks: Array<{ text: string; index: number }> = []
  const re = new RegExp(`<${tag}(?:\\s|>)[\\s\\S]*?<\\/${tag}>`, "gi")
  for (const match of text.matchAll(re)) {
    blocks.push({ text: match[0], index: match.index ?? 0 })
  }
  return blocks
}

function xmlTagMatches(text: string, tag: string): Array<{ value: string; index: number }> {
  const matches: Array<{ value: string; index: number }> = []
  const re = new RegExp(`<${tag}(?:\\s[^>]*|)>([\\s\\S]*?)<\\/${tag}>`, "gi")
  for (const match of text.matchAll(re)) {
    matches.push({ value: decodeXmlText(match[1] ?? ""), index: match.index ?? 0 })
  }
  return matches
}

function xmlTagValues(text: string, tag: string): string[] {
  return xmlTagMatches(text, tag).map((match) => match.value)
}

function decodeXmlText(value: string): string {
  return value
    .replace(/<!\[CDATA\[([\s\S]*?)]]>/g, "$1")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&amp;/g, "&")
    .trim()
}

function javaClassName(text: string): string | undefined {
  return text.match(/\b(?:class|interface|enum)\s+([A-Za-z_$][\w$]*)/)?.[1]
}

function extractWebServletRoutes(text: string, sourceFile: string, className: string): RouteEntry[] {
  const routes: RouteEntry[] = []
  for (const match of text.matchAll(/@WebServlet\s*(?:\(([\s\S]*?)\))?/g)) {
    const annotation = match[1] ?? ""
    const paths = extractQuotedRoutePaths(annotation)
    for (const path of paths.length > 0 ? paths : [`/${className}`]) {
      routes.push({
        method: "SERVLET",
        path: normalizeRoutePath(path),
        className,
        sourceFile,
        line: lineNumberAt(text, match.index ?? 0),
        authHint: extractAuthHint(text),
      })
    }
  }
  return routes
}

function extractQuotedRoutePaths(annotation: string): string[] {
  const paths: string[] = []
  for (const match of annotation.matchAll(/["']([^"']+)["']/g)) {
    const value = match[1]?.trim()
    if (!value) continue
    if (value.startsWith("/") || value.startsWith("*.")) paths.push(value)
  }
  return [...new Set(paths)]
}

function extractServletMethodRoutes(
  text: string,
  sourceFile: string,
  className: string,
  servletMappings: ServletMapping[],
): RouteEntry[] {
  const routes: RouteEntry[] = []
  const methodPattern = new RegExp(`\\b(?:public|protected)?\\s*(?:void|[\\w.$<>]+)\\s+(${SERVLET_METHODS.join("|")})\\s*\\([^)]*(?:ServletRequest|HttpServletRequest)[^)]*\\)`, "g")
  const mappedPaths = servletMappings.flatMap((mapping) => mapping.urlPatterns)
  const fallbackPaths = mappedPaths.length > 0 ? mappedPaths : [{ path: `/${className}`, line: 1 }]
  for (const match of text.matchAll(methodPattern)) {
    const servletMethod = match[1] ?? "service"
    for (const mapped of fallbackPaths) {
      routes.push({
        method: servletHttpMethod(servletMethod),
        path: normalizeRoutePath(mapped.path),
        className,
        sourceFile,
        line: lineNumberAt(text, match.index ?? 0),
        authHint: extractAuthHint(text),
      })
    }
  }
  return routes
}

function servletHttpMethod(method: string): string {
  switch (method) {
    case "doGet": return "GET"
    case "doPost": return "POST"
    case "doPut": return "PUT"
    case "doDelete": return "DELETE"
    case "doPatch": return "PATCH"
    case "doHead": return "HEAD"
    case "doOptions": return "OPTIONS"
    default: return "REQUEST"
  }
}

function jspRoutePath(root: string, file: string): string {
  const rel = relative(root, file).replace(/\\/g, "/")
  const lower = rel.toLowerCase()
  const markers = ["/src/main/webapp/", "/webapp/", "/webroot/", "/webcontent/"]
  for (const marker of markers) {
    const idx = `/${lower}`.indexOf(marker)
    if (idx !== -1) {
      const originalStart = idx + marker.length - 1
      return normalizeRoutePath(rel.slice(originalStart))
    }
  }
  return normalizeRoutePath(rel)
}

function jspClassName(rel: string): string {
  return rel.replace(/\.(jsp|jspx)$/i, "").replace(/[^A-Za-z0-9_$]+/g, "_")
}

function deduplicateRoutes(routes: RouteEntry[]): RouteEntry[] {
  const byKey = new Map<string, RouteEntry>()
  for (const route of routes) {
    const key = `${route.method}:${route.path}:${route.sourceFile}:${route.line}`
    if (!byKey.has(key)) byKey.set(key, route)
  }
  return [...byKey.values()].sort((a, b) => routeScore(b) - routeScore(a)
    || a.sourceFile.localeCompare(b.sourceFile)
    || a.line - b.line)
}

function routeScore(route: RouteEntry): number {
  const text = `${route.method} ${route.path} ${route.sourceFile}`.toLowerCase()
  let score = 0
  if (/servlet|jsp/.test(route.method.toLowerCase())) score += 25
  if (/controller|action|servlet|jsp|jspx/.test(text)) score += 20
  if (/upload|download|file|import|export|cmd|exec|sql|jndi|template|redirect|callback|auth|login/.test(text)) score += 20
  if (/web-inf\/web\.xml/.test(text)) score += 10
  return score
}

function extractHttpMethod(annotation: string): string {
  if (annotation.includes("@GetMapping")) return "GET"
  if (annotation.includes("@PostMapping")) return "POST"
  if (annotation.includes("@PutMapping")) return "PUT"
  if (annotation.includes("@DeleteMapping")) return "DELETE"
  if (annotation.includes("@PatchMapping")) return "PATCH"
  return "REQUEST"
}

function extractAuthHint(text: string): string | undefined {
  if (/@(Secured|PreAuthorize|RolesAllowed|AnonymousAccess)/.test(text)) return "有认证注解"
  if (/SecurityUtils|SecurityContext|Authentication/.test(text)) return "代码中有鉴权引用"
  return undefined
}

async function extractSecurityMechanisms(root: string): Promise<SecurityMechanism[]> {
  const mechanisms: SecurityMechanism[] = []

  async function scan(dir: string) {
    for await (const entry of new Bun.Glob("**/*.java").scan({ cwd: dir, dot: false })) {
      const fullPath = resolve(dir, entry)
      try {
        const text = await Bun.file(fullPath).text()
        for (const rule of JAVA_AUTH_PATTERNS) {
          for (const m of text.matchAll(new RegExp(rule.pattern.source, "g"))) {
            mechanisms.push({
              kind: rule.kind,
              name: entry,
              sourceFile: relative(root, fullPath),
              line: lineNumberAt(text, m.index ?? 0),
              detail: ("detail" in rule ? rule.detail : m[0]) ?? "",
            })
          }
        }
      } catch {
        // skip
      }
    }
  }

  try {
    await scan(root)
  } catch {
    // ignore
  }
  return mechanisms.slice(0, 100)
}

function lineNumberAt(text: string, index: number): number {
  return text.slice(0, index).split("\n").length
}

function dataFlowSummary(profile: { dependencies: DependencyFingerprint[]; routes: RouteEntry[] }): string[] {
  const summary: string[] = []
  const highRiskLibs = profile.dependencies.filter((d) => isHighRiskDep(d.name))
  if (highRiskLibs.length > 0) {
    summary.push(`检测到 ${highRiskLibs.length} 个高危组件依赖：${highRiskLibs.map((d) => d.name).join("、")}`)
  }
  if (profile.routes.length > 0) {
    summary.push(`发现 ${profile.routes.length} 个 HTTP 路由入口，Controller/Servlet/JSP 是主要攻击面来源。`)
  }
  if (highRiskLibs.length > 0 && profile.routes.length > 0) {
    summary.push("高危链路方向：HTTP Request → Controller/Servlet/JSP → Service/DAO/Util → Sink")
  }
  return summary
}

export async function analyzeProject(target: string, projectName?: string): Promise<ProjectProfile> {
  const root = resolve(target)
  const name = projectName ?? basename(root)
  const allFiles = await walkFiles(root)

  const language = detectLanguage(allFiles)
  const fileStats = buildFileStats(allFiles)
  const buildFiles = detectBuildFiles(allFiles, root)
  const directories = detectDirectories(allFiles, root)

  // Parse dependencies
  let dependencies: DependencyFingerprint[] = []
  for (const f of allFiles) {
    if (f.endsWith("pom.xml")) {
      dependencies.push(...(await parseMavenDeps(f, root)))
    }
    if (f.endsWith("package.json")) {
      try {
        const pkg = await Bun.file(f).json() as { dependencies?: Record<string, string>; devDependencies?: Record<string, string> }
        for (const [name, version] of Object.entries({ ...pkg.dependencies, ...pkg.devDependencies })) {
          dependencies.push({ ecosystem: "npm", name, version, sourceFile: relative(root, f) })
        }
      } catch { /* ignore */ }
    }
  }

  const routes = language === "java" ? await extractRoutes(root, allFiles) : []
  const securityMechanisms = language === "java" ? await extractSecurityMechanisms(root) : []
  const highRiskFiles = sortJavaAuditFiles(root, allFiles
    .filter((f) => /\.(java|jsp|jspx|xml|properties|ya?ml)$/i.test(f))
    .filter((f) => javaAuditFileScore(root, f) > 0))
    .slice(0, 180)
    .map((f) => relative(root, f))

  return {
    name,
    root,
    language,
    buildFiles,
    directories,
    fileStats,
    dependencies,
    routes,
    securityMechanisms,
    dataFlowSummary: dataFlowSummary({ dependencies, routes }),
    highRiskFiles,
  }
}
