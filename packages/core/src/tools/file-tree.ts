import { extname, isAbsolute, relative, resolve } from "node:path"

export interface FileTreeToolCall {
  tool: "file_tree" | "list_files"
  pattern?: string
  globs?: string[] | string
  maxResults?: number
}

interface FileTreeEntry {
  file: string
  score: number
  size: number
}

export async function runFileTreeTool(root: string, call: FileTreeToolCall): Promise<string> {
  const max = clampNumber(call.maxResults, 1, 800, 220)
  const pattern = safeRegex(call.pattern)
  const globs = normalizeGlobs(call.globs)
  const entries: FileTreeEntry[] = []

  for await (const entry of new Bun.Glob("**/*").scan({ cwd: root, dot: false })) {
    if (shouldSkip(entry)) continue
    if (!matchesGlobs(entry, globs)) continue
    if (pattern && !pattern.test(entry)) continue
    const file = resolve(root, entry)
    try {
      const stat = await Bun.file(file).stat()
      if (!stat.isFile()) continue
      entries.push({ file: entry, score: riskScore(entry), size: stat.size })
    } catch {
      // ignore unreadable files
    }
  }

  entries.sort((a, b) => b.score - a.score || a.file.localeCompare(b.file))
  const lines = entries.slice(0, max).map((entry) => `${entry.file} | ${entryLabel(entry.file)} | ${(entry.size / 1024).toFixed(1)}KB`)
  return `[file_tree]\n${lines.join("\n") || "(no files)"}`
}

export async function compactProjectTree(root: string, maxResults: number = 180): Promise<string> {
  return runFileTreeTool(root, {
    tool: "file_tree",
    maxResults,
    globs: ["*.java", "*.jsp", "*.jspx", "*.xml", "*.properties", "*.yml", "*.yaml", "*.jar", "*.war", "*.zip"],
  })
}

function normalizeGlobs(value: unknown): string[] {
  if (Array.isArray(value)) {
    return value.filter((item): item is string => typeof item === "string" && item.trim().length > 0).slice(0, 16)
  }
  if (typeof value === "string" && value.trim()) return [value.trim()]
  return ["*.java", "*.jsp", "*.jspx", "*.xml", "*.properties", "*.yml", "*.yaml", "*.jar", "*.war", "*.zip"]
}

function matchesGlobs(file: string, globs: string[]): boolean {
  const ext = extname(file).replace(/^\./, "").toLowerCase()
  return globs.some((glob) => {
    const normalized = glob.replace(/^\*\./, "").toLowerCase()
    if (normalized === glob.toLowerCase()) return file.toLowerCase().includes(glob.replace(/\*/g, "").toLowerCase())
    return ext === normalized
  })
}

function shouldSkip(entry: string): boolean {
  return /(^|\/)(\.git|\.night-agent|\.night_agent|node_modules|target|build|dist|output-audit|archive-sources|archive-decompiled)(\/|$)/.test(entry)
}

function riskScore(file: string): number {
  const lower = file.toLowerCase()
  const name = lower.split("/").pop() ?? lower
  let score = 0
  if (/\.(java|jsp|jspx)$/.test(lower)) score += 20
  if (/\.(xml|properties|ya?ml)$/.test(lower)) score += 8
  if (/\.(jar|war|zip)$/.test(lower)) score += 6
  if (/controller|action|endpoint|servlet/.test(name) || /(^|\/)(controller|controllers|action|actions|endpoint|endpoints|servlet|servlets)(\/|$)/.test(lower)) score += 40
  if (/filter|interceptor|listener|advice|security|auth|login|sso|shiro|permission/.test(name) || /(^|\/)(filter|filters|interceptor|interceptors|listener|listeners|security|auth)(\/|$)/.test(lower)) score += 36
  if (/upload|download|file|import|export|excel|template|report/.test(lower)) score += 30
  if (/service|impl|manager|handler/.test(lower)) score += 18
  if (/mapper|dao|repository|mybatis|sql/.test(lower)) score += 18
  if (/util|utils|json|xml|serialize|deser|jndi|cmd|exec|process|ognl|spel/.test(lower)) score += 18
  if (/web-inf\/lib|\/lib\//.test(lower)) score += 12
  if (/-sources\.(jar|zip)$/.test(lower)) score += 20
  if (/code-template|template-online/.test(lower)) score -= 25
  return score
}

function entryLabel(file: string): string {
  const lower = file.toLowerCase()
  const name = lower.split("/").pop() ?? lower
  const labels: string[] = []
  if (/controller|action|endpoint/.test(name) || /(^|\/)(controller|controllers|action|actions|endpoint|endpoints)(\/|$)/.test(lower)) labels.push("controller")
  if (/servlet/.test(name) || /(^|\/)(servlet|servlets)(\/|$)/.test(lower)) labels.push("servlet")
  if (/filter|interceptor|listener/.test(name) || /(^|\/)(filter|filters|interceptor|interceptors|listener|listeners)(\/|$)/.test(lower)) labels.push("web-hook")
  if (/jsp|jspx/.test(lower)) labels.push("jsp")
  if (/mapper|dao|repository/.test(lower)) labels.push("data")
  if (/upload|download|file|import|export/.test(lower)) labels.push("file-flow")
  if (/security|auth|login|shiro|permission/.test(lower)) labels.push("auth")
  if (/\.(jar|war|zip)$/.test(lower)) labels.push("archive")
  return labels.join(",") || "file"
}

function safeRegex(pattern: unknown): RegExp | null {
  if (typeof pattern !== "string" || !pattern.trim()) return null
  try {
    return new RegExp(pattern, "i")
  } catch {
    return null
  }
}

function clampNumber(value: unknown, min: number, max: number, fallback: number): number {
  const parsed = typeof value === "number" ? value : parseInt(String(value ?? ""), 10)
  if (!Number.isFinite(parsed)) return fallback
  return Math.max(min, Math.min(max, parsed))
}

export function constrainTreePath(root: string, file: string): string | null {
  const target = isAbsolute(file) ? resolve(file) : resolve(root, file)
  const rel = relative(root, target)
  if (rel.startsWith("..") || isAbsolute(rel)) return null
  return target
}
