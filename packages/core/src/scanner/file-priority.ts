import { basename, relative } from "node:path"

export function configuredAgentFileLimit(envName: string, fallback: number, min: number, max: number): number {
  const raw = process.env[envName]
  const parsed = raw ? parseInt(raw, 10) : fallback
  if (!Number.isFinite(parsed)) return fallback
  return Math.max(min, Math.min(max, parsed))
}

export function javaAuditFileScore(root: string, file: string): number {
  const rel = relative(root, file).toLowerCase()
  const name = basename(file).toLowerCase()
  let score = 0
  if (/\.(jsp|jspx)$/.test(rel)) score += 45
  if (/web-inf\/web\.xml$|struts.*\.xml$|tiles.*\.xml$|spring.*mvc.*\.xml$/.test(rel)) score += 40
  if (/controller|action|servlet|filter|listener|interceptor|endpoint|handler/.test(name)
    || /(^|\/)(controller|controllers|action|actions|servlet|servlets|filter|filters|listener|listeners|interceptor|interceptors)(\/|$)/.test(rel)) score += 35
  if (/upload|download|file|import|export|excel|template|report|redirect|callback|login|auth|sso/.test(rel)) score += 30
  if (/service|impl|manager|biz|facade|provider/.test(name)) score += 15
  if (/dao|mapper|repository|mybatis|sql/.test(rel)) score += 14
  if (/util|utils|json|xml|serialize|deser|jndi|cmd|exec|process|ognl|spel|security|shiro/.test(rel)) score += 14
  return score
}

export function sortJavaAuditFiles(root: string, files: Iterable<string>): string[] {
  return [...files].sort((a, b) => javaAuditFileScore(root, b) - javaAuditFileScore(root, a)
    || a.localeCompare(b))
}
