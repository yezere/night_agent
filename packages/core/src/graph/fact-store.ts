import type { Finding } from "../types/index.ts"
import { graphStoreScopeOrDefault } from "./store-scope.ts"

const defaultFacts = {
  facts: new Map<string, Finding>(),
  byCategory: new Map<string, Finding[]>(),
  bySeverity: new Map<string, Finding[]>(),
  byFile: new Map<string, Finding[]>(),
}

function store(): typeof defaultFacts {
  return graphStoreScopeOrDefault("fact-store")?.facts ?? defaultFacts
}

function id(): string {
  return `fact-${crypto.randomUUID().slice(0, 8)}`
}

export function addFinding(finding: Omit<Finding, "id" | "createdAt">): Finding {
  const f: Finding = { ...finding, id: id(), createdAt: Date.now() }
  const current = store()
  current.facts.set(f.id, f)
  index(f, current)
  return f
}

function index(f: Finding, current = store()) {
  const cat = f.category
  if (!current.byCategory.has(cat)) current.byCategory.set(cat, [])
  current.byCategory.get(cat)!.push(f)

  const sev = f.severity
  if (!current.bySeverity.has(sev)) current.bySeverity.set(sev, [])
  current.bySeverity.get(sev)!.push(f)

  const file = f.sink.file
  if (!current.byFile.has(file)) current.byFile.set(file, [])
  current.byFile.get(file)!.push(f)
}

export function getFinding(id: string): Finding | undefined {
  return store().facts.get(id)
}

export function getAllFindings(): Finding[] {
  return [...store().facts.values()]
}

export function getByCategory(category: string): Finding[] {
  return store().byCategory.get(category) ?? []
}

export function getBySeverity(severity: string): Finding[] {
  return store().bySeverity.get(severity) ?? []
}

export function getByFile(file: string): Finding[] {
  return store().byFile.get(file) ?? []
}

export function getConfirmedFindings(): Finding[] {
  return [...store().facts.values()].filter((f) => f.status === "confirmed")
}

export function updateFindingStatus(id: string, status: Finding["status"]): boolean {
  const f = store().facts.get(id)
  if (!f) return false
  f.status = status
  return true
}

export function clear() {
  const current = store()
  current.facts.clear()
  current.byCategory.clear()
  current.bySeverity.clear()
  current.byFile.clear()
}

export function restore(items: Finding[]): void {
  clear()
  const current = store()
  for (const item of items) {
    current.facts.set(item.id, item)
    index(item, current)
  }
}
