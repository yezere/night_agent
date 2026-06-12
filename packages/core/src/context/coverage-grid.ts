import type { CoverageGrid, CoverageDepth, CoverageUnit, CoverageStats } from "../types/index.ts"

export function createCoverageGrid(): CoverageGrid {
  return {
    totalUnits: 0,
    units: new Map(),
    byModule: new Map(),
  }
}

export function registerFile(grid: CoverageGrid, file: string, modules: string[]): CoverageUnit {
  const existing = grid.units.get(file)
  if (existing) {
    const previous = new Set(existing.modules?.length ? existing.modules : ["root"])
    existing.modules = mergeModules(existing.modules, modules)
    for (const mod of existing.modules) {
      if (previous.has(mod)) continue
      const stats = grid.byModule.get(mod)
      if (stats) {
        stats.total++
        stats[existing.depth]++
      } else {
        grid.byModule.set(mod, {
          total: 1,
          unvisited: existing.depth === "unvisited" ? 1 : 0,
          scanned: existing.depth === "scanned" ? 1 : 0,
          traced: existing.depth === "traced" ? 1 : 0,
          verified: existing.depth === "verified" ? 1 : 0,
        })
      }
    }
    return existing
  }

  const unit: CoverageUnit = {
    file,
    depth: "unvisited",
    hypothesisCount: 0,
    confirmedCount: 0,
    modules,
  }
  grid.units.set(file, unit)
  grid.totalUnits++

  for (const mod of modules.length > 0 ? modules : ["root"]) {
    const stats = grid.byModule.get(mod)
    if (stats) {
      stats.total++
      stats.unvisited++
    } else {
      grid.byModule.set(mod, { total: 1, unvisited: 1, scanned: 0, traced: 0, verified: 0 })
    }
  }
  return unit
}

function moveDepth(
  grid: CoverageGrid,
  file: string,
  from: CoverageDepth,
  to: CoverageDepth,
) {
  const unit = grid.units.get(file)
  if (!unit || unit.depth !== from) return
  unit.depth = to

  for (const mod of unit.modules?.length ? unit.modules : grid.byModule.keys()) {
    const stats = grid.byModule.get(mod)
    if (!stats || stats[from] <= 0) continue
    stats[from]--
    stats[to]++
  }
}

export function markScanned(grid: CoverageGrid, file: string) {
  moveDepth(grid, file, "unvisited", "scanned")
}

export function markRescanAttempt(grid: CoverageGrid, file: string, reason: string) {
  const unit = grid.units.get(file)
  if (!unit) return
  unit.rescanCount = (unit.rescanCount ?? 0) + 1
  unit.lastRescanAt = Date.now()
  unit.lastRescanReason = reason
  if (unit.depth === "unvisited") markScanned(grid, file)
}

export function markTraced(grid: CoverageGrid, file: string) {
  const unit = grid.units.get(file)
  if (!unit) return
  if (unit.depth === "unvisited") unit.depth = "traced"
  else moveDepth(grid, file, unit.depth, "traced")
}

export function markVerified(grid: CoverageGrid, file: string) {
  const unit = grid.units.get(file)
  if (!unit) return
  moveDepth(grid, file, unit.depth, "verified")
}

export function coveragePercent(grid: CoverageGrid): number {
  if (grid.totalUnits === 0) return 0
  let visited = 0
  for (const [, unit] of grid.units) {
    if (unit.depth !== "unvisited") visited++
  }
  return Math.round((visited / grid.totalUnits) * 100)
}

export function getCoverageGaps(grid: CoverageGrid): string[] {
  const gaps: string[] = []
  for (const [file, unit] of grid.units) {
    if (unit.depth === "unvisited") gaps.push(file)
  }
  return gaps
}

function mergeModules(existing: string[] | undefined, additions: string[]): string[] {
  const merged = new Set(existing?.length ? existing : ["root"])
  for (const addition of additions.length ? additions : ["root"]) merged.add(addition)
  return [...merged]
}
