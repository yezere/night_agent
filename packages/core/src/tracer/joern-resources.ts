import { readFileSync } from "node:fs"
import { cpus, totalmem } from "node:os"

export const JAVA_HOME = process.env.JAVA_HOME || "/usr/lib/jvm/java-17-openjdk-amd64"

export interface JoernResourcePlan {
  totalMemoryMb: number
  cpuCount: number
  traceConcurrency: number
  heapMb: number
  activeProcessorCount: number
  javaToolOptions: string
}

let cachedPlan: JoernResourcePlan | null = null
let cachedPlanKey = ""

export function detectJoernResourcePlan(): JoernResourcePlan {
  const planKey = [
    process.env.NIGHT_AGENT_TRACE_CONCURRENCY ?? "",
    process.env.NIGHT_AGENT_JOERN_XMX_MB ?? "",
    process.env.NIGHT_AGENT_JOERN_ACTIVE_PROCESSORS ?? "",
    process.env.NIGHT_AGENT_JOERN_JAVA_TOOL_OPTIONS ?? "",
    process.env.JAVA_TOOL_OPTIONS ?? "",
  ].join("|")
  if (cachedPlan && cachedPlanKey === planKey) return cachedPlan

  const totalMemoryMb = readSystemMemoryMb()
  const cpuCount = Math.max(1, cpus().length)
  const autoConcurrency = chooseTraceConcurrency(totalMemoryMb, cpuCount)
  const traceConcurrency = clampInt(readPositiveIntEnv("NIGHT_AGENT_TRACE_CONCURRENCY", autoConcurrency), 1, 5)
  const heapMb = chooseHeapMb(totalMemoryMb, traceConcurrency)
  const activeProcessorCount = chooseActiveProcessorCount(cpuCount, traceConcurrency)
  const javaToolOptions = buildJavaToolOptions(heapMb, activeProcessorCount)

  cachedPlan = {
    totalMemoryMb,
    cpuCount,
    traceConcurrency,
    heapMb,
    activeProcessorCount,
    javaToolOptions,
  }
  cachedPlanKey = planKey
  return cachedPlan
}

export function buildJoernEnv(): Record<string, string | undefined> {
  const plan = detectJoernResourcePlan()
  return {
    ...process.env,
    JAVA_HOME,
    PATH: `${JAVA_HOME}/bin:${process.env.PATH}`,
    JAVA_TOOL_OPTIONS: plan.javaToolOptions,
  }
}

export function stopChildProcess(proc: { pid?: number; kill: (signal?: number | NodeJS.Signals) => void }): void {
  if (typeof proc.pid === "number" && proc.pid > 0) {
    killProcessTree(proc.pid, "SIGTERM")
  } else {
    try {
      proc.kill("SIGTERM")
    } catch {
      // Process may already have exited.
    }
  }
  setTimeout(() => {
    if (typeof proc.pid === "number" && proc.pid > 0) {
      killProcessTree(proc.pid, "SIGKILL")
    } else {
      try {
        proc.kill("SIGKILL")
      } catch {
        // Process may already have exited.
      }
    }
  }, 3_000)
}

function killProcessTree(pid: number, signal: NodeJS.Signals): void {
  for (const child of childPids(pid)) {
    killProcessTree(child, signal)
  }
  try {
    process.kill(pid, signal)
  } catch {
    // Process may already have exited.
  }
}

function childPids(pid: number): number[] {
  try {
    const proc = Bun.spawnSync(["pgrep", "-P", String(pid)], {
      stdout: "pipe",
      stderr: "ignore",
    })
    return new TextDecoder()
      .decode(proc.stdout)
      .split(/\s+/)
      .map((value) => Number(value))
      .filter((value) => Number.isInteger(value) && value > 0)
  } catch {
    return []
  }
}

function chooseTraceConcurrency(totalMemoryMb: number, cpuCount: number): number {
  if (totalMemoryMb < 24_000) return 1
  if (totalMemoryMb < 64_000) return Math.min(2, Math.max(1, Math.floor(cpuCount / 4)))
  return Math.min(3, Math.max(1, Math.floor(cpuCount / 4)))
}

function chooseHeapMb(totalMemoryMb: number, traceConcurrency: number): number {
  const override = readPositiveIntEnv("NIGHT_AGENT_JOERN_XMX_MB", 0)
  if (override > 0) return override

  const safeBudgetMb = Math.floor(totalMemoryMb * 0.6)
  const perProcessBudgetMb = Math.floor(safeBudgetMb / Math.max(1, traceConcurrency))
  const targetMb =
    totalMemoryMb < 12_000 ? 2_048 :
      totalMemoryMb < 24_000 ? 2_560 :
        totalMemoryMb < 64_000 ? 3_072 :
          4_096
  return clampInt(Math.min(targetMb, perProcessBudgetMb), 1_536, 8_192)
}

function chooseActiveProcessorCount(cpuCount: number, traceConcurrency: number): number {
  const override = readPositiveIntEnv("NIGHT_AGENT_JOERN_ACTIVE_PROCESSORS", 0)
  if (override > 0) return override
  return clampInt(Math.floor(cpuCount / Math.max(1, traceConcurrency * 4)), 1, 4)
}

function buildJavaToolOptions(heapMb: number, activeProcessorCount: number): string {
  const explicit = process.env.NIGHT_AGENT_JOERN_JAVA_TOOL_OPTIONS
  if (explicit && explicit.trim()) return explicit.trim()

  const existing = process.env.JAVA_TOOL_OPTIONS?.trim() ?? ""
  const options = existing ? existing.split(/\s+/) : []
  const text = ` ${existing} `
  if (!/\s-Xmx/i.test(text)) options.push(`-Xmx${heapMb}m`)
  if (!/\s-XX:\+ExitOnOutOfMemoryError\s/.test(text)) options.push("-XX:+ExitOnOutOfMemoryError")
  if (!/\s-XX:\+UseG1GC\s/.test(text) && !/\s-XX:\+UseSerialGC\s/.test(text)) options.push("-XX:+UseG1GC")
  if (!/\s-XX:ActiveProcessorCount=/i.test(text)) options.push(`-XX:ActiveProcessorCount=${activeProcessorCount}`)
  return options.join(" ").trim()
}

function readSystemMemoryMb(): number {
  try {
    const text = readFileSync("/proc/meminfo", "utf-8")
    const match = /^MemTotal:\s+(\d+)\s+kB/m.exec(text)
    if (match?.[1]) return Math.max(1, Math.floor(Number(match[1]) / 1024))
  } catch {
    // Fall back to Node's os.totalmem().
  }
  return Math.max(1, Math.floor(totalmem() / 1_048_576))
}

function readPositiveIntEnv(name: string, fallback: number): number {
  const raw = process.env[name]
  if (!raw) return fallback
  const parsed = parseInt(raw, 10)
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback
}

function clampInt(value: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, value))
}
