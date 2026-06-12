import type { RipgrepMatch } from "../types/index.ts"

export interface RipgrepOptions {
  glob?: string // e.g. "*.java"
  maxDepth?: number
  ignoreCase?: boolean
  maxCount?: number
  contextLines?: number
  type?: string // rg --type
}

export async function ripgrepSearch(
  pattern: string,
  path: string,
  options: RipgrepOptions = {},
): Promise<RipgrepMatch[]> {
  const args: string[] = ["--json", "--no-heading", "--line-number"]

  if (options.glob) args.push("--glob", options.glob)
  if (options.maxDepth) args.push("--max-depth", String(options.maxDepth))
  if (options.ignoreCase !== false) args.push("--ignore-case")
  if (options.maxCount) args.push("--max-count", String(options.maxCount))
  if (options.contextLines) args.push("-C", String(options.contextLines))
  if (options.type) args.push("--type", options.type)

  args.push(pattern, path)

  try {
    const proc = Bun.spawn(["rg", ...args], {
      stdout: "pipe",
      stderr: "pipe",
    })
    const output = await new Response(proc.stdout).text()
    await proc.exited

    const lines = output.trim().split("\n").filter(Boolean)
    const matches: RipgrepMatch[] = []

    for (const line of lines) {
      try {
        const parsed = JSON.parse(line)
        if (parsed.type === "match") {
          const data = parsed.data
          matches.push({
            file: data.path.text,
            line: data.line_number,
            column: data.submatches?.[0]?.start ?? data.lines.text.indexOf(data.submatches?.[0]?.match?.text ?? ""),
            endLine: data.line_number,
            endColumn: (data.submatches?.[0]?.end ?? 0),
            match: data.submatches?.[0]?.match?.text ?? data.lines.text.trim(),
            context: data.lines.text.trim(),
          })
        }
      } catch {
        // Fallback: parse non-JSON output (rg without --json flag supported)
        const m = line.match(/^(.+?):(\d+):(\d+):(.+)$/)
        if (m) {
          matches.push({
            file: m[1]!,
            line: parseInt(m[2]!),
            column: parseInt(m[3]!),
            endLine: parseInt(m[2]!),
            endColumn: parseInt(m[3]!) + (m[4] ? m[4].length : 0),
            match: m[4]!,
            context: m[4]!,
          })
        }
      }
    }

    return matches
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err)
    if (msg.includes("No such file") || msg.includes("ENOENT")) {
      console.error(`  [ripgrep] rg not found. Install: apt install ripgrep or brew install ripgrep`)
      return []
    }
    throw err
  }
}

export async function rgAvailable(): Promise<boolean> {
  try {
    const proc = Bun.spawn(["rg", "--version"], { stdout: "pipe", stderr: "pipe" })
    await proc.exited
    return proc.exitCode === 0
  } catch {
    return false
  }
}
