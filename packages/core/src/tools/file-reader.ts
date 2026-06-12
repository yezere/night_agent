import type { CodeSnippet } from "../types/index.ts"

export async function readSnippet(
  filePath: string,
  targetLine: number,
  contextLines: number = 5,
): Promise<CodeSnippet | null> {
  try {
    const f = Bun.file(filePath)
    if (!(await f.exists())) return null

    const content = await f.text()
    const allLines = content.split("\n")

    const startLine = Math.max(1, targetLine - contextLines)
    const endLine = Math.min(allLines.length, targetLine + contextLines)

    const methodContext = extractMethodName(allLines, targetLine)

    const lines: string[] = []
    for (let i = startLine; i <= endLine; i++) {
      const code = allLines[i - 1] ?? ""
      const marker = i === targetLine ? ">>>" : "   "
      lines.push(`${marker} ${i}|${code}`)
    }

    return {
      file: filePath,
      targetLine,
      startLine,
      endLine,
      lines,
      methodContext,
    }
  } catch {
    return null
  }
}

export async function readMultipleSnippets(
  entries: Array<{ file: string; line: number }>,
  contextLines: number = 5,
): Promise<Map<string, CodeSnippet>> {
  const results = new Map<string, CodeSnippet>()
  for (const entry of entries) {
    const snippet = await readSnippet(entry.file, entry.line, contextLines)
    if (snippet) results.set(`${entry.file}:${entry.line}`, snippet)
  }
  return results
}

function extractMethodName(lines: string[], line: number): string | undefined {
  // Walk backwards from target line to find method declaration
  for (let i = line - 1; i >= Math.max(0, line - 50); i--) {
    const l = lines[i]?.trim() ?? ""
    // Match Java method declarations
    const m = l.match(
      /(?:public|private|protected|static|\s)+\s+[\w<>\[\],\s]+\s+(\w+)\s*\([^)]*\)\s*(?:throws\s+[\w\s,]+)?\s*\{?/,
    )
    if (m?.[1]) return m[1]
    // Match annotations preceding method
    if (l.startsWith("@") && !l.includes("(")) continue
  }
  return undefined
}

export function formatSnippetForLLM(snippet: CodeSnippet): string {
  let out = `File: ${snippet.file}\n`
  if (snippet.methodContext) out += `Method: ${snippet.methodContext}()\n`
  out += `Lines ${snippet.startLine}-${snippet.endLine}:\n\n`
  out += snippet.lines.join("\n")
  return out
}
