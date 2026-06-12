export interface ContextualReadOptions {
  patterns: RegExp[]
  maxWholeChars?: number
  maxInMemoryBytes?: number
  maxWindowChars?: number
  windowRadius?: number
  fallbackHeadChars?: number
}

const DEFAULT_MAX_WHOLE_CHARS = 180_000
const DEFAULT_MAX_IN_MEMORY_BYTES = 4_000_000
const DEFAULT_MAX_WINDOW_CHARS = 80_000
const DEFAULT_WINDOW_RADIUS = 18
const DEFAULT_FALLBACK_HEAD_CHARS = 80_000

export async function readContextualFile(file: string, options: ContextualReadOptions): Promise<string | null> {
  const stat = await Bun.file(file).stat()
  const maxWholeChars = options.maxWholeChars ?? DEFAULT_MAX_WHOLE_CHARS
  const maxInMemoryBytes = options.maxInMemoryBytes ?? DEFAULT_MAX_IN_MEMORY_BYTES

  if (stat.size <= maxWholeChars) {
    return Bun.file(file).text()
  }

  if (stat.size <= maxInMemoryBytes) {
    const text = await Bun.file(file).text()
    const windowed = buildWindowedContent(text, options)
    return windowed || `${text.slice(0, options.fallbackHeadChars ?? DEFAULT_FALLBACK_HEAD_CHARS)}\n/* clipped: no source/sink keyword window found */`
  }

  const streamWindowed = await streamWindowedContent(file, options)
  return streamWindowed || null
}

function buildWindowedContent(text: string, options: ContextualReadOptions): string {
  const lines = text.split("\n")
  const ranges: Array<[number, number]> = []
  const radius = options.windowRadius ?? DEFAULT_WINDOW_RADIUS

  lines.forEach((line, index) => {
    if (!matchesAny(line, options.patterns)) return
    const lineNo = index + 1
    ranges.push([Math.max(1, lineNo - radius), Math.min(lines.length, lineNo + radius)])
  })

  return renderRanges(lines, ranges, options.maxWindowChars ?? DEFAULT_MAX_WINDOW_CHARS)
}

async function streamWindowedContent(file: string, options: ContextualReadOptions): Promise<string> {
  const decoder = new TextDecoder()
  const radius = options.windowRadius ?? DEFAULT_WINDOW_RADIUS
  const maxChars = options.maxWindowChars ?? DEFAULT_MAX_WINDOW_CHARS
  const output: string[] = []
  const before: Array<{ lineNo: number; text: string }> = []
  let carry = ""
  let lineNo = 0
  let captureUntil = 0
  let lastAdded = 0
  let total = 0

  const addLine = (currentLineNo: number, text: string) => {
    if (total >= maxChars) return
    if (currentLineNo > lastAdded + 1 && output.length > 0) {
      const gap = "/* ... clipped ... */"
      output.push(gap)
      total += gap.length + 1
    }
    const rendered = renderLine(currentLineNo, text)
    output.push(rendered)
    total += rendered.length + 1
    lastAdded = currentLineNo
  }

  const processLine = (line: string) => {
    lineNo += 1
    const matched = matchesAny(line, options.patterns)
    if (matched) {
      for (const prev of before) addLine(prev.lineNo, prev.text)
      captureUntil = Math.max(captureUntil, lineNo + radius)
    }
    if (matched || lineNo <= captureUntil) addLine(lineNo, line)
    before.push({ lineNo, text: line })
    while (before.length > radius) before.shift()
  }

  for await (const chunk of Bun.file(file).stream()) {
    const text = carry + decoder.decode(chunk, { stream: true })
    const lines = text.split(/\r?\n/)
    carry = lines.pop() ?? ""
    for (const line of lines) {
      processLine(line)
      if (total >= maxChars) return output.join("\n")
    }
  }

  const tail = carry + decoder.decode()
  if (tail) processLine(tail)
  return output.join("\n")
}

function renderRanges(lines: string[], ranges: Array<[number, number]>, maxChars: number): string {
  const merged = mergeRanges(ranges)
  const output: string[] = []
  let total = 0
  let previousEnd = 0

  for (const [start, end] of merged) {
    if (total >= maxChars) break
    if (previousEnd > 0 && start > previousEnd + 1) {
      const gap = "/* ... clipped ... */"
      output.push(gap)
      total += gap.length + 1
    }
    for (let lineNo = start; lineNo <= end; lineNo++) {
      const rendered = renderLine(lineNo, lines[lineNo - 1] ?? "")
      output.push(rendered)
      total += rendered.length + 1
      if (total >= maxChars) break
    }
    previousEnd = end
  }

  return output.join("\n")
}

function mergeRanges(ranges: Array<[number, number]>): Array<[number, number]> {
  const sorted = ranges.sort((a, b) => a[0] - b[0])
  const merged: Array<[number, number]> = []
  for (const range of sorted) {
    const last = merged[merged.length - 1]
    if (!last || range[0] > last[1] + 1) {
      merged.push([...range])
    } else {
      last[1] = Math.max(last[1], range[1])
    }
  }
  return merged
}

function renderLine(lineNo: number, text: string): string {
  const clipped = text.length > 2_000 ? `${text.slice(0, 2_000)} /* line clipped */` : text
  return `/*L${lineNo}*/ ${clipped}`
}

function matchesAny(line: string, patterns: RegExp[]): boolean {
  return patterns.some((pattern) => {
    pattern.lastIndex = 0
    return pattern.test(line)
  })
}
