import type { ReactNode } from "react"

function splitTableRow(line: string): string[] {
  return line.trim().replace(/^\|/, "").replace(/\|$/, "").split("|").map((cell) => cell.trim())
}

function inline(text: string, keyPrefix: string): ReactNode[] {
  const parts = text.split(/(`[^`]+`|\*\*[^*]+\*\*)/g).filter(Boolean)
  return parts.map((part, index) => {
    if (part.startsWith("`") && part.endsWith("`")) return <code key={`${keyPrefix}-code-${index}`}>{part.slice(1, -1)}</code>
    if (part.startsWith("**") && part.endsWith("**")) return <strong key={`${keyPrefix}-strong-${index}`}>{part.slice(2, -2)}</strong>
    return part
  })
}

export function renderMarkdown(markdown: string): ReactNode[] {
  const lines = markdown.split("\n")
  const nodes: ReactNode[] = []
  let index = 0
  let key = 0

  while (index < lines.length) {
    const line = (lines[index] ?? "").trimEnd()
    if (!line.trim()) {
      index += 1
      continue
    }

    if (line.trim().startsWith("```")) {
      const lang = line.trim().slice(3).trim()
      const code: string[] = []
      index += 1
      while (index < lines.length && !(lines[index] ?? "").trim().startsWith("```")) {
        code.push(lines[index] ?? "")
        index += 1
      }
      if (index < lines.length) index += 1
      nodes.push(<pre key={`md-${key++}`} data-lang={lang || undefined}><code>{code.join("\n")}</code></pre>)
      continue
    }

    const heading = line.match(/^(#{1,4})\s+(.+)$/)
    if (heading) {
      const level = (heading[1] ?? "").length
      const body = inline(heading[2] ?? "", `md-${key}`)
      if (level === 1) nodes.push(<h1 key={`md-${key++}`}>{body}</h1>)
      else if (level === 2) nodes.push(<h2 key={`md-${key++}`}>{body}</h2>)
      else if (level === 3) nodes.push(<h3 key={`md-${key++}`}>{body}</h3>)
      else nodes.push(<h4 key={`md-${key++}`}>{body}</h4>)
      index += 1
      continue
    }

    if (line.trim() === "---") {
      nodes.push(<hr key={`md-${key++}`} />)
      index += 1
      continue
    }

    if (line.trim().startsWith("|") && index + 1 < lines.length && /^\s*\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)+\|?\s*$/.test(lines[index + 1] ?? "")) {
      const headers = splitTableRow(line)
      const rows: string[][] = []
      index += 2
      while (index < lines.length && (lines[index] ?? "").trim().startsWith("|")) {
        rows.push(splitTableRow(lines[index] ?? ""))
        index += 1
      }
      nodes.push(
        <div key={`md-${key++}`} className="markdown-table-wrap">
          <table>
            <thead><tr>{headers.map((cell, i) => <th key={i}>{inline(cell, `h-${key}-${i}`)}</th>)}</tr></thead>
            <tbody>{rows.map((row, r) => <tr key={r}>{row.map((cell, c) => <td key={c}>{inline(cell, `c-${key}-${r}-${c}`)}</td>)}</tr>)}</tbody>
          </table>
        </div>,
      )
      continue
    }

    if (/^\s*[-*]\s+/.test(line)) {
      const items: string[] = []
      while (index < lines.length && /^\s*[-*]\s+/.test(lines[index] ?? "")) {
        items.push((lines[index] ?? "").replace(/^\s*[-*]\s+/, ""))
        index += 1
      }
      nodes.push(<ul key={`md-${key++}`}>{items.map((item, i) => <li key={i}>{inline(item, `li-${key}-${i}`)}</li>)}</ul>)
      continue
    }

    if (/^\s*\d+\.\s+/.test(line)) {
      const items: string[] = []
      while (index < lines.length && /^\s*\d+\.\s+/.test(lines[index] ?? "")) {
        items.push((lines[index] ?? "").replace(/^\s*\d+\.\s+/, ""))
        index += 1
      }
      nodes.push(<ol key={`md-${key++}`}>{items.map((item, i) => <li key={i}>{inline(item, `oli-${key}-${i}`)}</li>)}</ol>)
      continue
    }

    if (line.trim().startsWith(">")) {
      const quotes: string[] = []
      while (index < lines.length && (lines[index] ?? "").trim().startsWith(">")) {
        quotes.push((lines[index] ?? "").replace(/^\s*>\s?/, ""))
        index += 1
      }
      nodes.push(<blockquote key={`md-${key++}`}>{quotes.map((q, i) => <p key={i}>{inline(q, `q-${key}-${i}`)}</p>)}</blockquote>)
      continue
    }

    const paragraph = [line.trim()]
    index += 1
    while (
      index < lines.length &&
      (lines[index] ?? "").trim() &&
      !/^(#{1,4})\s+/.test(lines[index] ?? "") &&
      !(lines[index] ?? "").trim().startsWith("```") &&
      !(lines[index] ?? "").trim().startsWith("|") &&
      !/^\s*[-*]\s+/.test(lines[index] ?? "") &&
      !/^\s*\d+\.\s+/.test(lines[index] ?? "") &&
      !(lines[index] ?? "").trim().startsWith(">")
    ) {
      paragraph.push((lines[index] ?? "").trim())
      index += 1
    }
    nodes.push(<p key={`md-${key++}`}>{inline(paragraph.join(" "), `p-${key}`)}</p>)
  }

  return nodes
}
