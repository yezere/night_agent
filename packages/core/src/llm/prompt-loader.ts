import { resolve, dirname } from "node:path"
import { readFileSync, existsSync } from "node:fs"

const SKILLS_DIR = resolve(import.meta.dir, "../../../../skills")

interface PromptTemplate {
  system: string
  user: string
}

/**
 * Load a prompt template from a Markdown file.
 *
 * Format: YAML frontmatter (name, description) followed by the prompt body.
 * The body is split into system (before first --- on its own line) and user (after).
 * Supports {{key}} template variable substitution.
 */
export function loadPrompt(skill: string, name: string, vars: Record<string, string> = {}): PromptTemplate | null {
  const path = resolve(SKILLS_DIR, skill, "prompts", `${name}.md`)
  try {
    if (!existsSync(path)) return null
    const raw = readFileSync(path, "utf-8")
    return parsePromptFile(raw, vars)
  } catch {
    return null
  }
}

function parsePromptFile(raw: string, vars: Record<string, string>): PromptTemplate {
  // Strip YAML frontmatter (between --- and ---)
  let body = raw
  if (body.startsWith("---")) {
    const end = body.indexOf("---", 3)
    if (end !== -1) body = body.slice(end + 3).trim()
  }

  // Split on "---" line to separate system from user prompt
  const parts = body.split(/\n---\n/)
  const system = interpolate(parts[0]?.trim() ?? "", vars)
  const user = interpolate(parts.slice(1).join("\n---\n").trim(), vars)

  return { system, user }
}

function interpolate(text: string, vars: Record<string, string>): string {
  let result = text
  for (const [key, value] of Object.entries(vars)) {
    result = result.replaceAll(`{{${key}}}`, value)
  }
  return result
}

/**
 * Try loading from external file; return null if not found (caller falls back to builtin).
 */
export function tryLoadPrompt(skill: string, name: string, vars: Record<string, string> = {}): PromptTemplate | null {
  return loadPrompt(skill, name, vars)
}
