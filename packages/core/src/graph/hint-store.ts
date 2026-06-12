import type { Note } from "../types/index.ts"
import { graphStoreScopeOrDefault } from "./store-scope.ts"

const defaultNotes = new Map<string, Note>()

function notes(): Map<string, Note> {
  return graphStoreScopeOrDefault("hint-store")?.notes.notes ?? defaultNotes
}

function id(): string {
  return `note-${crypto.randomUUID().slice(0, 8)}`
}

export function addNote(content: string, source: Note["source"], relatedIds: string[] = []): Note {
  const n: Note = { id: id(), content, source, relatedHypothesisIds: relatedIds }
  notes().set(n.id, n)
  return n
}

export function getAllNotes(): Note[] {
  return [...notes().values()]
}

export function getByHypothesis(hypothesisId: string): Note[] {
  return [...notes().values()].filter((n) => n.relatedHypothesisIds.includes(hypothesisId))
}

export function clear() {
  notes().clear()
}

export function restore(items: Note[]): void {
  const current = notes()
  current.clear()
  for (const item of items) {
    current.set(item.id, item)
  }
}
