import { BaseSolver, type SolverContext } from "./base-solver.ts"
import { generateJoernQueriesWithTools } from "../llm/llm-runner.ts"
import { addEvent } from "../runtime/event-log.ts"
import { AuditWorkspace } from "../runtime/audit-workspace.ts"
import type { AuditOptions, ProjectProfile, SourceEntry } from "../types/index.ts"

export class JoernQueryAgent extends BaseSolver {
  private options: AuditOptions
  private profile: ProjectProfile
  private workspace: AuditWorkspace
  private sources: SourceEntry[]
  private cpgPath?: string
  private generatedScripts: string[] = []

  constructor(ctx: SolverContext, options: AuditOptions, profile: ProjectProfile, workspace: AuditWorkspace, sources: SourceEntry[], cpgPath?: string) {
    super(ctx)
    this.options = options
    this.profile = profile
    this.workspace = workspace
    this.sources = sources
    this.cpgPath = cpgPath
  }

  async start(): Promise<void> {
    this.setStatus("busy")
    await this.ensureQueries()
    this.setStatus("idle")
  }

  async stop(): Promise<void> {
    this.setStatus("idle")
  }

  scripts(): string[] {
    return this.generatedScripts
  }

  private async ensureQueries(): Promise<void> {
    if (this.options.runJoern === false) {
      this.log("joern query generation skipped by --no-joern")
      return
    }

    if (!this.options.llmConfig) {
      throw new Error("JoernQueryAgent requires an AI config")
    }

    const hypotheses = this.workspace.getHypotheses()
    addEvent("explore", "info", "JoernQueryAgent generating queries", `${hypotheses.length} sink(s), ${this.sources.length} source(s)`)
    this.log(`generating project-specific joern queries from ${this.sources.length} source(s) and ${hypotheses.length} sink(s)`)
    this.generatedScripts = await generateJoernQueriesWithTools(
      this.options.llmConfig,
      this.profile,
      hypotheses,
      this.sources,
      this.options.outputDir,
      this.cpgPath,
    )
    addEvent("explore", "success", "JoernQueryAgent queries generated", `${this.generatedScripts.length} script(s)`)
  }
}
