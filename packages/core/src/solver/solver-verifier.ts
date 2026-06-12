import { relative, resolve } from "node:path"
import { readdirSync, statSync } from "node:fs"
import { BaseSolver, type SolverContext } from "./base-solver.ts"
import { verifyHypothesisBatchWithLLM, verifyHypothesisWithLLM, type SourceFileCandidate } from "../llm/llm-runner.ts"
import { readContextualFile } from "../utils/contextual-file.ts"
import { verifierChallengeForVerdict } from "../policies/verifier-integrity.ts"
import { buildVerifierEvidencePack } from "../graph/evidence-graph.ts"
import { addEvent } from "../runtime/event-log.ts"
import { saveCheckpoint } from "../runtime/checkpoint-store.ts"
import { AuditWorkspace } from "../runtime/audit-workspace.ts"
import type { AuditOptions, EvidenceBundle, Hypothesis, ProjectProfile, VerifierVerdict } from "../types/index.ts"
import { compareSeverity } from "../types/index.ts"
import { buildVerifierPriorityPlan, VERIFIER_HIGH_VALUE_CATEGORIES, type VerifierPriorityItem } from "./verifier-priority.ts"

const VERIFIER_CONTEXT_PATTERNS = [
  /@RequestMapping|@GetMapping|@PostMapping|@PutMapping|@DeleteMapping|@PatchMapping/,
  /@RequestParam|@RequestBody|@PathVariable|getParameter|getHeader|getInputStream|getReader|MultipartFile/,
  /Runtime\.getRuntime|ProcessBuilder|executeSql|findHql|createQuery|Statement|PreparedStatement|\$\{|#\{/,
  /new\s+File|FileUtil|Paths\.get|Files\.|getOriginalFilename|transferTo|encodingFilename|hash|Md5|canonical|normalize/i,
  /Template|\.process|noticeContent|iframe|freemarker|velocity/i,
  /parseObject|parseArray|readObject|autoType|JSONUtil|fastjson|hutool|redis/i,
  /OutputStream|ServletOutputStream|FileInputStream|InputStreamResource|ByteArrayResource|captcha|download/i,
  /StrictHttpFirewall|HttpFirewall|allowUrlEncodedSlash|ALLOW_ENCODED_SLASH|UrlPathHelper|PathPatternParser|encoded slash/i,
  /sanitize|escape|validate|whitelist|blacklist|permission|auth|PreAuthorize|RequiresPermissions/i,
]

export interface VerificationSummary {
  total: number
  confirmed: number
  dismissed: number
  revisit: number
  failed: number
}

export class SolverVerifier extends BaseSolver {
  private options: AuditOptions
  private profile: ProjectProfile
  private workspace: AuditWorkspace
  private cpgPath?: string
  private summary: VerificationSummary = { total: 0, confirmed: 0, dismissed: 0, revisit: 0, failed: 0 }

  constructor(ctx: SolverContext, options: AuditOptions, profile: ProjectProfile, workspace: AuditWorkspace, cpgPath?: string) {
    super(ctx)
    this.options = options
    this.profile = profile
    this.workspace = workspace
    this.cpgPath = cpgPath
  }

  async start(): Promise<void> {
    this.setStatus("busy")
    try {
      this.summary = await this.verifyAll()
    } finally {
      this.setStatus("idle")
    }
  }

  getSummary(): VerificationSummary {
    return { ...this.summary }
  }

  async stop(): Promise<void> {
    this.setStatus("idle")
  }

  private async verifyAll(): Promise<VerificationSummary> {
    if (!this.options.llmConfig) {
      throw new Error("StaticVerifierAgent requires an AI config")
    }

    const allCandidates = this.verificationCandidates()
    const plan = this.planVerification(allCandidates)
    const deferredByTriage = this.applyTriageDeferrals(plan.deferred)
    const candidates = plan.selected.map((item) => item.hypothesis)
    const priorityScores = new Map(plan.selected.map((item) => [item.hypothesis.id, item.score]))
    const summary: VerificationSummary = {
      total: allCandidates.length,
      confirmed: 0,
      dismissed: 0,
      revisit: deferredByTriage,
      failed: 0,
    }
    if (plan.deferred.length > 0 || plan.selected.length !== allCandidates.length) {
      const deferredReasons = formatDeferredReasonCounts(plan.deferred)
      this.log(
        `observer verifier triage selected ${plan.selected.length}/${allCandidates.length} hypothesis/hypotheses ` +
        `(deferred ${plan.deferred.length}; ${deferredReasons}; duplicateGroups=${plan.duplicateGroups}, budget=${plan.maxSelected})`,
      )
      addEvent(
        "reason",
        plan.deferred.length > 0 ? "warn" : "info",
        "Observer verifier triage",
        `selected ${plan.selected.length}/${allCandidates.length}, deferred ${plan.deferred.length}, duplicate groups ${plan.duplicateGroups}`,
        plan.deferred.slice(0, 20).map((item) => item.hypothesis.id),
      )
    }
    if (plan.deferred.length > 0) {
      this.log(`observer verifier triage deferred reasons: ${formatDeferredReasonCounts(plan.deferred)}`)
      this.log(
        `observer verifier triage deferred sample: ${
          plan.deferred.slice(0, 8).map((item) => formatDeferredSample(item)).join(", ")
        }`,
      )
    }
    if (candidates.length === 0) return summary

    const groups = this.groupCandidates(candidates, priorityScores)
    this.log(`StaticVerifierAgent reviewing ${candidates.length}/${allCandidates.length} selected hypothesis/hypotheses in ${groups.length} group(s)`)
    addEvent("reason", "info", "StaticVerifierAgent started", `${candidates.length}/${allCandidates.length} selected candidate(s), ${groups.length} group(s)`)

    const concurrency = clampNumber(Number(process.env.NIGHT_AGENT_VERIFIER_CONCURRENCY), 1, 6, 3)
    let cursor = 0
    const workers = Array.from({ length: concurrency }, async () => {
      while (cursor < groups.length) {
        const group = groups[cursor++]!
        try {
          const verdicts = await this.verifyGroup(group)
          for (const verdict of verdicts) {
            summary[verdict.status === "confirmed" ? "confirmed" : verdict.status === "dismissed" ? "dismissed" : "revisit"]++
          }
        } catch (err) {
          const msg = err instanceof Error ? err.message : String(err)
          this.log(`verifier group failed for ${group.map((hyp) => hyp.id).join(",")}: ${msg}`)
          for (const hyp of group) {
            summary.failed++
            addEvent("reason", "warn", "StaticVerifierAgent item failed", `${hyp.id}: ${msg}`)
            const fallback = fallbackVerdict("maybe_revisit", `StaticVerifierAgent failed: ${msg}`)
            this.applyVerdict(hyp, fallback)
          }
        }
        const done = summary.confirmed + summary.dismissed + summary.revisit + summary.failed
        await saveCheckpoint(this.options.outputDir, "verifying", this.workspace.checkpointState(), {
          cursor: done,
          total: allCandidates.length,
          note: `verification progress: ${done}/${allCandidates.length}`,
        })
        const pauseReason = this.options.isPauseRequested?.()
        if (pauseReason) {
          addEvent("reason", "warn", "StaticVerifierAgent paused", pauseReason)
          throw new Error(`AUDIT_PAUSED:${pauseReason}`)
        }
        if (done % 5 === 0 || done === allCandidates.length) {
          this.log(`verification progress: ${done}/${allCandidates.length} (${cursor}/${groups.length} group cursor)`)
        }
      }
    })
    await Promise.all(workers)
    addEvent("reason", "success", "StaticVerifierAgent completed", `${summary.confirmed} confirmed, ${summary.dismissed} dismissed, ${summary.revisit} revisit`)
    return summary
  }

  private verificationCandidates(): Hypothesis[] {
    const allowed = new Set<Hypothesis["status"]>(["confirmed", "maybe_revisit", "pending", "tracing"])
    return this.workspace.getHypotheses()
      .filter((hyp) => allowed.has(hyp.status) && shouldVerifyCandidate(hyp))
      .sort((a, b) => {
        const highValue = (VERIFIER_HIGH_VALUE_CATEGORIES.has(a.category) ? 0 : 1) - (VERIFIER_HIGH_VALUE_CATEGORIES.has(b.category) ? 0 : 1)
        if (highValue !== 0) return highValue
        return compareSeverity(a.severity, b.severity)
          || a.sinkFile.localeCompare(b.sinkFile)
          || a.sinkLine - b.sinkLine
      })
  }

  private groupCandidates(candidates: Hypothesis[], priorityScores: Map<string, number> = new Map()): Hypothesis[][] {
    const groups: Hypothesis[][] = []
    const byBase = new Map<string, Hypothesis[]>()
    for (const hyp of candidates) {
      const bucket = Math.floor(Math.max(0, hyp.sinkLine) / 80)
      const key = `${hyp.category}:${hyp.sinkFile}:${bucket}`
      const list = byBase.get(key)
      if (list) list.push(hyp)
      else byBase.set(key, [hyp])
    }

    for (const list of byBase.values()) {
      list.sort((a, b) => (priorityScores.get(b.id) ?? 0) - (priorityScores.get(a.id) ?? 0) || a.sinkLine - b.sinkLine)
      for (let i = 0; i < list.length; i += 8) groups.push(list.slice(i, i + 8))
    }
    return groups.sort((a, b) => groupPriority(b, priorityScores) - groupPriority(a, priorityScores)
      || compareSeverity(a[0]!.severity, b[0]!.severity)
      || a[0]!.sinkFile.localeCompare(b[0]!.sinkFile)
      || a[0]!.sinkLine - b[0]!.sinkLine)
  }

  private planVerification(candidates: Hypothesis[]): ReturnType<typeof buildVerifierPriorityPlan> {
    if (process.env.NIGHT_AGENT_VERIFIER_TRIAGE === "0") {
      const items = candidates.map((hypothesis) => ({
        hypothesis,
        score: legacyPriorityScore(hypothesis),
        reasons: ["triage disabled"],
        identityKey: `${hypothesis.category}:${hypothesis.sinkFile}:${hypothesis.sinkLine}:${hypothesis.sinkPattern}`,
      }))
      return {
        selected: items,
        deferred: [],
        items,
        maxSelected: candidates.length,
        duplicateGroups: 0,
      }
    }
    return buildVerifierPriorityPlan({
      profile: this.profile,
      candidates,
      sources: this.workspace.getSources(),
      evidenceBundles: this.workspace.getEvidenceBundles(),
      maxSelected: envInt("NIGHT_AGENT_VERIFIER_MAX_CANDIDATES", undefined, 1, Math.max(1, candidates.length)),
      duplicateRepresentatives: envInt("NIGHT_AGENT_VERIFIER_DUP_REPRESENTATIVES", 1, 1, 4),
    })
  }

  private applyTriageDeferrals(deferred: VerifierPriorityItem[]): number {
    let applied = 0
    for (const item of deferred) {
      const verdict: VerifierVerdict = {
        status: "maybe_revisit",
        confidence: "low",
        reason: `Observer verifier triage deferred LLM review: ${item.deferredReason}. This is not a confirmation or dismissal; verify manually or raise NIGHT_AGENT_VERIFIER_MAX_CANDIDATES with NIGHT_AGENT_VERIFIER_RECHECK_DEFERRED=1 for a deeper pass.`,
        evidence: [],
        checkedFiles: [],
        toolCalls: [],
        sanitizerSummary: [],
        missingEvidence: ["StaticVerifierAgent code-reading review was deferred by priority triage."],
        recommendedStatus: "maybe_revisit",
        createdAt: Date.now(),
      }
      const updated = this.workspace.recordVerifierVerdict(item.hypothesis.id, verdict, "Observer verifier triage")
      if (!updated) continue
      this.emit("hypothesis:updated", updated)
      applied++
    }
    return applied
  }

  private async verifyGroup(group: Hypothesis[]): Promise<VerifierVerdict[]> {
    if (group.length === 1) return [await this.verifyOne(group[0]!)]
    const files = await this.loadVerificationFilesForGroup(group)
    const relSink = relative(this.profile.root, group[0]!.sinkFile)
    this.log(`reviewing group size=${group.length} category=${group[0]!.category} sink=${relSink} ids=${group.map((hyp) => hyp.id).join(",")}`)
    const items = group.map((hyp) => ({ hypothesis: hyp, bundle: this.workspace.getEvidenceBundle(hyp.id) }))
    const verdictMap = await verifyHypothesisBatchWithLLM(
      this.options.llmConfig!,
      this.profile,
      items,
      files,
      this.options.outputDir,
      this.cpgPath,
    )

    const verdicts: VerifierVerdict[] = []
    for (const hyp of group) {
      let verdict = verdictMap.get(hyp.id)
      if (!verdict) {
        this.log(`batch verifier missed ${hyp.id}; falling back to single verifier`)
        verdict = await this.verifyOne(hyp)
        verdicts.push(verdict)
        continue
      }
      this.log(
        `group verdict ${hyp.id}: ${verdict.status}/${verdict.confidence} checked=${verdict.checkedFiles.length} ` +
        `evidence=${verdict.evidence.length} sanitizers=${verdict.sanitizerSummary?.length ?? 0} missing=${verdict.missingEvidence?.length ?? 0}`,
      )
      verdict = await this.maybeChallengeVerdict(hyp, verdict, files)
      verdict = this.applyVerdict(hyp, verdict)
      verdicts.push(verdict)
    }
    return verdicts
  }

  private async verifyOne(hyp: Hypothesis): Promise<VerifierVerdict> {
    const bundle = this.workspace.getEvidenceBundle(hyp.id)
    const files = await this.loadVerificationFiles(hyp)
    const relSink = relative(this.profile.root, hyp.sinkFile)
    const sourceLinks = bundle?.sourceLinks ?? hyp.sourceLinks ?? []
    this.log(
      `reviewing ${hyp.id}: ${hyp.category}/${hyp.severity} origin=${hyp.origin ?? "unknown"} status=${hyp.status} ` +
      `sink=${relSink}:${hyp.sinkLine} sources=${sourceLinks.length} files=${files.length}`,
    )
    const verdict = await verifyHypothesisWithLLM(
      this.options.llmConfig!,
      this.profile,
      hyp,
      bundle,
      files,
      this.options.outputDir,
      this.cpgPath,
    ) ?? fallbackVerdict("maybe_revisit", "StaticVerifierAgent did not return a parseable verdict")

    this.log(
      `verdict ${hyp.id}: ${verdict.status}/${verdict.confidence} checked=${verdict.checkedFiles.length} ` +
      `evidence=${verdict.evidence.length} sanitizers=${verdict.sanitizerSummary?.length ?? 0} missing=${verdict.missingEvidence?.length ?? 0}`,
    )
    const challenged = await this.maybeChallengeVerdict(hyp, verdict, files)
    const applied = this.applyVerdict(hyp, challenged)
    return applied
  }

  private applyVerdict(hyp: Hypothesis, verdict: VerifierVerdict): VerifierVerdict {
    verdict = this.normalizeVerdict(hyp, verdict)
    const current = this.workspace.getHypothesis(hyp.id) ?? hyp
    const severityNote = adjustSeverityForRuntimeConstraints(current, verdict)
    if (severityNote && !verdict.reason.includes(severityNote)) {
      verdict = {
        ...verdict,
        reason: `${verdict.reason}；${severityNote}`,
        sanitizerSummary: [...(verdict.sanitizerSummary ?? []), severityNote],
      }
    }
    current.verifierVerdict = verdict
    const updated = this.workspace.recordVerifierVerdict(hyp.id, verdict) ?? current
    this.emit("hypothesis:updated", updated)
    this.log(`verified ${hyp.id}: ${verdict.status} (${verdict.confidence}) — ${verdict.reason.slice(0, 160)}`)
    return verdict
  }

  private async maybeChallengeVerdict(hyp: Hypothesis, verdict: VerifierVerdict, files: SourceFileCandidate[]): Promise<VerifierVerdict> {
    const challenge = verifierChallengeForVerdict(hyp, verdict)
    if (!challenge) return verdict
    const bundle = this.workspace.getEvidenceBundle(hyp.id)
    this.log(`observer challenge ${hyp.id}: ${challenge}`)
    addEvent("reason", "warn", "Observer challenged verifier verdict", `${hyp.id}: ${challenge}`, [hyp.id])
    addEvent("reason", "info", "StaticVerifierAgent recheck queued", `${hyp.id}: ${challenge}`, [hyp.id])
    const challenged = await verifyHypothesisWithLLM(
      this.options.llmConfig!,
      this.profile,
      hyp,
      bundle,
      files,
      this.options.outputDir,
      this.cpgPath,
      challenge,
    ) ?? fallbackVerdict("maybe_revisit", `StaticVerifierAgent recheck failed after observer challenge: ${challenge}`)

    this.log(
      `re-verdict ${hyp.id}: ${challenged.status}/${challenged.confidence} checked=${challenged.checkedFiles.length} ` +
      `evidence=${challenged.evidence.length} sanitizers=${challenged.sanitizerSummary?.length ?? 0} missing=${challenged.missingEvidence?.length ?? 0}`,
    )
    addEvent("reason", "info", "StaticVerifierAgent recheck completed", `${hyp.id}: ${challenged.status}/${challenged.confidence} — ${challenged.reason.slice(0, 180)}`, [hyp.id])
    const remaining = verifierChallengeForVerdict(hyp, challenged)
    if (!remaining) return challenged
    return {
      ...challenged,
      status: "maybe_revisit",
      confidence: challenged.confidence === "low" ? "low" : "medium",
      reason: `${challenged.reason}；Observer challenge unresolved: ${remaining}`,
      missingEvidence: [
        ...(challenged.missingEvidence ?? []),
        remaining,
      ],
    }
  }

  private normalizeVerdict(hyp: Hypothesis, verdict: VerifierVerdict): VerifierVerdict {
    verdict = downgradeStructurallyWeakVerdict(hyp, verdict)
    if (verdict.status !== "dismissed") return verdict
    if (!["file-download", "path-traversal"].includes(hyp.category)) return verdict

    const text = [
      hyp.description,
      hyp.sinkCode,
      verdict.reason,
      ...(verdict.evidence ?? []),
      ...(verdict.sanitizerSummary ?? []),
    ].join("\n").toLowerCase()

    const hasFilePathSink = /fileinputstream|fileutil\.file|fileutil\.getinputstream|files\.read|outputstream|servletoutputstream|response\.getoutputstream/.test(text)
    const hasUserPathSignal = /@requestparam|getparameter|param:|path|filepath|filename/.test(text)
    const hasWeakTokenBarrier = /checkcode|checksum|substring\s*\(\s*0\s*,\s*6|hex|base64|decodehex|sm4|encrypt|mac|token/.test(text)
    const hasStrongPathBarrier = /canonical|getcanonical|normalize|allowlist|whitelist|base directory|base dir|startsWith\(|path traversal denied/.test(text)

    if (hasFilePathSink && hasUserPathSignal && hasWeakTokenBarrier && !hasStrongPathBarrier) {
      return {
        ...verdict,
        status: "maybe_revisit",
        confidence: verdict.confidence === "low" ? "low" : "medium",
        reason: `${verdict.reason}；StaticVerifierAgent safety downgrade: file path download/read sink uses user-influenced path guarded mainly by a custom short/derived token or encoding step, with no proven canonical base-directory allowlist. Keep for manual review instead of dismissing.`,
        missingEvidence: [
          ...(verdict.missingEvidence ?? []),
          "需要证明 path/check token 不可由攻击者获得或构造，且解码后的文件路径被限制在服务器白名单目录内。",
        ],
      }
    }

    return verdict
  }

  private async loadVerificationFiles(hyp: Hypothesis): Promise<SourceFileCandidate[]> {
    const bundle = this.workspace.getEvidenceBundle(hyp.id)
    const graphEvidence = this.graphEvidenceCandidate(hyp, bundle)
    const richGraphEvidence = graphEvidence?.rich ?? false
    const files = new Set<string>()
    files.add(hyp.sinkFile)

    for (const link of (bundle?.sourceLinks ?? hyp.sourceLinks ?? []).slice(0, 4)) {
      files.add(link.source.file)
    }
    for (const edge of (bundle?.dataflow ?? hyp.dataflowResult)?.paths?.[0]?.edges ?? []) {
      files.add(edge.file)
    }
    if (bundle?.route?.sourceFile) files.add(resolve(this.profile.root, bundle.route.sourceFile))
    for (const dep of this.profile.dependencies.slice(0, 20)) {
      if (/pom\.xml|build\.gradle|gradle\.properties|package\.json|WEB-INF\/lib/i.test(dep.sourceFile)) {
        files.add(resolve(this.profile.root, dep.sourceFile))
      }
    }
    for (const config of this.runtimeConfigFiles()) files.add(config)

    const loaded: SourceFileCandidate[] = []
    if (graphEvidence) loaded.push(graphEvidence.candidate)
    const sinkWindow = await this.loadSinkWindow(hyp)
    if (sinkWindow) loaded.push(sinkWindow)
    const fileLimit = richGraphEvidence ? 8 : 14
    for (const file of [...files].slice(0, fileLimit)) {
      const absolute = file.startsWith("/") ? file : resolve(this.profile.root, file)
      try {
        const content = await readContextualFile(absolute, {
          patterns: VERIFIER_CONTEXT_PATTERNS,
          maxWholeChars: 220_000,
          maxWindowChars: richGraphEvidence ? 80_000 : 120_000,
          windowRadius: richGraphEvidence ? 24 : 32,
        })
        if (content) loaded.push({ file: absolute, content })
      } catch {
        // Verifier tools can still read the file later if the model asks.
      }
    }

    if (loaded.length > 0) return loaded
    return [{ file: hyp.sinkFile, content: `/*L${hyp.sinkLine}*/ ${hyp.sinkCode}\n// ${relative(this.profile.root, hyp.sinkFile)}` }]
  }

  private async loadVerificationFilesForGroup(group: Hypothesis[]): Promise<SourceFileCandidate[]> {
    const files = new Set<string>()
    const graphEvidence = group
      .map((hyp) => this.graphEvidenceCandidate(hyp, this.workspace.getEvidenceBundle(hyp.id)))
      .filter((item): item is NonNullable<ReturnType<SolverVerifier["graphEvidenceCandidate"]>> => item != null)
    const richGraphEvidence = graphEvidence.some((item) => item.rich)
    for (const hyp of group) {
      files.add(hyp.sinkFile)
      const bundle = this.workspace.getEvidenceBundle(hyp.id)
      for (const link of (bundle?.sourceLinks ?? hyp.sourceLinks ?? []).slice(0, 4)) files.add(link.source.file)
      for (const edge of (bundle?.dataflow ?? hyp.dataflowResult)?.paths?.[0]?.edges ?? []) files.add(edge.file)
      if (bundle?.route?.sourceFile) files.add(resolve(this.profile.root, bundle.route.sourceFile))
    }
    for (const dep of this.profile.dependencies.slice(0, 20)) {
      if (/pom\.xml|build\.gradle|gradle\.properties|package\.json|WEB-INF\/lib/i.test(dep.sourceFile)) {
        files.add(resolve(this.profile.root, dep.sourceFile))
      }
    }
    for (const config of this.runtimeConfigFiles()) files.add(config)

    const loaded: SourceFileCandidate[] = []
    loaded.push(...graphEvidence.map((item) => item.candidate))
    for (const hyp of group.slice(0, 8)) {
      const sinkWindow = await this.loadSinkWindow(hyp)
      if (sinkWindow) loaded.push(sinkWindow)
    }
    const fileLimit = richGraphEvidence ? 10 : 18
    for (const file of [...files].slice(0, fileLimit)) {
      const absolute = file.startsWith("/") ? file : resolve(this.profile.root, file)
      try {
        const content = await readContextualFile(absolute, {
          patterns: VERIFIER_CONTEXT_PATTERNS,
          maxWholeChars: 240_000,
          maxWindowChars: richGraphEvidence ? 90_000 : 140_000,
          windowRadius: richGraphEvidence ? 26 : 36,
        })
        if (content) loaded.push({ file: absolute, content })
      } catch {
        // Verifier tools can still read the file later if the model asks.
      }
    }
    if (loaded.length > 0) return loaded
    return group.map((hyp) => ({ file: hyp.sinkFile, content: `/*L${hyp.sinkLine}*/ ${hyp.sinkCode}\n// ${relative(this.profile.root, hyp.sinkFile)}` }))
  }

  private graphEvidenceCandidate(
    hyp: Hypothesis,
    bundle?: EvidenceBundle,
  ): { candidate: SourceFileCandidate; rich: boolean } | null {
    const pack = buildVerifierEvidencePack(this.profile, hyp, bundle)
    if (!pack.content.trim()) return null
    return {
      rich: pack.rich,
      candidate: {
        file: resolve(this.profile.root, ".night-agent", "virtual-evidence", `${hyp.id}.verifier-pack.md`),
        content: pack.content,
      },
    }
  }

  private async loadSinkWindow(hyp: Hypothesis): Promise<SourceFileCandidate | null> {
    const absolute = hyp.sinkFile.startsWith("/") ? hyp.sinkFile : resolve(this.profile.root, hyp.sinkFile)
    try {
      const content = await readLineWindow(absolute, hyp.sinkLine, 95)
      if (!content) return null
      const rel = relative(this.profile.root, absolute)
      return {
        file: absolute,
        content: `// Forced verifier sink window for ${hyp.id}: ${hyp.category}/${hyp.severity} @ ${rel}:${hyp.sinkLine}
// This code is preloaded evidence. Judge the sink-containing method from this window before requesting more files.
${content}`,
      }
    } catch {
      return null
    }
  }

  private runtimeConfigFiles(): string[] {
    const files = new Set<string>()
    for (const rel of [...this.profile.buildFiles, ...this.profile.highRiskFiles]) {
      if (/pom\.xml$|build\.gradle$|application\.(properties|ya?ml)$|bootstrap\.(properties|ya?ml)$|applicationContext.*\.xml$/i.test(rel)) {
        files.add(resolve(this.profile.root, rel))
      }
      if (/config|security|firewall|tomcat|webmvc|websecurity/i.test(rel)
        && /\.(java|kt|xml|properties|ya?ml)$/i.test(rel)) {
        files.add(resolve(this.profile.root, rel))
      }
    }
    for (const rel of discoverRuntimeConfigFiles(this.profile.root, 24 - files.size)) files.add(rel)
    return [...files]
  }
}

function downgradeStructurallyWeakVerdict(hyp: Hypothesis, verdict: VerifierVerdict): VerifierVerdict {
  const challenge = verifierChallengeForVerdict(hyp, verdict)
  if (!challenge || verdict.status === "dismissed") return verdict
  return {
    ...verdict,
    status: "maybe_revisit",
    confidence: verdict.confidence === "low" ? "low" : "medium",
    reason: `${verdict.reason}；StaticVerifierAgent structural downgrade: ${challenge}`,
    missingEvidence: [
      ...(verdict.missingEvidence ?? []),
      challenge,
    ],
  }
}

function discoverRuntimeConfigFiles(root: string, limit: number): string[] {
  if (limit <= 0) return []
  const found: string[] = []
  const roots = ["src/main/java", "src/main/resources", "config", "conf"]
    .map((dir) => resolve(root, dir))
  const visit = (dir: string, depth: number) => {
    if (found.length >= limit || depth > 5) return
    let entries: string[]
    try {
      entries = readdirSync(dir)
    } catch {
      return
    }
    for (const name of entries) {
      if (found.length >= limit) return
      if (name === "target" || name === "build" || name === "node_modules" || name.startsWith(".")) continue
      const path = resolve(dir, name)
      let isDir = false
      try {
        const stat = statSync(path)
        isDir = stat.isDirectory()
      } catch {
        continue
      }
      if (isDir) {
        if (/config|security|firewall|tomcat|web|main|resources|java|conf/i.test(path)) visit(path, depth + 1)
        continue
      }
      const rel = relative(root, path)
      if (/pom\.xml$|build\.gradle$|application\.(properties|ya?ml)$|bootstrap\.(properties|ya?ml)$|applicationContext.*\.xml$/i.test(rel)
        || (/config|security|firewall|tomcat|webmvc|websecurity/i.test(rel) && /\.(java|kt|xml|properties|ya?ml)$/i.test(rel))) {
        found.push(path)
      }
    }
  }
  for (const dir of roots) visit(dir, 0)
  return found
}

function adjustSeverityForRuntimeConstraints(hyp: Hypothesis, verdict: VerifierVerdict): string | null {
  if (verdict.status !== "confirmed") return null
  const text = [
    hyp.description,
    hyp.sinkCode,
    verdict.reason,
    ...(verdict.sourceSinkTrace ?? []),
    ...(verdict.evidence ?? []),
    ...(verdict.barrierAnalysis ?? []),
    ...(verdict.sanitizerSummary ?? []),
  ].join("\n").toLowerCase()

  if (["file-download", "path-traversal"].includes(hyp.category) && hasFixedSuffixConstraint(text)) {
    return lowerSeverityToMedium(hyp, "fixed suffix constraint limits impact; classify as suffix-limited file read/write, not arbitrary file access")
  }

  if (hyp.category === "file-upload" && claimsUploadRce(text) && !provesUploadExecutableRuntime(text)) {
    return lowerSeverityToMedium(hyp, "upload RCE not proven under jar/non-executable storage semantics; treat as medium until executable web root or combination chain is proven")
  }

  return null
}

function lowerSeverityToMedium(hyp: Hypothesis, reason: string): string | null {
  if (compareSeverity(hyp.severity, "medium") >= 0) return null
  const old = hyp.severity
  hyp.severity = "medium"
  return `severity adjusted ${old}->medium: ${reason}`
}

function hasFixedSuffixConstraint(text: string): boolean {
  return /(\+|concat|append|拼接|追加).{0,80}\.(docx?|xlsx?|pdf|zip|png|jpe?g|json|txt|csv)\b|file(name)?\s*=\s*[^;\n]*\+\s*["']\.(docx?|xlsx?|pdf|zip|png|jpe?g|json|txt|csv)["']|后缀.{0,30}(固定|追加|拼接)|固定.{0,30}后缀/.test(text)
}

function claimsUploadRce(text: string): boolean {
  return /rce|remote code execution|代码执行|命令执行|jsp|jspx|war|webshell|getshell|可执行/.test(text)
}

function provesUploadExecutableRuntime(text: string): boolean {
  return /webapps|webroot|web-root|static web root|tomcat.{0,80}(war|webapps|jsp|external)|servlet container.{0,80}execute|外置tomcat|war包|jsp.{0,80}(解析|执行)|上传目录.{0,80}(可执行|会解析|web可达且执行)|jar.{0,80}(组合拳|additional gadget|needs chain|medium|非直接执行|不直接解析jsp)/.test(text)
}

function fallbackVerdict(status: VerifierVerdict["status"], reason: string): VerifierVerdict {
  return {
    status,
    confidence: "low",
    reason,
    evidence: [],
    checkedFiles: [],
    toolCalls: [],
    missingEvidence: [reason],
    recommendedStatus: status,
    createdAt: Date.now(),
  }
}

function groupPriority(group: Hypothesis[], priorityScores: Map<string, number>): number {
  return Math.max(0, ...group.map((hyp) => priorityScores.get(hyp.id) ?? legacyPriorityScore(hyp)))
}

function shouldVerifyCandidate(hyp: Hypothesis): boolean {
  if (!hyp.verifierVerdict) return true
  if (process.env.NIGHT_AGENT_VERIFIER_RECHECK_DEFERRED !== "1") return false
  return hyp.verifierVerdict.reason.startsWith("Observer verifier triage deferred LLM review:")
}

function formatDeferredReasonCounts(items: VerifierPriorityItem[]): string {
  const counts = new Map<string, number>()
  for (const item of items) {
    const key = deferredReasonKind(item)
    counts.set(key, (counts.get(key) ?? 0) + 1)
  }
  return [...counts.entries()].map(([key, count]) => `${key}=${count}`).join(", ")
}

function formatDeferredSample(item: VerifierPriorityItem): string {
  const representative = item.representativeId ? `->${item.representativeId}` : ""
  return `${item.hypothesis.id}${representative}:${item.hypothesis.category}:${item.score}:${deferredReasonKind(item)}`
}

function deferredReasonKind(item: VerifierPriorityItem): string {
  const reason = item.deferredReason ?? ""
  if (reason.startsWith("deferred intermediate-flow")) return "intermediate-flow"
  if (reason.startsWith("deferred duplicate")) return "same-evidence-duplicate"
  if (reason.startsWith("deferred by verifier priority budget")) return "priority-budget"
  return "other"
}

function legacyPriorityScore(hyp: Hypothesis): number {
  const severityScore: Record<Hypothesis["severity"], number> = {
    critical: 500,
    high: 390,
    medium: 280,
    low: 170,
    info: 60,
  }
  return (VERIFIER_HIGH_VALUE_CATEGORIES.has(hyp.category) ? 1_000 : 0) + severityScore[hyp.severity]
}

function envInt(name: string, fallback: number | undefined, min: number, max: number): number | undefined {
  const raw = process.env[name]
  if (raw == null || raw.trim() === "") return fallback
  const parsed = Number.parseInt(raw, 10)
  if (!Number.isFinite(parsed)) return fallback
  return Math.max(min, Math.min(max, parsed))
}

function clampNumber(value: number, min: number, max: number, fallback: number): number {
  if (!Number.isFinite(value)) return fallback
  return Math.max(min, Math.min(max, value))
}

async function readLineWindow(file: string, line: number, radius: number): Promise<string> {
  const text = await Bun.file(file).text()
  const lines = text.split(/\r?\n/)
  const safeLine = Math.max(1, Math.min(lines.length, Math.floor(line || 1)))
  const start = Math.max(1, safeLine - radius)
  const end = Math.min(lines.length, safeLine + radius)
  const output: string[] = []
  for (let current = start; current <= end; current++) {
    const raw = lines[current - 1] ?? ""
    const clipped = raw.length > 2_000 ? `${raw.slice(0, 2_000)} /* line clipped */` : raw
    output.push(`/*L${current}*/ ${clipped}`)
  }
  return output.join("\n")
}
