import type { Hypothesis, VerifierVerdict } from "../types/index.ts"
import { verifierSourceEvidenceProblem } from "../utils/source-evidence.ts"

export interface VerifierIntegrityOptions {
  decisionText?: string
  includeSourceEvidenceProblem?: boolean
}

export interface VerifierIntegrityResult {
  challenge: string | null
  problems: string[]
}

const BARRIER_SENSITIVE_CATEGORIES = new Set([
  "cmdi",
  "sqli",
  "file-download",
  "file-upload",
  "path-traversal",
  "ssti",
  "spel",
  "ognl",
  "expression",
  "deser",
  "ssrf",
  "xxe",
  "jndi",
])

export function evaluateVerifierIntegrity(
  hyp: Hypothesis,
  verdict: VerifierVerdict,
  options: VerifierIntegrityOptions = {},
): VerifierIntegrityResult {
  const challenge = verifierChallengeForVerdict(hyp, verdict, options)
  return {
    challenge,
    problems: verifierIntegrityProblems(hyp, verdict, options),
  }
}

export function verifierChallengeForVerdict(
  hyp: Hypothesis,
  verdict: VerifierVerdict,
  options: VerifierIntegrityOptions = {},
): string | null {
  if (verdict.status === "maybe_revisit") return null
  const context = verifierIntegrityContext(hyp, verdict, options)

  if (verdict.status === "confirmed") {
    if (context.missing.length > 0) {
      return `confirmed verdict still lists missing evidence (${context.missing.slice(0, 2).join("; ")}); resolve it or downgrade to maybe_revisit`
    }
    if (options.includeSourceEvidenceProblem !== false) {
      const sourceProblem = verifierSourceEvidenceProblem(hyp, verdict)
      if (sourceProblem) return sourceProblem
    }
    if (context.evidence.length < 2 || !hasLineAnchoredFact(context.evidence)) {
      return "confirmed verdict lacks source/sink file:line evidence; provide source, transform/helper, and sink facts or downgrade"
    }
    if (BARRIER_SENSITIVE_CATEGORIES.has(hyp.category) && context.barriers.length === 0) {
      return "confirmed verdict lacks barrierAnalysis/sanitizerSummary; identify checked barriers or state none found with inspected files"
    }
    const unresolvedBarriers = context.barriers.filter((barrier) =>
      isUnknownBarrier(barrier)
        && !(context.archiveTraversal && isArchiveTraversalKnownAbsentBarrier(barrier))
    )
    if (unresolvedBarriers.length > 0) {
      return "confirmed verdict contains unknown/incomplete barrier analysis; resolve helper/runtime evidence or downgrade"
    }
    if (["file-download", "path-traversal"].includes(hyp.category) && /checkcode|checksum|token|mac|sm4|encrypt|signature|sign|license|hex|base64|decode/.test(context.text)) {
      const provesBypass = /attacker can|攻击者可|可构造|可获得|默认|硬编码|泄露|does not cut|不能切断|不切断|not bind|not secret|public/.test(context.text)
      const provesSafe = /cannot construct|无法构造|不可构造|server secret|服务端密钥|签名验证|signature verified|notary\.verify|canonical|base[- ]?dir|allowlist|白名单目录/.test(context.text)
      if (!provesBypass && !provesSafe) {
        return "file path verdict mentions token/signature/encoding but does not prove whether attacker can construct it or whether it binds the path"
      }
    }
    if (["file-download", "path-traversal"].includes(hyp.category) && hasFixedSuffixConstraint(context.text) && !explainsSuffixLimitedImpact(context.text)) {
      return "file path verdict ignores fixed suffix constraint (for example .docx); classify as suffix-limited read/write instead of arbitrary file access, or prove bypass"
    }
    if (["file-download", "path-traversal"].includes(hyp.category) && mentionsEncodedSlashPathTraversal(context.text) && !isArchiveEntryTraversal(context.text) && !resolvesEncodedSlashRuntime(context.text)) {
      return "path-variable encoded slash traversal requires Spring/Tomcat runtime proof (StrictHttpFirewall allowUrlEncodedSlash or Tomcat ALLOW_ENCODED_SLASH); otherwise downgrade"
    }
    if (hyp.category === "file-upload") {
      const hasUploadChecks = /extension|扩展|后缀|allow|white|mime|content|magic|hash|rename|storage|web[- ]?root|可执行|execute|transferto|originalfilename/.test(context.text)
      if (!hasUploadChecks) {
        return "file-upload confirmed without checking extension allowlist, filename rewriting, content/MIME validation, and storage executability"
      }
      if (claimsUploadRce(context.text) && !provesUploadExecutableRuntime(context.text)) {
        return "file-upload RCE claim lacks proof that uploaded file is stored under an executable web root/container path; jar/embedded startup usually needs an additional gadget/combination and should not be high-confidence high severity"
      }
    }
    if (hyp.category === "deser") {
      const hasDeserChecks = /fastjson|jackson|hutool|xstream|xmldecoder|readobject|autotype|default typing|version|版本|redis|signature|notary|user[- ]controlled|外部可控/.test(context.text)
      if (!hasDeserChecks) {
        return "deserialization confirmed without proving library/version/config and user-controlled serialized data"
      }
    }
    if (["ssti", "spel", "ognl", "expression"].includes(hyp.category)) {
      const hasTemplateChecks = /template|freemarker|velocity|process|eval|interpret|模板|渲染|referenc|引用|write|写入|用户控制/.test(context.text)
      if (!hasTemplateChecks) {
        return "template/expression confirmed without proving user-controlled template/expression reaches the engine"
      }
    }
    return null
  }

  if (verdict.status === "dismissed") {
    const semanticDismissal = /semantic|语义|not this vulnerability|不是|captcha|验证码|generated|生成|parameter binding|参数绑定|preparedstatement|hutool|not fastjson|not xml|日期|canonical|allowlist|whitelist|白名单|hash|rename|签名|signature|notary\.verify/.test(context.text)
    if (context.evidence.length === 0 || !hasLineAnchoredFact(context.evidence)) {
      return "dismissed verdict lacks file:line evidence proving a semantic mismatch or effective barrier"
    }
    if (!semanticDismissal && context.barriers.length === 0) {
      return "dismissed verdict lacks an explicit semantic mismatch or effective barrier analysis"
    }
    if (["file-download", "path-traversal"].includes(hyp.category) && /checkcode|checksum|token|mac|sm4|encrypt|hex|base64|decode/.test(context.text) && !/canonical|base[- ]?dir|allowlist|whitelist|server[- ]chosen|服务端选择|notary\.verify|signature/.test(context.text)) {
      return "dismissed file path verdict relies on a custom token/encoding without proving a strong server-side path binding"
    }
  }

  return null
}

export function verifierIntegrityProblems(
  hyp: Hypothesis,
  verdict: VerifierVerdict,
  options: VerifierIntegrityOptions = {},
): string[] {
  if (verdict.status !== "confirmed") return []
  const context = verifierIntegrityContext(hyp, verdict, options)
  const problems: string[] = []
  if (context.missing.length > 0) problems.push("missingEvidence present")
  if (options.includeSourceEvidenceProblem) {
    const sourceProblem = verifierSourceEvidenceProblem(hyp, verdict)
    if (sourceProblem) problems.push(sourceProblem)
  }
  if (context.evidence.length < 2 || !hasLineAnchoredFact(context.evidence)) problems.push("weak source/sink file:line evidence")
  if (BARRIER_SENSITIVE_CATEGORIES.has(hyp.category) && context.barriers.length === 0) problems.push("missing barrier analysis")
  if (context.barriers.some((barrier) => isUnknownBarrier(barrier) && !(context.archiveTraversal && isArchiveTraversalKnownAbsentBarrier(barrier)))) problems.push("unknown barrier remains")
  if (["file-download", "path-traversal"].includes(hyp.category)
    && /checkcode|checksum|token|mac|sm4|encrypt|signature|sign|license|hex|base64|decode/.test(context.text)
    && !/(attacker can|攻击者可|可构造|可获得|默认|硬编码|泄露|does not cut|不能切断|不切断|not bind|canonical|base[- ]?dir|allowlist|whitelist|白名单目录|server secret|服务端密钥|签名验证|notary\.verify)/.test(context.text)) {
    problems.push("token/signature path barrier not resolved")
  }
  if (["file-download", "path-traversal"].includes(hyp.category) && hasFixedSuffixConstraint(context.text) && !explainsSuffixLimitedImpact(context.text)) {
    problems.push("fixed suffix constraint not resolved")
  }
  if (["file-download", "path-traversal"].includes(hyp.category) && mentionsEncodedSlashPathTraversal(context.text) && !isArchiveEntryTraversal(context.text) && !resolvesEncodedSlashRuntime(context.text)) {
    problems.push("encoded slash runtime config not proven")
  }
  if (hyp.category === "file-upload"
    && !/extension|扩展|后缀|allow|white|mime|content|magic|hash|rename|storage|web[- ]?root|可执行|execute|transferto|originalfilename/.test(context.text)) {
    problems.push("upload controls not checked")
  }
  if (hyp.category === "file-upload" && claimsUploadRce(context.text) && !provesUploadExecutableRuntime(context.text)) {
    problems.push("upload RCE executable runtime not proven")
  }
  return problems
}

function verifierIntegrityContext(
  hyp: Hypothesis,
  verdict: VerifierVerdict,
  options: VerifierIntegrityOptions,
): { evidence: string[]; barriers: string[]; missing: string[]; text: string; archiveTraversal: boolean } {
  const evidence = compactStrings([
    ...(verdict.sourceSinkTrace ?? []),
    ...(verdict.evidence ?? []),
  ])
  const barriers = compactStrings([
    ...(verdict.barrierAnalysis ?? []),
    ...(verdict.sanitizerSummary ?? []),
  ])
  const rawMissing = compactStrings(verdict.missingEvidence ?? [])
  const baseText = [
    hyp.description,
    hyp.sinkCode,
    verdict.reason,
    ...evidence,
    ...barriers,
    ...rawMissing,
    options.decisionText ?? "",
  ].join("\n").toLowerCase()
  const archiveTraversal = hasConfirmedArchiveEntryTraversal(baseText)
  const missing = rawMissing.filter((item) =>
    !isResolvedMissingEvidence(item)
      && !(archiveTraversal && isArchiveTraversalIrrelevantMissing(item))
  )
  const text = [
    hyp.description,
    hyp.sinkCode,
    verdict.reason,
    ...evidence,
    ...barriers,
    ...missing,
    options.decisionText ?? "",
  ].join("\n").toLowerCase()
  return { evidence, barriers, missing, text, archiveTraversal }
}

function compactStrings(values: string[]): string[] {
  return values.map((value) => value.trim()).filter(Boolean)
}

function hasLineAnchoredFact(values: string[]): boolean {
  return values.some((value) => /(?:^|\s|`)[\w./\\-]+:\d+\b/.test(value) || /\bline\s+\d+\b|第\s*\d+\s*行|L\d+\b/.test(value))
}

function isUnknownBarrier(value: string): boolean {
  return /unknown|unproven|missing|incomplete|not inspected|未证明|未确认|未读取|无法确认|证据不足|缺少|取决于|需确认|待确认|不清楚/.test(value.toLowerCase())
}

function isResolvedMissingEvidence(value: string): boolean {
  return /已通过|已确认|已读取|已证明|confirmed by|confirmed via|verified by|read_file|checked file|not required|无需|不需要/.test(value.toLowerCase())
}

function hasConfirmedArchiveEntryTraversal(text: string): boolean {
  return isArchiveEntryTraversal(text)
    && /zipentry|zip entry|entry\.getname|zipentryname|archive entry|条目名|zip条目/.test(text)
    && /fileoutputstream|new\s+fileoutputstream|outpath|dstpath|files\.copy|transferTo|写入|任意文件写/.test(text)
    && /no .{0,80}(canonical|normalize|saniti[sz]e|validat|base[- ]?dir|allowlist|whitelist)|without .{0,80}(canonical|normalize|saniti[sz]e|validat|base[- ]?dir|allowlist|whitelist)|does not .{0,40}(saniti[sz]e|validat|normalize)|未.{0,30}(校验|过滤|规范化|白名单|基目录)|没有.{0,30}(校验|过滤|规范化|白名单|基目录)|无任何.{0,30}(校验|过滤|规范化|白名单|基目录)/.test(text)
}

function isArchiveTraversalIrrelevantMissing(value: string): boolean {
  const text = value.toLowerCase()
  if (/encoded slash|urlencodedslash|allow_url_encoded_slash|allowencodedslash|stricthttpfirewall|tomcat allow_encoded_slash|path-variable|@pathvariable|路径变量|编码斜杠/.test(text)) return true
  return /unknown|incomplete|missing|未确认|缺少|无法确认/.test(text)
    && /barrier|runtime|helper|屏障|运行时|辅助/.test(text)
}

function isArchiveTraversalKnownAbsentBarrier(value: string): boolean {
  const text = value.toLowerCase()
  return /no .{0,80}(canonical|normalize|saniti[sz]e|validat|base[- ]?dir|allowlist|whitelist)|without .{0,80}(canonical|normalize|saniti[sz]e|validat|base[- ]?dir|allowlist|whitelist)|does not cut|does not .{0,40}(saniti[sz]e|validat|normalize)|未.{0,30}(校验|过滤|规范化|白名单|基目录)|没有.{0,30}(校验|过滤|规范化|白名单|基目录)|无任何.{0,30}(校验|过滤|规范化|白名单|基目录)/.test(text)
}

function hasFixedSuffixConstraint(text: string): boolean {
  return /(\+|concat|append|拼接|追加).{0,80}\.(docx?|xlsx?|pdf|zip|png|jpe?g|json|txt|csv)\b|file(name)?\s*=\s*[^;\n]*\+\s*["']\.(docx?|xlsx?|pdf|zip|png|jpe?g|json|txt|csv)["']|后缀.{0,30}(固定|追加|拼接)|固定.{0,30}后缀/.test(text)
}

function explainsSuffixLimitedImpact(text: string): boolean {
  return /suffix[- ]?limited|后缀受限|固定后缀|只能读取|只能写入|only .*\.|not arbitrary|不是任意|不能任意|任意\.(docx?|xlsx?|pdf|zip|png|jpe?g|json|txt|csv)|limited to|受限于/.test(text)
}

function mentionsEncodedSlashPathTraversal(text: string): boolean {
  return /%2f|%5c|encoded slash|urlencodedslash|allow_url_encoded_slash|allowencodedslash|pathvariable|@pathvariable|路径变量|路径段|\/\{[^}]+}/.test(text)
}

function isArchiveEntryTraversal(text: string): boolean {
  return /zip[- ]?slip|zipentry|zip entry|entry\.getname|zipentryname|archive entry|decompress|unzip|解压|压缩包|zip条目|条目名/.test(text)
}

function resolvesEncodedSlashRuntime(text: string): boolean {
  return /allowurlencodedslash\s*\(\s*true|setallowurlencodedslash\s*\(\s*true|allow_encoded_slash.{0,40}(true|enabled)|allow_encoded_slashes.{0,40}(true|enabled)|udecoder\.allow_encoded_slash.{0,40}(true|enabled)|stricthttpfirewall.{0,80}allowurlencodedslash|tomcat.{0,80}allow_encoded_slash|encoded slash.{0,80}(blocked|拦截|not allowed|默认不允许|denied|rejected)|%2f.{0,80}(blocked|拦截|not allowed|默认不允许|denied|rejected)/.test(text)
}

function claimsUploadRce(text: string): boolean {
  return /rce|remote code execution|代码执行|命令执行|jsp|jspx|war|webshell|getshell|可执行/.test(text)
}

function provesUploadExecutableRuntime(text: string): boolean {
  return /webapps|webroot|web-root|static web root|tomcat.{0,80}(war|webapps|jsp|external)|servlet container.{0,80}execute|外置tomcat|war包|jsp.{0,80}(解析|执行)|上传目录.{0,80}(可执行|会解析|web可达且执行)|jar.{0,80}(组合拳|additional gadget|needs chain|medium|非直接执行|不直接解析jsp)/.test(text)
}
