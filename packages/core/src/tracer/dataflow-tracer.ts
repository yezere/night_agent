import { resolve } from "node:path"
import { readFileSync } from "node:fs"
import type { DataflowTrace, Hypothesis, DataflowPath, SanitizerRef } from "../types/index.ts"
import { buildJoernEnv, stopChildProcess } from "./joern-resources.ts"

const DEFAULT_JOERN_HOME = process.env.HOME ? resolve(process.env.HOME, "joern", "joern-cli") : ""
const JOERN_HOME = process.env.JOERN_HOME || DEFAULT_JOERN_HOME
const JOERN = process.env.JOERN ?? (JOERN_HOME ? resolve(JOERN_HOME, "joern") : "joern")

const SANITIZER_PATTERNS = [
  { kind: "input-validation", pattern: /validate|sanitize|escape|normalize|whitelist|blacklist/i },
  { kind: "auth-check", pattern: /isAuthenticated|hasRole|hasPermission|checkPermission|checkAuth/i },
  { kind: "param-binding", pattern: /@RequestParam|@PathVariable|@RequestBody|@ModelAttribute/ },
  { kind: "sql-parameterized", pattern: /PreparedStatement|setString|setInt|setLong|\?/ },
  { kind: "path-normalize", pattern: /normalize|getCanonicalPath|Files\.resolve/ },
]

export async function traceDataflow(
  hypothesis: Hypothesis,
  cpgPath: string,
  outputDir: string,
  timeoutMs?: number,
): Promise<DataflowTrace> {
  const sinkRegex = extractSinkPattern(hypothesis)
  if (!sinkRegex) {
    return { reachable: false, paths: [], sanitizers: [], confidence: "low" }
  }

  const traceScript = resolve(outputDir, `trace-${hypothesis.id}.sc`)
  const hypId = hypothesis.id
  // Extract the basename of the sink file for filtering
  const sinkBasename = hypothesis.sinkFile.split("/").pop() ?? hypothesis.sinkFile
  const sinkLine = hypothesis.sinkLine

  const script = [
    "import io.shiftleft.semanticcpg.language._",
    "",
    `val sinkLine = ${sinkLine}`,
    `val sinkBasename = "${sinkBasename.replace(/"/g, '\\"')}"`,
    "",
    "// Find the sink by code pattern (primary) or by file basename + line (fallback)",
    "val sink = (cpg.call.code(\"\"\".*" + sinkRegex + ".*\"\"\").l ++",
    "  cpg.call.filter(c => c.file.name.headOption.exists(_.endsWith(sinkBasename)) && c.lineNumber.headOption.exists(_ == sinkLine)).l).distinct",
    "",
    "// Sources: parameters of controller methods, request annotations, and Servlet entry methods",
    "def source = (cpg.method.where(_.annotation.name(\".*Mapping.*\")).parameter ++",
    "  cpg.method.where(_.parameter.annotation.name(\".*RequestParam|RequestBody|PathVariable|RequestHeader.*\")).parameter ++",
    "  cpg.method.name(\"do(Get|Post|Put|Delete|Patch|Head|Options)|service\").parameter.typeFullName(\".*ServletRequest.*\") ++",
    "  cpg.method.where(_.parameter.typeFullName(\".*ServletRequest.*\")).parameter.typeFullName(\".*ServletRequest.*\")).dedup",
    "",
    `println(s"[Dataflow] Tracing \${sink.size} sink(s) for hypothesis ${hypId}")`,
    "",
    "sink.take(3).foreach { s =>",
    "  val flows = s.start.reachableByFlows(source).take(5).l",
    `  println(s"[Dataflow] Found \${flows.size} flow(s) to \${s.code.take(100)}")`,
    "  flows.foreach { flow =>",
    "    flow.elements.foreach { node =>",
    "      val fname = node.file.name.headOption.getOrElse(\"?\")",
    "      val lnum = node.lineNumber.getOrElse(-1)",
    "      val code = node.code.take(200).replace(\"\\n\", \" \")",
    "      println(s\"[Path] ${fname} | ${lnum} | ${code}\")",
    "    }",
    "    println(\"---\")",
    "  }",
    "}",
  ].join("\n")

  await Bun.write(traceScript, script)

  const proc = Bun.spawn([JOERN, cpgPath, "--script", traceScript], {
    stdout: "pipe",
    stderr: "pipe",
    env: buildJoernEnv(),
  })

  let killed = false
  let timer: ReturnType<typeof setTimeout> | undefined
  if (timeoutMs) {
    timer = setTimeout(() => {
      killed = true
      stopChildProcess(proc)
    }, timeoutMs)
  }

  const stdout = await new Response(proc.stdout).text()
  const stderr = await new Response(proc.stderr).text()
  const exitCode = await proc.exited
  if (timer) clearTimeout(timer)

  // Log stderr if the script failed (stderr may contain Scala compilation errors)
  if (stderr.trim() && (exitCode !== 0 || stdout.trim().length === 0)) {
    const stderrLog = resolve(outputDir, `stderr-${hypothesis.id}.txt`)
    await Bun.write(stderrLog, stderr.slice(0, 5000))
  }

  // Parse output
  const paths = parseDataflowOutput(stdout, hypothesis)
  const sanitizers = findSanitizers(paths, hypothesis.sinkFile)

  return {
    reachable: paths.length > 0,
    paths,
    sanitizers,
    confidence: paths.length > 0 ? "high" : "medium",
  }
}

/**
 * Map SinkAgent pattern names to Joern-compatible code regexes.
 * These must match actual Java method/constructor calls in the CPG.
 */
// NOTE: Patterns must work as Scala regex inside raw strings ("""...""").
// In Scala raw strings, backslash is literal: \( → regex-escaped (, \. → regex-escaped .
// All literal parens must have \(, all literal dots must have \.
const SINK_PATTERN_MAP: Record<string, string> = {
  // Command Injection
  "Runtime.exec": "\\.exec\\(",
  "ProcessBuilder": "new ProcessBuilder\\(",
  // Deserialization
  "ObjectInputStream.readObject": "\\.readObject\\(",
  "fastjson.parse": "\\.parse\\(Object|Array\\)?\\(",
  "ObjectMapper.readValue": "\\.readValue\\(",
  // SQL Injection
  "Statement.execute": "\\.execute\\(Query|Update\\)?\\(",
  // SSRF
  "network-request": "new URL\\(|\\.openConnection\\(|\\.(get|post)For(Entity|Object)\\(|\\.execute\\(",
  // File/Path
  "file-path": "new File\\(|Paths\\.get\\(|Files\\.(read|copy|write|newInputStream|newOutputStream)",
  // SSTI
  "Template.process": "\\.process\\(",
  // JNDI
  "InitialContext.lookup": "\\.lookup\\(",
  // XXE
  "xml-parse": "\\.parse\\(|\\.unmarshal\\(",
  // Spring route — NOT a sink, skip tracing
  "spring-route": "",
}

function extractSinkPattern(hyp: Hypothesis): string {
  // 1. Exact match from known sink map (preferred)
  const mapped = SINK_PATTERN_MAP[hyp.sinkPattern]
  if (mapped !== undefined) {
    if (mapped === "") return "" // spring-route etc.
    return mapped
  }

  // 2. Derive from sinkPattern by method name extraction
  const methodName = hyp.sinkPattern.split(".").pop() ?? ""

  if (methodName === "readObject") return "\\.readObject\\("
  if (methodName === "readValue") return "\\.readValue\\("
  if (methodName === "exec") return "\\.exec\\("
  if (methodName === "lookup") return "\\.lookup\\("
  if (methodName === "process") return "\\.process\\("
  if (methodName === "unmarshal") return "\\.unmarshal\\("

  // 3. Fallback: read the actual source file to get the sink code.
  try {
    const fileContent = readFileSync(hyp.sinkFile, "utf-8")
    const lines = fileContent.split("\n")
    if (hyp.sinkLine > 0 && hyp.sinkLine <= lines.length) {
      const code = lines[hyp.sinkLine - 1]?.trim() ?? ""
      if (code && code.length > 1 && code.length < 500) {
        // Escape for regex and try to extract a method/constructor call
        const escaped = code
          .replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
          .slice(0, 80)
        return ".*" + escaped + ".*"
      }
    }
  } catch {
    // File unreadable — fall through to last resort
  }

  // 4. Last resort: use the captured sinkCode.
  const escaped = hyp.sinkCode.replace(/[.*+?^${}()|[\]\\]/g, "\\$&").slice(0, 60)
  if (escaped.length > 2) return ".*" + escaped + ".*"
  return ""
}

function parseDataflowOutput(output: string, hyp: Hypothesis): DataflowPath[] {
  const paths: DataflowPath[] = []
  const pathBlocks = output.split("[Path] ")
  pathBlocks.shift() // remove header

  let currentEdges: DataflowPath["edges"] = []
  for (const block of pathBlocks) {
    const lines = block.trim().split("\n")
    for (const line of lines) {
      const parts = line.split(" | ")
      if (parts.length < 3) continue
      const file = parts[0]?.trim() ?? ""
      const lineNum = parseInt(parts[1]?.trim() ?? "0", 10)
      const code = parts.slice(2).join(" | ").trim()

      let kind: "source" | "propagation" | "sink" = "propagation"
      if (file === hyp.sinkFile && lineNum === hyp.sinkLine) kind = "sink"
      else if (/controller/i.test(file)) kind = "source"

      currentEdges.push({ file, line: lineNum, code, kind })
    }
    if (currentEdges.length > 0) {
      paths.push({ edges: currentEdges, sourceLabel: "HTTP Entry", sinkLabel: hyp.sinkPattern })
      currentEdges = []
    }
  }

  return paths
}

/** Quick reachability check — runs fast, uses simple source→sink traversal. */
export async function quickReachabilityCheck(
  hypothesis: Hypothesis,
  cpgPath: string,
  outputDir: string,
  timeoutMs: number = 30_000,
): Promise<DataflowTrace> {
  const sinkRegex = extractSinkPattern(hypothesis)
  if (!sinkRegex) {
    return { reachable: false, paths: [], sanitizers: [], confidence: "low" }
  }

  const traceScript = resolve(outputDir, `trace-conclude-${hypothesis.id}.sc`)
  const sinkBasename = hypothesis.sinkFile.split("/").pop() ?? hypothesis.sinkFile

  const script = [
    "import io.shiftleft.semanticcpg.language._",
    "",
    `val sinkBasename = "${sinkBasename.replace(/"/g, '\\"')}"`,
    "",
    "// Simplified sink search — just the code pattern",
    "val sink = cpg.call.code(\"\"\".*" + sinkRegex + ".*\"\"\").take(3).l",
    "",
    "// Simplified source — controller params plus Servlet request params",
    "def source = (cpg.method.where(_.annotation.name(\".*Mapping.*\")).parameter ++",
    "  cpg.method.name(\"do(Get|Post|Put|Delete|Patch|Head|Options)|service\").parameter.typeFullName(\".*ServletRequest.*\") ++",
    "  cpg.method.where(_.parameter.typeFullName(\".*ServletRequest.*\")).parameter.typeFullName(\".*ServletRequest.*\")).dedup",
    "",
    "if (sink.isEmpty) {",
    "  println(\"[Conclude] NO_SINK\")",
    "} else {",
    "  sink.foreach { s =>",
    "    val flows = s.start.reachableByFlows(source).take(2).l",
    "    println(s\"[Conclude] FLOWS \${flows.size} to \${s.code.take(100)}\")",
    "    flows.foreach { flow =>",
    "      flow.elements.take(15).foreach { node =>",
    "        val fname = node.file.name.headOption.getOrElse(\"?\")",
    "        val lnum = node.lineNumber.getOrElse(-1)",
    "        val code = node.code.take(200).replace(\"\\n\", \" \")",
    "        println(s\"[Path] \${fname} | \${lnum} | \${code}\")",
    "      }",
    "      println(\"---\")",
    "    }",
    "  }",
    "}",
  ].join("\n")

  await Bun.write(traceScript, script)

  const proc = Bun.spawn([JOERN, cpgPath, "--script", traceScript], {
    stdout: "pipe",
    stderr: "pipe",
    env: buildJoernEnv(),
  })

  let killed = false
  let timer: ReturnType<typeof setTimeout> | undefined
  if (timeoutMs) {
    timer = setTimeout(() => {
      killed = true
      stopChildProcess(proc)
    }, timeoutMs)
  }

  const stdout = await new Response(proc.stdout).text()
  await proc.exited
  if (timer) clearTimeout(timer)

  if (killed) {
    return { reachable: false, paths: [], sanitizers: [], confidence: "low" }
  }

  // Parse the simpler output
  if (stdout.includes("NO_SINK")) {
    return { reachable: false, paths: [], sanitizers: [], confidence: "low" }
  }

  const paths = parseDataflowOutput(stdout, hypothesis)
  if (paths.length === 0) {
    return { reachable: false, paths: [], sanitizers: [], confidence: "low" }
  }

  const sanitizers = findSanitizers(paths, hypothesis.sinkFile)
  return {
    reachable: true,
    paths,
    sanitizers,
    confidence: "low", // Conclude fallback always has lower confidence
  }
}

function findSanitizers(paths: DataflowPath[], sinkFile: string): SanitizerRef[] {
  const found: SanitizerRef[] = []
  for (const path of paths) {
    for (const edge of path.edges) {
      for (const sp of SANITIZER_PATTERNS) {
        if (sp.pattern.test(edge.code)) {
          // Check duplicate
          const dup = found.find((s) => s.file === edge.file && s.line === edge.line)
          if (!dup) {
            found.push({ kind: sp.kind, file: edge.file, line: edge.line, code: edge.code })
          }
        }
      }
    }
  }
  return found
}
