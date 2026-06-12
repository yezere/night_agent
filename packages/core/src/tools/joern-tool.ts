import { basename, isAbsolute, relative, resolve } from "node:path"

const JAVA_HOME = process.env.JAVA_HOME || "/usr/lib/jvm/java-21-openjdk-amd64"
const DEFAULT_JOERN_HOME = process.env.HOME ? resolve(process.env.HOME, "joern", "joern-cli") : ""
const JOERN_HOME = process.env.JOERN_HOME || DEFAULT_JOERN_HOME
const JOERN = process.env.JOERN ?? (JOERN_HOME ? resolve(JOERN_HOME, "joern") : "joern")

export interface JoernToolCall {
  tool: "joern_search" | "joern_script"
  query?: string
  script?: string
  sinkPattern?: string
  sourcePattern?: string
  file?: string
  line?: number
  maxResults?: number
}

export async function runJoernTool(cpgPath: string, outputDir: string, call: JoernToolCall): Promise<string> {
  if (!cpgPath) return `[${call.tool}] error: missing CPG path`
  if (call.tool === "joern_search") {
    const script = buildSearchScript(call)
    return runJoernScript(cpgPath, outputDir, script, "joern-tool-search", call.maxResults)
  }
  if (!call.script?.trim()) return "[joern_script] error: missing script"
  return runJoernScript(cpgPath, outputDir, sanitizeScript(call.script), "joern-tool-script", call.maxResults)
}

function buildSearchScript(call: JoernToolCall): string {
  const query = String(call.query ?? "sinks").toLowerCase()
  const max = clamp(call.maxResults, 1, 200, 80)
  const fileFilter = call.file ? fileFilterExpr(call.file) : "true"
  const lineFilter = Number.isFinite(call.line) ? `c.lineNumber.headOption.forall(_ == ${call.line})` : "true"

  if (query.includes("source")) {
    return `import io.shiftleft.semanticcpg.language._
val max = ${max}
val methods = cpg.method.where(_.annotation.name(".*Mapping.*")).l
methods.take(max).foreach { m =>
  val fname = m.file.name.headOption.getOrElse("?")
  val line = m.lineNumber.getOrElse(-1)
  println(s"[SourceMethod] $fname | $line | " + m.fullName)
  m.parameter.take(20).foreach { p => println(s"[SourceParam] $fname | " + p.lineNumber.getOrElse(line) + " | " + p.code) }
}
cpg.call.code(".*getParameter.*|.*getHeader.*|.*getInputStream.*|.*getReader.*").filter(c => ${fileFilter}).take(max).foreach { c =>
  println(s"[SourceCall] " + c.file.name.headOption.getOrElse("?") + " | " + c.lineNumber.getOrElse(-1) + " | " + c.code)
}`
  }

  if (query.includes("dataflow")) {
    const sourcePattern = escapeScalaRegex(call.sourcePattern || ".*Mapping.*")
    const sinkPattern = escapeScalaRegex(call.sinkPattern || ".*exec\\(.*|.*openConnection.*|.*execute\\(.*|.*readObject.*|.*parseObject.*|.*process\\(.*|.*FileInputStream.*|.*getOutputStream.*|.*FileUtil\\..*")
    return `import io.shiftleft.semanticcpg.language._
def source = cpg.method.where(_.annotation.name("${sourcePattern}")).parameter
def sink = cpg.call.code("${sinkPattern}").filter(c => ${fileFilter} && ${lineFilter})
sink.reachableByFlows(source).take(${max}).foreach { flow =>
  println("[Dataflow]")
  flow.elements.foreach { n =>
    println(n.file.name.headOption.getOrElse("?") + " | " + n.lineNumber.getOrElse(-1) + " | " + n.code.take(200).replace("\\n", " "))
  }
}`
  }

  const pattern = escapeScalaRegex(call.sinkPattern || ".*Runtime.*exec.*|.*ProcessBuilder.*|.*new URL.*|.*openConnection.*|.*InitialContext.*|.*lookup.*|.*parseObject.*|.*readObject.*|.*execute\\(.*|.*new File.*|.*Paths.get.*|.*Files\\.(read|copy|write|newInputStream|newOutputStream).*|.*FileInputStream.*|.*FileOutputStream.*|.*ServletOutputStream.*|.*getOutputStream.*|.*FileUtil\\.(file|exist|ls|del|read|readBytes|readUtf8String|write|writeBytes).*|.*Template.*|.*process\\(.*|.*parseExpression.*")
  return `import io.shiftleft.semanticcpg.language._
cpg.call.code("${pattern}").filter(c => ${fileFilter} && ${lineFilter}).take(${max}).foreach { c =>
  println("[Sink] " + c.file.name.headOption.getOrElse("?") + " | " + c.lineNumber.getOrElse(-1) + " | " + c.code.take(240).replace("\\n", " "))
}`
}

function fileFilterExpr(file: string): string {
  const safe = basename(file).replace(/"/g, "")
  return `c.file.name.headOption.exists(_.endsWith("${safe}"))`
}

function sanitizeScript(script: string): string {
  const cleaned = script
    .replace(/^```scala\s*\n?/gm, "")
    .replace(/^```\s*\n?/gm, "")
    .replace(/```\s*$/gm, "")
    .trim()
  return cleaned.includes("import io.shiftleft.semanticcpg.language._")
    ? cleaned
    : `import io.shiftleft.semanticcpg.language._\n${cleaned}`
}

async function runJoernScript(
  cpgPath: string,
  outputDir: string,
  script: string,
  prefix: string,
  maxResults?: number,
): Promise<string> {
  await Bun.$`mkdir -p ${outputDir}`
  const scriptPath = resolve(outputDir, `${prefix}-${crypto.randomUUID().slice(0, 8)}.sc`)
  await Bun.write(scriptPath, script)

  const proc = Bun.spawn([JOERN, cpgPath, "--script", scriptPath], {
    stdout: "pipe",
    stderr: "pipe",
    env: { ...process.env, JAVA_HOME, PATH: `${JAVA_HOME}/bin:${process.env.PATH}` },
  })
  const timer = setTimeout(() => proc.kill(), 90_000)
  const stdout = await new Response(proc.stdout).text()
  const stderr = await new Response(proc.stderr).text()
  const exitCode = await proc.exited
  clearTimeout(timer)

  const max = clamp(maxResults, 1, 200, 120)
  const body = `${stdout}\n${stderr}`
    .replace(/^\[INFO.*$/gm, "")
    .replace(/^executing.*$/gm, "")
    .split("\n")
    .filter(Boolean)
    .slice(0, max)
    .join("\n")
  const relScript = relative(outputDir, scriptPath)
  return `[${prefix}] exit=${exitCode} script=${relScript}\n${body || "(no output)"}`
}

function escapeScalaRegex(value: string): string {
  return value.replace(/\\/g, "\\\\").replace(/"/g, "\\\"")
}

function clamp(value: unknown, min: number, max: number, fallback: number): number {
  const parsed = typeof value === "number" ? value : parseInt(String(value ?? ""), 10)
  if (!Number.isFinite(parsed)) return fallback
  return Math.max(min, Math.min(max, parsed))
}
