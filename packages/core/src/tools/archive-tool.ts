import { basename, extname, isAbsolute, relative, resolve } from "node:path"

export interface ArchiveToolCall {
  tool: "archive_list" | "jar_entries" | "jar_extract_source" | "jar_javap" | "jar_decompile"
  file?: string
  pattern?: string
  maxResults?: number
}

const DEFAULT_JOERN_HOME = process.env.HOME ? resolve(process.env.HOME, "joern", "joern-cli") : ""
const CFR_JAR = process.env.CFR_JAR || (DEFAULT_JOERN_HOME
  ? resolve(DEFAULT_JOERN_HOME, "frontends", "jimple2cpg", "lib", "org.benf.cfr-0.152.jar")
  : "org.benf.cfr-0.152.jar")

interface ArchiveFile {
  file: string
  size: number
}

export async function runArchiveTool(root: string, outputDir: string, call: ArchiveToolCall): Promise<string> {
  switch (call.tool) {
    case "archive_list":
      return listArchives(root, call)
    case "jar_entries":
      return listJarEntries(root, call)
    case "jar_extract_source":
      return extractSourceJar(root, outputDir, call)
    case "jar_javap":
      return javapJar(root, call)
    case "jar_decompile":
      return decompileJar(root, outputDir, call)
  }
}

async function listArchives(root: string, call: ArchiveToolCall): Promise<string> {
  const max = clamp(call.maxResults, 1, 500, 120)
  const pattern = safeRegex(call.pattern)
  const archives: ArchiveFile[] = []

  for await (const entry of new Bun.Glob("**/*").scan({ cwd: root, dot: false })) {
    if (shouldSkip(entry)) continue
    if (!/\.(jar|war|zip)$/i.test(entry)) continue
    if (pattern && !pattern.test(entry)) continue
    const file = resolve(root, entry)
    try {
      const stat = await Bun.file(file).stat()
      archives.push({ file: entry, size: stat.size })
    } catch {
      // ignore unreadable archives
    }
  }

  archives.sort((a, b) => sourceJarRank(a.file) - sourceJarRank(b.file) || a.file.localeCompare(b.file))
  return `[archive_list]\n${archives.slice(0, max).map((item) => `${item.file} | ${(item.size / 1024).toFixed(1)}KB`).join("\n") || "(no archives)"}`
}

async function listJarEntries(root: string, call: ArchiveToolCall): Promise<string> {
  const jar = resolveArchive(root, call.file)
  if (!jar) return "[jar_entries] error: file outside project root or missing file"
  const max = clamp(call.maxResults, 1, 500, 160)
  const pattern = safeRegex(call.pattern)
  const entries = await jarTf(jar)
  const filtered = entries
    .filter((entry) => !pattern || pattern.test(entry))
    .slice(0, max)
  return `[jar_entries] ${relative(root, jar)}\n${filtered.join("\n") || "(no matching entries)"}`
}

async function extractSourceJar(root: string, outputDir: string, call: ArchiveToolCall): Promise<string> {
  const jar = resolveArchive(root, call.file)
  if (!jar) return "[jar_extract_source] error: file outside project root or missing file"
  const entries = (await jarTf(jar)).filter((entry) => entry.endsWith(".java"))
  if (entries.length === 0) return `[jar_extract_source] ${relative(root, jar)} has no .java entries`

  const max = clamp(call.maxResults, 1, 300, 120)
  const safeName = basename(jar).replace(/[^a-zA-Z0-9_.-]/g, "_")
  const extractDir = resolve(outputDir, "archive-sources", `${safeName}-${crypto.randomUUID().slice(0, 8)}`)
  await Bun.$`mkdir -p ${extractDir}`

  const selected = entries.slice(0, max)
  const proc = Bun.spawn(["jar", "xf", jar, ...selected], {
    cwd: extractDir,
    stdout: "pipe",
    stderr: "pipe",
  })
  const stderr = await new Response(proc.stderr).text()
  const exitCode = await proc.exited
  if (exitCode !== 0) return `[jar_extract_source] error: ${stderr.slice(0, 500)}`

  const preview: string[] = []
  for (const entry of selected.slice(0, 8)) {
    const file = resolve(extractDir, entry)
    try {
      const text = await Bun.file(file).text()
      preview.push(`--- ${relative(root, file)} ---\n${text.split("\n").slice(0, 40).join("\n")}`)
    } catch {
      // skip preview
    }
  }

  return `[jar_extract_source] ${relative(root, jar)} -> ${relative(root, extractDir)} (${selected.length}/${entries.length} java files)\n${preview.join("\n")}`
}

async function javapJar(root: string, call: ArchiveToolCall): Promise<string> {
  const jar = resolveArchive(root, call.file)
  if (!jar) return "[jar_javap] error: file outside project root or missing file"
  const pattern = safeRegex(call.pattern)
  const max = clamp(call.maxResults, 1, 30, 8)
  const classes = (await jarTf(jar))
    .filter((entry) => entry.endsWith(".class") && !entry.includes("$"))
    .map((entry) => entry.replace(/\.class$/, "").replaceAll("/", "."))
    .filter((className) => !pattern || pattern.test(className))
    .slice(0, max)

  const outputs: string[] = []
  for (const className of classes) {
    const proc = Bun.spawn(["javap", "-classpath", jar, "-p", className], {
      stdout: "pipe",
      stderr: "pipe",
    })
    const stdout = await new Response(proc.stdout).text()
    const stderr = await new Response(proc.stderr).text()
    await proc.exited
    outputs.push(`--- ${className} ---\n${(stdout || stderr).slice(0, 5000)}`)
  }
  return `[jar_javap] ${relative(root, jar)}\n${outputs.join("\n") || "(no matching classes)"}`
}

async function decompileJar(root: string, outputDir: string, call: ArchiveToolCall): Promise<string> {
  const jar = resolveArchive(root, call.file)
  if (!jar) return "[jar_decompile] error: file outside project root or missing file"
  if (!(await exists(CFR_JAR))) return `[jar_decompile] error: CFR jar not found at ${CFR_JAR}`

  const pattern = safeRegex(call.pattern)
  const max = clamp(call.maxResults, 1, 20, 6)
  const classes = (await jarTf(jar))
    .filter((entry) => entry.endsWith(".class") && !entry.includes("$"))
    .filter((entry) => !pattern || pattern.test(entry) || pattern.test(entry.replace(/\.class$/, "").replaceAll("/", ".")))
    .slice(0, max)

  if (classes.length === 0) return `[jar_decompile] ${relative(root, jar)}\n(no matching classes)`

  const safeName = basename(jar).replace(/[^a-zA-Z0-9_.-]/g, "_")
  const workDir = resolve(outputDir, "archive-decompiled", `${safeName}-${crypto.randomUUID().slice(0, 8)}`)
  await Bun.$`mkdir -p ${workDir}`

  const proc = Bun.spawn([
    "java",
    "-jar",
    CFR_JAR,
    jar,
    "--outputdir",
    workDir,
    "--silent",
    "true",
    "--extraclasspath",
    jar,
  ], {
    stdout: "pipe",
    stderr: "pipe",
  })
  const timer = setTimeout(() => proc.kill(), 90_000)
  const stderr = await new Response(proc.stderr).text()
  const exitCode = await proc.exited
  clearTimeout(timer)
  if (exitCode !== 0) return `[jar_decompile] error: ${stderr.slice(0, 700)}`

  const previews: string[] = []
  for (const entry of classes) {
    const javaPath = resolve(workDir, entry.replace(/\.class$/, ".java"))
    try {
      const text = await Bun.file(javaPath).text()
      previews.push(`--- ${relative(root, javaPath)} ---\n${text.split("\n").slice(0, 120).join("\n")}`)
    } catch {
      previews.push(`--- ${entry} ---\n(decompiled file not found; use jar_javap for this class)`)
    }
  }

  return `[jar_decompile] ${relative(root, jar)} -> ${relative(root, workDir)} (${classes.length} class preview(s))\n${previews.join("\n")}`
}

async function jarTf(jar: string): Promise<string[]> {
  const proc = Bun.spawn(["jar", "tf", jar], {
    stdout: "pipe",
    stderr: "pipe",
  })
  const stdout = await new Response(proc.stdout).text()
  await proc.exited
  return stdout.split("\n").map((line) => line.trim()).filter(Boolean)
}

function resolveArchive(root: string, file: unknown): string | null {
  if (typeof file !== "string" || !file.trim()) return null
  const target = isAbsolute(file) ? resolve(file) : resolve(root, file)
  const rel = relative(root, target)
  if (rel.startsWith("..") || isAbsolute(rel)) return null
  if (!/\.(jar|war|zip)$/i.test(target)) return null
  return target
}

function shouldSkip(entry: string): boolean {
  return /(^|\/)(\.git|\.night-agent|\.night_agent|node_modules|output-audit)(\/|$)/.test(entry)
}

function sourceJarRank(file: string): number {
  if (/-sources\.(jar|zip)$/i.test(file)) return 0
  if (/source/i.test(file)) return 1
  if (extname(file).toLowerCase() === ".war") return 2
  return 3
}

function safeRegex(pattern: unknown): RegExp | null {
  if (typeof pattern !== "string" || !pattern.trim()) return null
  try {
    return new RegExp(pattern, "i")
  } catch {
    return null
  }
}

function clamp(value: unknown, min: number, max: number, fallback: number): number {
  const parsed = typeof value === "number" ? value : parseInt(String(value ?? ""), 10)
  if (!Number.isFinite(parsed)) return fallback
  return Math.max(min, Math.min(max, parsed))
}

async function exists(file: string): Promise<boolean> {
  try {
    await Bun.file(file).stat()
    return true
  } catch {
    return false
  }
}
