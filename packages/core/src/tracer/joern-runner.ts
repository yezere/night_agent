import { basename, resolve } from "node:path"
import type { JoernRunResult, ProjectProfile } from "../types/index.ts"
import { buildJoernEnv, stopChildProcess } from "./joern-resources.ts"

const DEFAULT_JOERN_HOME = process.env.HOME ? resolve(process.env.HOME, "joern", "joern-cli") : ""
const JOERN_HOME = process.env.JOERN_HOME || DEFAULT_JOERN_HOME
const JAVASRC2CPG = process.env.JAVASRC2CPG ?? (JOERN_HOME ? resolve(JOERN_HOME, "javasrc2cpg") : "javasrc2cpg")
const JOERN = process.env.JOERN ?? (JOERN_HOME ? resolve(JOERN_HOME, "joern") : "joern")

export const QUERY_DIR = resolve(import.meta.dir, "../../../../skills/joern-audit/queries")

async function exists(path: string): Promise<boolean> {
  return Bun.file(path).exists().catch(() => false)
}

export async function listQueryScripts(dir: string): Promise<string[]> {
  const files: string[] = []
  try {
    for await (const entry of new Bun.Glob("*.sc").scan({ cwd: dir })) {
      files.push(entry)
    }
  } catch {
    // dir doesn't exist
  }
  return files
}

async function runCommand(command: string[], cwd: string, outputFile?: string, timeoutMs?: number): Promise<number> {
  const proc = Bun.spawn(command, {
    cwd,
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

  if (outputFile) {
    await Bun.write(
      outputFile,
      `${stdout}\n${stderr}`.replace(/^\[INFO.*$/gm, "").replace(/^executing.*$/gm, ""),
    )
  }
  return killed ? -1 : exitCode
}

async function collectJavaSourceRoots(
  target: string,
  outputDir: string,
  projectName: string,
): Promise<string> {
  const srcRoot = resolve(outputDir, `${projectName}-src`)
  await Bun.$`rm -rf ${srcRoot}`
  await Bun.$`mkdir -p ${srcRoot}`
  const proc = Bun.spawn(["find", target, "-path", "*/src/main/java", "-type", "d"], {
    stdout: "pipe",
  })
  const text = await new Response(proc.stdout).text()
  await proc.exited
  const dirs = text
    .split("\n")
    .map((s) => s.trim())
    .filter(Boolean)
  if (dirs.length === 0) {
    await Bun.$`ln -s ${target} ${resolve(srcRoot, projectName)}`
    return srcRoot
  }
  for (const dir of dirs) {
    const moduleName =
      dir
        .replace(target, "")
        .replace(/\/src\/main\/java$/, "")
        .replace(/^\//, "")
        .replaceAll("/", "_") || basename(target)
    await Bun.$`ln -s ${dir} ${resolve(srcRoot, moduleName)}`
  }
  return srcRoot
}

export async function generateCpg(
  profile: ProjectProfile,
  outputDir: string,
): Promise<{ cpgPath: string; ok: boolean; skippedReason?: string }> {
  await Bun.$`mkdir -p ${outputDir}`

  if (profile.language !== "java")
    return { cpgPath: "", ok: false, skippedReason: "not a java project" }
  if (!(await exists(JAVASRC2CPG)) || !(await exists(JOERN)))
    return { cpgPath: "", ok: false, skippedReason: `joern not found: ${JAVASRC2CPG} / ${JOERN}` }

  const cpgPath = resolve(outputDir, "project-cpg.bin")

  // Skip if CPG already exists AND is valid (> 1MB)
  if (await exists(cpgPath)) {
    try {
      const stat = await Bun.$`stat -c%s ${cpgPath}`.text()
      const sizeBytes = parseInt(stat.trim(), 10)
      if (sizeBytes < 1_000_000) {
        console.log(`  CPG at ${cpgPath} is only ${(sizeBytes / 1024).toFixed(0)}KB — regenerating`)
        await Bun.$`rm -rf ${cpgPath}`
      } else {
        console.log(`  CPG already exists at ${cpgPath} (${(sizeBytes / 1_048_576).toFixed(1)}MB), skipping generation`)
        return { cpgPath, ok: true }
      }
    } catch {
      console.log(`  Cannot validate existing CPG at ${cpgPath}, regenerating`)
      await Bun.$`rm -rf ${cpgPath}`
    }
  }

  // Use project root directly — javasrc2cpg auto-discovers Java sources.
  // Symlink-based source collection produces corrupt CPGs.
  const buildLog = resolve(outputDir, "joern-build.log")
  console.log(`  generating CPG: ${JAVASRC2CPG} ${profile.root} --output ${cpgPath}`)
  const exitCode = await runCommand([JAVASRC2CPG, profile.root, "--output", cpgPath], profile.root, buildLog, 1_800_000)

  if (exitCode !== 0) {
    return { cpgPath, ok: false, skippedReason: `CPG generation failed (exit ${exitCode})` }
  }

  return { cpgPath, ok: true }
}

export async function runJoern(
  profile: ProjectProfile,
  outputDir: string,
  runJoernEnabled: boolean,
  existingCpgPath?: string,
  queryDir: string = resolve(outputDir, "ai-joern-queries"),
): Promise<JoernRunResult> {
  await Bun.$`mkdir -p ${outputDir}`

  if (!runJoernEnabled) return { ran: false, skippedReason: "--no-joern", queryOutputs: [] }
  if (profile.language !== "java")
    return { ran: false, skippedReason: "not a java project", queryOutputs: [] }
  if (!(await exists(JAVASRC2CPG)) || !(await exists(JOERN))) {
    return {
      ran: false,
      skippedReason: `joern not found: ${JAVASRC2CPG} / ${JOERN}`,
      queryOutputs: [],
    }
  }

  const queryScripts = await listQueryScripts(queryDir)

  // Use existing CPG or generate one
  let cpgPath: string
  if (existingCpgPath) {
    cpgPath = existingCpgPath
  } else {
    const result = await generateCpg(profile, outputDir)
    if (!result.ok) return { ran: false, skippedReason: result.skippedReason, queryOutputs: [] }
    cpgPath = result.cpgPath
  }

  if (queryScripts.length === 0) {
    console.log(`  [!] No AI Joern query scripts found in ${queryDir}`)
    return {
      ran: true,
      cpgPath,
      queryOutputs: [],
      skippedReason: `no AI query scripts in ${queryDir} — per-hypothesis tracing still available`,
    }
  }

  console.log(`  using ${queryScripts.length} Joern query script(s): ${queryScripts.join(", ")}`)

  const queryOutputs: JoernRunResult["queryOutputs"] = []
  for (const script of queryScripts) {
    const outputFile = resolve(outputDir, `${script}.out.txt`)
    const exitCode = await runCommand(
      [JOERN, cpgPath, "--script", resolve(queryDir, script)],
      profile.root,
      outputFile,
      600_000,
    )
    queryOutputs.push({ name: script, outputFile, exitCode })
  }

  return { ran: true, cpgPath, queryOutputs }
}
