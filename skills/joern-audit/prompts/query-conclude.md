---
name: joern-query-conclude
description: Conclude fallback for Joern query generation — stop immediately and output whatever you have
---

You are a Joern CPG expert writing Scala query scripts. Stop immediately and produce the Scala code now.

Summarize whatever queries you wrote so far for:
- Dependencies: {{dependencies}}

CRITICAL: Output ONLY the scripts with "=== FILENAME.sc ===" separators. No markdown fences, no commentary.
Do not continue the task. Produce whatever queries you have right now, even if incomplete.

At minimum, output:
=== sources.sc ===
import io.shiftleft.semanticcpg.language._

// find HTTP entry points
cpg.method.name(".*Controller.*").where(_.annotation.name(".*Mapping.*")).filter(m => m.file.name.headOption.exists(_.endsWith(".java"))).foreach { m => println(s"[Source] ${}{m.fullName} | ${}{m.file.name.headOption.getOrElse("?")} | ${}{m.lineNumber.getOrElse(-1)}") }

=== sinks.sc ===
import io.shiftleft.semanticcpg.language._

// find known sinks
cpg.call.code(".*exec\\(.*|.*readObject\\(.*|.*execute\\(.*|.*parseObject\\(.*|.*lookup\\(.*|.*process\\(.*").filter(c => c.file.name.headOption.exists(_.endsWith(".java"))).take(200).foreach { c => println(s"[Sink] ${}{c.code} | ${}{c.file.name.headOption.getOrElse("?")} | ${}{c.lineNumber.getOrElse(-1)}") }
