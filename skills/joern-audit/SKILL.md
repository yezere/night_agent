---
name: joern-audit
description: CPG-based dataflow analysis for Java projects using Joern. Queries are generated dynamically based on the target project. AI learns from knowledge/joern-docs.md and writes fresh queries each time.
---

# joern-audit

Joern CPG dataflow analysis. No hardcoded queries — queries are regenerated per project.

## Query Generation Workflow

1. Read `knowledge/joern-docs.md` for CPG traversal patterns and best practices
2. Receive Bootstrap phase output: sink locations, source patterns, framework info, hypotheses
3. Write Joern query scripts based on the project's specific needs
4. Output queries to `skills/joern-audit/queries/` as `.sc` files

## Required Queries

### Always Generate
- **sources.sc** — Enumerate all user input entry points. Use annotation queries for Spring MVC (@RequestMapping, @GetMapping, etc.) and call queries for Servlet API (getParameter, getInputStream, etc.)
- **sinks.sc** — List all dangerous calls matched by SinkAgent candidates. Use `cpg.call.code()` with regex patterns for each sink category.
- **dataflow.sc** — Trace reachability from sources to sinks using `reachableByFlows`. Limit with `.take(100)`.

### Framework-Specific (generate based on dependencies)
- **deser.sc** — If fastjson/jackson present: trace from HTTP params to parseObject/readValue
- **ssti.sc** — If freemarker/velocity present: trace from user input to Template.process()
- **sqli.sc** — If mybatis present: trace from user input to SQL execution
- **auth-bypass.sc** — If Shiro present: find methods missing auth checks
- **xxe.sc** — If XML parsers present: trace to parse/unmarshal calls

## Query Design Principles

- Learn from `knowledge/joern-docs.md` before writing any queries
- `.filter(_.filename.endsWith(".java"))` to restrict to Java files
- `.take(100)` to limit results and prevent memory issues
- `.dedup` to remove duplicate flows
- Trace from sinks to sources (not the reverse) — more efficient
- Output format: `println(s"[Tag] field1 | field2 | field3")`

## Multi-File Format (CRITICAL)

Output each script with a separator line:
```
=== sources.sc ===
import io.shiftleft.semanticcpg.language._
// scala code here

=== sinks.sc ===
import io.shiftleft.semanticcpg.language._
// scala code here

=== dataflow.sc ===
import io.shiftleft.semanticcpg.language._
// scala code here
```

No markdown fences, no commentary — ONLY the separator lines and Scala code.

## Performance Notes

- Dataflow queries are expensive — narrow to confirmed sinks first
- Use `cpg.call.code("pattern").take(N)` to limit initial scope
- Run joern with `--script` per file, not all at once for large CPGs
- `.take()` early in the traversal chain, not at the end
