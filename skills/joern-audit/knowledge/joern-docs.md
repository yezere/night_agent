# Joern CPG Query Documentation

Condensed reference for writing Joern Scala query scripts that compile and run correctly.

## Required Import

```scala
import io.shiftleft.semanticcpg.language._
```

## CRITICAL: Correct Joern DSL Patterns

### Getting the filename from nodes

```scala
// For Call nodes — use .file.name (NOT .filename!)
c.file.name.headOption.getOrElse("unknown")

// For Method nodes — use .file.name
m.file.name.headOption.getOrElse("unknown")

// For Parameter nodes
p.file.name.headOption.getOrElse("unknown")

// Filtering by Java file extension
cpg.call.filter(c => c.file.name.headOption.exists(_.endsWith(".java")))
cpg.method.name(".*").filter(m => m.file.name.headOption.exists(_.endsWith(".java")))
```

### Annotation matching

```scala
// .name() takes a SINGLE regex STRING — NOT a Set, NOT multiple args
cpg.method.where(_.annotation.name(".*Mapping.*"))

// Match one specific annotation
cpg.annotation.name("RequestMapping")

// Match multiple — use regex alternation
cpg.method.where(_.annotation.name(".*RequestMapping.*|.*GetMapping.*|.*PostMapping.*"))
```

### Method name matching

```scala
cpg.method.name("exec")              // exact match
cpg.method.name(".*Controller.*")    // regex match
cpg.method.fullName(".*com\\.zzjee.*")
```

### Call code matching

```scala
cpg.call.name("exec")               // call name
cpg.call.code(".*exec\\(.*")        // regex on source code text
cpg.call.methodFullName(".*parse.*") // full qualified method name
```

### Line numbers

```scala
node.lineNumber.getOrElse(-1)        // Some(line) or None → -1
node.lineNumber.head                 // may throw if empty
```

### Output format

```scala
println(s"[Source] ${m.fullName} | ${m.file.name.headOption.getOrElse("?")} | ${m.lineNumber.getOrElse(-1)} | ${m.code.take(200)}")
println(s"[Sink] category | ${c.file.name.headOption.getOrElse("?")} | ${c.lineNumber.getOrElse(-1)} | ${c.code.take(200)}")
println(s"[Path] ${n.code.take(200)} | ${n.file.name.headOption.getOrElse("?")} | ${n.lineNumber.getOrElse(-1)}")
```

## Source Patterns (User-controllable input)

```scala
// Spring MVC Controller methods — find methods with mapping annotations
cpg.method.name(".*Controller.*")
  .where(_.annotation.name(".*Mapping.*"))
  .filter(m => m.file.name.headOption.exists(_.endsWith(".java")))
  .take(100)
  .foreach { m =>
    println(s"[Source] ${m.fullName} | ${m.file.name.headOption.getOrElse("?")} | ${m.lineNumber.getOrElse(-1)} | ${m.code.take(200)}")
  }

// HttpServletRequest parameters in Controller methods
cpg.parameter.typeFullName(".*HttpServletRequest.*")
  .filter(p => p.file.name.headOption.exists(_.endsWith(".java")))
  .take(100)
  .foreach { p =>
    println(s"[Source] ${p.method.fullName.headOption.getOrElse("?")} | ${p.file.name.headOption.getOrElse("?")} | ${p.lineNumber.getOrElse(-1)} | ${p.code.take(200)}")
  }

// Spring parameter annotations (find parameters annotated with @RequestParam etc.)
cpg.parameter.where(_.annotation.name(".*RequestParam.*|.*PathVariable.*|.*RequestBody.*|.*RequestHeader.*|.*CookieValue.*|.*ModelAttribute.*"))
  .filter(p => p.file.name.headOption.exists(_.endsWith(".java")))
  .take(100)
  .foreach { p =>
    println(s"[Source] ${p.name} | ${p.file.name.headOption.getOrElse("?")} | ${p.lineNumber.getOrElse(-1)} | ${p.code.take(200)}")
  }
```

## Sink Patterns (Dangerous calls)

```scala
// Command Injection
cpg.call.code(".*exec\\(.*")
  .filter(c => c.file.name.headOption.exists(_.endsWith(".java")))
  .take(100)
  .foreach { c =>
    println(s"[Sink] cmdi | ${c.file.name.headOption.getOrElse("?")} | ${c.lineNumber.getOrElse(-1)} | ${c.code}")
  }

// Deserialization
cpg.call.code(".*readObject\\(.*").take(100).foreach(c => println(s"[Sink] deser | ${c.file.name.headOption.getOrElse("?")} | ${c.lineNumber.getOrElse(-1)} | ${c.code}"))

// SQL Injection
cpg.call.code(".*execute\\(.*|.*executeQuery\\(.*|.*executeUpdate\\(.*").take(100).foreach(c => println(s"[Sink] sqli | ${c.file.name.headOption.getOrElse("?")} | ${c.lineNumber.getOrElse(-1)} | ${c.code}"))

// SSRF
cpg.call.code(".*openConnection\\(.*|.*getForObject\\(.*|.*postForObject\\(.*").take(100).foreach(c => println(s"[Sink] ssrf | ${c.file.name.headOption.getOrElse("?")} | ${c.lineNumber.getOrElse(-1)} | ${c.code}"))

// SSTI / Template Injection
cpg.call.code(".*process\\(.*").take(100).foreach(c => println(s"[Sink] ssti | ${c.file.name.headOption.getOrElse("?")} | ${c.lineNumber.getOrElse(-1)} | ${c.code}"))

// Path Traversal
cpg.call.code(".*Paths\\.get\\(.*|.*Files\\.read.*|.*Files\\.copy\\(.*|.*new File\\(.*").take(100).foreach(c => println(s"[Sink] pathtrav | ${c.file.name.headOption.getOrElse("?")} | ${c.lineNumber.getOrElse(-1)} | ${c.code}"))

// XXE
cpg.call.code(".*\\.parse\\(.*|.*\\.unmarshal\\(.*").take(100).foreach(c => println(s"[Sink] xxe | ${c.file.name.headOption.getOrElse("?")} | ${c.lineNumber.getOrElse(-1)} | ${c.code}"))

// MyBatis (SQL mappers)
cpg.call.code(".*Mapper\\..*|.*SqlSession\\..*").take(100).foreach(c => println(s"[Sink] mybatis | ${c.file.name.headOption.getOrElse("?")} | ${c.lineNumber.getOrElse(-1)} | ${c.code}"))
```

## Dataflow Queries

```scala
// Find Controller methods as sources
def source = cpg.method.name(".*Controller.*").where(_.annotation.name(".*Mapping.*"))

// Find dangerous calls as sinks  
def sink = cpg.call.code(".*exec\\(.*")

// Trace dataflow from source to sink
sink.reachableByFlows(source).take(100).foreach { flow =>
  flow.elements.foreach { node =>
    println(s"[Path] ${node.file.name.headOption.getOrElse("?")} | ${node.lineNumber.getOrElse(-1)} | ${node.code.take(200)}")
  }
  println("---")
}
```

## Performance Guidelines

- Always use `.take(N)` to limit results (max 100 for dataflow)
- Always filter to `.java` files
- Dataflow queries are expensive — narrow sources and sinks before `reachableByFlows`
- Use `.dedup` to remove duplicate flows
- `.take()` should be the LAST call in the chain before `.foreach`

## Multi-File Output Format

When outputting multiple scripts, use this format:
```
=== sources.sc ===
import io.shiftleft.semanticcpg.language._
[Scala code]

=== sinks.sc ===
import io.shiftleft.semanticcpg.language._
[Scala code]

=== dataflow.sc ===
import io.shiftleft.semanticcpg.language._
[Scala code]
```
