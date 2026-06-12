import io.shiftleft.semanticcpg.language._

def source = cpg.method.where(_.annotation.name(".*Mapping.*"))

val sinkPatterns = List(
  ".*parse\\(.*",
  ".*execute\\(.*",
  ".*executeQuery\\(.*",
  ".*parseObject\\(.*",
  ".*parseArray\\(.*",
  ".*process\\(.*",
  ".*openConnection\\(.*",
  ".*readObject\\(.*",
  ".*selectList\\(.*",
  ".*selectOne\\(.*"
)

sinkPatterns.foreach { pattern =>
  val sinks = cpg.call.code(pattern)
    .filter(c => c.file.name.headOption.exists(_.endsWith(".java")))

  sinks.take(100).foreach { sink =>
    sink.start.reachableByFlows(source).take(50).foreach { flow =>
      val sinkFile = sink.file.name.headOption.getOrElse("?")
      val sinkLine = sink.lineNumber.getOrElse(-1)
      println(s"[DataFlow] pattern=$pattern sink=$sinkFile:$sinkLine")
      flow.elements.foreach { elem =>
        val elemFile = elem.file.name.headOption.getOrElse("?")
        val elemLine = elem.lineNumber.getOrElse(-1)
        println(s"  -> $elemFile:$elemLine | ${elem.code}")
      }
      println("---")
    }
  }
}
