import io.shiftleft.semanticcpg.language._

def source = cpg.method.where(_.annotation.name(".*Mapping.*"))

def templateSinks = cpg.call
  .code(".*process\\(.*")
  .filter(c => c.file.name.headOption.exists(_.endsWith(".java")))

templateSinks.foreach { sink =>
  val sinkFile = sink.file.name.headOption.getOrElse("?")
  val sinkLine = sink.lineNumber.getOrElse(-1)
  println(s"[SSTI Sink] $sinkFile | $sinkLine | ${sink.code}")

  sink.start.reachableByFlows(source).take(50).foreach { flow =>
    println(s"[SSTI Flow] to $sinkFile:$sinkLine")
    flow.elements.foreach { elem =>
      val elemFile = elem.file.name.headOption.getOrElse("?")
      val elemLine = elem.lineNumber.getOrElse(-1)
      println(s"  -> $elemFile:$elemLine | ${elem.code}")
    }
    println("---")
  }
}
