import io.shiftleft.semanticcpg.language._

cpg.method
  .where(_.annotation.name(".*Mapping.*"))
  .filter(m => m.file.name.headOption.exists(_.endsWith(".java")))
  .foreach { m =>
    val fileName = m.file.name.headOption.getOrElse("?")
    val lineNum  = m.lineNumber.getOrElse(-1)
    println(s"[Source] ${m.fullName} | $fileName | $lineNum | ${m.code}")
  }