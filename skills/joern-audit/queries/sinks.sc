import io.shiftleft.semanticcpg.language._

val categories = List(
  ("saxparser-parse", ".*parse\\(.*".r),
  ("mybatis-select", ".*select\\(.*|.*selectList\\(.*|.*selectOne\\(.*".r),
  ("statement-execute", ".*execute\\(.*".r),
  ("fastjson-parseobject", ".*parseObject\\(.*".r),
  ("freemarker-process", ".*process\\(.*".r),
  ("url-openconnection", ".*openConnection\\(.*".r),
  ("fastjson-parsearray", ".*parseArray\\(.*".r),
  ("readobject", ".*readObject\\(.*".r),
  ("ObjectInputStream.readObject", ".*readObject\\(.*".r),
  ("statement-executequery", ".*executeQuery\\(.*".r)
)

categories.foreach { case (category, pattern) =>
  cpg.call.code(pattern.toString)
    .filter(c => c.file.name.headOption.exists(_.endsWith(".java")))
    .take(100)
    .foreach { c =>
      println(s"[Sink] $category | ${c.file.name.headOption.getOrElse("?")} | ${c.lineNumber.getOrElse(-1)} | ${c.code}")
    }
}