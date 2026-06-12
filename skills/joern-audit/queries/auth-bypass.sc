import io.shiftleft.semanticcpg.language._

// Find Shiro permission/role check calls
println("=== Shiro Permission Checks ===")
cpg.call.code(".*hasRole.*|.*requiresPermissions.*|.*isPermitted.*|.*hasPermission.*")
  .filter(c => c.file.name.headOption.exists(_.endsWith(".java")))
  .foreach { c =>
    val fileName = c.file.name.headOption.getOrElse("?")
    val lineNum  = c.lineNumber.getOrElse(-1)
    println(s"[AuthCheck] $fileName | $lineNum | ${c.code}")
  }

// Find Shiro annotations on methods
println("\n=== Shiro Secured Methods ===")
cpg.method
  .where(_.annotation.name(".*RequiresPermissions.*|.*RequiresRoles.*|.*RequiresAuthentication.*"))
  .filter(m => m.file.name.headOption.exists(_.endsWith(".java")))
  .foreach { m =>
    val fileName = m.file.name.headOption.getOrElse("?")
    val lineNum  = m.lineNumber.getOrElse(-1)
    println(s"[SecuredMethod] $fileName | $lineNum | ${m.name}")
  }

// Find Controller methods that lack Shiro annotations (potential auth bypass)
println("\n=== Controller Methods Without Auth Checks ===")
cpg.method
  .where(_.annotation.name(".*Mapping.*"))
  .filter(m => m.file.name.headOption.exists(_.endsWith(".java")))
  .filterNot { m =>
    m.annotation.name(".*RequiresPermissions.*|.*RequiresRoles.*").nonEmpty ||
    m.call.code(".*hasRole.*|.*isPermitted.*|.*hasPermission.*").nonEmpty
  }
  .foreach { m =>
    val fileName = m.file.name.headOption.getOrElse("?")
    val lineNum  = m.lineNumber.getOrElse(-1)
    println(s"[Unsecured] $fileName | $lineNum | ${m.name} | ${m.code}")
  }