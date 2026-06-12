import type { Severity } from "../types/index.ts"

// Hint rules are used to select files/windows and recover candidates for agents.
// They are not vulnerability verdict rules; Verifier/Judge still decide truth.

export interface TextSinkHint {
  category: string
  severity: Severity
  sinkPattern: string
  pattern: RegExp
  description: string
}

interface SinkNormalizer {
  value: string
  pattern: RegExp
  requires?: RegExp
}

export const JAVA_SOURCE_CONTEXT_PATTERNS: RegExp[] = [
  /@RequestMapping|@GetMapping|@PostMapping|@PutMapping|@DeleteMapping|@PatchMapping/,
  /@RequestParam|@RequestBody|@PathVariable|@RequestHeader|@CookieValue|@ModelAttribute/,
  /@WebServlet|extends\s+(?:HttpServlet|GenericServlet)|\b(?:doGet|doPost|doPut|doDelete|doPatch|service)\s*\(/,
  /HttpServletRequest|ServletRequest/,
  /\.getParameter\s*\(|\.getParameterValues\s*\(|\.getParameterNames\s*\(|\.getParameterMap\s*\(|\.getHeader\s*\(|\.getCookies\s*\(/,
  /\.getInputStream\s*\(|\.getReader\s*\(|\.getPart\s*\(|\.getParts\s*\(/,
  /\.getQueryString\s*\(|\.getRequestURI\s*\(|\.getPathInfo\s*\(|\.getServletPath\s*\(/,
  /\$\{\s*(?:param|paramValues|header|cookie|pageContext\.request)\b/,
  /<jsp:setProperty\b|<%[=@]?/,
  /MultipartFile|Part\s+\w+|FileItem/,
  /upload|download|callback|redirect|url|path|file|cmd|sql|jndi|template|expr/i,
]

export const JAVA_SINK_CONTEXT_PATTERNS: RegExp[] = [
  /Runtime\.getRuntime\(\)\.exec|\.exec\s*\(/,
  /new\s+ProcessBuilder\s*\(/,
  /new\s+URL\s*\(|\.openConnection\s*\(|RestTemplate|HttpClient/,
  /InitialContext\s*\(|\.lookup\s*\(/,
  /JSON\.parseObject|JSON\.parse|parseArray\s*\(/,
  /ObjectInputStream|\.readObject\s*\(/,
  /Statement|PreparedStatement|createStatement|prepareStatement|executeQuery\s*\(|executeUpdate\s*\(|executeLargeUpdate\s*\(/,
  /new\s+File\s*\(|Paths\.get\s*\(|Files\.(read|copy|write|newInputStream|newOutputStream)/,
  /Template|\.process\s*\(/,
  /DocumentBuilder|SAXParser|Unmarshaller|\.parse\s*\(/,
  /SpelExpressionParser|parseExpression|Ognl/,
  /MultipartFile|transferTo\s*\(|getOriginalFilename\s*\(|Part\s+\w+|\b(?:part|filePart|uploadPart)\s*\.write\s*\(|getSubmittedFileName\s*\(/i,
  /ServletOutputStream|OutputStream|ResponseEntity\s*<\s*(?:byte\[\]|Resource)|FileInputStream|InputStreamResource|ByteArrayResource|Files\.read/,
  /sendRedirect\s*\(|getRequestDispatcher\s*\(|\.forward\s*\(|\.include\s*\(|setHeader\s*\(\s*["']Location["']/,
  /response\.getWriter\s*\(\)|JspWriter|out\.(?:print|println|write)\s*\(|<%=/,
  /\$\{\s*(?:param|paramValues|header|cookie|pageContext\.request)\b/,
]

export const JAVA_TEXT_SINK_HINTS: TextSinkHint[] = [
  { category: "cmdi", severity: "high", sinkPattern: "Runtime.exec", pattern: /Runtime\.getRuntime\(\)\.exec|\.exec\s*\(/, description: "Runtime command execution sink" },
  { category: "cmdi", severity: "high", sinkPattern: "ProcessBuilder", pattern: /new\s+ProcessBuilder\s*\(/, description: "ProcessBuilder command execution sink" },
  { category: "ssrf", severity: "medium", sinkPattern: "network-request", pattern: /new\s+URL\s*\(|\.openConnection\s*\(/, description: "URL/network request sink" },
  { category: "jndi", severity: "high", sinkPattern: "InitialContext.lookup", pattern: /InitialContext\s*\(|\.lookup\s*\(/, description: "JNDI lookup sink" },
  { category: "deser", severity: "high", sinkPattern: "fastjson.parse", pattern: /JSON\.parseObject|JSON\.parse|parseArray\s*\(/, description: "Fastjson deserialization sink" },
  { category: "deser", severity: "high", sinkPattern: "ObjectInputStream.readObject", pattern: /ObjectInputStream|\.readObject\s*\(/, description: "Java native deserialization sink" },
  { category: "sqli", severity: "high", sinkPattern: "Statement.execute", pattern: /\b(?:Statement|PreparedStatement)\b|createStatement\s*\(|prepareStatement\s*\(|\b(?:stmt|statement|ps|preparedStatement)\s*\.\s*execute(?:Query|Update|LargeUpdate)?\s*\(/i, description: "Raw SQL execution sink" },
  { category: "path-traversal", severity: "medium", sinkPattern: "file-path", pattern: /new\s+File\s*\(|Paths\.get\s*\(|Files\.(read|copy|write|newInputStream|newOutputStream)/, description: "File path sink" },
  { category: "ssti", severity: "medium", sinkPattern: "Template.process", pattern: /\.process\s*\(/, description: "Template rendering sink" },
  { category: "xxe", severity: "medium", sinkPattern: "xml-parse", pattern: /DocumentBuilder|SAXParser|Unmarshaller|\.parse\s*\(/, description: "XML parsing sink" },
  { category: "spel", severity: "high", sinkPattern: "SpEL.parseExpression", pattern: /SpelExpressionParser|parseExpression/, description: "Expression parsing sink" },
  { category: "ognl", severity: "high", sinkPattern: "OGNL", pattern: /Ognl|ognl/i, description: "OGNL expression sink" },
  { category: "file-upload", severity: "medium", sinkPattern: "file-upload", pattern: /MultipartFile|transferTo\s*\(|getOriginalFilename\s*\(|Part\s+\w+|\b(?:part|filePart|uploadPart)\s*\.write\s*\(|getSubmittedFileName\s*\(/i, description: "File upload sink" },
  { category: "file-download", severity: "medium", sinkPattern: "file-download", pattern: /ServletOutputStream|OutputStream|ResponseEntity\s*<\s*(?:byte\[\]|Resource)|InputStreamResource|ByteArrayResource|Files\.read|FileInputStream/, description: "File download sink" },
  { category: "redirect", severity: "medium", sinkPattern: "response.sendRedirect", pattern: /sendRedirect\s*\(|setHeader\s*\(\s*["']Location["']|addHeader\s*\(\s*["']Location["']/, description: "Redirect sink" },
  { category: "path-traversal", severity: "medium", sinkPattern: "RequestDispatcher.forward", pattern: /getRequestDispatcher\s*\(|\.forward\s*\(|\.include\s*\(|pageContext\.forward/i, description: "Servlet/JSP forward/include sink" },
  { category: "xss", severity: "medium", sinkPattern: "response-write", pattern: /response\.getWriter\s*\(\)|out\.(?:print|println|write)\s*\(|JspWriter|<%=/, description: "Servlet/JSP response write sink" },
]

const JAVA_SINK_PATTERN_NORMALIZERS: SinkNormalizer[] = [
  { value: "Runtime.exec", pattern: /Runtime\.getRuntime\(\)\.exec|Runtime\.exec|\.exec\s*\(/i },
  { value: "ProcessBuilder", pattern: /ProcessBuilder/i },
  { value: "ObjectInputStream.readObject", pattern: /ObjectInputStream|readObject\s*\(/i },
  { value: "fastjson.parse", pattern: /JSON\.parse|parseObject|parseArray|fastjson/i },
  { value: "ObjectMapper.readValue", pattern: /ObjectMapper|readValue\s*\(/i },
  { value: "Statement.execute", pattern: /Statement|\.execute(Query|Update)?\s*\(|stmt\.execute/i },
  { value: "network-request", pattern: /new\s+URL\s*\(|openConnection\s*\(|RestTemplate|HttpClient|network-request/i },
  { value: "response.sendRedirect", pattern: /sendRedirect\s*\(|Location/i },
  { value: "RequestDispatcher.forward", pattern: /getRequestDispatcher\s*\(|\.forward\s*\(|\.include\s*\(|pageContext\.forward/i },
  { value: "response-write", pattern: /response\.getWriter|JspWriter|out\.(?:print|println|write)|<%=/i },
  { value: "file-upload", pattern: /MultipartFile|transferTo\s*\(|getOriginalFilename|\b(?:part|filePart|uploadPart)\s*\.write\s*\(|getSubmittedFileName/i },
  { value: "file-download", pattern: /Files\.read|FileInputStream|ServletOutputStream|ResponseEntity|download/i },
  { value: "file-path", pattern: /new\s+File\s*\(|Paths\.get|Files\./i },
  { value: "xml-parse", pattern: /DocumentBuilder|SAXParser|Unmarshaller|\.parse\s*\(/i, requires: /xml|xxe/i },
  { value: "Template.process", pattern: /Template|\.process\s*\(/i },
  { value: "SpEL.parseExpression", pattern: /SpelExpressionParser|parseExpression/i },
  { value: "OGNL", pattern: /Ognl|ognl/i },
  { value: "jndi-lookup", pattern: /InitialContext|lookup\s*\(|ldap:|rmi:/i },
]

const JAVA_SINK_CATEGORY_NORMALIZERS: SinkNormalizer[] = [
  { value: "cmdi", pattern: /Runtime\.exec|ProcessBuilder|cmdi|command|\.exec\s*\(/i },
  { value: "deser", pattern: /ObjectInputStream|readObject|fastjson|ObjectMapper|readValue|parseObject|parseArray|deser/i },
  { value: "sqli", pattern: /Statement\.execute|\.execute(Query|Update)?\s*\(|stmt\.execute|sqli|sql/i },
  { value: "ssrf", pattern: /network-request|new\s+URL\s*\(|openConnection|RestTemplate|HttpClient|ssrf/i },
  { value: "xss", pattern: /response-write|JspWriter|out\.(?:print|println|write)|<%=|xss|cross.?site/i },
  { value: "redirect", pattern: /sendRedirect|Location|redirect/i },
  { value: "path-traversal", pattern: /RequestDispatcher|forward\s*\(|include\s*\(|pageContext\.forward/i },
  { value: "file-upload", pattern: /file-upload|MultipartFile|transferTo|getOriginalFilename|upload/i },
  { value: "file-download", pattern: /file-download|download|Files\.read|FileInputStream|ResponseEntity/i },
  { value: "path-traversal", pattern: /path-traversal|file-path|new\s+File\s*\(|Paths\.get|Files\./i },
  { value: "xxe", pattern: /xml-parse|DocumentBuilder|SAXParser|Unmarshaller|xxe/i },
  { value: "ssti", pattern: /Template\.process|\.process\s*\(|ssti|template/i },
  { value: "spel", pattern: /SpEL|parseExpression|spel|expression/i },
  { value: "ognl", pattern: /OGNL|ognl/i },
  { value: "jndi", pattern: /jndi|InitialContext|lookup\s*\(/i },
]

export function normalizeJavaSinkPattern(rawPattern: string, code: string): string {
  const text = `${rawPattern} ${code}`
  for (const normalizer of JAVA_SINK_PATTERN_NORMALIZERS) {
    normalizer.pattern.lastIndex = 0
    if (normalizer.requires) normalizer.requires.lastIndex = 0
    if (normalizer.pattern.test(text) && (!normalizer.requires || normalizer.requires.test(text))) {
      return normalizer.value
    }
  }
  return rawPattern
}

export function normalizeJavaSinkCategory(rawCategory: string, sinkPattern: string, code: string): string {
  const text = `${rawCategory} ${sinkPattern} ${code}`
  for (const normalizer of JAVA_SINK_CATEGORY_NORMALIZERS) {
    normalizer.pattern.lastIndex = 0
    if (normalizer.pattern.test(text)) return normalizer.value
  }
  return rawCategory || "other"
}
