import type { AuditOptions, AuditReport } from "../types/index.ts"
import { AuditManager } from "../manager/audit-manager.ts"

/**
 * Backward-compatible wrapper around AuditManager.
 * Existing callers using `new CodeAuditAgent().run(options)` continue to work.
 */
export class CodeAuditAgent {
  async run(options: AuditOptions): Promise<AuditReport> {
    const manager = new AuditManager(options)
    return manager.run()
  }
}
