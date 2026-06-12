/**
 * Late-binding cancellation — Cairn pattern #10.
 *
 * Cancel can be called BEFORE a process is created. When the process is
 * later attached, the pending cancel automatically propagates.
 *
 * Thread-safe: all state transitions are guarded by a lock.
 */

import type { ChildProcess } from "node:child_process"

// Minimal interface — works with both Bun.spawn and node:child_process
interface CancellableProcess {
  kill(signal?: string): void
  killed: boolean
}

export class TaskCancellation {
  private _reason: string | null = null
  private _process: CancellableProcess | null = null
  private _lock = false

  private lock(): void {
    // Simple spin lock — sufficient for single-threaded JS runtime
    // where all async operations are cooperative
    if (this._lock) {
      throw new Error("TaskCancellation: concurrent access detected")
    }
    this._lock = true
  }

  private unlock(): void {
    this._lock = false
  }

  /** Whether cancellation has been requested. */
  get isCancelled(): boolean {
    return this._reason !== null
  }

  /** The reason for cancellation, if any. */
  get reason(): string | null {
    return this._reason
  }

  /**
   * Request cancellation. Returns false if already cancelled.
   * If a process is already attached, kills it immediately.
   */
  cancel(reason: string): boolean {
    this.lock()
    try {
      if (this._reason !== null) {
        return false // already cancelled
      }
      this._reason = reason
      const process = this._process
      if (process !== null) {
        // Process already exists — kill immediately
        process.kill("SIGTERM")
      }
      return true
    } finally {
      this.unlock()
    }
  }

  /**
   * Attach a process to this cancellation.
   * If cancellation was already requested (late-binding), the process
   * is killed immediately.
   */
  attachProcess(process: CancellableProcess): void {
    this.lock()
    try {
      this._process = process
      const reason = this._reason
      if (process !== null && reason !== null) {
        // Late-binding: cancel was requested before attach
        process.kill("SIGTERM")
      }
    } finally {
      this.unlock()
    }
  }

  /** Detach the current process (e.g., when it exits naturally). */
  detachProcess(): void {
    this.lock()
    try {
      this._process = null
    } finally {
      this.unlock()
    }
  }

  /** Reset the cancellation state. */
  reset(): void {
    this.lock()
    try {
      this._reason = null
      this._process = null
    } finally {
      this.unlock()
    }
  }
}
