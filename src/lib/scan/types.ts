// CybrScan — app ↔ scan-engine boundary (CYB-34, Workstream 1).
//
// The CANONICAL scan result schema lives in ./passive (Security, CYB-43, §7.2
// of the CYB-35 spec). The app does NOT define a competing shape — it persists
// and renders Security's `ScanResult` verbatim. This file only adds the small
// app-level concepts the engine library does not own: the scan *type* and the
// async `ScanEngine` the app calls (the library is pure/synchronous; the app
// needs an async, fetch-backed entry point).

import { z } from 'zod'
import type { ScanResult } from './passive'

// Re-export the canonical types so app code imports them from one place.
export type {
  ScanResult,
  Finding,
  Grade,
  Severity,
  CategoryKey,
  CategoryResult,
} from './passive'
export { scanResultSchema, GRADES, SEVERITIES } from './passive'

// Scan kind — an app concept. The free scan is passive/non-intrusive and needs
// no ownership proof; monitored scans run only against verified-owned domains.
export const SCAN_TYPES = ['passive_free', 'monitored'] as const
export const scanTypeSchema = z.enum(SCAN_TYPES)
export type ScanType = z.infer<typeof scanTypeSchema>

export interface ScanEngineInput {
  domain: string
  scanType: ScanType
}

// The async entry point the app (server action / scheduled job) calls. An
// adapter in ./index wraps Security's pure engine + the injected fetch layer.
export interface ScanEngine {
  readonly name: string
  runScan(input: ScanEngineInput): Promise<ScanResult>
}
