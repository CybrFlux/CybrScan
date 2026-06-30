// CybrScan — passive scan engine entry point (CYB-43, §7.2/§7.3).
//
// runPassiveScan() is the single chokepoint that turns SSRF-hardened
// observations into the §7.2 ScanResult: run checks → grade → fail-closed
// safe-output gate → schema-validate. It performs NO network I/O itself; the
// SSRF-hardened fetch layer (§6, owned by CTO + AppSec) supplies observations.
// (Economy of Mechanism, Complete Mediation.)

import {
  PASSIVE_CATEGORIES,
  scanResultSchema,
  type PassiveObservations,
  type ScanResult,
} from './types'
import { runChecks } from './checks'
import { gradeScan } from './grading'
import { assertReportSafe } from './formatter'

export const PASSIVE_ENGINE_VERSION = 'cybrscan-passive-1.0.0'

// Deterministic: same observations → same ScanResult.
export function runPassiveScan(obs: PassiveObservations): ScanResult {
  const findings = runChecks(obs)
  const { grade, score, categories } = gradeScan(findings, PASSIVE_CATEGORIES)

  const result: ScanResult = {
    target: obs.domain,
    tier: 'passive',
    status: 'complete',
    completedAt: obs.observedAt,
    grade,
    score,
    categories,
    findings,
    engineVersion: PASSIVE_ENGINE_VERSION,
  }

  // §8 hard rule: refuse to return anything carrying a payload/PoC. Fail closed.
  assertReportSafe(result)

  // Fail closed: never return a result the rest of the app cannot trust.
  return scanResultSchema.parse(result)
}

// Adapter for the app's async engine boundary (src/lib/scan/types.ts). The
// SSRF-hardened fetch layer is injected as `fetchObservations` so this library
// stays pure/testable and the engine remains the only thing touching the
// network. CTO wires the real fetcher in; tests inject a fake.
export type ObservationFetcher = (domain: string) => Promise<PassiveObservations>

export function createPassiveEngine(fetchObservations: ObservationFetcher) {
  return {
    name: 'cybrscan-passive',
    version: PASSIVE_ENGINE_VERSION,
    async scan(domain: string): Promise<ScanResult> {
      const obs = await fetchObservations(domain)
      return runPassiveScan(obs)
    },
  }
}
