// Scan engine resolver. App code calls getScanEngine() and never constructs an
// engine directly. The engine is Security's REAL passive engine (./passive);
// only the observation source swaps: a mock fetcher now, the SSRF-hardened fetch
// layer (§6, CTO/AppSec) when it lands — flip with SCAN_OBSERVATIONS, no UI
// changes.

import { createPassiveEngine, type ObservationFetcher } from './passive'
import { mockObservationFetcher } from './mock-fetcher'
import type { ScanEngine, ScanEngineInput } from './types'

const OBSERVATIONS_MOCK = 'mock'

function getObservationFetcher(): ObservationFetcher {
  const source = process.env.SCAN_OBSERVATIONS ?? OBSERVATIONS_MOCK
  switch (source) {
    case OBSERVATIONS_MOCK:
      return mockObservationFetcher
    // case 'live': return createHardenedFetcher()  // §6 SSRF-hardened layer (CTO/AppSec).
    default:
      throw new Error(`Unknown SCAN_OBSERVATIONS "${source}". Set SCAN_OBSERVATIONS=mock or a registered source.`)
  }
}

// Adapt the pure passive engine (scan(domain)) to the app's async ScanEngine
// (runScan({ domain, scanType })). Monitored scans reuse the same engine; the
// ownership gate is enforced by the caller before scanType 'monitored' is used.
export function getScanEngine(): ScanEngine {
  const engine = createPassiveEngine(getObservationFetcher())
  return {
    name: engine.name,
    async runScan(input: ScanEngineInput) {
      return engine.scan(input.domain)
    },
  }
}

export * from './types'
