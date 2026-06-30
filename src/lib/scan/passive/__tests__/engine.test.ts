// End-to-end engine tests (CYB-43): the library returns the §7.2 ScanResult
// shape for a test domain with a deterministic grade.

import { describe, it, expect } from 'vitest'
import { runPassiveScan, createPassiveEngine, PASSIVE_ENGINE_VERSION } from '../engine'
import { scanResultSchema, PASSIVE_CATEGORIES } from '../types'
import { cleanObservations } from './fixtures'

describe('runPassiveScan (§7.2 contract)', () => {
  it('returns a schema-valid ScanResult for a clean test domain', () => {
    const result = runPassiveScan(cleanObservations())
    expect(() => scanResultSchema.parse(result)).not.toThrow()
    expect(result.tier).toBe('passive')
    expect(result.status).toBe('complete')
    expect(result.engineVersion).toBe(PASSIVE_ENGINE_VERSION)
    expect(result.categories.map((c) => c.key)).toEqual([...PASSIVE_CATEGORIES])
  })

  it('grades a fully-hardened site A/100 with no findings', () => {
    const result = runPassiveScan(cleanObservations())
    expect(result.grade).toBe('A')
    expect(result.score).toBe(100)
    expect(result.findings).toEqual([])
  })

  it('drops below A and surfaces findings on a misconfigured site', () => {
    const obs = cleanObservations()
    const result = runPassiveScan({
      ...obs,
      tls: { ...obs.tls, present: false }, // critical
      dns: { ...obs.dns, spf: null }, // medium
    })
    expect(result.grade).not.toBe('A')
    expect(result.findings.some((f) => f.id === 'tls.missing')).toBe(true)
    expect(result.findings.some((f) => f.id === 'dns_email.spf.missing')).toBe(true)
    // tls category must be capped at F by the critical finding.
    expect(result.categories.find((c) => c.key === 'tls')!.grade).toBe('F')
  })

  it('is deterministic for identical observations', () => {
    expect(runPassiveScan(cleanObservations())).toEqual(runPassiveScan(cleanObservations()))
  })

  it('createPassiveEngine wires an injected (SSRF-hardened) fetcher', async () => {
    const engine = createPassiveEngine(async () => cleanObservations())
    const result = await engine.scan('example.com')
    expect(result.grade).toBe('A')
    expect(result.target).toBe('example.com')
  })
})
