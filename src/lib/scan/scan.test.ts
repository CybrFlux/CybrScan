import { describe, it, expect } from 'vitest'
import { getScanEngine, scanResultSchema, GRADES } from './index'
import { scanRequestSchema } from '@/lib/validations'

describe('scanRequestSchema', () => {
  it('should normalize a URL to a bare lowercase hostname when given a full URL', () => {
    const result = scanRequestSchema.parse({ domain: 'HTTPS://Example.com/path?q=1' })
    expect(result.domain).toBe('example.com')
  })

  it('should strip a trailing dot and port when present', () => {
    const result = scanRequestSchema.parse({ domain: 'sub.example.co.uk.:443' })
    expect(result.domain).toBe('sub.example.co.uk')
  })

  it('should reject a single-label host with no TLD', () => {
    expect(scanRequestSchema.safeParse({ domain: 'localhost' }).success).toBe(false)
  })

  it('should reject empty input', () => {
    expect(scanRequestSchema.safeParse({ domain: '   ' }).success).toBe(false)
  })
})

describe('getScanEngine (app boundary over the real passive engine)', () => {
  it('should return a schema-valid passive ScanResult when given a domain', async () => {
    const result = await getScanEngine().runScan({ domain: 'example.com', scanType: 'passive_free' })
    expect(scanResultSchema.safeParse(result).success).toBe(true)
    expect(result.tier).toBe('passive')
  })

  it('should be deterministic for the same domain', async () => {
    const engine = getScanEngine()
    const a = await engine.runScan({ domain: 'example.com', scanType: 'passive_free' })
    const b = await engine.runScan({ domain: 'example.com', scanType: 'passive_free' })
    expect(a.grade).toBe(b.grade)
    expect(a.score).toBe(b.score)
  })

  it('should produce a grade within the allowed A–F set', async () => {
    const result = await getScanEngine().runScan({ domain: 'cybrflux.online', scanType: 'passive_free' })
    expect(GRADES).toContain(result.grade)
  })
})
