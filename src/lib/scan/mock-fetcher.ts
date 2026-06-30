// Mock observation fetcher for the Week-1 vertical slice (CYB-34).
//
// Security's passive engine (./passive) is pure: it grades a PassiveObservations
// bundle that the SSRF-hardened fetch layer (§6 of the CYB-35 spec — the real
// remaining CTO/AppSec build) is meant to supply. Until that layer lands, this
// mock fetcher injects deterministic observations so the real engine + real
// grading run end-to-end against the UI. It performs NO network I/O.
//
// Deterministic per domain: a stable hash toggles a few realistic weaknesses so
// different domains produce different grades and genuine findings from the real
// engine — never random, so demos and tests reproduce.

import type { ObservationFetcher } from './passive'
import type {
  DnsObservation,
  HttpObservation,
  PassiveObservations,
  TlsObservation,
} from './passive/types'

const MOCK_OBSERVED_AT = '2026-07-01T12:00:00.000Z'

function domainHash(domain: string): number {
  return domain.split('').reduce((acc, ch) => (acc * 31 + ch.charCodeAt(0)) >>> 0, 0)
}

function hardenedHeaders(): Record<string, string> {
  return {
    'content-security-policy': "default-src 'self'; frame-ancestors 'none'",
    'strict-transport-security': 'max-age=63072000; includeSubDomains',
    'x-frame-options': 'DENY',
    'x-content-type-options': 'nosniff',
    'referrer-policy': 'strict-origin-when-cross-origin',
    'permissions-policy': 'geolocation=(), camera=(), microphone=()',
    'cross-origin-opener-policy': 'same-origin',
    'cross-origin-embedder-policy': 'require-corp',
  }
}

// Build a deterministic observation bundle, degrading specific controls based on
// the domain hash so the engine surfaces a realistic mix of findings.
export function mockObservationsFor(domain: string): PassiveObservations {
  const h = domainHash(domain)
  const weakHsts = (h & 1) === 1
  const weakSpf = (h & 2) === 2
  const expiringSoon = (h & 4) === 4

  const headers = hardenedHeaders()
  if (weakHsts) {
    delete headers['strict-transport-security']
  }

  const tls: TlsObservation = {
    present: true,
    protocol: 'TLSv1.3',
    validChain: true,
    hostnameMatches: true,
    selfSigned: false,
    daysUntilExpiry: expiringSoon ? 9 : 90,
  }

  const http: HttpObservation = {
    finalUrl: `https://${domain}/`,
    statusCode: 200,
    scheme: 'https',
    headers,
    setCookies: ['session=redacted; Path=/; Secure; HttpOnly; SameSite=Lax'],
    redirectChain: [],
    httpToHttpsRedirect: true,
    mixedContent: false,
  }

  const dns: DnsObservation = {
    mxPresent: true,
    spf: weakSpf ? null : 'v=spf1 include:_spf.example.com -all',
    dmarc: 'v=DMARC1; p=reject; rua=mailto:dmarc@example.com',
    dkimPresent: true,
    caaPresent: true,
    dnssec: true,
  }

  return { domain, observedAt: MOCK_OBSERVED_AT, tls, http, dns }
}

export const mockObservationFetcher: ObservationFetcher = async (domain: string) =>
  mockObservationsFor(domain)
