// Test fixtures for the passive check library (CYB-43).
//
// `cleanObservations()` is a fully-hardened site that must produce ZERO
// findings. Each regression test starts from clean and flips exactly one field
// to the bad config, asserting the specific finding fires; the clean baseline is
// the "fixed config" assertion (finding absent). This is the per-check
// fails-on-bad / passes-on-fixed pattern the §8/issue deliverable requires.

import type {
  DnsObservation,
  HttpObservation,
  PassiveObservations,
  TlsObservation,
} from '../types'

export function cleanTls(): TlsObservation {
  return {
    present: true,
    protocol: 'TLSv1.3',
    validChain: true,
    hostnameMatches: true,
    selfSigned: false,
    daysUntilExpiry: 90,
  }
}

export function cleanHeaders(): Record<string, string> {
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

export function cleanHttp(): HttpObservation {
  return {
    finalUrl: 'https://example.com/',
    statusCode: 200,
    scheme: 'https',
    headers: cleanHeaders(),
    setCookies: ['session=redacted; Path=/; Secure; HttpOnly; SameSite=Lax'],
    redirectChain: [],
    httpToHttpsRedirect: true,
    mixedContent: false,
  }
}

export function cleanDns(): DnsObservation {
  return {
    mxPresent: true,
    spf: 'v=spf1 include:_spf.example.com -all',
    dmarc: 'v=DMARC1; p=reject; rua=mailto:dmarc@example.com',
    dkimPresent: true,
    caaPresent: true,
    dnssec: true,
  }
}

export function cleanObservations(): PassiveObservations {
  return {
    domain: 'example.com',
    observedAt: '2026-07-01T12:00:00.000Z',
    tls: cleanTls(),
    http: cleanHttp(),
    dns: cleanDns(),
  }
}
