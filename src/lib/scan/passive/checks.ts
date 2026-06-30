// CybrScan — passive check library (CYB-43, §2 Tier-P checks).
//
// Each exported check is a PURE function of the observations (no network I/O —
// see types.ts boundary note). A check decides WHICH catalog findings apply and
// attaches short, factual evidence. Severity/copy come from catalog.ts so the
// rubric stays single-source. Every evidence string is a plain observation, not
// a payload (§8) — the formatter re-verifies before emit.

import type {
  DnsObservation,
  Finding,
  HttpObservation,
  PassiveObservations,
  TlsObservation,
} from './types'
import { CATALOG, type FindingId } from './catalog'

// ── finding factory ─────────────────────────────────────────────────────────

function finding(id: FindingId, evidence: string): Finding {
  const entry = CATALOG[id]
  return {
    id,
    severity: entry.severity,
    title: entry.title,
    explanation: entry.explanation,
    remediation: entry.remediation,
    category: entry.category,
    evidence,
  }
}

// HTTP header names are case-insensitive; the fetch layer lowercases them once
// at the boundary. We defend anyway by lowercasing the lookup key.
function header(headers: Readonly<Record<string, string>>, name: string): string | undefined {
  return headers[name.toLowerCase()]
}
function hasHeader(headers: Readonly<Record<string, string>>, name: string): boolean {
  return header(headers, name) !== undefined
}

const WEAK_PROTOCOLS: ReadonlyArray<string> = ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.0', 'TLSv1.1']
const EXPIRY_SOON_DAYS = 15

// ── TLS / transport ─────────────────────────────────────────────────────────

export function checkTls(tls: TlsObservation, http: HttpObservation): Finding[] {
  const findings: Finding[] = []

  if (!tls.present) {
    findings.push(finding('tls.missing', 'No TLS handshake succeeded on port 443.'))
  } else {
    if (typeof tls.daysUntilExpiry === 'number' && tls.daysUntilExpiry < 0) {
      findings.push(finding('tls.expired', `Certificate expired ${Math.abs(tls.daysUntilExpiry)} day(s) ago.`))
    } else if (typeof tls.daysUntilExpiry === 'number' && tls.daysUntilExpiry < EXPIRY_SOON_DAYS) {
      findings.push(finding('tls.expiring_soon', `Certificate expires in ${tls.daysUntilExpiry} day(s).`))
    }
    if (tls.hostnameMatches === false) {
      findings.push(finding('tls.hostname_mismatch', 'Certificate SAN/CN does not cover the requested hostname.'))
    }
    if (tls.selfSigned === true) {
      findings.push(finding('tls.self_signed', 'Certificate does not chain to a trusted CA.'))
    }
    if (tls.protocol && WEAK_PROTOCOLS.includes(tls.protocol)) {
      findings.push(finding('tls.weak_protocol', `Negotiated protocol: ${tls.protocol}.`))
    }
    if (http.scheme === 'http') {
      findings.push(finding('tls.served_over_http', `Final URL after redirects used scheme: http.`))
    }
  }

  // Transport hygiene that is independent of cert validity.
  if (http.httpToHttpsRedirect === false) {
    findings.push(finding('tls.no_https_redirect', 'A plain-HTTP request was not redirected to HTTPS.'))
  }
  if (http.scheme === 'https' && http.mixedContent === true) {
    findings.push(finding('tls.mixed_content', 'HTTPS page references one or more http:// sub-resources.'))
  }

  return findings
}

// ── Security headers ────────────────────────────────────────────────────────

export function checkHeaders(http: HttpObservation): Finding[] {
  const { headers } = http
  const findings: Finding[] = []

  if (!hasHeader(headers, 'content-security-policy')) {
    findings.push(finding('headers.csp.missing', 'Response had no Content-Security-Policy header.'))
  }
  // HSTS is only delivered/honored over HTTPS; on plain HTTP the transport
  // findings already capture the problem, so we don't double-flag.
  if (http.scheme === 'https' && !hasHeader(headers, 'strict-transport-security')) {
    findings.push(finding('headers.hsts.missing', 'Response had no Strict-Transport-Security header.'))
  }
  const csp = header(headers, 'content-security-policy') ?? ''
  if (!hasHeader(headers, 'x-frame-options') && !/frame-ancestors/i.test(csp)) {
    findings.push(finding('headers.xfo.missing', 'No X-Frame-Options header and no CSP frame-ancestors directive.'))
  }
  if (!hasHeader(headers, 'x-content-type-options')) {
    findings.push(finding('headers.xcto.missing', 'Response had no X-Content-Type-Options header.'))
  }
  if (!hasHeader(headers, 'referrer-policy')) {
    findings.push(finding('headers.referrer_policy.missing', 'Response had no Referrer-Policy header.'))
  }
  if (!hasHeader(headers, 'permissions-policy')) {
    findings.push(finding('headers.permissions_policy.missing', 'Response had no Permissions-Policy header.'))
  }
  if (!hasHeader(headers, 'cross-origin-opener-policy')) {
    findings.push(finding('headers.coop.missing', 'Response had no Cross-Origin-Opener-Policy header.'))
  }
  if (!hasHeader(headers, 'cross-origin-embedder-policy')) {
    findings.push(finding('headers.coep.missing', 'Response had no Cross-Origin-Embedder-Policy header.'))
  }

  return findings
}

// ── Cookies ─────────────────────────────────────────────────────────────────

// Parse the NAME only from a raw Set-Cookie value. We deliberately never read
// or surface the cookie VALUE (it can be a session secret) — §5/§8.
function cookieName(raw: string): string {
  const namePart = raw.split(';')[0] ?? ''
  return (namePart.split('=')[0] ?? '').trim()
}
function cookieHasAttr(raw: string, attr: string): boolean {
  // Match attribute as a token, e.g. "; Secure" or "; SameSite=Lax".
  return new RegExp(`;\\s*${attr}(\\s*=|\\s*;|\\s*$)`, 'i').test(raw)
}

export function checkCookies(http: HttpObservation): Finding[] {
  const cookies = http.setCookies
  if (cookies.length === 0) return []

  const findings: Finding[] = []
  const missing = (attr: string) =>
    cookies.filter((c) => !cookieHasAttr(c, attr)).map(cookieName).filter(Boolean)

  const noSecure = missing('Secure')
  if (noSecure.length > 0) {
    findings.push(
      finding('cookies.secure.missing', `${noSecure.length} cookie(s) without Secure: ${noSecure.join(', ')}.`),
    )
  }
  const noHttpOnly = missing('HttpOnly')
  if (noHttpOnly.length > 0) {
    findings.push(
      finding('cookies.httponly.missing', `${noHttpOnly.length} cookie(s) without HttpOnly: ${noHttpOnly.join(', ')}.`),
    )
  }
  const noSameSite = missing('SameSite')
  if (noSameSite.length > 0) {
    findings.push(
      finding('cookies.samesite.missing', `${noSameSite.length} cookie(s) without SameSite: ${noSameSite.join(', ')}.`),
    )
  }

  return findings
}

// ── DNS / email hardening ───────────────────────────────────────────────────

export function checkDnsEmail(dns: DnsObservation): Finding[] {
  const findings: Finding[] = []

  if (dns.spf == null) {
    findings.push(finding('dns_email.spf.missing', 'No "v=spf1" TXT record found.'))
  } else if (/\+all\b/i.test(dns.spf) || /(^|\s)all\b/i.test(dns.spf.replace(/[~\-?]all/i, ''))) {
    // Permissive "+all" (explicit or bare "all", which defaults to pass).
    findings.push(finding('dns_email.spf.weak', 'SPF record authorizes all senders ("+all"/bare "all").'))
  }

  if (dns.dmarc == null) {
    findings.push(finding('dns_email.dmarc.missing', 'No "_dmarc" TXT record found.'))
  } else if (/p\s*=\s*none/i.test(dns.dmarc)) {
    findings.push(finding('dns_email.dmarc.weak', 'DMARC policy is "p=none" (monitor only).'))
  }

  if (dns.mxPresent === true && dns.dkimPresent === false) {
    findings.push(finding('dns_email.dkim.missing', 'Domain accepts mail (MX present) but no DKIM record was found.'))
  }
  if (dns.caaPresent === false) {
    findings.push(finding('dns_email.caa.missing', 'No CAA record found.'))
  }
  if (dns.dnssec === false) {
    findings.push(finding('dns_email.dnssec.missing', 'DNSSEC is not enabled for the zone.'))
  }

  return findings
}

// ── Aggregate ───────────────────────────────────────────────────────────────

// Runs every passive check over the observations. Order is stable so output is
// deterministic. Exposure (OSINT) is intentionally NOT here — it is Pro-only and
// runs only on the verified-owner path (§9).
export function runChecks(obs: PassiveObservations): Finding[] {
  return [
    ...checkTls(obs.tls, obs.http),
    ...checkHeaders(obs.http),
    ...checkCookies(obs.http),
    ...checkDnsEmail(obs.dns),
  ]
}
