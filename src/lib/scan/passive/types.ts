// CybrScan — passive check library types (CYB-43, §2/§7.2 of the CYB-35 spec).
//
// SECURITY BOUNDARY: every check in this library is a PURE ANALYZER over
// evidence that the SSRF-hardened fetch layer (§6) has already collected. The
// checks never make a network request themselves. That separation is a
// security property, not an accident:
//   - the single egress chokepoint (§7.3) stays the only thing that touches the
//     network, so it is the only thing that needs SSRF hardening;
//   - the grading library is deterministic and unit-testable with no I/O.
// Lenses: Economy of Mechanism, Complete Mediation, Minimize Attack Surface.

import { z } from 'zod'

// ── Grades & severities ─────────────────────────────────────────────────────

// A–F grade returned to the customer (§7.2). Ordered best → worst.
export const GRADES = ['A', 'B', 'C', 'D', 'F'] as const
export const gradeSchema = z.enum(GRADES)
export type Grade = z.infer<typeof gradeSchema>

// Finding severity (§7.2). Ordered most → least severe.
export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const
export const severitySchema = z.enum(SEVERITIES)
export type Severity = z.infer<typeof severitySchema>

// Category keys + canonical weights from §7.2. `exposure` (OSINT) is Pro-only
// per §9 and is NOT produced by the anonymous passive scan; weights are
// re-normalized over the categories actually evaluated (see grading.ts).
export const CATEGORY_KEYS = ['tls', 'headers', 'dns_email', 'cookies', 'exposure'] as const
export const categoryKeySchema = z.enum(CATEGORY_KEYS)
export type CategoryKey = z.infer<typeof categoryKeySchema>

export const CATEGORY_WEIGHTS: Readonly<Record<CategoryKey, number>> = {
  tls: 0.25,
  headers: 0.25,
  dns_email: 0.15,
  cookies: 0.1,
  exposure: 0.25,
}

// Categories the anonymous/free passive scan evaluates (§9 excludes exposure).
export const PASSIVE_CATEGORIES: ReadonlyArray<CategoryKey> = [
  'tls',
  'headers',
  'dns_email',
  'cookies',
]

// ── Finding (§7.2) ──────────────────────────────────────────────────────────

// SAFE OUTPUT (§8 hard rule): `evidence` is a short factual observation, never
// a PoC/payload/attack step. The formatter enforces this at emit time.
export const findingSchema = z.object({
  id: z.string().min(1),
  severity: severitySchema,
  title: z.string().min(1).max(200),
  explanation: z.string().min(1).max(2000),
  remediation: z.string().min(1).max(2000),
  category: categoryKeySchema,
  evidence: z.string().min(1).max(500),
})
export type Finding = z.infer<typeof findingSchema>

export const categoryResultSchema = z.object({
  key: categoryKeySchema,
  grade: gradeSchema,
  weight: z.number().min(0).max(1),
  score: z.number().int().min(0).max(100),
})
export type CategoryResult = z.infer<typeof categoryResultSchema>

// The §7.2 `data` shape the engine returns and the app persists/renders.
export const scanResultSchema = z.object({
  target: z.string().min(1),
  tier: z.literal('passive'),
  status: z.literal('complete'),
  completedAt: z.string().datetime(),
  grade: gradeSchema,
  score: z.number().int().min(0).max(100),
  categories: z.array(categoryResultSchema),
  findings: z.array(findingSchema),
  engineVersion: z.string().min(1),
})
export type ScanResult = z.infer<typeof scanResultSchema>

// ── Observations (input to the checks) ──────────────────────────────────────
// What the SSRF-hardened fetch layer supplies. Optional fields model "could not
// observe" (fail-closed: an unobservable control is treated as absent, never
// assumed present).

export interface TlsObservation {
  present: boolean // a TLS handshake succeeded over 443
  protocol?: string // negotiated protocol, e.g. 'TLSv1.3'
  validChain?: boolean // chain verified to a trusted root
  hostnameMatches?: boolean // cert SAN/CN matches the requested host
  selfSigned?: boolean
  daysUntilExpiry?: number // negative => already expired
}

export interface RedirectHop {
  from: string
  to: string
  status: number
}

export interface HttpObservation {
  finalUrl: string
  statusCode: number
  scheme: 'http' | 'https'
  // Header names MUST be lowercased by the fetch layer (HTTP headers are
  // case-insensitive; we normalize once at the boundary).
  headers: Readonly<Record<string, string>>
  setCookies: ReadonlyArray<string> // raw Set-Cookie values from this one response
  redirectChain: ReadonlyArray<RedirectHop>
  httpToHttpsRedirect?: boolean // a plain-HTTP request 301/302'd to HTTPS
  mixedContent?: boolean // HTTPS page references http:// subresources
}

export interface DnsObservation {
  mxPresent?: boolean // domain advertises mail (DKIM/SPF only matter if so)
  spf?: string | null // raw "v=spf1 ..." record or null if absent
  dmarc?: string | null // raw "v=DMARC1; ..." record or null if absent
  dkimPresent?: boolean
  caaPresent?: boolean
  dnssec?: boolean
}

export interface PassiveObservations {
  domain: string
  observedAt: string // ISO 8601
  tls: TlsObservation
  http: HttpObservation
  dns: DnsObservation
}
