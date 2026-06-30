// CybrScan — finding catalog + severity mapping table (CYB-43, §8).
//
// This file IS the severity rubric the CISO reviews. Every passive finding the
// engine can emit is defined here exactly once: its category, its severity, the
// plain-English explanation, the concrete remediation, and a CVSS-informed
// rationale that makes the severity defensible and consistent.
//
// Checks decide WHICH findings fire from the observations; they pull the static
// copy + severity from this table and append only short, safe evidence. Keeping
// severity in one reviewable table (not scattered across checks) is deliberate:
// it is the artifact the rubric review (§8, "AppSec owns the rubric table")
// signs off on.
//
// SAFE OUTPUT (§8): no entry here contains a payload, PoC, or attack step. The
// formatter re-verifies this at emit time (formatter.ts).

import type { CategoryKey, Severity } from './types'

export interface CatalogEntry {
  readonly category: CategoryKey
  readonly severity: Severity
  readonly title: string
  readonly explanation: string
  readonly remediation: string
  // CVSS 3.1 base score + vector that INFORMS (does not mechanically dictate)
  // the severity band. `null` for hygiene/info items with no meaningful base
  // vector. Bands: critical 9.0–10, high 7.0–8.9, medium 4.0–6.9, low 0.1–3.9.
  readonly cvss: { readonly score: number; readonly vector: string } | null
  readonly rationale: string
}

// Finding IDs are stable, dotted, and namespaced by category. They are part of
// the API contract (used for diffing in §7.4 monthly re-scan) — do not rename.
export const CATALOG = {
  // ── TLS / transport (category: tls) ───────────────────────────────────────
  'tls.missing': {
    category: 'tls',
    severity: 'critical',
    title: 'Site is not served over HTTPS',
    explanation:
      'No working TLS was found, so traffic to this site can be read or modified by anyone on the network path. Visitors have no confidentiality or integrity.',
    remediation:
      'Obtain a TLS certificate (e.g. a free one from Let’s Encrypt) and serve all traffic over HTTPS. Redirect every HTTP request to HTTPS.',
    cvss: { score: 9.1, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N' },
    rationale:
      'Network-adjacent attacker fully compromises confidentiality and integrity of all traffic; no auth required. High C/I impact → critical.',
  },
  'tls.served_over_http': {
    category: 'tls',
    severity: 'high',
    title: 'Final page was delivered over plain HTTP',
    explanation:
      'After following redirects the page still loaded over unencrypted HTTP. Anything entered on the page can be intercepted.',
    remediation:
      'Terminate the redirect chain on an HTTPS URL and serve the canonical site over HTTPS only.',
    cvss: { score: 7.4, vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N' },
    rationale:
      'Same impact as missing TLS but typically a misconfiguration (HTTPS exists elsewhere), so attack complexity is higher → high.',
  },
  'tls.expired': {
    category: 'tls',
    severity: 'high',
    title: 'TLS certificate has expired',
    explanation:
      'The certificate is past its expiry date. Browsers show a full-page security warning, and the identity of the site can no longer be trusted.',
    remediation:
      'Renew the certificate immediately and automate renewal (e.g. ACME / certbot) so it cannot lapse again.',
    cvss: { score: 7.5, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N' },
    rationale:
      'Users are trained through the warning and may proceed, enabling interception; authentication of the endpoint is lost → high.',
  },
  'tls.hostname_mismatch': {
    category: 'tls',
    severity: 'high',
    title: 'TLS certificate does not match the hostname',
    explanation:
      'The certificate presented is not valid for this domain, so browsers cannot verify they are talking to the real site.',
    remediation:
      'Issue or install a certificate whose Subject Alternative Names include this exact hostname.',
    cvss: { score: 7.4, vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N' },
    rationale: 'Endpoint authentication fails, enabling impersonation/MITM → high.',
  },
  'tls.self_signed': {
    category: 'tls',
    severity: 'high',
    title: 'TLS certificate is self-signed / not trusted',
    explanation:
      'The certificate does not chain to a trusted authority, so its identity cannot be independently verified.',
    remediation:
      'Replace the self-signed certificate with one from a publicly trusted CA.',
    cvss: { score: 7.4, vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N' },
    rationale: 'No trust anchor → impersonation possible → high.',
  },
  'tls.weak_protocol': {
    category: 'tls',
    severity: 'medium',
    title: 'Outdated TLS protocol version negotiated',
    explanation:
      'The server negotiated a TLS/SSL version (below TLS 1.2) with known cryptographic weaknesses.',
    remediation:
      'Disable SSLv3, TLS 1.0 and TLS 1.1. Require TLS 1.2 as a minimum and prefer TLS 1.3.',
    cvss: { score: 5.9, vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N' },
    rationale:
      'Exploitation requires an active downgrade/MITM position and specific conditions → medium.',
  },
  'tls.expiring_soon': {
    category: 'tls',
    severity: 'low',
    title: 'TLS certificate expires soon',
    explanation:
      'The certificate is valid but close to expiry. If it lapses, visitors will be blocked by browser warnings.',
    remediation:
      'Renew now and enable automated renewal so the certificate is replaced well before expiry.',
    cvss: null,
    rationale: 'Availability/operational hygiene, not yet exploitable → low.',
  },
  'tls.no_https_redirect': {
    category: 'tls',
    severity: 'medium',
    title: 'HTTP is not redirected to HTTPS',
    explanation:
      'Plain-HTTP requests are served instead of being redirected to HTTPS, so a first visit can happen entirely in clear text.',
    remediation:
      'Return a 301 redirect from every HTTP URL to its HTTPS equivalent, then add HSTS to prevent downgrade on later visits.',
    cvss: { score: 5.3, vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N' },
    rationale: 'Enables SSL-strip on the initial request; needs a network position → medium.',
  },
  'tls.mixed_content': {
    category: 'tls',
    severity: 'medium',
    title: 'HTTPS page loads insecure (HTTP) sub-resources',
    explanation:
      'The secure page pulls in scripts, styles or images over plain HTTP. Those resources can be tampered with, undermining the page’s security.',
    remediation:
      'Serve all sub-resources over HTTPS and add a Content-Security-Policy with "upgrade-insecure-requests".',
    cvss: { score: 6.1, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N' },
    rationale: 'Active sub-resources allow script tampering across the trust boundary → medium.',
  },

  // ── Security headers (category: headers) ──────────────────────────────────
  'headers.csp.missing': {
    category: 'headers',
    severity: 'high',
    title: 'No Content-Security-Policy header',
    explanation:
      'Without a Content-Security-Policy the browser has no allow-list for scripts, so a single injected script can run with full page privileges. CSP is the strongest in-browser defense against cross-site scripting.',
    remediation:
      'Add a strict, nonce-based Content-Security-Policy. Start in report-only mode to tune it, then enforce.',
    cvss: { score: 6.5, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N' },
    rationale:
      'Missing defense-in-depth that materially raises XSS blast radius; not itself a flaw → high cap on the category, medium-leaning base.',
  },
  'headers.hsts.missing': {
    category: 'headers',
    severity: 'medium',
    title: 'No Strict-Transport-Security (HSTS) header',
    explanation:
      'Without HSTS, browsers will still attempt plain HTTP on later visits, leaving a window for downgrade attacks.',
    remediation:
      'Send "Strict-Transport-Security: max-age=63072000; includeSubDomains" on all HTTPS responses once you are confident every subdomain is HTTPS-ready.',
    cvss: { score: 5.3, vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N' },
    rationale: 'Closes the SSL-strip window; requires MITM to exploit → medium.',
  },
  'headers.xfo.missing': {
    category: 'headers',
    severity: 'medium',
    title: 'No X-Frame-Options / frame-ancestors protection',
    explanation:
      'The page can be embedded in a frame on an attacker site, enabling clickjacking of authenticated actions.',
    remediation:
      'Set "X-Frame-Options: DENY" (or SAMEORIGIN) and a CSP "frame-ancestors ’self’" directive.',
    cvss: { score: 4.3, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N' },
    rationale: 'Clickjacking needs user interaction and yields limited integrity impact → medium.',
  },
  'headers.xcto.missing': {
    category: 'headers',
    severity: 'low',
    title: 'No X-Content-Type-Options header',
    explanation:
      'Without "nosniff", browsers may guess (MIME-sniff) a response type and execute content in an unintended, riskier way.',
    remediation: 'Add "X-Content-Type-Options: nosniff" to all responses.',
    cvss: { score: 3.1, vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N' },
    rationale: 'Edge-case enabler for content-type confusion → low.',
  },
  'headers.referrer_policy.missing': {
    category: 'headers',
    severity: 'low',
    title: 'No Referrer-Policy header',
    explanation:
      'Full URLs (which may contain sensitive tokens or identifiers) can leak to third-party sites via the Referer header.',
    remediation: 'Add "Referrer-Policy: strict-origin-when-cross-origin" (or stricter).',
    cvss: { score: 3.1, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N' },
    rationale: 'Limited, conditional information disclosure → low.',
  },
  'headers.permissions_policy.missing': {
    category: 'headers',
    severity: 'low',
    title: 'No Permissions-Policy header',
    explanation:
      'Powerful browser features (camera, microphone, geolocation) are not explicitly restricted, widening the attack surface if the page is compromised.',
    remediation:
      'Add a Permissions-Policy that disables features the site does not use, e.g. "geolocation=(), camera=(), microphone=()".',
    cvss: null,
    rationale: 'Defense-in-depth hardening, no direct impact → low.',
  },
  'headers.coop.missing': {
    category: 'headers',
    severity: 'low',
    title: 'No Cross-Origin-Opener-Policy header',
    explanation:
      'Without COOP, a page opened by or opening another window can be referenced cross-origin, enabling some cross-window attacks.',
    remediation: 'Add "Cross-Origin-Opener-Policy: same-origin".',
    cvss: null,
    rationale: 'Process-isolation hardening, no direct impact → low.',
  },
  'headers.coep.missing': {
    category: 'headers',
    severity: 'info',
    title: 'No Cross-Origin-Embedder-Policy header',
    explanation:
      'COEP is required only for sites using cross-origin isolation (e.g. SharedArrayBuffer). Informational for most sites.',
    remediation:
      'If you need cross-origin isolation, add "Cross-Origin-Embedder-Policy: require-corp". Otherwise no action is required.',
    cvss: null,
    rationale: 'Only relevant for specific advanced features → info.',
  },

  // ── Cookies (category: cookies) ───────────────────────────────────────────
  'cookies.secure.missing': {
    category: 'cookies',
    severity: 'medium',
    title: 'Cookie set without the Secure flag',
    explanation:
      'A cookie can be sent over plain HTTP, so it may be captured by a network attacker. Session cookies without Secure are a common account-takeover vector.',
    remediation: 'Add the "Secure" attribute to every cookie so it is only sent over HTTPS.',
    cvss: { score: 5.9, vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N' },
    rationale: 'Session/credential cookie exposure under MITM → medium.',
  },
  'cookies.httponly.missing': {
    category: 'cookies',
    severity: 'medium',
    title: 'Cookie set without the HttpOnly flag',
    explanation:
      'A cookie readable by JavaScript can be stolen if the site has any cross-site scripting flaw, turning XSS into session theft.',
    remediation:
      'Add "HttpOnly" to session/auth cookies so client-side scripts cannot read them.',
    cvss: { score: 5.4, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N' },
    rationale: 'Amplifies any XSS into credential theft → medium.',
  },
  'cookies.samesite.missing': {
    category: 'cookies',
    severity: 'low',
    title: 'Cookie set without an explicit SameSite attribute',
    explanation:
      'Without an explicit SameSite policy, the cookie may be sent on cross-site requests, contributing to cross-site request forgery (CSRF) risk.',
    remediation:
      'Set "SameSite=Lax" (or Strict for sensitive cookies) explicitly on every cookie.',
    cvss: { score: 3.1, vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N' },
    rationale: 'CSRF contributor, defaults vary by browser → low.',
  },

  // ── DNS / email hardening (category: dns_email) ───────────────────────────
  'dns_email.spf.missing': {
    category: 'dns_email',
    severity: 'medium',
    title: 'No SPF record',
    explanation:
      'Without an SPF record, anyone can send email that appears to come from this domain, enabling spoofing and phishing of your customers.',
    remediation:
      'Publish an SPF TXT record listing your authorized senders and ending in "-all", e.g. "v=spf1 include:_spf.yourprovider.com -all".',
    cvss: { score: 5.3, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N' },
    rationale: 'Enables email spoofing / brand abuse against third parties → medium.',
  },
  'dns_email.spf.weak': {
    category: 'dns_email',
    severity: 'medium',
    title: 'SPF record uses a permissive "+all"',
    explanation:
      'An SPF record ending in "+all" authorizes the whole internet to send as your domain, which is worse than having no record.',
    remediation: 'Change the SPF record to end in "-all" (fail) or at least "~all" (softfail).',
    cvss: { score: 5.3, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N' },
    rationale: 'Actively authorizes spoofing → medium.',
  },
  'dns_email.dmarc.missing': {
    category: 'dns_email',
    severity: 'medium',
    title: 'No DMARC record',
    explanation:
      'DMARC tells receiving mail servers what to do with mail that fails SPF/DKIM. Without it, spoofed mail is more likely to be delivered.',
    remediation:
      'Publish a DMARC record at _dmarc.<domain>, starting at "v=DMARC1; p=none" with reporting, then tighten to "p=quarantine"/"p=reject".',
    cvss: { score: 5.3, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N' },
    rationale: 'Missing anti-spoofing enforcement → medium.',
  },
  'dns_email.dmarc.weak': {
    category: 'dns_email',
    severity: 'low',
    title: 'DMARC policy is "p=none" (monitor only)',
    explanation:
      'A DMARC policy of "p=none" only reports abuse; it does not stop spoofed mail from being delivered.',
    remediation:
      'After reviewing DMARC reports, move the policy to "p=quarantine" and then "p=reject".',
    cvss: null,
    rationale: 'Reporting present but not yet enforcing → low.',
  },
  'dns_email.dkim.missing': {
    category: 'dns_email',
    severity: 'low',
    title: 'No DKIM signing detected',
    explanation:
      'DKIM cryptographically signs outbound mail so receivers can verify it was not altered. Its absence weakens DMARC enforcement.',
    remediation:
      'Enable DKIM signing in your mail provider and publish the provided public key as a DNS TXT record.',
    cvss: null,
    rationale: 'Email integrity hardening, conditional on sending mail → low.',
  },
  'dns_email.caa.missing': {
    category: 'dns_email',
    severity: 'low',
    title: 'No CAA record',
    explanation:
      'A CAA record restricts which certificate authorities may issue certificates for your domain, reducing the risk of mis-issuance.',
    remediation:
      'Add a CAA record naming your CA, e.g. "0 issue ’letsencrypt.org’".',
    cvss: null,
    rationale: 'Reduces mis-issuance risk, no direct exploit → low.',
  },
  'dns_email.dnssec.missing': {
    category: 'dns_email',
    severity: 'low',
    title: 'DNSSEC is not enabled',
    explanation:
      'Without DNSSEC, DNS answers for your domain are not cryptographically signed and could be forged by an on-path attacker.',
    remediation:
      'Enable DNSSEC at your DNS provider and publish the DS record at your registrar.',
    cvss: null,
    rationale: 'Defense-in-depth against DNS spoofing → low.',
  },
} as const satisfies Record<string, CatalogEntry>

export type FindingId = keyof typeof CATALOG

export function catalogEntry(id: FindingId): CatalogEntry {
  return CATALOG[id]
}

export const ALL_FINDING_IDS = Object.keys(CATALOG) as ReadonlyArray<FindingId>
