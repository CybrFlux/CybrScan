// Regression tests per passive check (CYB-43): each asserts the finding FIRES
// on the bad config and is ABSENT on the fixed (clean) config.

import { describe, it, expect } from 'vitest'
import { checkTls, checkHeaders, checkCookies, checkDnsEmail } from '../checks'
import { cleanHttp, cleanTls, cleanDns, cleanHeaders } from './fixtures'

function ids(findings: ReadonlyArray<{ id: string }>): string[] {
  return findings.map((f) => f.id)
}

describe('checkTls', () => {
  it('clean config produces no TLS findings', () => {
    expect(checkTls(cleanTls(), cleanHttp())).toEqual([])
  })

  it('flags tls.missing when no handshake, but not on the fixed config', () => {
    const bad = checkTls({ ...cleanTls(), present: false }, cleanHttp())
    expect(ids(bad)).toContain('tls.missing')
    expect(ids(checkTls(cleanTls(), cleanHttp()))).not.toContain('tls.missing')
  })

  it('flags tls.expired on a past-due cert, not on a valid one', () => {
    const bad = checkTls({ ...cleanTls(), daysUntilExpiry: -3 }, cleanHttp())
    expect(ids(bad)).toContain('tls.expired')
    expect(ids(checkTls(cleanTls(), cleanHttp()))).not.toContain('tls.expired')
  })

  it('flags tls.expiring_soon within the window, not on a long-lived cert', () => {
    const bad = checkTls({ ...cleanTls(), daysUntilExpiry: 5 }, cleanHttp())
    expect(ids(bad)).toContain('tls.expiring_soon')
    expect(ids(checkTls(cleanTls(), cleanHttp()))).not.toContain('tls.expiring_soon')
  })

  it('flags tls.hostname_mismatch, not on a matching cert', () => {
    const bad = checkTls({ ...cleanTls(), hostnameMatches: false }, cleanHttp())
    expect(ids(bad)).toContain('tls.hostname_mismatch')
    expect(ids(checkTls(cleanTls(), cleanHttp()))).not.toContain('tls.hostname_mismatch')
  })

  it('flags tls.self_signed, not on a CA-trusted cert', () => {
    const bad = checkTls({ ...cleanTls(), selfSigned: true }, cleanHttp())
    expect(ids(bad)).toContain('tls.self_signed')
    expect(ids(checkTls(cleanTls(), cleanHttp()))).not.toContain('tls.self_signed')
  })

  it('flags tls.weak_protocol on TLS 1.0, not on TLS 1.3', () => {
    const bad = checkTls({ ...cleanTls(), protocol: 'TLSv1' }, cleanHttp())
    expect(ids(bad)).toContain('tls.weak_protocol')
    expect(ids(checkTls(cleanTls(), cleanHttp()))).not.toContain('tls.weak_protocol')
  })

  it('flags tls.served_over_http when the final page is HTTP, not HTTPS', () => {
    const bad = checkTls(cleanTls(), { ...cleanHttp(), scheme: 'http' })
    expect(ids(bad)).toContain('tls.served_over_http')
    expect(ids(checkTls(cleanTls(), cleanHttp()))).not.toContain('tls.served_over_http')
  })

  it('flags tls.no_https_redirect when HTTP is not redirected', () => {
    const bad = checkTls(cleanTls(), { ...cleanHttp(), httpToHttpsRedirect: false })
    expect(ids(bad)).toContain('tls.no_https_redirect')
    expect(ids(checkTls(cleanTls(), cleanHttp()))).not.toContain('tls.no_https_redirect')
  })

  it('flags tls.mixed_content on an HTTPS page with HTTP subresources', () => {
    const bad = checkTls(cleanTls(), { ...cleanHttp(), mixedContent: true })
    expect(ids(bad)).toContain('tls.mixed_content')
    expect(ids(checkTls(cleanTls(), cleanHttp()))).not.toContain('tls.mixed_content')
  })
})

describe('checkHeaders', () => {
  it('clean config produces no header findings', () => {
    expect(checkHeaders(cleanHttp())).toEqual([])
  })

  const cases: ReadonlyArray<[string, string]> = [
    ['content-security-policy', 'headers.csp.missing'],
    ['strict-transport-security', 'headers.hsts.missing'],
    ['x-frame-options', 'headers.xfo.missing'],
    ['x-content-type-options', 'headers.xcto.missing'],
    ['referrer-policy', 'headers.referrer_policy.missing'],
    ['permissions-policy', 'headers.permissions_policy.missing'],
    ['cross-origin-opener-policy', 'headers.coop.missing'],
    ['cross-origin-embedder-policy', 'headers.coep.missing'],
  ]

  for (const [headerName, findingId] of cases) {
    it(`flags ${findingId} when ${headerName} is absent, not when present`, () => {
      const headers = cleanHeaders()
      delete headers[headerName]
      // CSP carries frame-ancestors; dropping it would also trip xfo. Restore a
      // bare x-frame-options so we isolate the CSP case.
      if (headerName === 'content-security-policy') headers['x-frame-options'] = 'DENY'
      // X-Frame-Options is satisfied by CSP frame-ancestors; remove it so the
      // bad config genuinely lacks clickjacking protection.
      if (headerName === 'x-frame-options') headers['content-security-policy'] = "default-src 'self'"
      const bad = checkHeaders({ ...cleanHttp(), headers })
      expect(ids(bad)).toContain(findingId)
      expect(ids(checkHeaders(cleanHttp()))).not.toContain(findingId)
    })
  }

  it('does not flag xfo when CSP frame-ancestors is present without X-Frame-Options', () => {
    const headers = cleanHeaders()
    delete headers['x-frame-options'] // CSP still has frame-ancestors 'none'
    expect(ids(checkHeaders({ ...cleanHttp(), headers }))).not.toContain('headers.xfo.missing')
  })
})

describe('checkCookies', () => {
  it('clean fully-flagged cookie produces no findings', () => {
    expect(checkCookies(cleanHttp())).toEqual([])
  })

  it('flags cookies.secure.missing when Secure is absent', () => {
    const bad = checkCookies({ ...cleanHttp(), setCookies: ['sid=x; HttpOnly; SameSite=Lax'] })
    expect(ids(bad)).toContain('cookies.secure.missing')
  })

  it('flags cookies.httponly.missing when HttpOnly is absent', () => {
    const bad = checkCookies({ ...cleanHttp(), setCookies: ['sid=x; Secure; SameSite=Lax'] })
    expect(ids(bad)).toContain('cookies.httponly.missing')
  })

  it('flags cookies.samesite.missing when SameSite is absent', () => {
    const bad = checkCookies({ ...cleanHttp(), setCookies: ['sid=x; Secure; HttpOnly'] })
    expect(ids(bad)).toContain('cookies.samesite.missing')
  })

  it('never surfaces the cookie value in evidence (§8/§5)', () => {
    const bad = checkCookies({ ...cleanHttp(), setCookies: ['sid=SUPERSECRETVALUE; SameSite=Lax'] })
    for (const f of bad) expect(f.evidence).not.toContain('SUPERSECRETVALUE')
  })
})

describe('checkDnsEmail', () => {
  it('clean DNS produces no findings', () => {
    expect(checkDnsEmail(cleanDns())).toEqual([])
  })

  it('flags dns_email.spf.missing when no SPF record', () => {
    const bad = checkDnsEmail({ ...cleanDns(), spf: null })
    expect(ids(bad)).toContain('dns_email.spf.missing')
  })

  it('flags dns_email.spf.weak on a permissive +all', () => {
    const bad = checkDnsEmail({ ...cleanDns(), spf: 'v=spf1 +all' })
    expect(ids(bad)).toContain('dns_email.spf.weak')
    expect(ids(bad)).not.toContain('dns_email.spf.missing')
  })

  it('flags dns_email.dmarc.missing when no DMARC record', () => {
    const bad = checkDnsEmail({ ...cleanDns(), dmarc: null })
    expect(ids(bad)).toContain('dns_email.dmarc.missing')
  })

  it('flags dns_email.dmarc.weak on p=none', () => {
    const bad = checkDnsEmail({ ...cleanDns(), dmarc: 'v=DMARC1; p=none' })
    expect(ids(bad)).toContain('dns_email.dmarc.weak')
  })

  it('flags dns_email.dkim.missing only when mail is accepted', () => {
    const withMail = checkDnsEmail({ ...cleanDns(), dkimPresent: false, mxPresent: true })
    expect(ids(withMail)).toContain('dns_email.dkim.missing')
    const noMail = checkDnsEmail({ ...cleanDns(), dkimPresent: false, mxPresent: false })
    expect(ids(noMail)).not.toContain('dns_email.dkim.missing')
  })

  it('flags dns_email.caa.missing and dns_email.dnssec.missing when disabled', () => {
    const bad = checkDnsEmail({ ...cleanDns(), caaPresent: false, dnssec: false })
    expect(ids(bad)).toContain('dns_email.caa.missing')
    expect(ids(bad)).toContain('dns_email.dnssec.missing')
  })
})
