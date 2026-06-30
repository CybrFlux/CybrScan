import Link from 'next/link'
import { notFound } from 'next/navigation'
import { createClient } from '@/lib/supabase/server'
import { scanResultSchema, SEVERITIES, type Severity } from '@/lib/scan'

const GRADE_STYLES: Record<string, string> = {
  A: 'bg-green-100 text-green-800',
  B: 'bg-lime-100 text-lime-800',
  C: 'bg-yellow-100 text-yellow-800',
  D: 'bg-orange-100 text-orange-800',
  F: 'bg-red-100 text-red-800',
}

const SEVERITY_STYLES: Record<Severity, string> = {
  critical: 'bg-red-100 text-red-800',
  high: 'bg-orange-100 text-orange-800',
  medium: 'bg-yellow-100 text-yellow-800',
  low: 'bg-blue-100 text-blue-800',
  info: 'bg-gray-100 text-gray-700',
}

const CATEGORY_LABELS: Record<string, string> = {
  tls: 'TLS / SSL',
  headers: 'Security headers',
  dns_email: 'DNS & email',
  cookies: 'Cookies',
  exposure: 'Public exposure',
}

const SEVERITY_ORDER: Record<Severity, number> = Object.fromEntries(
  SEVERITIES.map((s, i) => [s, i]),
) as Record<Severity, number>

export default async function ScanResultPage({ params }: { params: { id: string } }) {
  const supabase = await createClient()
  const { data, error } = await supabase
    .from('scans')
    .select('id, domain, status, result, created_at')
    .eq('id', params.id)
    .maybeSingle()

  if (error || !data) {
    notFound()
  }

  const parsed = scanResultSchema.safeParse(data.result)
  const findings = parsed.success
    ? [...parsed.data.findings].sort(
        (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity],
      )
    : []

  return (
    <div className="space-y-6">
      <Link href="/dashboard" className="text-sm text-gray-500 hover:underline">
        ← Back to dashboard
      </Link>

      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold">{data.domain}</h1>
          <p className="text-sm text-gray-500">Passive security scan</p>
        </div>
        {parsed.success && (
          <div className="flex items-center gap-3">
            <span className="text-sm text-gray-500">{parsed.data.score}/100</span>
            <span
              className={`flex h-14 w-14 items-center justify-center rounded-lg text-2xl font-bold ${
                GRADE_STYLES[parsed.data.grade] ?? 'bg-gray-100 text-gray-700'
              }`}
            >
              {parsed.data.grade}
            </span>
          </div>
        )}
      </div>

      {!parsed.success ? (
        <p className="rounded-md bg-yellow-50 p-4 text-sm text-yellow-800">
          {data.status === 'failed'
            ? 'This scan could not be completed. Please run it again.'
            : 'This scan is still in progress. Refresh in a moment.'}
        </p>
      ) : (
        <>
          <section className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            {parsed.data.categories.map((cat) => (
              <div key={cat.key} className="rounded-md border bg-white p-3">
                <p className="text-xs text-gray-500">
                  {CATEGORY_LABELS[cat.key] ?? cat.key}
                </p>
                <p className="mt-1 flex items-baseline gap-2">
                  <span
                    className={`rounded px-1.5 py-0.5 text-sm font-bold ${
                      GRADE_STYLES[cat.grade] ?? 'bg-gray-100 text-gray-700'
                    }`}
                  >
                    {cat.grade}
                  </span>
                  <span className="text-xs text-gray-400">{cat.score}/100</span>
                </p>
              </div>
            ))}
          </section>

          <section className="space-y-3">
            <h2 className="text-sm font-semibold text-gray-700">
              Findings ({findings.length})
            </h2>
            {findings.length === 0 ? (
              <p className="rounded-md bg-green-50 p-4 text-sm text-green-800">
                No issues found on the passive checks. Nice work.
              </p>
            ) : (
              <ul className="space-y-3">
                {findings.map((finding) => (
                  <li key={finding.id} className="rounded-md border bg-white p-4 space-y-2">
                    <div className="flex items-center justify-between gap-3">
                      <h3 className="text-sm font-medium">{finding.title}</h3>
                      <span
                        className={`rounded px-2 py-0.5 text-xs font-semibold ${SEVERITY_STYLES[finding.severity]}`}
                      >
                        {finding.severity}
                      </span>
                    </div>
                    <p className="text-sm text-gray-600">{finding.explanation}</p>
                    <p className="text-xs text-gray-400">{finding.evidence}</p>
                    <p className="text-sm text-gray-900">
                      <span className="font-medium">Fix: </span>
                      {finding.remediation}
                    </p>
                  </li>
                ))}
              </ul>
            )}
          </section>
        </>
      )}
    </div>
  )
}
