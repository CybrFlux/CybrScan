import Link from 'next/link'
import { createClient } from '@/lib/supabase/server'
import { ScanRequestForm } from './scans/scan-request-form'

type ScanRow = {
  id: string
  domain: string
  status: string
  grade: string | null
  created_at: string
}

const GRADE_STYLES: Record<string, string> = {
  A: 'bg-green-100 text-green-800',
  B: 'bg-lime-100 text-lime-800',
  C: 'bg-yellow-100 text-yellow-800',
  D: 'bg-orange-100 text-orange-800',
  F: 'bg-red-100 text-red-800',
}

const RECENT_SCANS_LIMIT = 20

export default async function DashboardPage() {
  const supabase = await createClient()
  const { data, error } = await supabase
    .from('scans')
    .select('id, domain, status, grade, created_at')
    .order('created_at', { ascending: false })
    .limit(RECENT_SCANS_LIMIT)

  const scans: ScanRow[] = error ? [] : ((data as ScanRow[]) ?? [])

  return (
    <div className="space-y-8">
      <section className="space-y-3">
        <div>
          <h1 className="text-xl font-semibold">Scan a website</h1>
          <p className="text-sm text-gray-500">
            Enter a domain to run a free passive security scan and get an A–F grade.
          </p>
        </div>
        <ScanRequestForm />
      </section>

      <section className="space-y-3">
        <h2 className="text-sm font-semibold text-gray-700">Recent scans</h2>
        {scans.length === 0 ? (
          <p className="text-sm text-gray-400">No scans yet. Run your first scan above.</p>
        ) : (
          <ul className="divide-y rounded-md border bg-white">
            {scans.map((scan) => (
              <li key={scan.id}>
                <Link
                  href={`/dashboard/scans/${scan.id}`}
                  className="flex items-center justify-between px-4 py-3 hover:bg-gray-50 transition-colors"
                >
                  <span className="text-sm font-medium">{scan.domain}</span>
                  <span className="flex items-center gap-3">
                    {scan.grade && (
                      <span
                        className={`rounded px-2 py-0.5 text-xs font-semibold ${
                          GRADE_STYLES[scan.grade] ?? 'bg-gray-100 text-gray-700'
                        }`}
                      >
                        {scan.grade}
                      </span>
                    )}
                    <span className="text-xs text-gray-400">{scan.status}</span>
                  </span>
                </Link>
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  )
}
