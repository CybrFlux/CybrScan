'use server'

import { redirect } from 'next/navigation'
import { revalidatePath } from 'next/cache'
import { createClient } from '@/lib/supabase/server'
import { scanRequestSchema } from '@/lib/validations'
import { getScanEngine } from '@/lib/scan'

export type ScanFormState = { error: string | null }

// Week-1 vertical slice: validate -> run the (mock) engine inline -> persist a
// completed scan row -> redirect to the result page. The inline run keeps the
// slice demoable without a queue; Workstream 2's monthly re-scan replaces this
// with a queued job writing the same `scans` row via the service role.
export async function createScanRequest(
  _prev: ScanFormState,
  formData: FormData,
): Promise<ScanFormState> {
  const parsed = scanRequestSchema.safeParse({ domain: formData.get('domain') })
  if (!parsed.success) {
    return { error: parsed.error.errors[0]?.message ?? 'Invalid domain' }
  }

  const supabase = await createClient()
  const {
    data: { user },
  } = await supabase.auth.getUser()
  if (!user) {
    redirect('/login')
  }

  const { domain } = parsed.data
  let scanId: string

  try {
    const engine = getScanEngine()
    const result = await engine.runScan({ domain, scanType: 'passive_free' })

    const { data, error } = await supabase
      .from('scans')
      .insert({
        account_id: user.id,
        domain,
        scan_type: 'passive_free',
        status: 'complete',
        grade: result.grade,
        score: result.score,
        result,
      })
      .select('id')
      .single()

    if (error || !data) {
      return { error: 'Could not save your scan. Please try again.' }
    }
    scanId = data.id
  } catch {
    // Record the failure so the customer sees it rather than a silent drop.
    await supabase.from('scans').insert({
      account_id: user.id,
      domain,
      scan_type: 'passive_free',
      status: 'failed',
      error: 'Scan engine error',
    })
    return { error: 'The scan could not be completed. Please try again shortly.' }
  }

  revalidatePath('/dashboard')
  redirect(`/dashboard/scans/${scanId}`)
}
