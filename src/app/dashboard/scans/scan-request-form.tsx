'use client'

import { useFormState, useFormStatus } from 'react-dom'
import { createScanRequest, type ScanFormState } from './actions'

const INITIAL_STATE: ScanFormState = { error: null }

function SubmitButton() {
  const { pending } = useFormStatus()
  return (
    <button
      type="submit"
      disabled={pending}
      className="rounded-md bg-black px-4 py-2 text-sm text-white hover:bg-gray-800 disabled:opacity-50 transition-colors"
    >
      {pending ? 'Scanning…' : 'Scan'}
    </button>
  )
}

export function ScanRequestForm() {
  const [state, formAction] = useFormState(createScanRequest, INITIAL_STATE)

  return (
    <form action={formAction} className="space-y-2">
      <div className="flex gap-2">
        <input
          name="domain"
          type="text"
          inputMode="url"
          autoComplete="off"
          placeholder="example.com"
          aria-label="Domain to scan"
          required
          className="flex-1 rounded-md border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-black"
        />
        <SubmitButton />
      </div>
      {state.error && <p className="text-sm text-red-600">{state.error}</p>}
    </form>
  )
}
