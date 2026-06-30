'use client'

import { useState } from 'react'
import { createClient } from '@/lib/supabase/client'
import { loginSchema } from '@/lib/validations'

export default function LoginPage() {
  const [email, setEmail] = useState('')
  const [status, setStatus] = useState<'idle' | 'loading' | 'sent' | 'error'>('idle')
  const [errorMessage, setErrorMessage] = useState('')

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setStatus('loading')
    setErrorMessage('')

    const result = loginSchema.safeParse({ email })
    if (!result.success) {
      setStatus('error')
      setErrorMessage(result.error.errors[0]?.message ?? 'Invalid email')
      return
    }

    const supabase = createClient()
    const { error } = await supabase.auth.signInWithOtp({
      email: result.data.email,
      options: { emailRedirectTo: `${window.location.origin}/auth/callback` },
    })

    if (error) {
      setStatus('error')
      setErrorMessage('Could not send login link. Please try again.')
      return
    }

    setStatus('sent')
  }

  return (
    <main className="flex min-h-screen items-center justify-center px-4">
      <div className="w-full max-w-sm space-y-6">
        <div className="text-center space-y-1">
          <h1 className="text-2xl font-bold">Sign in</h1>
          <p className="text-sm text-gray-500">We&apos;ll email you a magic link.</p>
        </div>

        {status === 'sent' ? (
          <p className="text-center text-sm text-green-700 bg-green-50 rounded-md p-4">
            Check your email — a sign-in link is on its way.
          </p>
        ) : (
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label htmlFor="email" className="block text-sm font-medium mb-1">
                Email address
              </label>
              <input
                id="email"
                type="email"
                autoComplete="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full rounded-md border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-black"
              />
            </div>

            {status === 'error' && (
              <p className="text-sm text-red-600">{errorMessage}</p>
            )}

            <button
              type="submit"
              disabled={status === 'loading'}
              className="w-full rounded-md bg-black px-4 py-2 text-sm text-white hover:bg-gray-800 disabled:opacity-50 transition-colors"
            >
              {status === 'loading' ? 'Sending…' : 'Send magic link'}
            </button>
          </form>
        )}
      </div>
    </main>
  )
}
