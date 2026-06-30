import { z } from 'zod'

export const emailSchema = z.string().email('Invalid email address')

export const loginSchema = z.object({
  email: emailSchema,
})

export const profileUpdateSchema = z.object({
  full_name: z.string().min(1, 'Name is required').max(100, 'Name too long').trim(),
  avatar_url: z.string().url('Invalid URL').optional().or(z.literal('')),
})

// CybrScan — scan request input (CYB-34).
// Accepts a bare domain or a URL, normalizes to a lowercase hostname, and
// rejects anything that is not a public-looking hostname. We intentionally do
// NOT accept IPs, localhost, or ports here — the free scan targets real domains
// only, and the ownership/safety gate (Security) governs anything beyond that.
const HOSTNAME_REGEX = /^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$/

export const domainSchema = z
  .string()
  .trim()
  .min(1, 'Enter a domain to scan')
  .max(253, 'Domain is too long')
  .transform((raw) => {
    const withoutScheme = raw.replace(/^https?:\/\//i, '')
    const hostOnly = withoutScheme.split('/')[0] ?? ''
    return (hostOnly.split(':')[0] ?? '').toLowerCase().replace(/\.$/, '')
  })
  .refine((host) => HOSTNAME_REGEX.test(host), {
    message: 'Enter a valid domain, e.g. example.com',
  })

export const scanRequestSchema = z.object({
  domain: domainSchema,
})

export type LoginInput = z.infer<typeof loginSchema>
export type ProfileUpdateInput = z.infer<typeof profileUpdateSchema>
export type ScanRequestInput = z.infer<typeof scanRequestSchema>
