// CybrScan subscription tiers (CYB-34, Workstream 1 — billing scaffold).
//
// Source of truth for tier metadata shared by the pricing UI and the Stripe
// Checkout flow (Founding Engineer, Week 2). Stripe price IDs are NOT hardcoded
// — they come from env so test/live modes and CRO's final price objects swap
// without code changes. CRO (CYB) owns final pricing + the actual price IDs.

export const SUBSCRIPTION_TIERS = ['starter', 'pro', 'business'] as const
export type SubscriptionTier = (typeof SUBSCRIPTION_TIERS)[number]

export interface TierConfig {
  readonly id: SubscriptionTier
  readonly name: string
  readonly monthlyPriceUsd: number
  readonly priceIdEnvVar: string
  readonly domains: number
  readonly features: ReadonlyArray<string>
}

// Prices are illustrative defaults from the brief; CRO finalizes. The display
// price and the Stripe price object must be kept in sync by the billing impl.
export const TIER_CONFIG: Readonly<Record<SubscriptionTier, TierConfig>> = {
  starter: {
    id: 'starter',
    name: 'Starter',
    monthlyPriceUsd: 29,
    priceIdEnvVar: 'STRIPE_PRICE_STARTER',
    domains: 1,
    features: ['1 verified domain', 'Weekly monitoring', 'Email alerts'],
  },
  pro: {
    id: 'pro',
    name: 'Pro',
    monthlyPriceUsd: 99,
    priceIdEnvVar: 'STRIPE_PRICE_PRO',
    domains: 5,
    features: ['5 domains', 'Daily monitoring', 'OSINT exposure feed', 'Monthly report'],
  },
  business: {
    id: 'business',
    name: 'Business',
    monthlyPriceUsd: 299,
    priceIdEnvVar: 'STRIPE_PRICE_BUSINESS',
    domains: 25,
    features: ['25 domains', 'API access', 'White-label reports', 'Priority support'],
  },
}

// Resolve the Stripe price ID for a tier at call time. Throws if the env var is
// missing so a misconfigured deploy fails fast rather than charging wrong.
export function getStripePriceId(tier: SubscriptionTier): string {
  const envVar = TIER_CONFIG[tier].priceIdEnvVar
  const priceId = process.env[envVar]
  if (!priceId) {
    throw new Error(`Missing Stripe price ID env var ${envVar} for tier "${tier}".`)
  }
  return priceId
}
