# Scoping & Acceptance-Criteria Checklist

> Complete before first sprint starts. Every unchecked item is a delivery risk.

---

## Part A — Scope Lock

### A1. Intake complete

- [ ] Intake questionnaire signed by client decision maker
- [ ] Explicit out-of-scope list reviewed and accepted by client
- [ ] All "Needs Clarification" features resolved or deferred to a named future phase

### A2. Functional requirements

For each feature in scope:

- [ ] User story written: *"As a [role], I want [action] so that [value]."*
- [ ] Acceptance criteria are testable (Given/When/Then or numbered steps)
- [ ] Edge cases documented (empty states, error states, permission boundaries)
- [ ] Mobile / responsive requirement stated per feature

### A3. Non-functional requirements

- [ ] Performance budget defined (e.g. "< 2 s LCP on 4G")
- [ ] Uptime SLA agreed (e.g. "99.5% monthly")
- [ ] Browser / device matrix confirmed
- [ ] Accessibility level confirmed (default: WCAG 2.1 AA)

### A4. Integrations

- [ ] Each third-party API has a sandbox environment available
- [ ] API credentials / keys handed over or documented in 1Password
- [ ] Rate limits and pricing tiers reviewed
- [ ] Fallback behavior defined for each integration if it goes down

---

## Part B — Technical Readiness

### B1. Environments

- [ ] Production environment provisioned (Vercel project + Supabase project)
- [ ] Staging/preview environment configured
- [ ] Environment variables documented in `.env.example`
- [ ] Secrets stored in Vercel env vars (not committed to repo)

### B2. Repo & CI

- [ ] GitHub repo created from `client-project-starter` template
- [ ] Branch protection on `main` (require PR + 1 review + CI green)
- [ ] CI pipeline runs: type-check, lint, unit tests, build
- [ ] Deployment pipeline: preview on PR, production on merge to `main`

### B3. Database

- [ ] Schema baseline applied (users, sessions, audit_log tables)
- [ ] Row Level Security enabled on all user-scoped tables
- [ ] Migrations tracked in `/supabase/migrations/`
- [ ] Seed data available for local development

### B4. Auth

- [ ] Auth provider configured (Supabase Auth default, or custom)
- [ ] Required OAuth providers enabled (Google, GitHub, etc.)
- [ ] Email templates customised with client branding
- [ ] Session expiry and refresh strategy documented

---

## Part C — Acceptance Criteria Template

Copy this block for **each deliverable feature**:

```
### Feature: [Feature Name]

**User story:** As a [role], I want [action] so that [value].

**Acceptance criteria:**
1. Given [context], when [action], then [expected outcome].
2. Given [context], when [action], then [expected outcome].
3. Error case: Given [bad input / failure], when [action], then [graceful handling].

**Edge cases:**
- Empty state: [what the UI shows when there is no data]
- Permissions: [who can and cannot access this]
- Mobile: [behaviour on small screen]

**Out of scope for this feature:**
- [anything the client might assume is included but isn't]

**Test evidence required:**
- [ ] Screenshot / screen recording of happy path
- [ ] Screenshot of error state
- [ ] Lighthouse score (if performance-critical)
```

---

## Part D — Pre-Launch Gate

All items must be checked before any production deployment:

### D1. Quality

- [ ] All acceptance criteria for all in-scope features pass
- [ ] No `console.error` or unhandled rejections in browser console
- [ ] No hardcoded secrets in repo (`git grep -r "sk_live\|password\|api_key"` clean)
- [ ] TypeScript strict mode: zero `any`, zero type errors
- [ ] ESLint: zero errors (warnings reviewed)

### D2. Security

- [ ] All user input validated with Zod schemas
- [ ] SQL injection: only parameterized queries / Supabase client used
- [ ] XSS: no `dangerouslySetInnerHTML` without sanitization
- [ ] CSRF: Next.js Server Actions used for mutations (not raw fetch)
- [ ] Auth middleware protects all `/dashboard` and `/api/v1/` routes
- [ ] Rate limiting on auth endpoints (Upstash Redis or Vercel middleware)
- [ ] CORS configured (not `*`)
- [ ] `.env.example` committed; `.env.local` in `.gitignore`

### D3. Performance

- [ ] Lighthouse Performance ≥ 90 on production URL
- [ ] LCP < 2.5 s on simulated 4G
- [ ] No unused npm packages (`npx depcheck` clean)
- [ ] Images via `next/image` (no raw `<img>` tags)

### D4. Accessibility

- [ ] `axe` DevTools scan: zero critical / serious violations
- [ ] Keyboard navigation works for all interactive elements
- [ ] All images have `alt` text

### D5. Client sign-off

- [ ] UAT completed by client (or waived in writing)
- [ ] Client approves staging deployment
- [ ] DNS / domain transfer complete
- [ ] Go-live window agreed and comms sent

---

*Last updated by:* ___________  *Date:* ___________
