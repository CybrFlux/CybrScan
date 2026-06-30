# Definition of Done & Project Handoff Template

---

## Definition of Done (DoD)

A feature is **done** when every item below is true — not before.

| # | Criterion | Notes |
|---|---|---|
| 1 | All acceptance criteria pass (see scoping checklist) | Evidence: screenshot / test output linked |
| 2 | Code merged to `main` via approved PR (1+ review, CI green) | PR link: |
| 3 | Zero TypeScript errors (`tsc --noEmit` clean) | |
| 4 | Zero ESLint errors | |
| 5 | Unit tests cover the new behaviour; overall coverage ≥ 80 % | |
| 6 | No hardcoded secrets; `.env.example` updated if new vars added | |
| 7 | Deployed to staging and smoke-tested | Staging URL: |
| 8 | Client or PM has seen it on staging (async OK) | Confirmed by: |

A **release** is done when, in addition to all of the above:

| # | Criterion | Notes |
|---|---|---|
| R1 | Pre-launch gate (scoping-checklist Part D) fully checked | |
| R2 | Client UAT sign-off obtained (or formally waived) | |
| R3 | Production deploy succeeded; rollback plan documented | |
| R4 | Monitoring / alerting active (Vercel error alerts + Sentry) | |
| R5 | Handoff document completed and delivered to client | |

---

## Project Handoff Template

> Complete and send to the client contact within 48 hours of go-live.

---

### Section 1 — Project Summary

**Client:** ___________________________

**Project name:** ___________________________

**Go-live date:** ___________________________

**CybrFlux delivery lead:** ___________________________

**Brief description of what was built:**

> (2–4 sentences)

---

### Section 2 — Access & Credentials

> All secrets must be delivered via 1Password share or agreed secure channel — never email.

| System | URL / Identifier | Credential location |
|---|---|---|
| Production app | | 1Password vault: |
| Supabase dashboard | | 1Password vault: |
| Vercel dashboard | | 1Password vault: |
| GitHub repo | | Access granted to: |
| DNS / domain registrar | | 1Password vault: |
| Error monitoring (Sentry) | | 1Password vault: |
| Any third-party APIs | | 1Password vault: |

---

### Section 3 — Architecture Overview

**Stack:**

- Frontend: Next.js (App Router) · TypeScript · Tailwind CSS · shadcn/ui
- Backend: Next.js Server Actions + API routes
- Database: Supabase (Postgres) · Row Level Security enabled
- Auth: Supabase Auth
- Hosting: Vercel (preview + production)
- CI/CD: GitHub Actions → Vercel

**Repository:** `github.com/cybrflux/[repo-name]`

**Key directories:**

| Path | Purpose |
|---|---|
| `src/app/` | Next.js App Router pages and layouts |
| `src/components/` | Shared UI components |
| `src/lib/` | Utilities, Supabase client, validators |
| `supabase/migrations/` | Database migration history |
| `.github/workflows/` | CI pipeline |

---

### Section 4 — Runbook

#### Deploy a code change

1. Create a branch from `main`: `git checkout -b feat/your-change`
2. Make changes, commit, push.
3. Open a PR on GitHub — a Vercel preview URL is auto-generated.
4. Get 1 approval + CI green → merge to `main`.
5. Vercel auto-deploys to production within ~90 seconds.

#### Apply a database migration

```bash
# Install Supabase CLI if needed
npm install -g supabase

# Log in
supabase login

# Link to your project (run once per machine)
supabase link --project-ref <ref-from-supabase-dashboard>

# Create a new migration
supabase migration new your_migration_name

# Edit the generated file in supabase/migrations/
# Then push to remote
supabase db push
```

#### Rotate a secret

1. Generate the new secret in the provider's dashboard.
2. Update in Vercel: Settings → Environment Variables → edit the var → redeploy.
3. Update in 1Password vault.
4. Revoke the old secret in the provider's dashboard.

#### Rollback production

Vercel keeps the last 20 deployments. From the Vercel dashboard:
1. Go to Deployments tab.
2. Find the last known-good deployment.
3. Click **Promote to Production**.

---

### Section 5 — Known Limitations & Future Work

List anything deliberately deferred, known edge cases, or recommended next steps:

| Item | Severity | Notes |
|---|---|---|
| | | |
| | | |
| | | |

---

### Section 6 — Support Window

| Period | Coverage |
|---|---|
| First 30 days post-launch | Bug fixes included (no new features) |
| After 30 days | Per separate retainer or SOW |

Bug reports: email `platform@cybrflux.online` with subject `[BUG] <project-name> — <one-line summary>`.

---

### Section 7 — Sign-off

By signing below, both parties confirm the project deliverables match the agreed scope.

| | Name | Signature | Date |
|---|---|---|---|
| Client representative | | | |
| CybrFlux delivery lead | | | |

---

*Template version: 1.0 — maintained in `client-project-starter/docs/`*
