# CybrFlux Client Project Starter

Spin up a new fixed-scope client project in minutes. Built on Next.js 14 (App Router), Supabase, and Vercel.

---

## Quick Start

```bash
# 1. Use this template
gh repo create cybrflux/<client-slug>-app \
  --template cybrflux/client-project-starter \
  --private --clone
cd <client-slug>-app

# 2. Install dependencies
npm install

# 3. Copy env template and fill in your Supabase project keys
cp .env.example .env.local
# → edit .env.local

# 4. Apply DB baseline migration
npx supabase link --project-ref <your-supabase-ref>
npx supabase db push

# 5. Run dev server
npm run dev
# → http://localhost:3000
```

Done. Auth is wired, DB schema is applied, CI runs on every PR.

---

## Stack

| Layer | Choice |
|---|---|
| Framework | Next.js 14 (App Router) |
| Language | TypeScript (strict) |
| Styling | Tailwind CSS + shadcn/ui |
| Database | Supabase (Postgres + RLS) |
| Auth | Supabase Auth |
| Validation | Zod |
| State | TanStack Query (server) + Zustand (client) |
| Forms | react-hook-form + Zod |
| Testing | Vitest + Playwright |
| CI | GitHub Actions |
| Deploy | Vercel |

---

## Project Structure

```
client-project-starter/
├── .github/
│   └── workflows/
│       └── ci.yml              # typecheck → lint → test → build
├── src/
│   ├── app/
│   │   ├── layout.tsx
│   │   ├── page.tsx
│   │   ├── (auth)/
│   │   │   ├── login/page.tsx
│   │   │   └── callback/route.ts
│   │   └── dashboard/
│   │       ├── layout.tsx      # auth-guard layout
│   │       └── page.tsx
│   ├── components/
│   │   └── ui/                 # shadcn/ui components
│   ├── lib/
│   │   ├── supabase/
│   │   │   ├── client.ts       # browser client
│   │   │   └── server.ts       # server/RSC client
│   │   ├── validations.ts      # shared Zod schemas
│   │   └── utils.ts            # cn() and helpers
│   └── middleware.ts           # auth + route protection
├── supabase/
│   └── migrations/
│       └── 00001_baseline.sql  # users, audit_log, RLS
├── .env.example
├── .eslintrc.json
├── next.config.ts
├── tailwind.config.ts
├── tsconfig.json
└── docs/
    ├── intake-questionnaire.md
    ├── scoping-checklist.md
    └── definition-of-done-and-handoff.md
```

---

## Docs (fill out in order for every engagement)

1. **[Intake questionnaire](docs/intake-questionnaire.md)** — PM/CEO fills this in the first meeting.
2. **[Scoping & acceptance checklist](docs/scoping-checklist.md)** — locked before sprint 1.
3. **[Definition of done & handoff](docs/definition-of-done-and-handoff.md)** — filled at go-live.

---

## Environment Variables

See `.env.example` for all required variables. Never commit `.env.local`.

---

## CI/CD

| Trigger | Action |
|---|---|
| PR opened / updated | typecheck + lint + tests + preview deploy (Vercel) |
| Merge to `main` | production deploy (Vercel) |

Branch protection on `main`: 1 required review + CI green.

---

## Adding a Feature

1. Copy the acceptance criteria block from `docs/scoping-checklist.md` Part C.
2. Fill it out and get client sign-off before writing code.
3. Create a branch `feat/<short-name>`, open a PR, get a review.
4. Verify all DoD criteria before merging.
