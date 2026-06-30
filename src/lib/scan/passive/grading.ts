// CybrScan — deterministic A–F grading (CYB-43, §8 rubric + §7.2 roll-up).
//
// "A–F is deterministic, not vibes." Given the same findings, this module
// always returns the same grade. Conservative by design: we would rather
// under-claim than wrongly grade a site "A".
//
// Rules (§8):
//   - A category's letter is driven by its WORST unresolved finding, softened by
//     count: a single `critical` caps the category at F; `high` caps at D;
//     `medium` caps at C; only `low`/`info` can reach A/B.
//   - NO overall "A" if any critical or high finding exists ANYWHERE.
//   - Overall is the weighted roll-up of category scores (§7.2 weights),
//     re-normalized over the categories actually evaluated.

import type { CategoryKey, CategoryResult, Finding, Grade, Severity } from './types'
import { CATEGORY_WEIGHTS } from './types'

// Score → letter bands (shared with the rest of the engine).
const GRADE_BANDS: ReadonlyArray<{ min: number; grade: Grade }> = [
  { min: 90, grade: 'A' },
  { min: 75, grade: 'B' },
  { min: 60, grade: 'C' },
  { min: 40, grade: 'D' },
  { min: 0, grade: 'F' },
]

// Per-finding score penalty by severity. Count-softening falls out of summing
// penalties: more findings at a level push the category score down within its
// allowed band. Info never penalizes.
const SEVERITY_PENALTY: Readonly<Record<Severity, number>> = {
  critical: 100,
  high: 45,
  medium: 22,
  low: 8,
  info: 0,
}

// Hard letter cap implied by the single worst finding in a set (§8).
const SEVERITY_CAP: Readonly<Record<Severity, Grade>> = {
  critical: 'F',
  high: 'D',
  medium: 'C',
  low: 'B',
  info: 'A',
}

const GRADE_ORDER: ReadonlyArray<Grade> = ['A', 'B', 'C', 'D', 'F']

function gradeRank(g: Grade): number {
  return GRADE_ORDER.indexOf(g)
}
// Returns the worse (higher rank) of two grades.
function worseGrade(a: Grade, b: Grade): Grade {
  return gradeRank(a) >= gradeRank(b) ? a : b
}
function bandFromScore(score: number): Grade {
  const band = GRADE_BANDS.find((b) => score >= b.min)
  return band ? band.grade : 'F'
}
function worstSeverity(findings: ReadonlyArray<Finding>): Severity | null {
  const order: ReadonlyArray<Severity> = ['critical', 'high', 'medium', 'low', 'info']
  return order.find((s) => findings.some((f) => f.severity === s)) ?? null
}

// Category score: start at 100, subtract penalties, floor at 0. Deterministic.
export function categoryScore(findings: ReadonlyArray<Finding>): number {
  const penalty = findings.reduce((sum, f) => sum + SEVERITY_PENALTY[f.severity], 0)
  return Math.max(0, 100 - penalty)
}

// Category letter: band from score, but never better than the cap implied by
// the worst finding present.
export function categoryGrade(findings: ReadonlyArray<Finding>): Grade {
  const score = categoryScore(findings)
  const banded = bandFromScore(score)
  const worst = worstSeverity(findings)
  if (worst === null || worst === 'info') return banded
  return worseGrade(banded, SEVERITY_CAP[worst])
}

export interface Grading {
  grade: Grade
  score: number
  categories: CategoryResult[]
}

// Roll up findings across the evaluated categories into the §7.2 shape.
// `evaluated` lists the categories the scan actually ran (so weights normalize
// correctly when, e.g., OSINT exposure was not run on the free tier).
export function gradeScan(
  findings: ReadonlyArray<Finding>,
  evaluated: ReadonlyArray<CategoryKey>,
): Grading {
  const totalWeight = evaluated.reduce((s, k) => s + CATEGORY_WEIGHTS[k], 0)

  const categories: CategoryResult[] = evaluated.map((key) => {
    const inCat = findings.filter((f) => f.category === key)
    const normWeight = totalWeight > 0 ? CATEGORY_WEIGHTS[key] / totalWeight : 0
    return {
      key,
      grade: categoryGrade(inCat),
      weight: Math.round(normWeight * 100) / 100,
      score: categoryScore(inCat),
    }
  })

  // Weighted overall score (use exact normalized weights, not the rounded
  // display weights, so the math is precise and deterministic).
  const overallScore = Math.round(
    categories.reduce((sum, c) => {
      const exact = totalWeight > 0 ? CATEGORY_WEIGHTS[c.key] / totalWeight : 0
      return sum + c.score * exact
    }, 0),
  )

  let overallGrade = bandFromScore(overallScore)

  // §8 hard rule: no overall "A" while any critical/high finding exists anywhere.
  const hasCriticalOrHigh = findings.some((f) => f.severity === 'critical' || f.severity === 'high')
  if (hasCriticalOrHigh && overallGrade === 'A') {
    overallGrade = 'B'
  }

  return { grade: overallGrade, score: overallScore, categories }
}
