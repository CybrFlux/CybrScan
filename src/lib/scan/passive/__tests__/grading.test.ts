// Deterministic A–F grading tests (CYB-43, §8 rubric).

import { describe, it, expect } from 'vitest'
import { categoryGrade, categoryScore, gradeScan } from '../grading'
import { PASSIVE_CATEGORIES, type Finding } from '../types'

function mk(severity: Finding['severity'], category: Finding['category'], id = `${category}.x`): Finding {
  return {
    id,
    severity,
    category,
    title: 't',
    explanation: 'e',
    remediation: 'r',
    evidence: 'v',
  }
}

describe('categoryGrade caps from worst finding (§8)', () => {
  it('a single critical caps the category at F', () => {
    expect(categoryGrade([mk('critical', 'tls')])).toBe('F')
  })
  it('a single high caps the category at D or worse', () => {
    expect(categoryGrade([mk('high', 'headers')])).toBe('D')
  })
  it('a single medium caps the category at C or worse', () => {
    expect(categoryGrade([mk('medium', 'cookies')])).toBe('C')
  })
  it('only low/info can reach A/B', () => {
    expect(['A', 'B']).toContain(categoryGrade([mk('low', 'dns_email')]))
    expect(categoryGrade([])).toBe('A')
  })
  it('count softening: more findings score no higher than fewer', () => {
    const one = categoryScore([mk('low', 'headers', 'a')])
    const three = categoryScore([mk('low', 'headers', 'a'), mk('low', 'headers', 'b'), mk('low', 'headers', 'c')])
    expect(three).toBeLessThanOrEqual(one)
  })
})

describe('gradeScan overall roll-up (§7.2/§8)', () => {
  it('clean scan (no findings) grades A with score 100', () => {
    const g = gradeScan([], PASSIVE_CATEGORIES)
    expect(g.grade).toBe('A')
    expect(g.score).toBe(100)
  })

  it('never returns overall A when any high finding exists anywhere', () => {
    const g = gradeScan([mk('high', 'headers')], PASSIVE_CATEGORIES)
    expect(g.grade).not.toBe('A')
  })

  it('never returns overall A when any critical finding exists anywhere', () => {
    const g = gradeScan([mk('critical', 'tls')], PASSIVE_CATEGORIES)
    expect(g.grade).not.toBe('A')
  })

  it('weights re-normalize to sum ~1 over evaluated categories', () => {
    const g = gradeScan([], PASSIVE_CATEGORIES)
    const sum = g.categories.reduce((s, c) => s + c.weight, 0)
    expect(sum).toBeGreaterThan(0.98)
    expect(sum).toBeLessThan(1.02)
    expect(g.categories.map((c) => c.key)).toEqual([...PASSIVE_CATEGORIES])
  })

  it('is deterministic: identical input yields identical output', () => {
    const findings = [mk('high', 'headers', 'h'), mk('low', 'dns_email', 'd')]
    expect(gradeScan(findings, PASSIVE_CATEGORIES)).toEqual(gradeScan(findings, PASSIVE_CATEGORIES))
  })

  it('finding order does not change the grade (order-independent)', () => {
    const a = [mk('high', 'headers', 'h'), mk('medium', 'cookies', 'c')]
    const b = [mk('medium', 'cookies', 'c'), mk('high', 'headers', 'h')]
    expect(gradeScan(a, PASSIVE_CATEGORIES).grade).toBe(gradeScan(b, PASSIVE_CATEGORIES).grade)
    expect(gradeScan(a, PASSIVE_CATEGORIES).score).toBe(gradeScan(b, PASSIVE_CATEGORIES).score)
  })
})
