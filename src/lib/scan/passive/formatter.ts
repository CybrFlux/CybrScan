// CybrScan — safe report formatter (CYB-43, §7.2 output + §8 safe-output rule).
//
// Turns a graded ScanResult into the customer-facing report. Two guarantees:
//   1. Deterministic ordering (severity, then stable finding id).
//   2. SAFE OUTPUT: every emitted string passes the payload guard. If a finding
//      ever carried a PoC/payload, formatting FAILS CLOSED (throws) rather than
//      shipping it. This is the §8 hard rule enforced in code.

import type { Finding, ScanResult, Severity } from './types'
import { assertSafeOutput } from './safe-output'

const SEVERITY_RANK: Readonly<Record<Severity, number>> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
}

// Deterministic sort: most severe first, then by id (stable, locale-independent).
export function sortFindings(findings: ReadonlyArray<Finding>): Finding[] {
  return [...findings].sort((a, b) => {
    const bySeverity = SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity]
    return bySeverity !== 0 ? bySeverity : (a.id < b.id ? -1 : a.id > b.id ? 1 : 0)
  })
}

// Runs the §8 safe-output gate over every customer-visible string in the report.
// Throws UnsafeReportError on any payload-like content.
export function assertReportSafe(result: ScanResult): void {
  const fields = result.findings.flatMap((f) => [f.title, f.explanation, f.remediation, f.evidence])
  assertSafeOutput(fields)
}

export interface ReportLine {
  severity: Severity
  title: string
  explanation: string
  remediation: string
  evidence: string
  category: string
}

export interface SafeReport {
  target: string
  grade: ScanResult['grade']
  score: number
  generatedAt: string
  categories: ScanResult['categories']
  findings: ReportLine[]
  summary: string
}

function summarize(result: ScanResult): string {
  const counts = result.findings.reduce<Record<string, number>>((acc, f) => {
    acc[f.severity] = (acc[f.severity] ?? 0) + 1
    return acc
  }, {})
  const parts = (['critical', 'high', 'medium', 'low'] as const)
    .filter((s) => counts[s])
    .map((s) => `${counts[s]} ${s}`)
  const body = parts.length > 0 ? parts.join(', ') : 'no notable issues'
  return `Security grade ${result.grade} (${result.score}/100) for ${result.target}: ${body}.`
}

// Build the structured safe report. Enforces the safe-output rule first.
export function formatReport(result: ScanResult): SafeReport {
  assertReportSafe(result)
  const ordered = sortFindings(result.findings)
  return {
    target: result.target,
    grade: result.grade,
    score: result.score,
    generatedAt: result.completedAt,
    categories: result.categories,
    findings: ordered.map((f) => ({
      severity: f.severity,
      title: f.title,
      explanation: f.explanation,
      remediation: f.remediation,
      evidence: f.evidence,
      category: f.category,
    })),
    summary: summarize(result),
  }
}

// Plain-English markdown rendering for email/dashboard. Also safe-gated.
export function formatReportMarkdown(result: ScanResult): string {
  const report = formatReport(result)
  const lines: string[] = [
    `# CybrScan report — ${report.target}`,
    '',
    `**Grade: ${report.grade}** · Score ${report.score}/100 · ${report.generatedAt}`,
    '',
    report.summary,
    '',
    '## Findings',
  ]
  if (report.findings.length === 0) {
    lines.push('', 'No passive findings. Keep monitoring on a paid plan to catch regressions.')
  }
  for (const f of report.findings) {
    lines.push(
      '',
      `### [${f.severity.toUpperCase()}] ${f.title}`,
      '',
      f.explanation,
      '',
      `**How to fix:** ${f.remediation}`,
      '',
      `_Evidence: ${f.evidence}_`,
    )
  }
  return lines.join('\n')
}
