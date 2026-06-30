// CybrScan — safe-output guard (CYB-43, §8 hard rule).
//
// "Reports contain severity + remediation, NEVER a working exploit, payload, or
// step-by-step attack." This module is the enforcement point for that rule. The
// formatter runs every customer-facing string through `assertSafeOutput`, so a
// check (or a future contributor) that tries to embed a PoC fails CLOSED — the
// scan errors rather than shipping an attacker's checklist.
//
// Lenses: Fail Securely, Secure Defaults, Open Design (rules are explicit and
// reviewable, not obscure).

export class UnsafeReportError extends Error {
  readonly violations: ReadonlyArray<string>
  constructor(violations: ReadonlyArray<string>) {
    super(`Refusing to emit report: output contains payload-like content (${violations.join(', ')})`)
    this.name = 'UnsafeReportError'
    this.violations = violations
  }
}

// Denylist of payload/exploit signatures. We match on attack SYNTAX, not on
// security vocabulary — words like "exploit" or "injection" appear legitimately
// in explanations, so we never flag those. We flag things that look like an
// actual payload a reader could copy and fire.
const PAYLOAD_PATTERNS: ReadonlyArray<{ name: string; re: RegExp }> = [
  { name: 'script-tag', re: /<\s*script[\s>]/i },
  { name: 'js-event-handler', re: /\son(?:error|load|click|mouseover)\s*=/i },
  { name: 'js-uri', re: /javascript:\s*[a-z(]/i },
  { name: 'sql-tautology', re: /['"]\s*or\s+['"]?\d+['"]?\s*=\s*['"]?\d+/i },
  { name: 'sql-union-select', re: /\bunion\b[\s\S]{0,40}\bselect\b/i },
  { name: 'sql-drop', re: /;\s*drop\s+table\b/i },
  { name: 'path-traversal', re: /(?:\.\.\/){2,}|(?:\.\.\\){2,}/ },
  { name: 'shell-chain', re: /[;|&]\s*(?:rm|cat|curl|wget|bash|sh|nc|ncat|powershell)\b/i },
  { name: 'command-substitution', re: /\$\([^)]+\)|`[^`]+`/ },
  { name: 'template-injection', re: /\{\{[\s\S]{0,40}[*+/].*\}\}|\$\{[\s\S]{0,40}\}/ },
  { name: 'hex-shellcode', re: /(?:\\x[0-9a-f]{2}){4,}/i },
  { name: 'ssrf-metadata-endpoint', re: /169\.254\.169\.254|metadata\.google\.internal/i },
]

export interface SafetyViolation {
  pattern: string
  match: string
}

// Returns every payload signature found in `text` (empty => safe).
export function scanForPayloads(text: string): ReadonlyArray<SafetyViolation> {
  return PAYLOAD_PATTERNS.flatMap(({ name, re }) => {
    const m = re.exec(text)
    return m ? [{ pattern: name, match: m[0].slice(0, 40) }] : []
  })
}

export function isSafeOutput(text: string): boolean {
  return scanForPayloads(text).length === 0
}

// Throws UnsafeReportError if any field carries payload-like content. Used as a
// final gate before a report leaves the engine.
export function assertSafeOutput(fields: ReadonlyArray<string>): void {
  const violations = fields.flatMap((f) =>
    scanForPayloads(f).map((v) => `${v.pattern}:"${v.match}"`),
  )
  if (violations.length > 0) {
    throw new UnsafeReportError(violations)
  }
}
