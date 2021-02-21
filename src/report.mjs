/**
 * Report envelope, rule severity table and deterministic ordering.
 *
 * Severity decides whether a run passes or fails, so it is defined exactly
 * once, here, and every finding takes its severity from this table. A literal
 * severity at each construction site is the shape that drifts silently: one
 * security-relevant rule flipped from `error` to `warning` turns a refusal into
 * a green build with every test still passing.
 */

export const TOOL_ID = 'robots-policy-auditor'
export const REPORT_SCHEMA_VERSION = '1'
export const CONFIG_SCHEMA_VERSION = '1'

export const SEVERITIES = Object.freeze(['error', 'warning', 'info'])

/**
 * The authoritative rule catalog.
 *
 * `docs/robots-rules.md` is asserted against this object in both directions, so
 * the shipped catalog and the documented one cannot drift apart. Rule ids are
 * stable: renaming one is a breaking change recorded in the changelog.
 */
export const RULE_SEVERITY = Object.freeze({
  'check-unevaluable': 'error',
  'crawl-decision': 'info',
  'crawl-expectation-mismatch': 'error',
  'directive-conflict': 'warning',
  'disallow-is-not-deindex': 'info',
  'duplicate-group': 'info',
  'empty-group': 'info',
  'index-expectation-mismatch': 'error',
  'indexing-unverified': 'warning',
  'input-not-utf8': 'error',
  'input-too-large': 'error',
  'input-unreadable': 'error',
  'invalid-rule-path': 'warning',
  'invalid-user-agent': 'warning',
  'limit-exceeded': 'error',
  'malformed-line': 'warning',
  'meta-outside-head': 'warning',
  'no-evidence': 'error',
  'noindex-behind-disallow': 'error',
  'nonstandard-directive': 'info',
  'robots-txt-noindex': 'warning',
  'rule-outside-group': 'warning',
  'unknown-directive': 'warning',
  'unknown-index-directive': 'warning',
})

export const EVIDENCE_LIMIT = 200

/**
 * Control characters that would let input content forge report structure.
 *
 * Written as code points rather than escapes in a regular expression: a
 * literal U+2028 inside a regex literal is a syntax error, and an invisible
 * one in source is a defect waiting to be pasted somewhere worse.
 */
function isUnprintable(code) {
  return code < 0x20 || code === 0x7f || code === 0x2028 || code === 0x2029
}

/**
 * Order by UTF-16 code unit.
 *
 * Never `localeCompare`: collation depends on ICU data that differs between
 * Node builds, which has already produced a real ordering bug in this catalog.
 */
export function byCodeUnit(left, right) {
  if (left === right) return 0
  return left < right ? -1 : 1
}

/** The severity the catalog assigns to a rule. An unknown rule is a bug, not a default. */
export function severityOf(ruleId) {
  if (!Object.hasOwn(RULE_SEVERITY, ruleId)) {
    throw new TypeError(
      `Unknown ruleId "${String(ruleId).slice(0, 60)}": every finding must come from RULE_SEVERITY`,
    )
  }
  return RULE_SEVERITY[ruleId]
}

/**
 * A bounded, single-line excerpt.
 *
 * robots.txt, captured headers and captured HTML are data. Nothing from them is
 * ever emitted at full length or with its control characters intact.
 */
export function excerpt(text) {
  let cleaned = ''
  for (const character of String(text)) {
    cleaned += isUnprintable(character.codePointAt(0)) ? ' ' : character
  }
  const flattened = cleaned.replace(/\s+/g, ' ').trim()
  if (flattened.length <= EVIDENCE_LIMIT) return flattened
  return `${flattened.slice(0, EVIDENCE_LIMIT)}...`
}

/**
 * Build one finding.
 *
 * `severity` is not a parameter. It cannot be passed, overridden or defaulted
 * at a call site; it is looked up from the single table above.
 */
export function makeFinding(ruleId, message, location = {}, extra = {}) {
  const finding = { ruleId, severity: severityOf(ruleId), message, location: {} }
  if (location.file !== undefined && location.file !== null) finding.location.file = location.file
  if (location.pointer !== undefined && location.pointer !== null) finding.location.pointer = location.pointer
  if (extra.evidence !== undefined && extra.evidence !== null) finding.evidence = excerpt(extra.evidence)
  if (extra.suggestion !== undefined && extra.suggestion !== null) finding.suggestion = extra.suggestion
  return finding
}

/**
 * Compare two location pointers segment by segment, comparing all-digit
 * segments numerically.
 *
 * Plain code-unit order would place `/checks/10` before `/checks/2`, which is
 * deterministic but reads as a shuffle. Numeric-aware segment comparison is
 * equally deterministic — no locale is consulted — and keeps a report in the
 * order the operator wrote the input.
 */
export function comparePointers(left, right) {
  if (left === right) return 0
  const leftParts = left.split('/')
  const rightParts = right.split('/')
  const shared = Math.min(leftParts.length, rightParts.length)
  for (let index = 0; index < shared; index += 1) {
    const a = leftParts[index]
    const b = rightParts[index]
    if (a === b) continue
    if (/^[0-9]+$/.test(a) && /^[0-9]+$/.test(b)) return Number(a) < Number(b) ? -1 : 1
    return byCodeUnit(a, b)
  }
  if (leftParts.length === rightParts.length) return 0
  return leftParts.length < rightParts.length ? -1 : 1
}

/**
 * Sort findings by the documented key: location.file, then location.pointer,
 * then ruleId, then message. The last two make the order total, so two findings
 * sharing a location never depend on the order they were produced in.
 */
export function sortFindings(findings) {
  return [...findings].sort((left, right) => {
    const fileOrder = byCodeUnit(left.location.file ?? '', right.location.file ?? '')
    if (fileOrder !== 0) return fileOrder
    const pointerOrder = comparePointers(left.location.pointer ?? '', right.location.pointer ?? '')
    if (pointerOrder !== 0) return pointerOrder
    const ruleOrder = byCodeUnit(left.ruleId, right.ruleId)
    if (ruleOrder !== 0) return ruleOrder
    return byCodeUnit(left.message, right.message)
  })
}

/**
 * Assemble the report envelope and decide the status.
 *
 * This is the only place in the tool where `status` is set, so every path that
 * could reach a pass goes through the two guards below:
 *
 *  - `incomplete` wins over everything. Evidence that was missing, undecodable
 *    or bounded out is never reported as a pass, whatever the severities were.
 *  - `checked === 0` is never a pass either. A run that decided nothing has
 *    proved nothing, and green on no evidence is a defect, not a clean bill.
 */
export function buildReport({ findings = [], checked = 0, incomplete = false, summary = {} } = {}) {
  const collected = [...findings]
  let blocked = Boolean(incomplete)

  if (checked === 0) {
    blocked = true
    if (!collected.some((finding) => finding.ruleId === 'no-evidence')) {
      collected.push(
        makeFinding('no-evidence', 'No check produced a decision, so this run verified nothing.', {}, {
          suggestion: 'supply at least one evaluable check in the checks document',
        }),
      )
    }
  }

  const errors = collected.filter((finding) => finding.severity === 'error').length
  const warnings = collected.filter((finding) => finding.severity === 'warning').length
  let status = 'pass'
  if (blocked) status = 'incomplete'
  else if (errors > 0) status = 'fail'

  return {
    schemaVersion: REPORT_SCHEMA_VERSION,
    tool: TOOL_ID,
    status,
    summary: { checked, errors, warnings, ...summary },
    findings: sortFindings(collected),
  }
}

/** Map a status onto the documented process exit code. */
export function exitCodeFor(report) {
  if (report.status === 'pass') return 0
  if (report.status === 'fail') return 1
  return 2
}

const SEVERITY_WIDTH = 7

/** The human summary. The CLI writes this to stderr, never to stdout. */
export function formatReport(report) {
  const summary = report.summary
  const lines = [`${report.tool}: ${report.status}`]
  lines.push(
    `  checked ${summary.checked} url/agent pair(s): ` +
      `${summary.allowed ?? 0} crawlable, ${summary.disallowed ?? 0} disallowed, ` +
      `${summary.indexBlocked ?? 0} index-blocked, ${summary.indexUnverified ?? 0} indexing unverified`,
  )
  lines.push(`  ${summary.errors} error(s), ${summary.warnings} warning(s)`)
  for (const finding of report.findings) {
    const where = finding.location.file ?? '-'
    const pointer = finding.location.pointer === undefined ? '' : ` ${finding.location.pointer}`
    lines.push(`  ${finding.severity.padEnd(SEVERITY_WIDTH)} ${finding.ruleId}  ${where}${pointer}`)
    lines.push(`          ${finding.message}`)
    if (finding.evidence !== undefined) lines.push(`          evidence: ${finding.evidence}`)
  }
  lines.push('  crawl permission and indexing are separate axes: a disallowed URL can still be indexed.')
  return `${lines.join('\n')}\n`
}
