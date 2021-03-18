import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { dirname, resolve } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

import { RULE_SEVERITY, SEVERITIES, makeFinding, severityOf } from '../src/index.mjs'

const projectDirectory = resolve(dirname(fileURLToPath(import.meta.url)), '..')

/**
 * Severity decides whether a run fails or passes, so it is the one thing in
 * this tool most worth pinning down.
 *
 * Two dozen construction sites each carrying their own literal is exactly the
 * shape that drifts silently: flipping one security-relevant rule from `error`
 * to `warning` turns a refusal into a green build with every test still
 * passing. These tests assert that the single table, the documented catalog and
 * the shipped source all agree.
 */

async function documentedSeverities() {
  const text = await readFile(resolve(projectDirectory, 'docs/robots-rules.md'), 'utf8')
  const rows = [...text.matchAll(/\|\s*`([a-z0-9-]+)`\s*\|\s*(error|warning|info)\s*\|/g)]
  return Object.fromEntries(rows.map((row) => [row[1], row[2]]))
}

async function emittedRuleIds() {
  const sources = ['src/index.mjs', 'src/report.mjs', 'src/robots-txt.mjs', 'src/directives.mjs']
  const found = new Set()
  for (const file of sources) {
    const text = await readFile(resolve(projectDirectory, file), 'utf8')
    for (const match of text.matchAll(/makeFinding\(\s*'([a-z0-9-]+)'/g)) found.add(match[1])
    for (const match of text.matchAll(/ruleId:\s*'([a-z0-9-]+)'/g)) found.add(match[1])
  }
  return found
}

test('the documented rule catalog matches the severity table exactly', async () => {
  const documented = await documentedSeverities()
  assert.deepEqual(
    Object.keys(documented).sort(),
    Object.keys(RULE_SEVERITY).sort(),
    'docs/robots-rules.md and RULE_SEVERITY list different rules',
  )
  assert.deepEqual(documented, { ...RULE_SEVERITY })
})

test('every rule id the source emits is defined in the table', async () => {
  for (const ruleId of await emittedRuleIds()) {
    assert.ok(Object.hasOwn(RULE_SEVERITY, ruleId), `${ruleId} is emitted but missing from RULE_SEVERITY`)
  }
})

test('every rule in the table is emitted somewhere in the source', async () => {
  const emitted = await emittedRuleIds()
  for (const ruleId of Object.keys(RULE_SEVERITY)) {
    assert.ok(emitted.has(ruleId), `${ruleId} is in RULE_SEVERITY but nothing emits it`)
  }
})

test('an unknown rule id throws rather than defaulting to a severity', () => {
  assert.throws(() => severityOf('made-up-rule'), /Unknown ruleId "made-up-rule"/)
  assert.throws(() => makeFinding('made-up-rule', 'message', {}), /every finding must come from RULE_SEVERITY/)
})

test('severity cannot be passed in at a construction site', () => {
  const finding = makeFinding('indexing-unverified', 'message', { file: 'checks.json' }, { severity: 'info' })
  assert.equal(finding.severity, 'warning')
})

test('the rules that decide a refusal or a real defect are errors, not warnings', () => {
  // Downgrading any of these turns a run that must fail into a green build.
  assert.equal(RULE_SEVERITY['noindex-behind-disallow'], 'error')
  assert.equal(RULE_SEVERITY['crawl-expectation-mismatch'], 'error')
  assert.equal(RULE_SEVERITY['index-expectation-mismatch'], 'error')
  assert.equal(RULE_SEVERITY['check-unevaluable'], 'error')
  assert.equal(RULE_SEVERITY['input-unreadable'], 'error')
  assert.equal(RULE_SEVERITY['input-not-utf8'], 'error')
  assert.equal(RULE_SEVERITY['input-too-large'], 'error')
  assert.equal(RULE_SEVERITY['limit-exceeded'], 'error')
  assert.equal(RULE_SEVERITY['no-evidence'], 'error')
})

/**
 * `disallow-is-not-deindex` is the honest observation this tool exists to make.
 * It is deliberately `info`: a disallowed URL with no noindex is a normal,
 * correct configuration, and failing a build over it would teach operators to
 * add the noindex that `noindex-behind-disallow` then has to refuse.
 */
test('the honest observation about disallow is informational, and the unreachable noindex is not', () => {
  assert.equal(RULE_SEVERITY['disallow-is-not-deindex'], 'info')
  assert.equal(RULE_SEVERITY['noindex-behind-disallow'], 'error')
})

test('the table is frozen and every severity it uses is one the contract defines', () => {
  assert.equal(Object.isFrozen(RULE_SEVERITY), true)
  for (const [ruleId, severity] of Object.entries(RULE_SEVERITY)) {
    assert.ok(SEVERITIES.includes(severity), `${ruleId} has the severity ${severity}`)
  }
})

test('the catalog is listed in sorted order, so a new rule lands where it is looked for', () => {
  const listed = Object.keys(RULE_SEVERITY)
  const sorted = [...listed].sort((left, right) => (left === right ? 0 : left < right ? -1 : 1))
  assert.deepEqual(listed, sorted)
})
