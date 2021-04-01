import assert from 'node:assert/strict'
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

import {
  ConfigError,
  auditRobotsPolicy,
  buildReport,
  byCodeUnit,
  comparePointers,
  excerpt,
  exitCodeFor,
  makeFinding,
  sortFindings,
} from '../src/index.mjs'

const projectDirectory = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const CLEAN = join(projectDirectory, 'examples/clean/robots-audit.config.json')
const BROKEN = join(projectDirectory, 'examples/broken/robots-audit.config.json')

/** Write a throwaway input tree. Returns its root and a disposer. */
async function makeTree(files) {
  const root = await mkdtemp(join(tmpdir(), 'robots-policy-auditor-'))
  for (const [name, content] of Object.entries(files)) {
    const target = join(root, name)
    await mkdir(dirname(target), { recursive: true })
    await writeFile(target, content)
  }
  return { root, dispose: () => rm(root, { recursive: true, force: true }) }
}

function config(extra = {}) {
  return JSON.stringify({
    schemaVersion: '1',
    site: { origin: 'https://example.com' },
    robotsTxt: 'robots.txt',
    checks: 'checks.json',
    ...extra,
  })
}

function checks(entries) {
  return JSON.stringify({ schemaVersion: '1', checks: entries })
}

function findingsOf(report, ruleId) {
  return report.findings.filter((finding) => finding.ruleId === ruleId)
}

test('the clean example passes and exits 0', async () => {
  const report = await auditRobotsPolicy({ configFile: CLEAN })
  assert.equal(report.status, 'pass')
  assert.equal(exitCodeFor(report), 0)
  assert.deepEqual(report.summary, {
    checked: 7,
    errors: 0,
    warnings: 0,
    allowed: 4,
    disallowed: 3,
    indexBlocked: 1,
    indexUnverified: 0,
  })
})

test('every expectation in the clean example is met by the decision it names', async () => {
  const report = await auditRobotsPolicy({ configFile: CLEAN })
  assert.deepEqual(
    findingsOf(report, 'crawl-decision').map((finding) => finding.message),
    [
      'crawl=allow index=indexable for "ExampleBot" at /.',
      'crawl=disallow index=indexable for "ExampleBot" at /internal/notes.',
      'crawl=disallow index=indexable for "GPTBot" at /search?q=shoes.',
      'crawl=allow index=indexable for "GPTBot" at /search/help.',
      'crawl=allow index=blocked for "ExampleBot" at /drafts/2026-plan.',
      'crawl=allow index=indexable for "ExampleBot" at /data/export.json.',
      'crawl=disallow index=indexable for "OtherBot" at /data/export.json.',
    ],
  )
  assert.equal(findingsOf(report, 'crawl-expectation-mismatch').length, 0)
  assert.equal(findingsOf(report, 'index-expectation-mismatch').length, 0)
})

test('each decision names the rule that won and the line it came from', async () => {
  const report = await auditRobotsPolicy({ configFile: CLEAN })
  assert.deepEqual(
    findingsOf(report, 'crawl-decision').map((finding) => finding.evidence),
    [
      'crawl: Allow: / (line 10, 1 octet) in the agent group [ExampleBot]; index: none',
      'crawl: Disallow: /internal/ (line 11, 10 octets) in the agent group [ExampleBot]; index: none',
      'crawl: Disallow: /search (line 5, 7 octets) in the global "*" group [*]; index: none',
      'crawl: Allow: /search/help (line 6, 12 octets) in the global "*" group [*]; index: none',
      'crawl: Allow: / (line 10, 1 octet) in the agent group [ExampleBot]; index: meta robots "noindex, nofollow" (capture/drafts-2026-plan.html line 5)',
      'crawl: Allow: / (line 10, 1 octet) in the agent group [ExampleBot]; index: none',
      'crawl: Disallow: /*.json$ (line 7, 8 octets) in the global "*" group [*]; index: none',
    ],
  )
})

test('the broken example fails and exits 1', async () => {
  const report = await auditRobotsPolicy({ configFile: BROKEN })
  assert.equal(report.status, 'fail')
  assert.equal(exitCodeFor(report), 1)
  assert.deepEqual(report.summary, {
    checked: 5,
    errors: 4,
    warnings: 8,
    allowed: 2,
    disallowed: 3,
    indexBlocked: 3,
    indexUnverified: 0,
  })
})

/**
 * The documented order, asserted as an exact structure over three files, seven
 * pointers and several rules sharing a pointer. Reversing any one of the sort
 * keys — file, pointer, ruleId — changes this list, which a pairwise
 * "is sorted" check over findings from a single file could never detect.
 */
test('findings are ordered by file, then pointer, then rule id', async () => {
  const report = await auditRobotsPolicy({ configFile: BROKEN })
  assert.deepEqual(
    report.findings.map((finding) => [finding.location.file, finding.location.pointer, finding.ruleId]),
    [
      ['capture/legacy-page.html', '/line/0005', 'unknown-index-directive'],
      ['capture/notes.html', '/line/0008', 'meta-outside-head'],
      ['checks.json', '/checks/0', 'crawl-decision'],
      ['checks.json', '/checks/0', 'crawl-expectation-mismatch'],
      ['checks.json', '/checks/0', 'noindex-behind-disallow'],
      ['checks.json', '/checks/1', 'crawl-decision'],
      ['checks.json', '/checks/1', 'noindex-behind-disallow'],
      ['checks.json', '/checks/2', 'crawl-decision'],
      ['checks.json', '/checks/2', 'index-expectation-mismatch'],
      ['checks.json', '/checks/3', 'crawl-decision'],
      ['checks.json', '/checks/3', 'directive-conflict'],
      ['checks.json', '/checks/4', 'crawl-decision'],
      ['checks.json', '/checks/4', 'disallow-is-not-deindex'],
      ['robots.txt', '/line/0002', 'rule-outside-group'],
      ['robots.txt', '/line/0006', 'nonstandard-directive'],
      ['robots.txt', '/line/0007', 'robots-txt-noindex'],
      ['robots.txt', '/line/0008', 'invalid-rule-path'],
      ['robots.txt', '/line/0009', 'duplicate-group'],
      ['robots.txt', '/line/0011', 'malformed-line'],
      ['robots.txt', '/line/0012', 'unknown-directive'],
    ],
  )
})

test('an array pointer is ordered by its index, not by its spelling', () => {
  const pointers = ['/checks/10', '/checks/2', '/checks/1', '/checks/20', '/checks/3']
  const sorted = sortFindings(
    pointers.map((pointer) => makeFinding('crawl-decision', 'x', { file: 'checks.json', pointer })),
  )
  assert.deepEqual(
    sorted.map((finding) => finding.location.pointer),
    ['/checks/1', '/checks/2', '/checks/3', '/checks/10', '/checks/20'],
  )
  assert.equal(comparePointers('/checks/2', '/checks/10'), -1)
  assert.equal(comparePointers('/line/0002', '/line/0010'), -1)
})

/**
 * Ordering is by UTF-16 code unit, and the point of saying so is that it is
 * *not* `localeCompare`. Collation consults ICU data that differs between Node
 * builds, so a report ordered by it is reproducible on one machine and not on
 * the next — and the same two runs this suite compares byte for byte would
 * still agree, because they run in the same process.
 *
 * Every pair below is one the two orderings disagree about, so the assertions
 * fail the moment `byCodeUnit` starts consulting a locale.
 */
test('ordering is by UTF-16 code unit, never by locale collation', () => {
  // Uppercase precedes lowercase by code unit; collation folds case and puts
  // these the other way round.
  assert.equal(byCodeUnit('Z', 'a'), -1)
  // "-" (U+002D) precedes "_" (U+005F); collation weighs punctuation
  // separately and puts these the other way round too.
  assert.equal(byCodeUnit('a-b', 'a_b'), -1)
  assert.equal(byCodeUnit('a', 'a'), 0)
  assert.equal(byCodeUnit('b', 'a'), 1)

  // The same disagreement through the exported sort, on each key it uses.
  const byFile = sortFindings(
    ['capture/a_b.html', 'capture/a-b.html', 'capture/A-c.html'].map((file) =>
      makeFinding('crawl-decision', 'x', { file }),
    ),
  )
  assert.deepEqual(
    byFile.map((finding) => finding.location.file),
    ['capture/A-c.html', 'capture/a-b.html', 'capture/a_b.html'],
  )
  const byMessage = sortFindings(
    ['apple', 'Zebra'].map((message) => makeFinding('crawl-decision', message, { file: 'checks.json' })),
  )
  assert.deepEqual(
    byMessage.map((finding) => finding.message),
    ['Zebra', 'apple'],
  )
  // comparePointers falls back on the same comparator for a non-numeric
  // segment, so it inherits the guarantee rather than restating it.
  assert.equal(comparePointers('/Z/1', '/a/1'), -1)
})

test('running twice over identical inputs produces byte-identical output', async () => {
  const first = await auditRobotsPolicy({ configFile: BROKEN })
  const second = await auditRobotsPolicy({ configFile: BROKEN })
  assert.equal(JSON.stringify(first), JSON.stringify(second))
})

/**
 * The acceptance requirement this tool exists for: a disallow is never reported
 * as removal from an index.
 */
test('a disallowed URL with no directive is reported as still indexable, not as deindexed', async () => {
  const tree = await makeTree({
    'robots.txt': 'User-agent: *\nDisallow: /private\n',
    'checks.json': checks([{ userAgent: 'GPTBot', url: 'https://example.com/private/report' }]),
    'capture.json': JSON.stringify({
      schemaVersion: '1',
      responses: [{ url: 'https://example.com/private/report', headers: {} }],
    }),
    'audit.config.json': config({ capture: 'capture.json' }),
  })
  try {
    const report = await auditRobotsPolicy({ configFile: join(tree.root, 'audit.config.json') })
    const decision = findingsOf(report, 'crawl-decision')[0]
    assert.equal(decision.message, 'crawl=disallow index=indexable for "GPTBot" at /private/report.')

    const honest = findingsOf(report, 'disallow-is-not-deindex')
    assert.equal(honest.length, 1)
    assert.match(honest[0].message, /can still be indexed from external links/)
    assert.equal(report.summary.indexBlocked, 0)

    const serialized = JSON.stringify(report)
    assert.ok(!/deindex(ed|es)\b/i.test(serialized), 'no finding may claim the URL was deindexed')
  } finally {
    await tree.dispose()
  }
})

test('a noindex served behind a disallow is reported as unreachable', async () => {
  const tree = await makeTree({
    'robots.txt': 'User-agent: *\nDisallow: /private\n',
    'checks.json': checks([{ userAgent: 'GPTBot', url: 'https://example.com/private/report' }]),
    'capture.json': JSON.stringify({
      schemaVersion: '1',
      responses: [{ url: 'https://example.com/private/report', headers: { 'X-Robots-Tag': 'noindex' } }],
    }),
    'audit.config.json': config({ capture: 'capture.json' }),
  })
  try {
    const report = await auditRobotsPolicy({ configFile: join(tree.root, 'audit.config.json') })
    const blocked = findingsOf(report, 'noindex-behind-disallow')
    assert.equal(blocked.length, 1)
    assert.equal(blocked[0].severity, 'error')
    assert.match(blocked[0].message, /never fetches the response, so it never sees the directive/)
    assert.equal(report.status, 'fail')
  } finally {
    await tree.dispose()
  }
})

test('an indexing directive scoped to another agent does not decide this agent', async () => {
  const tree = await makeTree({
    'robots.txt': 'User-agent: *\nAllow: /\n',
    'checks.json': checks([
      { userAgent: 'GoogleBot', url: 'https://example.com/page' },
      { userAgent: 'GPTBot', url: 'https://example.com/page' },
    ]),
    'capture.json': JSON.stringify({
      schemaVersion: '1',
      responses: [{ url: 'https://example.com/page', headers: { 'x-robots-tag': 'googlebot: noindex' } }],
    }),
    'audit.config.json': config({ capture: 'capture.json' }),
  })
  try {
    const report = await auditRobotsPolicy({ configFile: join(tree.root, 'audit.config.json') })
    assert.deepEqual(
      findingsOf(report, 'crawl-decision').map((finding) => finding.message),
      [
        'crawl=allow index=blocked for "GoogleBot" at /page.',
        'crawl=allow index=indexable for "GPTBot" at /page.',
      ],
    )
  } finally {
    await tree.dispose()
  }
})

test('a header carrying anything but X-Robots-Tag never reaches the report', async () => {
  const secret = 'Bearer wholly-invented-token-value'
  const tree = await makeTree({
    'robots.txt': 'User-agent: *\nAllow: /\n',
    'checks.json': checks([{ userAgent: 'GPTBot', url: 'https://example.com/page' }]),
    'capture.json': JSON.stringify({
      schemaVersion: '1',
      responses: [
        {
          url: 'https://example.com/page',
          headers: { authorization: secret, 'set-cookie': 'session=abc123', 'x-robots-tag': 'noindex' },
        },
      ],
    }),
    'audit.config.json': config({ capture: 'capture.json' }),
  })
  try {
    const report = await auditRobotsPolicy({ configFile: join(tree.root, 'audit.config.json') })
    const serialized = JSON.stringify(report)
    assert.ok(!serialized.includes(secret), 'an authorization value must never be echoed')
    assert.ok(!serialized.includes('session=abc123'), 'a cookie must never be echoed')
    assert.ok(!serialized.toLowerCase().includes('authorization'), 'an unread header name must not be echoed')
    assert.equal(report.summary.indexBlocked, 1)
  } finally {
    await tree.dispose()
  }
})

/**
 * Control characters written as escapes, never as literals: a raw U+2028 in a
 * source file is invisible, and one pasted somewhere worse is a defect waiting
 * to happen. ESC opens a terminal escape sequence, NUL truncates a C string,
 * and U+2028 / U+2029 end a line for some parsers — all of them let input
 * content forge structure in whatever reads the report.
 */
const CONTROL_CHARACTERS = '\u001b[31m\u0000\u007f\u2028\u2029'

/** Every string anywhere in a report, so nothing hides in a field this test forgot. */
function allStrings(value) {
  if (typeof value === 'string') return [value]
  if (Array.isArray(value)) return value.flatMap(allStrings)
  if (value !== null && typeof value === 'object') return Object.values(value).flatMap(allStrings)
  return []
}

test('evidence from an input is bounded and stripped of control characters', async () => {
  const longPath = 'a'.repeat(400)
  const tree = await makeTree({
    'robots.txt': `User-agent: *\nDisallow: /${longPath}\n`,
    'checks.json': checks([{ userAgent: 'GPTBot', url: `https://example.com/${longPath}` }]),
    'capture.json': JSON.stringify({
      schemaVersion: '1',
      responses: [
        {
          url: `https://example.com/${longPath}`,
          headers: { 'x-robots-tag': `noindex${CONTROL_CHARACTERS}` },
        },
      ],
    }),
    'audit.config.json': config({ capture: 'capture.json' }),
  })
  try {
    const report = await auditRobotsPolicy({ configFile: join(tree.root, 'audit.config.json') })

    for (const finding of report.findings) {
      if (finding.evidence === undefined) continue
      assert.ok(finding.evidence.length <= 203, `evidence was ${finding.evidence.length} characters`)
    }

    // The header value reached the report — so the rest of this test is about
    // what was removed from it, not about a fixture that never arrived.
    const directive = report.findings.find((finding) => finding.ruleId === 'unknown-index-directive')
    assert.ok(directive, 'the mangled directive must be reported')
    assert.ok(directive.evidence.includes('[31m'), 'the directive text itself must survive')

    for (const text of allStrings(report)) {
      const offending = [...text].findIndex((character) => {
        const code = character.codePointAt(0)
        return code < 0x20 || code === 0x7f || code === 0x2028 || code === 0x2029
      })
      assert.equal(offending, -1, `a control character reached the report in ${JSON.stringify(text)}`)
    }
  } finally {
    await tree.dispose()
  }
})

test('excerpt replaces every control character it is given', () => {
  assert.equal(excerpt(`no index${CONTROL_CHARACTERS}`), 'no index [31m')
  assert.equal(excerpt('one\ttwo\nthree'), 'one two three')
  // A bare replacement character is printable text and is kept as it is.
  assert.equal(excerpt('caf\uFFFD'), 'caf\uFFFD')
  assert.equal(excerpt('a'.repeat(400)).length, 203)
})

test('an unknown configuration key is refused rather than ignored', async () => {
  const tree = await makeTree({
    'robots.txt': 'User-agent: *\nAllow: /\n',
    'checks.json': checks([{ userAgent: 'GPTBot', url: 'https://example.com/page' }]),
    'audit.config.json': JSON.stringify({
      schemaVersion: '1',
      site: { origin: 'https://example.com' },
      robotsTxt: 'robots.txt',
      checks: 'checks.json',
      captures: 'capture.json',
    }),
  })
  try {
    await assert.rejects(
      auditRobotsPolicy({ configFile: join(tree.root, 'audit.config.json') }),
      (error) => error instanceof ConfigError && error.rule === 'unknown-key' && /captures/.test(error.message),
    )
  } finally {
    await tree.dispose()
  }
})

test('an unknown expectation value is refused rather than silently skipped', async () => {
  const tree = await makeTree({
    'robots.txt': 'User-agent: *\nAllow: /\n',
    'checks.json': checks([{ userAgent: 'GPTBot', url: 'https://example.com/page', expect: { crawl: 'blocked' } }]),
    'audit.config.json': config(),
  })
  try {
    await assert.rejects(
      auditRobotsPolicy({ configFile: join(tree.root, 'audit.config.json') }),
      (error) => error instanceof ConfigError && /expect.crawl must be one of allow, disallow/.test(error.message),
    )
  } finally {
    await tree.dispose()
  }
})

test('an unknown limit name is refused rather than ignored', async () => {
  const tree = await makeTree({
    'robots.txt': 'User-agent: *\nAllow: /\n',
    'checks.json': checks([{ userAgent: 'GPTBot', url: 'https://example.com/page' }]),
    'audit.config.json': config({ limits: { maxRobotsByte: 10 } }),
  })
  try {
    await assert.rejects(
      auditRobotsPolicy({ configFile: join(tree.root, 'audit.config.json') }),
      (error) => error instanceof ConfigError && error.rule === 'unknown-limit',
    )
  } finally {
    await tree.dispose()
  }
})

test('two capture entries for the same URL are refused as ambiguous', async () => {
  const tree = await makeTree({
    'robots.txt': 'User-agent: *\nAllow: /\n',
    'checks.json': checks([{ userAgent: 'GPTBot', url: 'https://example.com/page' }]),
    'capture.json': JSON.stringify({
      schemaVersion: '1',
      responses: [
        { url: 'https://example.com/page', headers: { 'x-robots-tag': 'noindex' } },
        { url: 'https://example.com/page?', headers: {} },
      ],
    }),
    'audit.config.json': config({ capture: 'capture.json' }),
  })
  try {
    await assert.rejects(
      auditRobotsPolicy({ configFile: join(tree.root, 'audit.config.json') }),
      (error) => error instanceof ConfigError && error.rule === 'ambiguous-capture',
    )
  } finally {
    await tree.dispose()
  }
})

test('a report with nothing checked is never a pass, whatever its findings say', () => {
  const empty = buildReport({ findings: [], checked: 0, incomplete: false })
  assert.equal(empty.status, 'incomplete')
  assert.equal(exitCodeFor(empty), 2)
  assert.deepEqual(
    empty.findings.map((finding) => finding.ruleId),
    ['no-evidence'],
  )

  const withInfo = buildReport({
    findings: [makeFinding('crawl-decision', 'a decision that decided nothing', { file: 'checks.json' })],
    checked: 0,
    incomplete: false,
  })
  assert.equal(withInfo.status, 'incomplete')
})

test('an incomplete run is never a pass even with no error-severity finding', () => {
  const report = buildReport({
    findings: [makeFinding('indexing-unverified', 'not verified', { file: 'checks.json', pointer: '/checks/0' })],
    checked: 1,
    incomplete: true,
  })
  assert.deepEqual(
    { status: report.status, errors: report.summary.errors, exit: exitCodeFor(report) },
    { status: 'incomplete', errors: 0, exit: 2 },
  )
})
