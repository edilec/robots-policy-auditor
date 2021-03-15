import assert from 'node:assert/strict'
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import test from 'node:test'

import { auditRobotsPolicy, exitCodeFor } from '../src/index.mjs'

/**
 * Every path in this tool that sets `incomplete` has a test here.
 *
 * The reason is specific: deleting one `incomplete = true` line elsewhere in
 * this catalog let an entirely unread input report `pass` with the whole suite
 * still green. Each test below asserts the status is exactly `incomplete`, so
 * removing the flag turns the run into `pass` or `fail` and the test fails.
 *
 * The three cases whose finding is only a *warning* are marked: for those, the
 * flag is the sole thing standing between the run and a green build.
 */

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

const ONE_CHECK = checks([{ userAgent: 'GPTBot', url: 'https://example.com/page' }])
const OPEN_ROBOTS = 'User-agent: *\nAllow: /\n'

async function audit(files, limits = {}) {
  const tree = await makeTree(files)
  try {
    return await auditRobotsPolicy({ configFile: join(tree.root, 'audit.config.json'), limits })
  } finally {
    await tree.dispose()
  }
}

function ruleIds(report) {
  return report.findings.map((finding) => finding.ruleId)
}

test('a robots.txt that is not there is incomplete, never a pass', async () => {
  const report = await audit({ 'checks.json': ONE_CHECK, 'audit.config.json': config() })
  assert.equal(report.status, 'incomplete')
  assert.equal(exitCodeFor(report), 2)
  assert.ok(ruleIds(report).includes('input-unreadable'))
})

test('a robots.txt that is a directory is incomplete, never a pass', async () => {
  const tree = await makeTree({
    'robots.txt/placeholder': 'not a file',
    'checks.json': ONE_CHECK,
    'audit.config.json': config(),
  })
  try {
    const report = await auditRobotsPolicy({ configFile: join(tree.root, 'audit.config.json') })
    assert.equal(report.status, 'incomplete')
    assert.equal(report.findings.find((finding) => finding.ruleId === 'input-unreadable').message.includes('not a regular file'), true)
  } finally {
    await tree.dispose()
  }
})

test('a robots.txt whose bytes are not UTF-8 is incomplete, never a pass', async () => {
  const tree = await makeTree({ 'checks.json': ONE_CHECK, 'audit.config.json': config() })
  try {
    // A lone 0xFF can begin no UTF-8 sequence, so the decode fails outright.
    await writeFile(join(tree.root, 'robots.txt'), Buffer.from([0x55, 0x73, 0x65, 0x72, 0xff, 0x0a]))
    const report = await auditRobotsPolicy({ configFile: join(tree.root, 'audit.config.json') })
    assert.equal(report.status, 'incomplete')
    assert.equal(exitCodeFor(report), 2)
    assert.ok(ruleIds(report).includes('input-not-utf8'))
  } finally {
    await tree.dispose()
  }
})

/**
 * The decode is what decides whether a file is UTF-8 — not a search of the
 * decoded text for U+FFFD. A robots.txt may legitimately contain that
 * character, and a file of undecodable bytes decodes to the same one, so
 * inferring encoding from content reports undecodable bytes as a pass.
 */
test('a valid UTF-8 robots.txt containing U+FFFD is still parsed and can pass', async () => {
  const report = await audit({
    'robots.txt': 'User-agent: *\n# a replacement character follows: �\nAllow: /\n',
    'checks.json': checks([
      { userAgent: 'GPTBot', url: 'https://example.com/page', expect: { crawl: 'allow' } },
    ]),
    'capture.json': JSON.stringify({
      schemaVersion: '1',
      responses: [{ url: 'https://example.com/page', headers: {} }],
    }),
    'audit.config.json': config({ capture: 'capture.json' }),
  })
  assert.equal(report.status, 'pass')
  assert.ok(!ruleIds(report).includes('input-not-utf8'))
})

test('a robots.txt above its byte limit is incomplete, never a pass', async () => {
  const report = await audit(
    { 'robots.txt': `${OPEN_ROBOTS}${'#'.repeat(500)}`, 'checks.json': ONE_CHECK, 'audit.config.json': config() },
    { maxRobotsBytes: 32 },
  )
  assert.equal(report.status, 'incomplete')
  assert.ok(ruleIds(report).includes('input-too-large'))
})

const PARSE_LIMITS = [
  {
    limit: 'maxRobotsLines',
    value: 4,
    robots: Array.from({ length: 10 }, () => 'User-agent: *').join('\n'),
  },
  {
    limit: 'maxGroups',
    value: 2,
    robots: Array.from({ length: 6 }, (unused, index) => `User-agent: bot${index}\nDisallow: /x`).join('\n'),
  },
  {
    limit: 'maxRulesPerGroup',
    value: 3,
    robots: ['User-agent: *', ...Array.from({ length: 9 }, (unused, index) => `Disallow: /p${index}`)].join('\n'),
  },
]

for (const scenario of PARSE_LIMITS) {
  test(`the ${scenario.limit} limit makes the run incomplete and names itself`, async () => {
    const report = await audit(
      { 'robots.txt': scenario.robots, 'checks.json': ONE_CHECK, 'audit.config.json': config() },
      { [scenario.limit]: scenario.value },
    )
    assert.equal(report.status, 'incomplete')
    assert.equal(exitCodeFor(report), 2)
    const limit = report.findings.find((finding) => finding.ruleId === 'limit-exceeded')
    assert.ok(limit.message.includes(scenario.limit), `expected the message to name ${scenario.limit}`)
    assert.equal(limit.suggestion, `raise limits.${scenario.limit} or shorten the file`)
  })
}

test('a checks document that cannot be parsed is incomplete, never a pass', async () => {
  const report = await audit({
    'robots.txt': OPEN_ROBOTS,
    'checks.json': '{ "schemaVersion": "1", "checks": [',
    'audit.config.json': config(),
  })
  assert.equal(report.status, 'incomplete')
  assert.ok(ruleIds(report).includes('input-unreadable'))
})

test('more checks than the limit allows are not silently trimmed', async () => {
  const report = await audit(
    {
      'robots.txt': OPEN_ROBOTS,
      'checks.json': checks(
        Array.from({ length: 6 }, (unused, index) => ({
          userAgent: 'GPTBot',
          url: `https://example.com/page-${index}`,
        })),
      ),
      'audit.config.json': config(),
    },
    { maxChecks: 2 },
  )
  assert.equal(report.status, 'incomplete')
  assert.equal(report.summary.checked, 0)
  assert.ok(report.findings.find((finding) => finding.ruleId === 'limit-exceeded').message.includes('maxChecks'))
})

test('a capture that cannot be parsed is incomplete, never a pass', async () => {
  const report = await audit({
    'robots.txt': OPEN_ROBOTS,
    'checks.json': ONE_CHECK,
    'capture.json': 'not json at all',
    'audit.config.json': config({ capture: 'capture.json' }),
  })
  assert.equal(report.status, 'incomplete')
  assert.ok(ruleIds(report).includes('input-unreadable'))
})

test('more capture entries than the limit allows are not silently trimmed', async () => {
  const report = await audit(
    {
      'robots.txt': OPEN_ROBOTS,
      'checks.json': ONE_CHECK,
      'capture.json': JSON.stringify({
        schemaVersion: '1',
        responses: Array.from({ length: 5 }, (unused, index) => ({
          url: `https://example.com/page-${index}`,
          headers: {},
        })),
      }),
      'audit.config.json': config({ capture: 'capture.json' }),
    },
    { maxCaptureEntries: 2 },
  )
  assert.equal(report.status, 'incomplete')
  assert.ok(report.findings.find((finding) => finding.ruleId === 'limit-exceeded').message.includes('maxCaptureEntries'))
})

test('more header values than the limit allows are not silently trimmed', async () => {
  const report = await audit(
    {
      'robots.txt': OPEN_ROBOTS,
      'checks.json': ONE_CHECK,
      'capture.json': JSON.stringify({
        schemaVersion: '1',
        responses: [
          {
            url: 'https://example.com/page',
            headers: { 'x-robots-tag': Array.from({ length: 5 }, () => 'noindex') },
          },
        ],
      }),
      'audit.config.json': config({ capture: 'capture.json' }),
    },
    { maxHeaderValues: 2 },
  )
  assert.equal(report.status, 'incomplete')
  assert.ok(report.findings.find((finding) => finding.ruleId === 'limit-exceeded').message.includes('maxHeaderValues'))
})

test('a captured document that is not there is incomplete, never a pass', async () => {
  const report = await audit({
    'robots.txt': OPEN_ROBOTS,
    'checks.json': ONE_CHECK,
    'capture.json': JSON.stringify({
      schemaVersion: '1',
      responses: [{ url: 'https://example.com/page', html: 'capture/missing.html' }],
    }),
    'audit.config.json': config({ capture: 'capture.json' }),
  })
  assert.equal(report.status, 'incomplete')
  const unreadable = report.findings.find((finding) => finding.ruleId === 'input-unreadable')
  assert.equal(unreadable.location.file, 'capture/missing.html')
})

test('a captured document above its byte limit is incomplete, never a pass', async () => {
  const report = await audit(
    {
      'robots.txt': OPEN_ROBOTS,
      'checks.json': ONE_CHECK,
      'capture/page.html': `<html><head>${'<!-- padding -->'.repeat(40)}</head></html>`,
      'capture.json': JSON.stringify({
        schemaVersion: '1',
        responses: [{ url: 'https://example.com/page', html: 'capture/page.html' }],
      }),
      'audit.config.json': config({ capture: 'capture.json' }),
    },
    { maxHtmlBytes: 64 },
  )
  assert.equal(report.status, 'incomplete')
  assert.ok(ruleIds(report).includes('input-too-large'))
})

test('a captured document whose bytes are not UTF-8 is incomplete, never a pass', async () => {
  const tree = await makeTree({
    'robots.txt': OPEN_ROBOTS,
    'checks.json': ONE_CHECK,
    'capture.json': JSON.stringify({
      schemaVersion: '1',
      responses: [{ url: 'https://example.com/page', html: 'capture/page.html' }],
    }),
    'audit.config.json': config({ capture: 'capture.json' }),
  })
  try {
    await mkdir(join(tree.root, 'capture'), { recursive: true })
    await writeFile(join(tree.root, 'capture/page.html'), Buffer.from([0x3c, 0x68, 0x74, 0x6d, 0x6c, 0xc3, 0x28]))
    const report = await auditRobotsPolicy({ configFile: join(tree.root, 'audit.config.json') })
    assert.equal(report.status, 'incomplete')
    assert.ok(ruleIds(report).includes('input-not-utf8'))
  } finally {
    await tree.dispose()
  }
})

test('more meta elements than the limit allows are not silently trimmed', async () => {
  const metas = Array.from({ length: 6 }, () => '<meta name="robots" content="noindex">').join('\n')
  const report = await audit(
    {
      'robots.txt': OPEN_ROBOTS,
      'checks.json': ONE_CHECK,
      'capture/page.html': `<html><head>\n${metas}\n</head></html>`,
      'capture.json': JSON.stringify({
        schemaVersion: '1',
        responses: [{ url: 'https://example.com/page', html: 'capture/page.html' }],
      }),
      'audit.config.json': config({ capture: 'capture.json' }),
    },
    { maxMetaTags: 2 },
  )
  assert.equal(report.status, 'incomplete')
  assert.ok(report.findings.find((finding) => finding.ruleId === 'limit-exceeded').message.includes('maxMetaTags'))
})

test('a check that names no absolute URL is incomplete, never a pass', async () => {
  const report = await audit({
    'robots.txt': OPEN_ROBOTS,
    'checks.json': checks([
      { userAgent: 'GPTBot', url: '/relative/path' },
      { userAgent: 'GPTBot', url: 'https://example.com/page' },
    ]),
    'audit.config.json': config(),
  })
  assert.equal(report.status, 'incomplete')
  assert.equal(report.summary.checked, 1)
  assert.equal(report.findings.find((finding) => finding.ruleId === 'check-unevaluable').location.pointer, '/checks/0')
})

test('a check on another origin is incomplete, never a pass', async () => {
  const report = await audit({
    'robots.txt': OPEN_ROBOTS,
    'checks.json': checks([
      { userAgent: 'GPTBot', url: 'https://other.example.net/page' },
      { userAgent: 'GPTBot', url: 'https://example.com/page' },
    ]),
    'audit.config.json': config(),
  })
  assert.equal(report.status, 'incomplete')
  assert.equal(report.summary.checked, 1)
  assert.match(
    report.findings.find((finding) => finding.ruleId === 'check-unevaluable').message,
    /robots.txt applies only to its own origin/,
  )
})

/**
 * Warning-only incomplete, case 1. Every finding here is `info` or `warning`,
 * so `errors` is zero and the `incomplete` flag is the only thing that keeps
 * this run from reporting `pass` and exiting 0.
 */
test('an indexing axis with no capture at all is incomplete, never a pass', async () => {
  const report = await audit({
    'robots.txt': OPEN_ROBOTS,
    'checks.json': checks([{ userAgent: 'GPTBot', url: 'https://example.com/page', expect: { crawl: 'allow' } }]),
    'audit.config.json': config(),
  })
  assert.deepEqual(
    { status: report.status, errors: report.summary.errors, exit: exitCodeFor(report) },
    { status: 'incomplete', errors: 0, exit: 2 },
  )
  assert.equal(report.summary.indexUnverified, 1)
  assert.equal(report.findings.find((finding) => finding.ruleId === 'indexing-unverified').severity, 'warning')
})

/** Warning-only incomplete, case 2: a capture that covers other URLs but not this one. */
test('a URL the capture does not cover is incomplete, never a pass', async () => {
  const report = await audit({
    'robots.txt': OPEN_ROBOTS,
    'checks.json': checks([{ userAgent: 'GPTBot', url: 'https://example.com/page' }]),
    'capture.json': JSON.stringify({
      schemaVersion: '1',
      responses: [{ url: 'https://example.com/elsewhere', headers: {} }],
    }),
    'audit.config.json': config({ capture: 'capture.json' }),
  })
  assert.deepEqual(
    { status: report.status, errors: report.summary.errors },
    { status: 'incomplete', errors: 0 },
  )
  assert.match(
    report.findings.find((finding) => finding.ruleId === 'indexing-unverified').message,
    /No captured response covers/,
  )
})

/** Warning-only incomplete, case 3: an entry that states nothing about indexing. */
test('a capture entry declaring neither headers nor a document is incomplete, never a pass', async () => {
  const report = await audit({
    'robots.txt': OPEN_ROBOTS,
    'checks.json': checks([{ userAgent: 'GPTBot', url: 'https://example.com/page' }]),
    'capture.json': JSON.stringify({
      schemaVersion: '1',
      responses: [{ url: 'https://example.com/page', status: 200 }],
    }),
    'audit.config.json': config({ capture: 'capture.json' }),
  })
  assert.deepEqual(
    { status: report.status, errors: report.summary.errors },
    { status: 'incomplete', errors: 0 },
  )
  assert.match(
    report.findings.find((finding) => finding.ruleId === 'indexing-unverified').message,
    /Silence is not evidence/,
  )
})

/** Warning-only incomplete, case 4: a directive this tool has no clock to resolve. */
test('a time-dependent directive is incomplete, never a pass', async () => {
  const report = await audit({
    'robots.txt': OPEN_ROBOTS,
    'checks.json': checks([{ userAgent: 'GPTBot', url: 'https://example.com/page' }]),
    'capture.json': JSON.stringify({
      schemaVersion: '1',
      responses: [
        {
          url: 'https://example.com/page',
          headers: { 'x-robots-tag': 'unavailable_after: 2027-01-01T00:00:00Z' },
        },
      ],
    }),
    'audit.config.json': config({ capture: 'capture.json' }),
  })
  assert.deepEqual(
    { status: report.status, errors: report.summary.errors },
    { status: 'incomplete', errors: 0 },
  )
  assert.match(
    report.findings.find((finding) => finding.ruleId === 'indexing-unverified').message,
    /depends on the current time, and this tool has no clock/,
  )
})

test('an empty checks list reports that it verified nothing', async () => {
  const report = await audit({
    'robots.txt': OPEN_ROBOTS,
    'checks.json': checks([]),
    'audit.config.json': config(),
  })
  assert.deepEqual(
    { status: report.status, checked: report.summary.checked, exit: exitCodeFor(report) },
    { status: 'incomplete', checked: 0, exit: 2 },
  )
  assert.deepEqual(ruleIds(report), ['no-evidence'])
})
