import assert from 'node:assert/strict'
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import test from 'node:test'

import { auditRobotsPolicy, exitCodeFor } from '../src/index.mjs'

/**
 * Indexing evidence that was declared and never read is *unknown*, not
 * *indexable*.
 *
 * A capture entry that names a document makes `declaresEvidence` true before
 * anything has been read. If the document is then missing, undecodable or
 * bounded out, the directive list is empty for a reason that has nothing to do
 * with the site, and reporting `index=indexable` from it invents two things at
 * once: an indexing verdict nobody obtained, and the `index-expectation-mismatch`
 * error that follows from comparing a check against it. That error names a
 * defect in the audited site which the run has no evidence for at all.
 *
 * Five paths reach that state, and each one is a case below. The last two tests
 * hold the opposite line: a directive that *was* read still decides, and
 * evidence that was read and carried nothing is still a pass.
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
    capture: 'capture.json',
    ...extra,
  })
}

const OPEN_ROBOTS = 'User-agent: *\nAllow: /\n'

/** One check that expects a noindex, so a fabricated verdict becomes a visible error. */
const EXPECTS_BLOCKED = JSON.stringify({
  schemaVersion: '1',
  checks: [{ userAgent: 'GPTBot', url: 'https://example.com/page', expect: { index: 'blocked' } }],
})

function capture(response) {
  return JSON.stringify({ schemaVersion: '1', responses: [{ url: 'https://example.com/page', ...response }] })
}

function ruleIds(report) {
  return report.findings.map((finding) => finding.ruleId)
}

async function audit(files, limits = {}) {
  const tree = await makeTree(files)
  try {
    return await auditRobotsPolicy({ configFile: join(tree.root, 'audit.config.json'), limits })
  } finally {
    await tree.dispose()
  }
}

const UNREAD = [
  {
    name: 'a captured document that is not there',
    files: { 'capture.json': capture({ html: 'capture/missing.html' }) },
    limits: {},
    reason: 'could not be read',
  },
  {
    name: 'a captured document whose bytes are not UTF-8',
    files: {
      // A bare 0xC3 begins a two-byte sequence that 0x28 cannot finish.
      'capture/page.html': Buffer.from([0x3c, 0x68, 0x74, 0x6d, 0x6c, 0xc3, 0x28]),
      'capture.json': capture({ html: 'capture/page.html' }),
    },
    limits: {},
    reason: 'is not valid UTF-8',
  },
  {
    name: 'a captured document above its byte limit',
    files: {
      'capture/page.html': `<html><head>${'<!-- padding -->'.repeat(40)}</head></html>`,
      'capture.json': capture({ html: 'capture/page.html' }),
    },
    limits: { maxHtmlBytes: 64 },
    reason: 'above the maxHtmlBytes limit',
  },
  {
    name: 'X-Robots-Tag values above the maxHeaderValues limit',
    files: {
      'capture.json': capture({ headers: { 'x-robots-tag': ['noindex', 'noindex', 'noindex', 'noindex'] } }),
    },
    limits: { maxHeaderValues: 2 },
    reason: 'above the maxHeaderValues limit',
  },
  {
    name: 'meta elements cut off at the maxMetaTags limit',
    files: {
      'capture/page.html': `<html><head>\n${[
        '<meta name="robots" content="index">',
        '<meta name="robots" content="index">',
        '<meta name="robots" content="index">',
        '<meta name="robots" content="index">',
        '<meta name="robots" content="noindex">',
      ].join('\n')}\n</head></html>`,
      'capture.json': capture({ html: 'capture/page.html' }),
    },
    limits: { maxMetaTags: 2 },
    reason: 'truncated at the maxMetaTags limit',
  },
]

for (const scenario of UNREAD) {
  test(`${scenario.name} leaves indexing unverified, never indexable`, async () => {
    const report = await audit(
      {
        'robots.txt': OPEN_ROBOTS,
        'checks.json': EXPECTS_BLOCKED,
        'audit.config.json': config(),
        ...scenario.files,
      },
      scenario.limits,
    )

    assert.equal(report.status, 'incomplete')
    assert.equal(exitCodeFor(report), 2)
    assert.equal(report.summary.indexUnverified, 1)
    assert.equal(report.summary.indexBlocked, 0)

    const unverified = report.findings.find((finding) => finding.ruleId === 'indexing-unverified')
    assert.ok(unverified, 'evidence that was never read must be reported unverified')
    assert.match(unverified.message, /was not fully read/)
    assert.ok(
      unverified.message.includes(scenario.reason),
      `expected the finding to name why the evidence was not read: ${scenario.reason}`,
    )

    // The fabrication this guards against: an error blaming the audited site
    // for a verdict that came from evidence nobody obtained.
    assert.ok(
      !ruleIds(report).includes('index-expectation-mismatch'),
      'a mismatch must not be claimed against evidence that was never read',
    )
    const decision = report.findings.find((finding) => finding.ruleId === 'crawl-decision')
    assert.match(decision.message, /index=unverified/)
  })
}

/**
 * The rule only runs one way. A directive that *was* read and says noindex
 * decides the URL blocked, because nothing still unread could lift it — the
 * restrictive reading is the one an auditor must assume.
 */
test('a noindex that was read still decides, even beside evidence that was not', async () => {
  const report = await audit({
    'robots.txt': OPEN_ROBOTS,
    'checks.json': EXPECTS_BLOCKED,
    'capture.json': capture({ headers: { 'x-robots-tag': 'noindex' }, html: 'capture/missing.html' }),
    'audit.config.json': config(),
  })

  assert.equal(report.summary.indexBlocked, 1)
  assert.equal(report.summary.indexUnverified, 0)
  assert.ok(!ruleIds(report).includes('index-expectation-mismatch'))
  assert.match(
    report.findings.find((finding) => finding.ruleId === 'crawl-decision').message,
    /index=blocked/,
  )
  // The unreadable document is still reported, and still makes the run incomplete.
  assert.equal(report.status, 'incomplete')
  assert.ok(ruleIds(report).includes('input-unreadable'))
})

/**
 * And the over-correction it must not become: evidence that was read in full
 * and carried no directive is a decided `indexable`, not an unverified one.
 */
test('evidence that was read and carried nothing is indexable, and passes', async () => {
  const report = await audit({
    'robots.txt': OPEN_ROBOTS,
    'checks.json': JSON.stringify({
      schemaVersion: '1',
      checks: [{ userAgent: 'GPTBot', url: 'https://example.com/page', expect: { index: 'indexable' } }],
    }),
    'capture/page.html': '<html><head><title>page</title></head><body>text</body></html>',
    'capture.json': capture({ headers: {}, html: 'capture/page.html' }),
    'audit.config.json': config(),
  })

  assert.equal(report.status, 'pass')
  assert.equal(exitCodeFor(report), 0)
  assert.equal(report.summary.indexUnverified, 0)
  assert.match(
    report.findings.find((finding) => finding.ruleId === 'crawl-decision').message,
    /index=indexable/,
  )
})
