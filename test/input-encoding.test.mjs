import assert from 'node:assert/strict'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

import { ConfigError, auditRobotsPolicy, exitCodeFor } from '../src/index.mjs'

/**
 * The JSON inputs are decoded as strictly as robots.txt and the captured
 * documents are.
 *
 * `readFile(file, 'utf8')` is lossy: an undecodable byte becomes U+FFFD and the
 * document still parses. A capture read that way turns `noindex` plus one stray
 * byte into an unrecognised directive, and the URL it was protecting is then
 * reported `index=indexable` by a run that exits 0 — an input nobody ever read
 * reaching a pass. Each test here writes real undecodable bytes into one JSON
 * input, and the last one holds the opposite line: text that decodes is parsed,
 * whatever characters it contains.
 */

async function makeTree(files) {
  const root = await mkdtemp(join(tmpdir(), 'robots-policy-auditor-'))
  for (const [name, content] of Object.entries(files)) {
    await writeFile(join(root, name), content)
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

const OPEN_ROBOTS = 'User-agent: *\nAllow: /\n'
const ONE_CHECK = JSON.stringify({
  schemaVersion: '1',
  checks: [{ userAgent: 'GPTBot', url: 'https://example.com/page' }],
})

function ruleIds(report) {
  return report.findings.map((finding) => finding.ruleId)
}

/** JSON bytes with a lone 0xFF, which can begin no UTF-8 sequence, inside one value. */
function undecodable(text, marker) {
  const parts = text.split(marker)
  assert.equal(parts.length, 2, 'the marker must appear exactly once')
  return Buffer.concat([Buffer.from(parts[0], 'utf8'), Buffer.from([0xff]), Buffer.from(parts[1], 'utf8')])
}

test('a capture whose bytes are not UTF-8 is never decoded into a directive', async () => {
  const tree = await makeTree({
    'robots.txt': OPEN_ROBOTS,
    'checks.json': ONE_CHECK,
    'audit.config.json': config({ capture: 'capture.json' }),
  })
  try {
    const capture = JSON.stringify({
      schemaVersion: '1',
      responses: [{ url: 'https://example.com/page', headers: { 'x-robots-tag': 'noindexMARK' } }],
    })
    await writeFile(join(tree.root, 'capture.json'), undecodable(capture, 'MARK'))
    const report = await auditRobotsPolicy({ configFile: join(tree.root, 'audit.config.json') })

    assert.equal(report.status, 'incomplete')
    assert.equal(exitCodeFor(report), 2)
    assert.ok(ruleIds(report).includes('input-not-utf8'))
    assert.equal(report.summary.indexUnverified, 1)
    // The mangled `noindex` must not surface as a directive that was read: a
    // corrupted byte makes the evidence unknown, not misspelled.
    assert.ok(!ruleIds(report).includes('unknown-index-directive'))
    assert.ok(
      report.findings.some((finding) => finding.message.includes('index=unverified')),
      'the indexing axis must be unverified, never indexable, when the capture was not read',
    )
  } finally {
    await tree.dispose()
  }
})

test('a checks document whose bytes are not UTF-8 is incomplete, never a pass', async () => {
  const tree = await makeTree({
    'robots.txt': OPEN_ROBOTS,
    'audit.config.json': config(),
  })
  try {
    await writeFile(join(tree.root, 'checks.json'), undecodable(ONE_CHECK, 'GPTBot'))
    const report = await auditRobotsPolicy({ configFile: join(tree.root, 'audit.config.json') })

    assert.equal(report.status, 'incomplete')
    assert.equal(exitCodeFor(report), 2)
    assert.equal(report.summary.checked, 0)
    const notUtf8 = report.findings.find((finding) => finding.ruleId === 'input-not-utf8')
    assert.equal(notUtf8.location.file, 'checks.json')
    assert.equal(notUtf8.severity, 'error')
  } finally {
    await tree.dispose()
  }
})

test('a config whose bytes are not UTF-8 is refused outright', async () => {
  const tree = await makeTree({ 'robots.txt': OPEN_ROBOTS, 'checks.json': ONE_CHECK })
  try {
    await writeFile(join(tree.root, 'audit.config.json'), undecodable(config(), 'robots.txt'))
    await assert.rejects(
      () => auditRobotsPolicy({ configFile: join(tree.root, 'audit.config.json') }),
      (error) => {
        assert.ok(error instanceof ConfigError)
        assert.match(error.message, /not valid UTF-8/)
        return true
      },
    )
  } finally {
    await tree.dispose()
  }
})

/**
 * The other direction, which matters just as much: the decode decides, not a
 * search for U+FFFD in decoded text. A capture may legitimately carry that
 * character, and refusing it would reject a correct input.
 */
test('a valid UTF-8 capture containing U+FFFD is parsed and can pass', async () => {
  const tree = await makeTree({
    'robots.txt': OPEN_ROBOTS,
    'checks.json': JSON.stringify({
      schemaVersion: '1',
      checks: [{ userAgent: 'GPTBot', url: 'https://example.com/page', expect: { index: 'blocked' } }],
    }),
    'capture.json': JSON.stringify({
      schemaVersion: '1',
      responses: [
        { url: 'https://example.com/page', headers: { 'x-robots-tag': 'noindex' }, note: 'replacement � here' },
      ],
    }),
    'audit.config.json': config({ capture: 'capture.json' }),
  })
  try {
    const report = await auditRobotsPolicy({ configFile: join(tree.root, 'audit.config.json') })
    assert.equal(report.status, 'pass')
    assert.equal(exitCodeFor(report), 0)
    assert.equal(report.summary.indexBlocked, 1)
    assert.ok(!ruleIds(report).includes('input-not-utf8'))
  } finally {
    await tree.dispose()
  }
})
