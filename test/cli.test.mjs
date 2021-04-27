import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'

const run = promisify(execFile)
const projectDirectory = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const CLI = join(projectDirectory, 'bin/robots-policy-auditor.mjs')
const CLEAN = join(projectDirectory, 'examples/clean/robots-audit.config.json')
const BROKEN = join(projectDirectory, 'examples/broken/robots-audit.config.json')

/** Run the real CLI and return its exit code with both streams, never throwing. */
async function cli(args) {
  try {
    const { stdout, stderr } = await run(process.execPath, [CLI, ...args])
    return { code: 0, stdout, stderr }
  } catch (error) {
    return { code: error.code ?? 1, stdout: error.stdout ?? '', stderr: error.stderr ?? '' }
  }
}

async function makeTree(files) {
  const root = await mkdtemp(join(tmpdir(), 'robots-policy-auditor-cli-'))
  for (const [name, content] of Object.entries(files)) {
    const target = join(root, name)
    await mkdir(dirname(target), { recursive: true })
    await writeFile(target, content)
  }
  return { root, dispose: () => rm(root, { recursive: true, force: true }) }
}

test('the clean example exits 0 and puts a parseable report on stdout', async () => {
  const result = await cli(['--config', CLEAN])
  assert.equal(result.code, 0)
  const report = JSON.parse(result.stdout)
  assert.deepEqual(
    { schemaVersion: report.schemaVersion, tool: report.tool, status: report.status },
    { schemaVersion: '1', tool: 'robots-policy-auditor', status: 'pass' },
  )
  assert.equal(report.summary.checked, 7)
})

test('the broken example exits 1 and reports its errors', async () => {
  const result = await cli(['--config', BROKEN])
  assert.equal(result.code, 1)
  const report = JSON.parse(result.stdout)
  assert.equal(report.status, 'fail')
  assert.equal(report.summary.errors, 4)
})

test('stdout carries the report and nothing else, while the summary goes to stderr', async () => {
  const result = await cli(['--config', CLEAN])
  assert.doesNotThrow(() => JSON.parse(result.stdout))
  assert.match(result.stderr, /robots-policy-auditor: pass/)
  assert.match(result.stderr, /crawl permission and indexing are separate axes/)
})

async function oneAgentResult(userAgent) {
  const tree = await makeTree({
    'robots.txt': 'User-agent: *\nAllow: /\n',
    'checks.json': JSON.stringify({
      schemaVersion: '1',
      checks: [{ userAgent, url: 'https://example.com/' }],
    }),
    'capture.json': JSON.stringify({
      schemaVersion: '1',
      responses: [{ url: 'https://example.com/', headers: {} }],
    }),
    'audit.config.json': JSON.stringify({
      schemaVersion: '1',
      site: { origin: 'https://example.com' },
      robotsTxt: 'robots.txt',
      checks: 'checks.json',
      capture: 'capture.json',
    }),
  })
  try {
    return await cli(['--config', join(tree.root, 'audit.config.json')])
  } finally {
    await tree.dispose()
  }
}

async function oneUrlResult({ url, responses = [{ url, headers: {} }], origin = 'https://example.test' }) {
  const tree = await makeTree({
    'robots.txt': 'User-agent: *\nAllow: /\n',
    'checks.json': JSON.stringify({ schemaVersion: '1', checks: [{ userAgent: 'ExampleBot', url }] }),
    'capture.json': JSON.stringify({ schemaVersion: '1', responses }),
    'audit.config.json': JSON.stringify({
      schemaVersion: '1', site: { origin }, robotsTxt: 'robots.txt', checks: 'checks.json', capture: 'capture.json',
    }),
  })
  try {
    return await cli(['--config', join(tree.root, 'audit.config.json')])
  } finally {
    await tree.dispose()
  }
}

test('a matched URL query affects the decision but stays out of JSON and human crawl-decision text', async () => {
  const ordinary = await oneUrlResult({ url: 'https://example.test/path?item=ordinary' })
  assert.equal(ordinary.code, 0)
  assert.equal(JSON.parse(ordinary.stdout).status, 'pass')

  const secret = 'SYNTHETIC_SECRET_CANARY'
  const result = await oneUrlResult({ url: `https://example.test/path?token=${secret}` })
  const report = JSON.parse(result.stdout)
  assert.equal(result.code, 0)
  assert.equal(report.status, 'pass')
  assert.equal(report.summary.checked, 1)
  assert.deepEqual(report.findings.map((finding) => finding.ruleId), ['crawl-decision'])
  assert.equal(report.findings[0].location.pointer, '/checks/0')
  assert.equal(report.findings[0].message, 'crawl=allow index=indexable for "ExampleBot" at /checks/0.')
  assert.match(report.findings[0].evidence, /Allow: \/ \(line 2, 1 octet\)/u)
  assert.equal(result.stdout.includes(secret), false)
  assert.equal(result.stderr.includes(secret), false)
  assert.match(result.stderr, /crawl-decision/u)
})

test('missing, empty and unread captures keep checked URL queries out of indexing-unverified reports', async () => {
  const secret = 'SYNTHETIC_SECRET_CANARY'
  const url = `https://example.test/path?token=${secret}`
  const complete = await oneUrlResult({ url })
  assert.equal(complete.code, 0)
  assert.equal(JSON.parse(complete.stdout).status, 'pass')

  for (const [responses, reason] of [
    [[], /No captured response covers/u],
    [[{ url }], /declares neither headers nor a document/u],
    [[{ url, html: 'missing.html' }], /was not fully read/u],
  ]) {
    const result = await oneUrlResult({ url, responses })
    const report = JSON.parse(result.stdout)
    assert.equal(result.code, 2)
    assert.equal(report.status, 'incomplete')
    assert.equal(report.summary.checked, 1)
    assert.equal(report.summary.indexUnverified, 1)
    const unverified = report.findings.filter((finding) => finding.ruleId === 'indexing-unverified')
    assert.equal(unverified.length, 1)
    assert.equal(unverified[0].location.pointer, '/checks/0')
    assert.match(unverified[0].message, reason)
    assert.match(unverified[0].message, /\/checks\/0/u)
    assert.equal(result.stdout.includes(secret), false)
    assert.equal(result.stderr.includes(secret), false)
  }
})

test('a malformed checked URL stays unevaluable without copying its value into either CLI stream', async () => {
  const ordinary = await oneUrlResult({ url: 'not-a-url', responses: [] })
  assert.equal(ordinary.code, 2)
  assert.equal(JSON.parse(ordinary.stdout).status, 'incomplete')

  const secret = 'SYNTHETIC_SECRET_CANARY'
  const result = await oneUrlResult({ url: `not-a-url?token=${secret}`, responses: [] })
  const report = JSON.parse(result.stdout)
  assert.equal(result.code, 2)
  assert.equal(report.status, 'incomplete')
  assert.equal(report.summary.checked, 0)
  assert.deepEqual(report.findings.map((finding) => finding.ruleId), ['no-evidence', 'check-unevaluable'])
  const unevaluable = report.findings.find((finding) => finding.ruleId === 'check-unevaluable')
  assert.equal(unevaluable.location.pointer, '/checks/0')
  assert.match(unevaluable.message, /does not declare an absolute URL/u)
  assert.equal(unevaluable.evidence, undefined)
  assert.equal(result.stdout.includes(secret), false)
  assert.equal(result.stderr.includes(secret), false)
})

test('a different-origin check is incomplete without exposing its origin or URL query', async () => {
  const sameOrigin = await oneUrlResult({ url: 'https://example.test/path?item=ordinary' })
  assert.equal(sameOrigin.code, 0)
  assert.equal(JSON.parse(sameOrigin.stdout).status, 'pass')

  const secret = 'SYNTHETIC_SECRET_CANARY'
  const result = await oneUrlResult({ url: `https://other.test/path?token=${secret}`, responses: [] })
  const report = JSON.parse(result.stdout)
  assert.equal(result.code, 2)
  assert.equal(report.status, 'incomplete')
  assert.equal(report.summary.checked, 0)
  assert.deepEqual(report.findings.map((finding) => finding.ruleId), ['no-evidence', 'check-unevaluable'])
  const unevaluable = report.findings.find((finding) => finding.ruleId === 'check-unevaluable')
  assert.equal(unevaluable.location.pointer, '/checks/0')
  assert.match(unevaluable.message, /origin different from the configured site/u)
  assert.equal(unevaluable.evidence, undefined)
  assert.equal(result.stdout.includes('other.test'), false)
  assert.equal(result.stderr.includes('other.test'), false)
  assert.equal(result.stdout.includes(secret), false)
  assert.equal(result.stderr.includes(secret), false)
})

test('invalid site and capture URL diagnostics refuse configuration without repeating URL data', async () => {
  const valid = await oneUrlResult({ url: 'https://example.test/path' })
  assert.equal(valid.code, 0)
  assert.equal(JSON.parse(valid.stdout).status, 'pass')

  const secret = 'SYNTHETIC_SECRET_CANARY'
  const schemeSecret = 'syntheticsecretcanary'
  for (const [options, expected] of [
    [{ url: 'https://example.test/path', origin: `not-a-url?token=${secret}` }, /site\.origin must be an absolute http\(s\) URL/u],
    [{ url: 'https://example.test/path', origin: `https://example.test/path?token=${secret}` }, /site\.origin must be a bare origin/u],
    [{ url: 'https://example.test/path', origin: `${schemeSecret}:payload` }, /site\.origin must use http or https/u],
    [{ url: 'https://example.test/path', responses: [{ url: `not-a-url?token=${secret}`, headers: {} }] }, /responses\[0\]\.url is not an absolute URL/u],
  ]) {
    const result = await oneUrlResult(options)
    assert.equal(result.code, 2)
    assert.equal(result.stdout, '')
    assert.match(result.stderr, expected)
    assert.equal(result.stderr.includes(secret), false)
    assert.equal(result.stderr.includes(schemeSecret), false)
  }
})

async function oneDirectiveResult(directive) {
  const tree = await makeTree({
    'robots.txt': `User-agent: *\nAllow: /\n${directive}: value\n`,
    'checks.json': JSON.stringify({
      schemaVersion: '1',
      checks: [{ userAgent: 'ExampleBot', url: 'https://example.com/' }],
    }),
    'capture.json': JSON.stringify({
      schemaVersion: '1',
      responses: [{ url: 'https://example.com/', headers: {} }],
    }),
    'audit.config.json': JSON.stringify({
      schemaVersion: '1',
      site: { origin: 'https://example.com' },
      robotsTxt: 'robots.txt',
      checks: 'checks.json',
      capture: 'capture.json',
    }),
  })
  try {
    return await cli(['--config', join(tree.root, 'audit.config.json')])
  } finally {
    await tree.dispose()
  }
}

function assertUnknownDirectiveReport(result) {
  assert.equal(result.code, 0)
  const report = JSON.parse(result.stdout)
  assert.equal(report.status, 'pass')
  assert.equal(report.summary.checked, 1)
  assert.deepEqual(report.findings.map((finding) => finding.ruleId), ['crawl-decision', 'unknown-directive'])
  assert.match(result.stdout, /unrecognised directive/)
  assert.match(result.stderr, /unknown-directive/)
}

test('an ordinary unknown robots directive remains a visible warning', async () => {
  const result = await oneDirectiveResult('X-Thing')
  assertUnknownDirectiveReport(result)
  assert.match(result.stdout, /X-Thing/)
  assert.match(result.stderr, /x-thing/)
})

test('C1 and bidi characters in unknown robots directives cannot reach either CLI stream', async () => {
  for (const code of [0x0085, 0x202e]) {
    const character = String.fromCharCode(code)
    const result = await oneDirectiveResult(`X${character}-Thing`)
    assertUnknownDirectiveReport(result)
    assert.equal(result.stdout.includes(character), false, `U+${code.toString(16)} reached JSON stdout`)
    assert.equal(result.stderr.includes(character), false, `U+${code.toString(16)} reached human stderr`)
  }
})

test('C1 and bidi characters in config keys cannot reach the CLI diagnostic', async () => {
  for (const code of [0x0085, 0x202e]) {
    const character = String.fromCharCode(code)
    const tree = await makeTree({
      'audit.config.json': JSON.stringify({
        schemaVersion: '1',
        site: { origin: 'https://example.com' },
        robotsTxt: 'robots.txt',
        checks: 'checks.json',
        [`surprise${character}`]: true,
      }),
    })
    try {
      const result = await cli(['--config', join(tree.root, 'audit.config.json')])
      assert.equal(result.code, 2)
      assert.equal(result.stdout, '')
      assert.match(result.stderr, /unknown key/)
      assert.equal(result.stderr.includes(character), false, `U+${code.toString(16)} reached config stderr`)
    } finally {
      await tree.dispose()
    }
  }
})

test('C1 and bidi characters in unknown CLI options cannot reach the usage diagnostic', async () => {
  for (const code of [0x0085, 0x202e]) {
    const character = String.fromCharCode(code)
    const result = await cli([`--surprise${character}`])
    assert.equal(result.code, 2)
    assert.equal(result.stdout, '')
    assert.match(result.stderr, /unknown option/)
    assert.equal(result.stderr.includes(character), false, `U+${code.toString(16)} reached option stderr`)
  }
})

function assertOneAgentReport(result) {
  assert.equal(result.code, 0)
  const report = JSON.parse(result.stdout)
  assert.equal(report.status, 'pass')
  assert.equal(report.summary.checked, 1)
  assert.deepEqual(report.findings.map((finding) => finding.ruleId), ['crawl-decision'])
  assert.match(result.stdout, /ExampleBot/)
  assert.match(result.stderr, /crawl-decision/)
}

test('an ordinary user agent still yields one visible, passing CLI decision', async () => {
  const result = await oneAgentResult('ExampleBot')
  assertOneAgentReport(result)
  assert.match(result.stderr, /ExampleBot/)
})

test('an invisible-only user agent is unevaluable before any crawl decision', async () => {
  for (const code of [0x0085, 0x200e, 0x034f]) {
    const character = String.fromCharCode(code)
    const result = await oneAgentResult(character)
    assert.equal(result.code, 2, `U+${code.toString(16)} must not decide crawling`)
    const report = JSON.parse(result.stdout)
    assert.equal(report.status, 'incomplete')
    assert.equal(report.summary.checked, 0)
    assert.deepEqual(report.findings.map((finding) => finding.ruleId), ['no-evidence', 'check-unevaluable'])
    assert.equal(result.stdout.includes(character), false)
    assert.equal(result.stderr.includes(character), false)
  }
})

test('C1 controls in a user agent cannot reach JSON stdout or human stderr', async () => {
  for (const code of [0x0080, 0x0085, 0x009b, 0x009f]) {
    const character = String.fromCharCode(code)
    const result = await oneAgentResult(`ExampleBot${character}`)
    assertOneAgentReport(result)
    assert.equal(result.stdout.includes(character), false, `U+${code.toString(16)} reached JSON stdout`)
    assert.equal(result.stderr.includes(character), false, `U+${code.toString(16)} reached human stderr`)
  }
})

test('bidi controls in a user agent cannot reach JSON stdout or human stderr', async () => {
  for (const code of [0x200e, 0x200f, 0x202a, 0x202e, 0x2066, 0x2069]) {
    const character = String.fromCharCode(code)
    const result = await oneAgentResult(`ExampleBot${character}`)
    assertOneAgentReport(result)
    assert.equal(result.stdout.includes(character), false, `U+${code.toString(16)} reached JSON stdout`)
    assert.equal(result.stderr.includes(character), false, `U+${code.toString(16)} reached human stderr`)
  }
})

test('a visible agent with a default-ignorable suffix remains decidable without leaking it', async () => {
  const character = String.fromCharCode(0x034f)
  const result = await oneAgentResult(`ExampleBot${character}`)
  assertOneAgentReport(result)
  assert.equal(result.stdout.includes(character), false)
  assert.equal(result.stderr.includes(character), false)
})

test('--json suppresses the human summary and leaves stdout byte-identical', async () => {
  const plain = await cli(['--config', CLEAN])
  const json = await cli(['--config', CLEAN, '--json'])
  assert.equal(json.stderr, '')
  assert.equal(json.stdout, plain.stdout)
})

test('two runs over the same inputs write byte-identical stdout', async () => {
  const first = await cli(['--config', BROKEN, '--json'])
  const second = await cli(['--config', BROKEN, '--json'])
  assert.equal(first.stdout, second.stdout)
  assert.ok(first.stdout.length > 0)
})

test('--help exits 0 and writes no report to stdout', async () => {
  const result = await cli(['--help'])
  assert.equal(result.code, 0)
  assert.equal(result.stdout, '')
  assert.match(result.stderr, /Usage:\n {2}robots-policy-auditor --config FILE/)
  assert.match(result.stderr, /a disallowed URL can still be\nindexed from external links/)
})

test('an unknown option exits 2 with an empty stdout', async () => {
  const result = await cli(['--config', CLEAN, '--verbose'])
  assert.equal(result.code, 2)
  assert.equal(result.stdout, '')
  assert.match(result.stderr, /unknown option "--verbose"/)
})

test('a missing --config exits 2 with an empty stdout', async () => {
  const result = await cli(['--json'])
  assert.equal(result.code, 2)
  assert.equal(result.stdout, '')
  assert.match(result.stderr, /--config is required/)
})

test('a config file that is not there exits 2 with an empty stdout', async () => {
  const result = await cli(['--config', join(projectDirectory, 'examples/nowhere.json')])
  assert.equal(result.code, 2)
  assert.equal(result.stdout, '')
  assert.match(result.stderr, /The config could not be read/)
})

test('an unreadable input exits 2 with an incomplete report on stdout', async () => {
  const tree = await makeTree({
    'checks.json': JSON.stringify({
      schemaVersion: '1',
      checks: [{ userAgent: 'GPTBot', url: 'https://example.com/page' }],
    }),
    'audit.config.json': JSON.stringify({
      schemaVersion: '1',
      site: { origin: 'https://example.com' },
      robotsTxt: 'robots.txt',
      checks: 'checks.json',
    }),
  })
  try {
    const result = await cli(['--config', join(tree.root, 'audit.config.json'), '--json'])
    assert.equal(result.code, 2)
    const report = JSON.parse(result.stdout)
    assert.equal(report.status, 'incomplete')
    const unreadable = report.findings.find((finding) => finding.ruleId === 'input-unreadable')
    assert.equal(unreadable.location.file, 'robots.txt')
    assert.equal(unreadable.severity, 'error')
  } finally {
    await tree.dispose()
  }
})

test('--limit wires a documented limit all the way through to enforcement', async () => {
  const tree = await makeTree({
    'robots.txt': `User-agent: *\nAllow: /\n${'# padding\n'.repeat(20)}`,
    'checks.json': JSON.stringify({
      schemaVersion: '1',
      checks: [{ userAgent: 'GPTBot', url: 'https://example.com/page' }],
    }),
    'capture.json': JSON.stringify({
      schemaVersion: '1',
      responses: [{ url: 'https://example.com/page', headers: {} }],
    }),
    'audit.config.json': JSON.stringify({
      schemaVersion: '1',
      site: { origin: 'https://example.com' },
      robotsTxt: 'robots.txt',
      checks: 'checks.json',
      capture: 'capture.json',
    }),
  })
  try {
    const configFile = join(tree.root, 'audit.config.json')

    const unbounded = await cli(['--config', configFile, '--json'])
    assert.equal(unbounded.code, 0)
    assert.equal(JSON.parse(unbounded.stdout).status, 'pass')

    const bounded = await cli(['--config', configFile, '--json', '--limit', 'maxRobotsLines=5'])
    assert.equal(bounded.code, 2)
    const report = JSON.parse(bounded.stdout)
    assert.equal(report.status, 'incomplete')
    assert.ok(report.findings.some((finding) => finding.ruleId === 'limit-exceeded'))
  } finally {
    await tree.dispose()
  }
})

test('a limit override on the command line beats the one in the config', async () => {
  const tree = await makeTree({
    'robots.txt': `User-agent: *\nAllow: /\n${'# padding\n'.repeat(20)}`,
    'checks.json': JSON.stringify({
      schemaVersion: '1',
      checks: [{ userAgent: 'GPTBot', url: 'https://example.com/page' }],
    }),
    'capture.json': JSON.stringify({
      schemaVersion: '1',
      responses: [{ url: 'https://example.com/page', headers: {} }],
    }),
    'audit.config.json': JSON.stringify({
      schemaVersion: '1',
      site: { origin: 'https://example.com' },
      robotsTxt: 'robots.txt',
      checks: 'checks.json',
      capture: 'capture.json',
      limits: { maxRobotsLines: 5 },
    }),
  })
  try {
    const configFile = join(tree.root, 'audit.config.json')
    assert.equal((await cli(['--config', configFile, '--json'])).code, 2)
    assert.equal((await cli(['--config', configFile, '--json', '--limit', 'maxRobotsLines=500'])).code, 0)
  } finally {
    await tree.dispose()
  }
})

test('an unknown --limit name exits 2 with an empty stdout', async () => {
  const result = await cli(['--config', CLEAN, '--limit', 'maxRobotLines=5'])
  assert.equal(result.code, 2)
  assert.equal(result.stdout, '')
  assert.match(result.stderr, /unknown limit "maxRobotLines"/)
})

test('a --limit without a value exits 2 with an empty stdout', async () => {
  for (const args of [['--limit', 'maxChecks'], ['--limit', 'maxChecks=0'], ['--limit', 'maxChecks=x']]) {
    const result = await cli(['--config', CLEAN, ...args])
    assert.equal(result.code, 2, `expected exit 2 for ${args.join(' ')}`)
    assert.equal(result.stdout, '')
  }
})

test('the help text lists every limit the tool enforces', async () => {
  const { DEFAULT_LIMITS } = await import('../src/index.mjs')
  const help = (await cli(['--help'])).stderr
  for (const name of Object.keys(DEFAULT_LIMITS)) {
    assert.ok(help.includes(`${name} (${DEFAULT_LIMITS[name]})`), `--help does not document ${name}`)
  }
})
