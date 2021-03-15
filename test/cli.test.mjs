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
