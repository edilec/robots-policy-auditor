import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { mkdtemp, mkdir, rm, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'

import { ConfigError, auditRobotsPolicy } from '../src/index.mjs'

const run = promisify(execFile)
const projectDirectory = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const CLI = join(projectDirectory, 'bin/robots-policy-auditor.mjs')

/**
 * Rejecting "../" and absolute paths is not confinement.
 *
 * A symbolic link planted inside the declared root points wherever it likes,
 * and a checker that only inspects the spelling of a path follows it straight
 * out of the tree — then echoes what it read into the report. These tests plant
 * links to a file and to a directory outside the root and assert that nothing
 * from outside reaches any output stream.
 */

const MARKER = 'OUT-OF-ROOT-CANARY-Sv7Qd'

/**
 * Build an input root beside a sibling directory that is outside it. Returns
 * both paths and a disposer.
 */
async function makeSandbox() {
  const base = await mkdtemp(join(tmpdir(), 'robots-policy-auditor-confine-'))
  const root = join(base, 'site')
  const outside = join(base, 'outside')
  await mkdir(root, { recursive: true })
  await mkdir(outside, { recursive: true })

  await writeFile(join(outside, 'secret.txt'), `User-agent: *\nDisallow: /${MARKER}\n`)
  await writeFile(join(outside, 'secret.html'), `<html><head><meta name="robots" content="${MARKER}"></head></html>`)
  await writeFile(
    join(outside, 'checks.json'),
    JSON.stringify({ schemaVersion: '1', checks: [{ userAgent: MARKER, url: 'https://example.com/page' }] }),
  )
  await writeFile(join(root, 'robots.txt'), 'User-agent: *\nAllow: /\n')
  await writeFile(
    join(root, 'checks.json'),
    JSON.stringify({ schemaVersion: '1', checks: [{ userAgent: 'GPTBot', url: 'https://example.com/page' }] }),
  )

  return { base, root, outside, dispose: () => rm(base, { recursive: true, force: true }) }
}

async function writeConfig(root, extra) {
  const document = {
    schemaVersion: '1',
    site: { origin: 'https://example.com' },
    robotsTxt: 'robots.txt',
    checks: 'checks.json',
    ...extra,
  }
  await writeFile(join(root, 'audit.config.json'), JSON.stringify(document))
  return join(root, 'audit.config.json')
}

async function refusalFor(configFile) {
  try {
    const report = await auditRobotsPolicy({ configFile })
    assert.fail(`expected a refusal, got status ${report.status}: ${JSON.stringify(report)}`)
  } catch (error) {
    assert.ok(error instanceof ConfigError, `expected ConfigError, got ${error.name}: ${error.message}`)
    assert.ok(!error.message.includes(MARKER), 'the refusal must not echo out-of-root content')
    return error
  }
}

test('a robots.txt symlinked to a file outside the root is refused, not followed', async () => {
  const sandbox = await makeSandbox()
  try {
    await rm(join(sandbox.root, 'robots.txt'))
    await symlink(join(sandbox.outside, 'secret.txt'), join(sandbox.root, 'robots.txt'))
    const error = await refusalFor(await writeConfig(sandbox.root, {}))
    assert.equal(error.rule, 'input-escapes-root')
    assert.match(error.message, /Nothing was read from it/)
  } finally {
    await sandbox.dispose()
  }
})

test('a path through a symlinked directory outside the root is refused, not followed', async () => {
  const sandbox = await makeSandbox()
  try {
    await symlink(sandbox.outside, join(sandbox.root, 'linked'))
    const error = await refusalFor(await writeConfig(sandbox.root, { robotsTxt: 'linked/secret.txt' }))
    assert.equal(error.rule, 'input-escapes-root')
  } finally {
    await sandbox.dispose()
  }
})

test('a checks document symlinked outside the root is refused, not followed', async () => {
  const sandbox = await makeSandbox()
  try {
    await symlink(join(sandbox.outside, 'checks.json'), join(sandbox.root, 'linked-checks.json'))
    const error = await refusalFor(await writeConfig(sandbox.root, { checks: 'linked-checks.json' }))
    assert.equal(error.rule, 'input-escapes-root')
  } finally {
    await sandbox.dispose()
  }
})

test('a captured document symlinked outside the root is refused, not followed', async () => {
  const sandbox = await makeSandbox()
  try {
    await mkdir(join(sandbox.root, 'capture'), { recursive: true })
    await symlink(join(sandbox.outside, 'secret.html'), join(sandbox.root, 'capture/page.html'))
    await writeFile(
      join(sandbox.root, 'capture.json'),
      JSON.stringify({
        schemaVersion: '1',
        responses: [{ url: 'https://example.com/page', html: 'capture/page.html' }],
      }),
    )
    const error = await refusalFor(await writeConfig(sandbox.root, { capture: 'capture.json' }))
    assert.equal(error.rule, 'input-escapes-root')
    assert.match(error.message, /capture responses\[0\].html/)
  } finally {
    await sandbox.dispose()
  }
})

test('a relative path that climbs out of the root is refused', async () => {
  const sandbox = await makeSandbox()
  try {
    const error = await refusalFor(await writeConfig(sandbox.root, { robotsTxt: '../outside/secret.txt' }))
    assert.equal(error.rule, 'input-outside-root')
  } finally {
    await sandbox.dispose()
  }
})

test('an absolute path is refused', async () => {
  const sandbox = await makeSandbox()
  try {
    const error = await refusalFor(
      await writeConfig(sandbox.root, { robotsTxt: join(sandbox.outside, 'secret.txt') }),
    )
    assert.equal(error.rule, 'input-not-relative')
  } finally {
    await sandbox.dispose()
  }
})

test('the input root itself may sit behind a symlink', async () => {
  const sandbox = await makeSandbox()
  try {
    const linkedRoot = join(sandbox.base, 'linked-site')
    await symlink(sandbox.root, linkedRoot)
    await writeConfig(sandbox.root, {})
    const report = await auditRobotsPolicy({ configFile: join(linkedRoot, 'audit.config.json') })
    assert.equal(report.summary.checked, 1)
  } finally {
    await sandbox.dispose()
  }
})

test('a refused run writes nothing to stdout and leaks nothing to stderr', async () => {
  const sandbox = await makeSandbox()
  try {
    await rm(join(sandbox.root, 'robots.txt'))
    await symlink(join(sandbox.outside, 'secret.txt'), join(sandbox.root, 'robots.txt'))
    const configFile = await writeConfig(sandbox.root, {})

    let failure = null
    try {
      await run(process.execPath, [CLI, '--config', configFile])
    } catch (error) {
      failure = error
    }
    assert.ok(failure !== null, 'the CLI must not exit 0 on a refused run')
    assert.equal(failure.code, 2)
    assert.equal(failure.stdout, '')
    assert.ok(!failure.stderr.includes(MARKER), 'stderr must not carry out-of-root content')
    assert.match(failure.stderr, /leaves the input root through a symbolic link/)
  } finally {
    await sandbox.dispose()
  }
})
