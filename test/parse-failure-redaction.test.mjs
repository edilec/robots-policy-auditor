import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { cp, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'

import { parseFailureDetail } from '../src/report.mjs'

const run = promisify(execFile)
const projectDirectory = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const CLI = join(projectDirectory, 'bin/robots-policy-auditor.mjs')
const CLEAN_DIRECTORY = join(projectDirectory, 'examples/clean')
const CONFIG_NAME = 'robots-audit.config.json'

/**
 * A parse failure does not quote the document it failed on.
 *
 * V8 reports a parse failure two ways, and one of them embeds the input:
 * `Unexpected token 'A', "AKIAIOSFODNN7EXAMPLE" is not valid JSON`.
 * `readJsonDocument` interpolated that message, and it is the reader for the
 * config, the checks document and the capture alike, so a document short enough
 * to be nothing but a credential was reproduced in full -- in the report on
 * stdout, in the human summary on stderr, and in the config refusal on stderr.
 * `excerpt` never helped and never could: it cuts from the end and the quoted
 * span is at the front.
 *
 * The canary is the AWS documentation placeholder, not a key. Every assertion
 * walks it down to eight characters, because V8 quotes a ten-character window
 * once the input is long enough: asserting only the whole string passes while
 * ten characters of the secret still ship.
 */

const CANARY = 'AKIAIOSFODNN7EXAMPLE'
const SHORTEST_PREFIX = 8

async function cli(args) {
  try {
    const { stdout, stderr } = await run(process.execPath, [CLI, ...args])
    return { code: 0, stdout, stderr }
  } catch (error) {
    return { code: error.code ?? 1, stdout: error.stdout ?? '', stderr: error.stderr ?? '' }
  }
}

/** Every prefix of the canary from eight characters to its full length. */
function assertNoPrefix({ stdout, stderr }) {
  for (let length = SHORTEST_PREFIX; length <= CANARY.length; length += 1) {
    const prefix = CANARY.slice(0, length)
    assert.equal(stdout.includes(prefix), false, `stdout carried the first ${length} characters of the canary`)
    assert.equal(stderr.includes(prefix), false, `stderr carried the first ${length} characters of the canary`)
  }
}

/** A copy of the clean example with one file replaced by the given text. */
async function withReplaced(name, text, body) {
  const root = await mkdtemp(join(tmpdir(), 'robots-policy-auditor-parse-failure-'))
  try {
    await cp(CLEAN_DIRECTORY, root, { recursive: true })
    await writeFile(join(root, name), text)
    const result = await cli(['--config', join(root, CONFIG_NAME)])
    assertNoPrefix(result)
    return await body(result)
  } finally {
    await rm(root, { recursive: true, force: true })
  }
}

test('a checks document that is only a credential is not echoed by its own parse error', async () => {
  await withReplaced('checks.json', CANARY, ({ code, stdout, stderr }) => {
    assert.equal(code, 2)
    const finding = JSON.parse(stdout).findings.find((row) => row.message.includes('not valid JSON'))
    assert.notEqual(finding, undefined, 'the run still said the checks document was not JSON')
    assert.match(finding.message, /token/, 'the diagnostic still says what went wrong')
    assert.match(stderr, /not valid JSON/, 'the human summary still says the document was unreadable')
  })
})

test('a config that is only a credential is not echoed on stderr', async () => {
  await withReplaced(CONFIG_NAME, CANARY, ({ code, stderr }) => {
    assert.equal(code, 2)
    assert.match(stderr, /The config is not valid JSON/, 'the refusal still says why the config was refused')
  })
})

test('a document that fails after a valid property keeps its position, line and column', async () => {
  // V8 answers this one with the safe spelling: a position and no quoted span.
  // A parse error that says nothing is a different defect.
  await withReplaced('checks.json', `{"schemaVersion": "1" ${CANARY}}`, ({ stdout }) => {
    const finding = JSON.parse(stdout).findings.find((row) => row.message.includes('not valid JSON'))
    assert.match(finding.message, /at position \d+/, 'the position a reader needs is still there')
    assert.match(finding.message, /line \d+ column \d+/, 'line and column are still there')
  })
})

test('a secret deep inside a longer document is not echoed by the windowed spelling', async () => {
  // The third V8 spelling quotes a window rather than a prefix and carries no
  // position; only the offending token survives it.
  await withReplaced('checks.json', `{"schemaVersion": "1", "checks": ${CANARY}}`, ({ stdout }) => {
    const finding = JSON.parse(stdout).findings.find((row) => row.message.includes('not valid JSON'))
    assert.match(finding.message, /unexpected token/)
  })
})

test('parseFailureDetail keeps the position and drops the quoted input', () => {
  const caught = (text) => {
    try {
      JSON.parse(text)
      return null
    } catch (error) {
      return error
    }
  }

  const quoted = caught(CANARY)
  assert.equal(quoted.message.includes(CANARY), true, 'V8 still quotes the input, so this test still has a subject')
  assert.equal(parseFailureDetail(quoted).includes(CANARY.slice(0, SHORTEST_PREFIX)), false)

  const detail = parseFailureDetail(caught(`{"a": 1 ${CANARY}}`))
  assert.equal(detail.includes(CANARY.slice(0, SHORTEST_PREFIX)), false)
  assert.match(detail, /at position \d+ \(line \d+ column \d+\)$/)

  assert.equal(parseFailureDetail(caught('password=hunter2-correct-horse')).includes('password'), false)
  assert.equal(parseFailureDetail(caught('')), 'Unexpected end of JSON input')
  assert.equal(parseFailureDetail(undefined), 'the document could not be parsed as JSON')
})
