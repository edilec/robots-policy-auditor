import assert from 'node:assert/strict'
import test from 'node:test'

import { addressesAgent, decideIndexing, extractMetaRobots, parseXRobotsTag } from '../src/directives.mjs'

const LIMITS = { maxMetaTags: 500 }

function names(parsed) {
  return parsed.directives.map((directive) => directive.name)
}

test('an unscoped X-Robots-Tag addresses every agent', () => {
  const parsed = parseXRobotsTag('noindex, nofollow')
  assert.equal(parsed.agent, '*')
  assert.deepEqual(names(parsed), ['noindex', 'nofollow'])
  assert.deepEqual(parsed.problems, [])
})

test('an X-Robots-Tag can be scoped to one product token', () => {
  const parsed = parseXRobotsTag('googlebot: noindex, nofollow')
  assert.equal(parsed.agent, 'googlebot')
  assert.deepEqual(names(parsed), ['noindex', 'nofollow'])
})

test('a directive that contains a colon is not mistaken for an agent scope', () => {
  const parsed = parseXRobotsTag('unavailable_after: 2027-01-01T00:00:00Z')
  assert.equal(parsed.agent, '*')
  assert.deepEqual(names(parsed), ['unavailable_after'])
})

test('a parameterised directive keeps its name and stays unscoped', () => {
  const parsed = parseXRobotsTag('max-snippet: -1, max-image-preview: large')
  assert.equal(parsed.agent, '*')
  assert.deepEqual(names(parsed), ['max-snippet', 'max-image-preview'])
  assert.deepEqual(parsed.problems, [])
})

test('a misspelled directive is reported rather than silently ignored', () => {
  const parsed = parseXRobotsTag('no-index')
  assert.deepEqual(
    parsed.problems.map((problem) => [problem.ruleId, problem.name]),
    [['unknown-index-directive', 'no-index']],
  )
  assert.equal(decideIndexing([{ ...parsed, kind: 'header' }]).state, 'indexable')
})

test('directive names are compared case-insensitively', () => {
  assert.deepEqual(names(parseXRobotsTag('NoIndex, NOFOLLOW')), ['noindex', 'nofollow'])
})

test('a robots meta element in the head is read', () => {
  const html = [
    '<!doctype html>',
    '<html><head>',
    '<meta charset="utf-8">',
    '<meta name="robots" content="noindex, nofollow">',
    '</head><body></body></html>',
  ].join('\n')
  const extracted = extractMetaRobots(html, LIMITS)
  assert.deepEqual(
    extracted.metas.map((meta) => [meta.agent, meta.content, meta.line, meta.effective]),
    [['*', 'noindex, nofollow', 4, true]],
  )
})

test('an agent-scoped meta element keeps its agent', () => {
  const html = '<html><head><meta name="googlebot" content="noindex"></head></html>'
  const extracted = extractMetaRobots(html, LIMITS)
  assert.deepEqual(
    extracted.metas.map((meta) => [meta.agent, meta.effective]),
    [['googlebot', true]],
  )
})

test('a meta element after the head is reported as ineffective, not as a block', () => {
  const html = [
    '<html>',
    '<head><title>t</title></head>',
    '<body>',
    '<meta name="robots" content="noindex">',
    '</body>',
    '</html>',
  ].join('\n')
  const extracted = extractMetaRobots(html, LIMITS)
  assert.deepEqual(
    extracted.metas.map((meta) => [meta.line, meta.effective]),
    [[4, false]],
  )
})

test('a directive inside an HTML comment is not a directive', () => {
  const html = [
    '<html><head>',
    '<!-- <meta name="robots" content="noindex"> was removed in 2025 -->',
    '<meta name="robots" content="all">',
    '</head></html>',
  ].join('\n')
  const extracted = extractMetaRobots(html, LIMITS)
  assert.deepEqual(
    extracted.metas.map((meta) => [meta.content, meta.line]),
    [['all', 3]],
  )
})

test('a directive inside a script body is not a directive', () => {
  const html = [
    '<html><head>',
    '<script>',
    'const template = \'<meta name="robots" content="noindex">\'',
    '</script>',
    '<meta name="robots" content="index">',
    '</head></html>',
  ].join('\n')
  const extracted = extractMetaRobots(html, LIMITS)
  assert.deepEqual(
    extracted.metas.map((meta) => [meta.content, meta.line]),
    [['index', 5]],
  )
})

test('a meta element that is not about robots is ignored', () => {
  const html = [
    '<html><head>',
    '<meta name="viewport" content="width=device-width">',
    '<meta name="description" content="noindex is discussed in this article">',
    '<meta property="og:title" content="noindex">',
    '</head></html>',
  ].join('\n')
  assert.deepEqual(extractMetaRobots(html, LIMITS).metas, [])
})

test('a misspelled meta directive is reported with its line', () => {
  const html = ['<html><head>', '<meta name="robots" content="no-index">', '</head></html>'].join('\n')
  const extracted = extractMetaRobots(html, LIMITS)
  assert.deepEqual(
    extracted.problems.map((problem) => [problem.ruleId, problem.name, problem.line]),
    [['unknown-index-directive', 'no-index', 2]],
  )
})

test('single quotes, no quotes and odd spacing are all read', () => {
  const html = [
    '<html><head>',
    "<meta name='robots' content='noindex'>",
    '<meta   name = "robots"   content = "nofollow" >',
    '<meta name=robots content=noarchive>',
    '</head></html>',
  ].join('\n')
  const extracted = extractMetaRobots(html, LIMITS)
  assert.deepEqual(
    extracted.metas.map((meta) => meta.content),
    ['noindex', 'nofollow', 'noarchive'],
  )
})

test('an element whose name merely starts with "meta" is not a meta element', () => {
  const html = '<html><head><metadata name="robots" content="noindex"></metadata></head></html>'
  assert.deepEqual(extractMetaRobots(html, LIMITS).metas, [])
})

test('the meta limit stops extraction and names itself', () => {
  const body = Array.from({ length: 8 }, () => '<meta name="robots" content="noindex">').join('\n')
  const extracted = extractMetaRobots(`<html><head>\n${body}\n</head></html>`, { maxMetaTags: 3 })
  assert.deepEqual(extracted.truncated, { limit: 'maxMetaTags', value: 3, actual: 4 })
})

test('an agent scope of "*" addresses every agent, and a named one only itself', () => {
  assert.equal(addressesAgent('*', 'GPTBot'), true)
  assert.equal(addressesAgent('googlebot', 'GoogleBot'), true)
  assert.equal(addressesAgent('googlebot', 'GPTBot'), false)
})

test('no directive at all is indexable, and says so with no winner', () => {
  assert.deepEqual(decideIndexing([]), { state: 'indexable', winner: null, conflicting: null, timeDependent: null })
})

test('a blocking directive wins over a permitting one and is named as the winner', () => {
  const header = { kind: 'header', agent: '*', directives: [{ name: 'noindex', raw: 'noindex' }], content: 'noindex' }
  const meta = { kind: 'meta', agent: '*', directives: [{ name: 'index', raw: 'index' }], content: 'index' }
  const decision = decideIndexing([header, meta])
  assert.equal(decision.state, 'blocked')
  assert.equal(decision.winner, header)
  assert.equal(decision.conflicting, meta)
})

test('"none" blocks indexing just as "noindex" does', () => {
  const meta = { kind: 'meta', agent: '*', directives: [{ name: 'none', raw: 'none' }], content: 'none' }
  assert.equal(decideIndexing([meta]).state, 'blocked')
})

test('a time-dependent directive is neither indexable nor blocked', () => {
  const header = {
    kind: 'header',
    agent: '*',
    directives: [{ name: 'unavailable_after', raw: 'unavailable_after: 2027-01-01' }],
    content: 'unavailable_after: 2027-01-01',
  }
  const decision = decideIndexing([header])
  assert.equal(decision.state, 'time-dependent')
  assert.equal(decision.winner, header)
})
