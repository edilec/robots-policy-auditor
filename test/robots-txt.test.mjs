import assert from 'node:assert/strict'
import test from 'node:test'

import {
  decideCrawl,
  extractProductToken,
  matchTargetOf,
  normalizePattern,
  octetLength,
  parseRobotsTxt,
  patternMatches,
  selectGroups,
} from '../src/robots-txt.mjs'

const LIMITS = { maxRobotsLines: 10000, maxGroups: 1000, maxRulesPerGroup: 5000 }

function parse(text, overrides = {}) {
  return parseRobotsTxt(text, { ...LIMITS, ...overrides })
}

function decide(text, agent, url) {
  const parsed = parse(text)
  return decideCrawl(parsed.groups, agent, new URL(url))
}

/**
 * A fixture with the structure of the example in RFC 9309 section 5.1: a global
 * group with a wildcard rule and an end-anchored rule, an agent group that
 * re-opens paths its own Disallow closed, one group naming two agents, and a
 * group with no rules at all. The paths are this project's own.
 *
 * Line numbers are asserted, so the layout below is part of the fixture.
 *   1 User-Agent: *            5 (blank)               11 User-Agent: barbot
 *   2 Disallow: *.gif$         6 User-Agent: foobot    12 User-Agent: bazbot
 *   3 Disallow: /catalog/      7 Disallow: /           13 Disallow: /catalog/page.html
 *   4 Allow: /publications/    8 Allow: /catalog/page.html
 *                              9 Allow: /catalog/allowed.gif
 *                             15 User-Agent: quxbot
 */
const STANDARD = [
  'User-Agent: *',
  'Disallow: *.gif$',
  'Disallow: /catalog/',
  'Allow: /publications/',
  '',
  'User-Agent: foobot',
  'Disallow: /',
  'Allow: /catalog/page.html',
  'Allow: /catalog/allowed.gif',
  '',
  'User-Agent: barbot',
  'User-Agent: bazbot',
  'Disallow: /catalog/page.html',
  '',
  'User-Agent: quxbot',
  '',
].join('\n')

const STANDARD_CASES = [
  {
    what: 'an agent group re-opens a path its own Disallow closed',
    agent: 'foobot',
    url: 'https://example.com/catalog/page.html',
    expected: { permission: 'allow', agentMatch: 'specific', type: 'allow', raw: '/catalog/page.html', line: 8 },
  },
  {
    what: 'the blanket Disallow still applies where no Allow is longer',
    agent: 'foobot',
    url: 'https://example.com/catalog/other.html',
    expected: { permission: 'disallow', agentMatch: 'specific', type: 'disallow', raw: '/', line: 7 },
  },
  {
    what: 'the global group does not reach an agent that has its own group',
    agent: 'foobot',
    url: 'https://example.com/catalog/allowed.gif',
    expected: { permission: 'allow', agentMatch: 'specific', type: 'allow', raw: '/catalog/allowed.gif', line: 9 },
  },
  {
    what: 'a group naming two agents governs the first of them',
    agent: 'barbot',
    url: 'https://example.com/catalog/page.html',
    expected: { permission: 'disallow', agentMatch: 'specific', type: 'disallow', raw: '/catalog/page.html', line: 13 },
  },
  {
    what: 'a group naming two agents governs the second of them',
    agent: 'bazbot',
    url: 'https://example.com/catalog/page.html',
    expected: { permission: 'disallow', agentMatch: 'specific', type: 'disallow', raw: '/catalog/page.html', line: 13 },
  },
  {
    what: 'an agent with a group of its own is not governed by the global group',
    agent: 'barbot',
    url: 'https://example.com/catalog/other.html',
    expected: { permission: 'allow', agentMatch: 'specific', type: null, raw: null, line: null },
  },
  {
    what: 'a group with no rules leaves its agent unrestricted',
    agent: 'quxbot',
    url: 'https://example.com/catalog/page.html',
    expected: { permission: 'allow', agentMatch: 'specific', type: null, raw: null, line: null },
  },
  {
    what: 'an unknown agent falls back to the global group',
    agent: 'unknownbot',
    url: 'https://example.com/catalog/page.html',
    expected: { permission: 'disallow', agentMatch: 'global', type: 'disallow', raw: '/catalog/', line: 3 },
  },
  {
    what: 'an unknown agent is caught by an end-anchored wildcard rule',
    agent: 'unknownbot',
    url: 'https://example.com/image.gif',
    expected: { permission: 'disallow', agentMatch: 'global', type: 'disallow', raw: '*.gif$', line: 2 },
  },
  {
    what: 'the longer rule wins when a wildcard rule and a prefix rule both match',
    agent: 'unknownbot',
    url: 'https://example.com/publications/report.gif',
    expected: { permission: 'allow', agentMatch: 'global', type: 'allow', raw: '/publications/', line: 4 },
  },
  {
    what: 'the longest match wins between two disallow rules',
    agent: 'unknownbot',
    url: 'https://example.com/catalog/allowed.gif',
    expected: { permission: 'disallow', agentMatch: 'global', type: 'disallow', raw: '/catalog/', line: 3 },
  },
  {
    what: 'product tokens are matched case-insensitively',
    agent: 'FooBot',
    url: 'https://example.com/catalog/page.html',
    expected: { permission: 'allow', agentMatch: 'specific', type: 'allow', raw: '/catalog/page.html', line: 8 },
  },
  {
    what: 'the query string is part of what a rule matches',
    agent: 'unknownbot',
    url: 'https://example.com/catalog/?page=2',
    expected: { permission: 'disallow', agentMatch: 'global', type: 'disallow', raw: '/catalog/', line: 3 },
  },
]

for (const scenario of STANDARD_CASES) {
  test(`RFC 9309: ${scenario.what}`, () => {
    const decision = decide(STANDARD, scenario.agent, scenario.url)
    assert.deepEqual(
      {
        permission: decision.permission,
        agentMatch: decision.agentMatch,
        type: decision.rule === null ? null : decision.rule.type,
        raw: decision.rule === null ? null : decision.rule.raw,
        line: decision.rule === null ? null : decision.rule.line,
      },
      scenario.expected,
    )
  })
}

test('an Allow beats a Disallow of the same length', () => {
  const text = ['User-agent: *', 'Allow: /folder', 'Disallow: /folder'].join('\n')
  const decision = decide(text, 'anybot', 'https://example.com/folder/page')
  assert.equal(decision.permission, 'allow')
  assert.equal(decision.rule.line, 2)
})

test('an Allow beats a Disallow of the same length whichever is written first', () => {
  const text = ['User-agent: *', 'Disallow: /folder', 'Allow: /folder'].join('\n')
  const decision = decide(text, 'anybot', 'https://example.com/folder/page')
  assert.equal(decision.permission, 'allow')
  assert.equal(decision.rule.line, 3)
})

test('a longer Disallow beats a shorter Allow', () => {
  const text = ['User-agent: *', 'Allow: /page', 'Disallow: /*.htm'].join('\n')
  const decision = decide(text, 'anybot', 'https://example.com/page.htm')
  assert.deepEqual(
    { permission: decision.permission, raw: decision.rule.raw },
    { permission: 'disallow', raw: '/*.htm' },
  )
})

test('an end-anchored root Allow opens only the root', () => {
  const text = ['User-agent: *', 'Disallow: /', 'Allow: /$'].join('\n')
  assert.equal(decide(text, 'anybot', 'https://example.com/').permission, 'allow')
  assert.equal(decide(text, 'anybot', 'https://example.com/page').permission, 'disallow')
})

test('an empty Disallow value places no restriction', () => {
  const parsed = parse(['User-agent: *', 'Disallow:'].join('\n'))
  assert.deepEqual(parsed.groups[0].rules, [])
  assert.equal(decide(['User-agent: *', 'Disallow:'].join('\n'), 'anybot', 'https://example.com/x').permission, 'allow')
})

test('a robots.txt with no group at all leaves every agent unrestricted', () => {
  const decision = decide('# nothing here\n', 'anybot', 'https://example.com/x')
  assert.deepEqual(
    { permission: decision.permission, agentMatch: decision.agentMatch, rule: decision.rule },
    { permission: 'allow', agentMatch: 'none', rule: null },
  )
})

test('groups naming the same product token are merged', () => {
  const text = [
    'User-agent: examplebot',
    'Disallow: /one',
    '',
    'User-agent: examplebot',
    'Disallow: /two',
  ].join('\n')
  assert.equal(decide(text, 'examplebot', 'https://example.com/one').permission, 'disallow')
  assert.equal(decide(text, 'examplebot', 'https://example.com/two').permission, 'disallow')
  const duplicate = parse(text).problems.filter((problem) => problem.ruleId === 'duplicate-group')
  assert.equal(duplicate.length, 1)
  assert.equal(duplicate[0].line, 1)
})

test('a user-agent line after rules opens a new group, not a second agent for the old one', () => {
  const text = ['User-agent: onebot', 'Disallow: /one', 'User-agent: twobot', 'Disallow: /two'].join('\n')
  const parsed = parse(text)
  assert.equal(parsed.groups.length, 2)
  assert.equal(decide(text, 'onebot', 'https://example.com/two').permission, 'allow')
  assert.equal(decide(text, 'twobot', 'https://example.com/two').permission, 'disallow')
})

test('percent-encoding is normalized on both sides before matching', () => {
  const encoded = ['User-agent: *', 'Disallow: /caf%C3%A9/'].join('\n')
  const literal = ['User-agent: *', 'Disallow: /café/'].join('\n')
  const url = 'https://example.com/café/menu'
  assert.equal(decide(encoded, 'anybot', url).permission, 'disallow')
  assert.equal(decide(literal, 'anybot', url).permission, 'disallow')
})

test('an escaped separator is not the same octet as a separator', () => {
  const text = ['User-agent: *', 'Disallow: /a%2Fb'].join('\n')
  assert.equal(decide(text, 'anybot', 'https://example.com/a/b').permission, 'allow')
  assert.equal(decide(text, 'anybot', 'https://example.com/a%2Fb').permission, 'disallow')
})

test('percent escapes of unreserved octets are decoded, and reserved ones keep uppercase hex', () => {
  assert.equal(normalizePattern('/%7Euser/%2fpath%3f'), '/~user/%2Fpath%3F')
  assert.equal(matchTargetOf(new URL('https://example.com/%7Euser?q=1')), '/~user?q=1')
})

test('a trailing percent sign is left alone rather than mis-decoded', () => {
  assert.equal(normalizePattern('/discount%'), '/discount%')
  assert.equal(normalizePattern('/discount%A'), '/discount%A')
})

test('pattern length is measured in octets, not in characters', () => {
  assert.equal(octetLength('/café'), 6)
  assert.equal(octetLength(normalizePattern('/café')), 10)
})

const PATTERN_CASES = [
  { pattern: '/', target: '/anything', matches: true },
  { pattern: '/fish', target: '/fish.html', matches: true },
  { pattern: '/fish', target: '/Fish.html', matches: false },
  { pattern: '/fish*', target: '/fishheads/yummy.html', matches: true },
  { pattern: '/fish/', target: '/fish', matches: false },
  { pattern: '/*.php', target: '/index.php', matches: true },
  { pattern: '/*.php', target: '/windows.PHP', matches: false },
  { pattern: '/*.php$', target: '/filename.php', matches: true },
  { pattern: '/*.php$', target: '/filename.php?parameters', matches: false },
  { pattern: '/fish*.php', target: '/fish.php', matches: true },
  { pattern: '/fish*.php', target: '/fishheads/catfish.php?parameters', matches: true },
  { pattern: '/$', target: '/', matches: true },
  { pattern: '/$', target: '/page', matches: false },
  { pattern: '*', target: '/anything', matches: true },
  { pattern: '/a*b*c', target: '/axxbxxc', matches: true },
  { pattern: '/a*b*c', target: '/axxcxxb', matches: false },
  { pattern: '/a*$', target: '/abc', matches: true },
  { pattern: '/price$sale', target: '/price$sale', matches: true },
]

for (const scenario of PATTERN_CASES) {
  test(`pattern "${scenario.pattern}" ${scenario.matches ? 'matches' : 'does not match'} "${scenario.target}"`, () => {
    assert.equal(patternMatches(scenario.pattern, scenario.target), scenario.matches)
  })
}

test('a product token is the leading run of letters, dashes and underscores', () => {
  assert.equal(extractProductToken('ExampleBot/2.0 (+https://example.com/bot)'), 'ExampleBot')
  assert.equal(extractProductToken('*'), '*')
  assert.equal(extractProductToken('* # every agent'), '*')
  // A leading "*" is the global group only when it stands alone, so "*bot"
  // names no usable token at all -- which is reported rather than guessed at.
  assert.equal(extractProductToken('*bot'), null)
  assert.equal(extractProductToken('   '), null)
  assert.equal(extractProductToken('2bot'), null)
})

test('group selection reports whether the agent, the global group or nothing matched', () => {
  const parsed = parse(STANDARD)
  assert.equal(selectGroups(parsed.groups, 'foobot').match, 'specific')
  assert.equal(selectGroups(parsed.groups, 'nosuchbot').match, 'global')
  assert.equal(selectGroups(parse('User-agent: onlybot\nDisallow: /').groups, 'otherbot').match, 'none')
})

/**
 * RFC 9309 section 2.2.1: a product token is compared in full. Prefix or
 * substring matching is the failure that silently hands one agent another
 * agent's rules — `GPTBot` governed by the group written for `GPTBot-Image`,
 * or `ExampleBot` by the group written for `Example` — and it flips real crawl
 * decisions in both directions, which is why both are asserted here.
 */
test('a product token is compared in full, never as a prefix', () => {
  const longerToken = ['User-agent: GPTBot-Image', 'Disallow: /', '', 'User-agent: *', 'Allow: /'].join('\n')
  const shorterToken = ['User-agent: Example', 'Disallow: /', '', 'User-agent: *', 'Allow: /'].join('\n')

  // The group's token extends past the agent's name: not this agent's group.
  const other = decide(longerToken, 'GPTBot', 'https://example.com/page')
  assert.equal(other.agentMatch, 'global')
  assert.equal(other.permission, 'allow')
  // The agent's name extends past the group's token: still not its group.
  const longer = decide(shorterToken, 'ExampleBot', 'https://example.com/page')
  assert.equal(longer.agentMatch, 'global')
  assert.equal(longer.permission, 'allow')
  // And the agent the group was written for is governed by it.
  const own = decide(longerToken, 'GPTBot-Image', 'https://example.com/page')
  assert.equal(own.agentMatch, 'specific')
  assert.equal(own.permission, 'disallow')

  const groups = parse(longerToken).groups
  assert.equal(selectGroups(groups, 'GPTBot').match, 'global')
  assert.equal(selectGroups(groups, 'GPTBot-Image').match, 'specific')
  // In full, but not case-sensitively: the comparison must not over-correct
  // into refusing a token that differs only in case.
  assert.equal(selectGroups(groups, 'gptbot-image').match, 'specific')
  assert.equal(decide(longerToken, 'gptbot-image', 'https://example.com/page').permission, 'disallow')
})

test('syntax problems are reported with the line that produced them', () => {
  const text = [
    'Disallow: /orphan',
    'User-agent: *',
    'Disallow: relative-path',
    'Crawl-delay: 5',
    'Noindex: /legacy',
    'not a directive',
    'Made-up: value',
    'User-agent: ',
  ].join('\n')
  const parsed = parse(text)
  assert.deepEqual(
    parsed.problems.map((problem) => [problem.line, problem.ruleId]),
    [
      [1, 'rule-outside-group'],
      [3, 'invalid-rule-path'],
      [4, 'nonstandard-directive'],
      [5, 'robots-txt-noindex'],
      [6, 'malformed-line'],
      [7, 'unknown-directive'],
      [8, 'invalid-user-agent'],
      [2, 'empty-group'],
    ],
  )
})

test('a comment is stripped before a directive is read', () => {
  const parsed = parse(['User-agent: * # every crawler', 'Disallow: /secret # not really'].join('\n'))
  assert.equal(parsed.groups[0].agents[0].token, '*')
  assert.equal(parsed.groups[0].rules[0].raw, '/secret')
})

test('a sitemap declaration is read without joining a group', () => {
  const parsed = parse(['User-agent: *', 'Disallow: /x', 'Sitemap: https://example.com/sitemap.xml'].join('\n'))
  assert.deepEqual(parsed.sitemaps, [{ value: 'https://example.com/sitemap.xml', line: 3 }])
  assert.equal(parsed.groups[0].rules.length, 1)
})

test('the line limit stops the parse and names itself', () => {
  const text = Array.from({ length: 12 }, () => 'User-agent: *').join('\n')
  const parsed = parse(text, { maxRobotsLines: 5 })
  assert.deepEqual(parsed.truncated, { limit: 'maxRobotsLines', value: 5, actual: 12 })
  assert.deepEqual(parsed.groups, [])
})

test('the group limit stops the parse and names itself', () => {
  const text = Array.from({ length: 6 }, (unused, index) => `User-agent: bot${index}\nDisallow: /x`).join('\n')
  const parsed = parse(text, { maxGroups: 3 })
  assert.equal(parsed.truncated.limit, 'maxGroups')
  assert.equal(parsed.truncated.value, 3)
})

test('the rules-per-group limit stops the parse and names itself', () => {
  const text = ['User-agent: *', ...Array.from({ length: 8 }, (unused, index) => `Disallow: /p${index}`)].join('\n')
  const parsed = parse(text, { maxRulesPerGroup: 4 })
  assert.equal(parsed.truncated.limit, 'maxRulesPerGroup')
  assert.equal(parsed.truncated.value, 4)
})

test('a BOM-free CRLF file parses the same as an LF one', () => {
  const lf = parse(['User-agent: *', 'Disallow: /x'].join('\n'))
  const crlf = parse(['User-agent: *', 'Disallow: /x'].join('\r\n'))
  assert.deepEqual(
    crlf.groups.map((group) => group.rules.map((rule) => rule.raw)),
    lf.groups.map((group) => group.rules.map((rule) => rule.raw)),
  )
})
