/**
 * robots.txt parsing and RFC 9309 rule matching.
 *
 * This module is pure: it takes already-decoded text and returns groups, rules
 * and structured problems. It never touches the filesystem and never decides a
 * report status, so the matching rules can be tested directly against the
 * standard without a fixture tree in the way.
 *
 * Matching follows RFC 9309 (Robots Exclusion Protocol):
 *
 *  - group selection is by product token, compared case-insensitively and in
 *    full — not as a prefix or a substring (section 2.2.1);
 *  - groups naming the same product token are merged (section 2.2.1);
 *  - an agent with no group of its own falls back to the "*" group, and with no
 *    "*" group either it is unrestricted (section 2.2.1);
 *  - within the selected group the most specific match wins, "most specific"
 *    meaning the most octets in the rule pattern, and an Allow beats a Disallow
 *    of the same length (section 2.2.2);
 *  - "*" matches any sequence of characters and a trailing "$" anchors the end
 *    of the path (section 2.2.3).
 */

/** A product token, per RFC 9309: one or more of ALPHA / "-" / "_". */
const PRODUCT_TOKEN = /^[A-Za-z_-]+/

const UNRESERVED = /^[A-Za-z0-9\-._~]$/
const HEX_PAIR = /^[0-9A-Fa-f]{2}$/

const GROUP_FIELDS = new Set(['user-agent', 'allow', 'disallow'])
const NON_GROUP_FIELDS = new Set(['sitemap'])

/**
 * Fields that are widely deployed but are not part of RFC 9309. They are
 * reported so an operator knows the tool read them and did not act on them.
 */
const NONSTANDARD_FIELDS = new Set(['crawl-delay', 'host', 'clean-param', 'request-rate', 'visit-time'])

/**
 * Extract the product token a `User-agent` value names.
 *
 * "*" is the global group only when it stands alone or is followed by
 * whitespace, matching the reference implementation: `*bot` is a product token
 * spelling, not a wildcard, because RFC 9309 gives no wildcard semantics to the
 * user-agent line at all.
 */
export function extractProductToken(value) {
  const trimmed = String(value).trim()
  if (trimmed === '') return null
  if (trimmed[0] === '*' && (trimmed.length === 1 || /\s/.test(trimmed[1]))) return '*'
  const match = PRODUCT_TOKEN.exec(trimmed)
  return match === null ? null : match[0]
}

/**
 * Normalize percent-encoding so a rule and a URL that mean the same octets
 * compare equal: percent-escapes of unreserved characters are decoded, and
 * every other escape keeps its escape with uppercase hex digits (RFC 3986
 * section 6.2.2.2).
 */
export function normalizePercentEncoding(value) {
  let out = ''
  for (let index = 0; index < value.length; index += 1) {
    const character = value[index]
    if (character !== '%' || index + 2 >= value.length) {
      out += character
      continue
    }
    const pair = value.slice(index + 1, index + 3)
    if (!HEX_PAIR.test(pair)) {
      out += character
      continue
    }
    const decoded = String.fromCharCode(Number.parseInt(pair, 16))
    out += UNRESERVED.test(decoded) ? decoded : `%${pair.toUpperCase()}`
    index += 2
  }
  return out
}

/** Percent-encode the octets a rule pattern spells literally, so it can meet a URL-encoded path. */
function encodeNonAscii(value) {
  let out = ''
  for (const character of value) {
    if (character.codePointAt(0) < 0x80) out += character
    else out += encodeURIComponent(character)
  }
  return out
}

/** The comparable form of a rule pattern: literal octets encoded, escapes normalized. */
export function normalizePattern(pattern) {
  return normalizePercentEncoding(encodeNonAscii(pattern))
}

/**
 * The comparable form of the part of a URL a robots rule applies to: the path
 * plus the query, which RFC 9309 matches together.
 */
export function matchTargetOf(url) {
  return normalizePercentEncoding(`${url.pathname}${url.search}`)
}

/** Octet length, which is what RFC 9309 compares when deciding which match is most specific. */
export function octetLength(value) {
  return Buffer.byteLength(value, 'utf8')
}

/**
 * Does a robots.txt path pattern match a target path?
 *
 * Greedy leftmost matching is correct for patterns whose only metacharacter is
 * "*", and the trailing "$" is handled by anchoring the final literal segment.
 * No regular expression is built from input, so no input can make matching
 * expensive.
 */
export function patternMatches(pattern, target) {
  let anchored = false
  let body = pattern
  if (body.endsWith('$')) {
    anchored = true
    body = body.slice(0, -1)
  }
  const segments = body.split('*')
  if (!target.startsWith(segments[0])) return false
  let position = segments[0].length

  for (let index = 1; index < segments.length; index += 1) {
    const segment = segments[index]
    const isLast = index === segments.length - 1
    if (isLast && anchored) {
      if (segment === '') return true
      return target.endsWith(segment) && target.length - segment.length >= position
    }
    if (segment === '') continue
    const found = target.indexOf(segment, position)
    if (found === -1) return false
    position = found + segment.length
  }

  return anchored ? position === target.length : true
}

/**
 * Parse robots.txt text into groups, sitemap declarations and problems.
 *
 * Limits are enforced here rather than trusted to the caller: a robots.txt is
 * untrusted input, and a parser without bounds is one generated file away from
 * never finishing. Hitting a limit stops the parse and sets `truncated`, which
 * the caller turns into an incomplete run — never a silently shorter answer.
 */
export function parseRobotsTxt(text, limits) {
  const groups = []
  const sitemaps = []
  const problems = []
  const lines = text.split(/\r\n|\r|\n/)
  let truncated = null

  if (lines.length > limits.maxRobotsLines) {
    return {
      groups,
      sitemaps,
      problems,
      truncated: { limit: 'maxRobotsLines', value: limits.maxRobotsLines, actual: lines.length },
    }
  }

  let current = null
  let seenRule = false

  for (let index = 0; index < lines.length; index += 1) {
    const lineNumber = index + 1
    const raw = lines[index]
    const hash = raw.indexOf('#')
    const withoutComment = hash === -1 ? raw : raw.slice(0, hash)
    const trimmed = withoutComment.trim()
    if (trimmed === '') continue

    const colon = trimmed.indexOf(':')
    if (colon === -1) {
      problems.push({
        ruleId: 'malformed-line',
        line: lineNumber,
        message: `Line ${lineNumber} has no ":" separator, so it declares no directive and is ignored.`,
        evidence: trimmed,
      })
      continue
    }

    const field = trimmed.slice(0, colon).trim().toLowerCase()
    const value = trimmed.slice(colon + 1).trim()

    if (field === 'user-agent') {
      if (current === null || seenRule) {
        current = { agents: [], rules: [], startLine: lineNumber }
        groups.push(current)
        seenRule = false
        if (groups.length > limits.maxGroups) {
          truncated = { limit: 'maxGroups', value: limits.maxGroups, actual: groups.length }
          break
        }
      }
      const token = extractProductToken(value)
      if (token === null) {
        problems.push({
          ruleId: 'invalid-user-agent',
          line: lineNumber,
          message: `Line ${lineNumber} declares a user-agent with no usable product token, so the group it opens can never be selected.`,
          evidence: value,
        })
        continue
      }
      current.agents.push({ token, raw: value, line: lineNumber })
      continue
    }

    if (field === 'allow' || field === 'disallow') {
      if (current === null) {
        problems.push({
          ruleId: 'rule-outside-group',
          line: lineNumber,
          message: `Line ${lineNumber} declares "${field}" before any user-agent line, so it belongs to no group and is ignored.`,
          evidence: trimmed,
        })
        continue
      }
      seenRule = true
      if (value === '') {
        // "Disallow:" with an empty value places no restriction, and "Allow:"
        // with an empty value grants nothing beyond the default. Both are valid
        // and both match nothing, so neither becomes a rule.
        continue
      }
      if (!value.startsWith('/') && !value.startsWith('*')) {
        problems.push({
          ruleId: 'invalid-rule-path',
          line: lineNumber,
          message: `Line ${lineNumber} declares a ${field} path that begins with neither "/" nor "*", which RFC 9309 does not define, so the rule is ignored.`,
          evidence: value,
        })
        continue
      }
      current.rules.push({
        type: field,
        pattern: normalizePattern(value),
        raw: value,
        line: lineNumber,
      })
      if (current.rules.length > limits.maxRulesPerGroup) {
        truncated = { limit: 'maxRulesPerGroup', value: limits.maxRulesPerGroup, actual: current.rules.length }
        break
      }
      continue
    }

    if (field === 'noindex') {
      problems.push({
        ruleId: 'robots-txt-noindex',
        line: lineNumber,
        message: `Line ${lineNumber} declares "noindex" in robots.txt. That is not part of RFC 9309, the major crawlers do not honour it, and it removes nothing from an index.`,
        evidence: trimmed,
      })
      continue
    }

    if (NON_GROUP_FIELDS.has(field)) {
      sitemaps.push({ value, line: lineNumber })
      continue
    }

    if (NONSTANDARD_FIELDS.has(field)) {
      problems.push({
        ruleId: 'nonstandard-directive',
        line: lineNumber,
        message: `Line ${lineNumber} declares "${field}", which is outside RFC 9309. It was read but takes no part in any decision here.`,
        evidence: trimmed,
      })
      continue
    }

    problems.push({
      ruleId: 'unknown-directive',
      line: lineNumber,
      message: `Line ${lineNumber} declares the unrecognised directive "${field.slice(0, 40)}", which no crawler is required to act on.`,
      evidence: trimmed,
    })
  }

  for (const group of groups) {
    if (group.rules.length === 0 && group.agents.length > 0) {
      problems.push({
        ruleId: 'empty-group',
        line: group.startLine,
        message: `The group opened at line ${group.startLine} declares no allow or disallow rule, so every URL is crawlable for the agents it names.`,
        evidence: group.agents.map((agent) => agent.token).join(', '),
      })
    }
  }

  const tokenLines = new Map()
  for (const group of groups) {
    for (const agent of group.agents) {
      const key = agent.token.toLowerCase()
      if (!tokenLines.has(key)) tokenLines.set(key, [])
      tokenLines.get(key).push(agent.line)
    }
  }
  const duplicateTokens = [...tokenLines.entries()]
    .filter(([, seenLines]) => seenLines.length > 1)
    .sort((left, right) => (left[0] === right[0] ? 0 : left[0] < right[0] ? -1 : 1))
  for (const [token, seenLines] of duplicateTokens) {
    problems.push({
      ruleId: 'duplicate-group',
      line: seenLines[0],
      message: `The product token "${token.slice(0, 40)}" heads more than one group (lines ${seenLines.join(', ')}). RFC 9309 merges those records, and so does this tool.`,
      evidence: `lines ${seenLines.join(', ')}`,
    })
  }

  return { groups, sitemaps, problems, truncated }
}

/**
 * Choose the groups that govern one agent.
 *
 * An explicit product token beats "*", and an agent named by no group at all
 * falls back to "*". `match` says which of those happened, so a report can tell
 * an operator that an unknown agent was governed by the global group rather
 * than leaving them to infer it.
 */
export function selectGroups(groups, agent) {
  const token = extractProductToken(agent)
  const wanted = token === null ? null : token.toLowerCase()

  const specific =
    wanted === null || wanted === '*'
      ? []
      : groups.filter((group) => group.agents.some((entry) => entry.token !== '*' && entry.token.toLowerCase() === wanted))
  if (specific.length > 0) return { match: 'specific', token, groups: specific }

  const global = groups.filter((group) => group.agents.some((entry) => entry.token === '*'))
  if (global.length > 0) return { match: 'global', token, groups: global }

  return { match: 'none', token, groups: [] }
}

/**
 * Decide whether one agent may crawl one URL, and report which rule decided it.
 *
 * The winning rule is part of the answer, not a debugging aid: "disallowed"
 * without the line that disallowed it cannot be acted on or argued with.
 */
export function decideCrawl(groups, agent, url) {
  const selection = selectGroups(groups, agent)
  const target = matchTargetOf(url)
  let winner = null

  for (const group of selection.groups) {
    for (const rule of group.rules) {
      if (!patternMatches(rule.pattern, target)) continue
      const length = octetLength(rule.pattern)
      if (winner === null || length > winner.length) {
        winner = { rule, length, group }
        continue
      }
      // Equal length: an Allow beats a Disallow (RFC 9309 section 2.2.2). Two
      // rules of the same type and length say the same thing, so the first one
      // in the file keeps the decision and the order stays stable.
      if (length === winner.length && rule.type === 'allow' && winner.rule.type === 'disallow') {
        winner = { rule, length, group }
      }
    }
  }

  const groupAgents =
    winner === null
      ? selection.groups.flatMap((group) => group.agents.map((entry) => entry.token))
      : winner.group.agents.map((entry) => entry.token)

  return {
    permission: winner !== null && winner.rule.type === 'disallow' ? 'disallow' : 'allow',
    rule: winner === null ? null : { ...winner.rule, octets: winner.length },
    agentMatch: selection.match,
    groupAgents,
    target,
  }
}
