/**
 * Indexing directives: `X-Robots-Tag` response headers and `<meta name=robots>`.
 *
 * These are a different axis from robots.txt. robots.txt decides whether a
 * crawler may *fetch* a URL; these decide what an indexer may do with a
 * response it has already fetched. The two are routinely confused, and the
 * confusion is the defect this tool exists to surface, so they are parsed by
 * separate code and never merged into one verdict.
 *
 * Everything here is an imported capture. This tool performs no network
 * request, so a URL the capture does not cover has an *unknown* indexing state
 * — which is reported as unverified, never as indexable.
 */

/** Directives defined by the major indexers. Anything else is a probable typo. */
const KNOWN_DIRECTIVES = new Set([
  'all',
  'follow',
  'index',
  'indexifembedded',
  'max-image-preview',
  'max-snippet',
  'max-video-preview',
  'noarchive',
  'nofollow',
  'noimageindex',
  'none',
  'noodp',
  'nopagereadaloud',
  'nosnippet',
  'nositelinkssearchbox',
  'notranslate',
  'noydir',
  'unavailable_after',
])

/** Directives that keep a page out of an index. */
export const BLOCKING_DIRECTIVES = Object.freeze(['noindex', 'none'])

/**
 * Directives whose effect depends on the current time. This tool has no clock
 * — a report that changed with the hour could not be compared between runs —
 * so a URL carrying one is reported unverified rather than guessed at.
 */
export const TIME_DEPENDENT_DIRECTIVES = Object.freeze(['unavailable_after'])

const PRODUCT_TOKEN = /^[A-Za-z_-]+$/
const ATTRIBUTE = /([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*("[^"]*"|'[^']*'|[^\s"'`=<>]+)/g

function normalizeToken(value) {
  return value.trim().toLowerCase()
}

/**
 * Split one `X-Robots-Tag` value into its agent scope and its directives.
 *
 * A leading `agent:` prefix scopes the whole value to that product token, which
 * is why `unavailable_after: <date>` has to be excluded by name: it also
 * contains a colon, and treating it as an agent would silently drop a real
 * directive.
 */
export function parseXRobotsTag(value) {
  const text = String(value)
  const problems = []
  let agent = '*'
  let body = text

  const colon = text.indexOf(':')
  if (colon !== -1) {
    const candidate = text.slice(0, colon).trim()
    const lowered = candidate.toLowerCase()
    if (PRODUCT_TOKEN.test(candidate) && !KNOWN_DIRECTIVES.has(lowered) && lowered !== 'noindex') {
      agent = candidate
      body = text.slice(colon + 1)
    }
  }

  const directives = []
  for (const part of body.split(',')) {
    const trimmed = part.trim()
    if (trimmed === '') continue
    const separator = trimmed.indexOf(':')
    const name = normalizeToken(separator === -1 ? trimmed : trimmed.slice(0, separator))
    if (name === '') continue
    if (name !== 'noindex' && !KNOWN_DIRECTIVES.has(name)) {
      problems.push({ ruleId: 'unknown-index-directive', name, raw: trimmed })
    }
    directives.push({ name, raw: trimmed })
  }

  return { agent, directives, problems }
}

/** Mask a region of HTML with spaces, preserving newlines so line numbers stay true. */
function maskRegion(text, start, end) {
  let masked = ''
  for (let index = start; index < end; index += 1) {
    masked += text[index] === '\n' ? '\n' : ' '
  }
  return `${text.slice(0, start)}${masked}${text.slice(end)}`
}

/**
 * Blank out comments and the bodies of script and style elements.
 *
 * A `<meta name=robots content=noindex>` inside a comment or a script string is
 * documentation or data, not a directive, and reporting it as one would claim a
 * page is out of the index when nothing is keeping it out.
 */
function maskInertRegions(html) {
  let text = html
  const lower = () => text.toLowerCase()

  for (;;) {
    const start = lower().indexOf('<!--')
    if (start === -1) break
    const end = lower().indexOf('-->', start + 4)
    text = maskRegion(text, start, end === -1 ? text.length : end + 3)
  }

  for (const element of ['script', 'style']) {
    let from = 0
    for (;;) {
      const open = lower().indexOf(`<${element}`, from)
      if (open === -1) break
      const openEnd = text.indexOf('>', open)
      if (openEnd === -1) {
        text = maskRegion(text, open, text.length)
        break
      }
      const close = lower().indexOf(`</${element}`, openEnd)
      const end = close === -1 ? text.length : close
      text = maskRegion(text, openEnd + 1, end)
      from = openEnd + 1
    }
  }

  return text
}

function lineOf(text, offset) {
  let line = 1
  for (let index = 0; index < offset && index < text.length; index += 1) {
    if (text[index] === '\n') line += 1
  }
  return line
}

function unquote(value) {
  if (value.length >= 2 && (value[0] === '"' || value[0] === "'") && value[value.length - 1] === value[0]) {
    return value.slice(1, -1)
  }
  return value
}

/**
 * Extract robots meta elements from captured HTML.
 *
 * `name` is either `robots`, which addresses every indexer, or a product token
 * addressing one. `http-equiv` is deliberately not read: the major indexers do
 * not honour a robots directive delivered that way, and honouring it here would
 * report a page as blocked when it is not.
 *
 * A directive after the head ends is reported and treated as ineffective, which
 * is the conservative reading — the risk being warned about is a page staying
 * in an index, so a directive that may be ignored must not be counted as one
 * that removed it.
 */
export function extractMetaRobots(html, limits) {
  const masked = maskInertRegions(html)
  const lowered = masked.toLowerCase()
  const metas = []
  const problems = []
  let truncated = null

  const headEnd = (() => {
    const closing = lowered.indexOf('</head')
    const body = lowered.indexOf('<body')
    const candidates = [closing, body].filter((offset) => offset !== -1)
    return candidates.length === 0 ? Number.POSITIVE_INFINITY : Math.min(...candidates)
  })()

  let from = 0
  for (;;) {
    const open = lowered.indexOf('<meta', from)
    if (open === -1) break
    const next = masked[open + 5]
    if (next !== undefined && !/[\s/>]/.test(next)) {
      from = open + 5
      continue
    }
    const close = masked.indexOf('>', open)
    const end = close === -1 ? masked.length : close
    const inner = masked.slice(open + 5, end)
    from = end + 1

    const attributes = new Map()
    ATTRIBUTE.lastIndex = 0
    let attribute = ATTRIBUTE.exec(inner)
    while (attribute !== null) {
      attributes.set(attribute[1].toLowerCase(), unquote(attribute[2]))
      attribute = ATTRIBUTE.exec(inner)
    }

    const name = attributes.get('name')
    if (name === undefined) continue
    const token = name.trim()
    if (token === '' || !PRODUCT_TOKEN.test(token)) continue
    const lowerName = token.toLowerCase()
    const isRobotsName = lowerName === 'robots'
    if (!isRobotsName && attributes.get('content') === undefined) continue

    const content = attributes.get('content') ?? ''
    const directives = []
    for (const part of content.split(',')) {
      const trimmed = part.trim()
      if (trimmed === '') continue
      const separator = trimmed.indexOf(':')
      const directiveName = normalizeToken(separator === -1 ? trimmed : trimmed.slice(0, separator))
      if (directiveName === '') continue
      directives.push({ name: directiveName, raw: trimmed })
    }
    if (!isRobotsName && directives.length === 0) continue

    // A meta element naming something that is not an indexer — "viewport",
    // "description" — is not a robots directive at all. Only names that carry
    // at least one recognised robots directive are treated as one.
    const looksLikeRobots =
      isRobotsName || directives.some((directive) => directive.name === 'noindex' || KNOWN_DIRECTIVES.has(directive.name))
    if (!looksLikeRobots) continue

    for (const directive of directives) {
      if (directive.name !== 'noindex' && !KNOWN_DIRECTIVES.has(directive.name)) {
        problems.push({
          ruleId: 'unknown-index-directive',
          name: directive.name,
          raw: directive.raw,
          line: lineOf(masked, open),
        })
      }
    }

    metas.push({
      agent: isRobotsName ? '*' : token,
      directives,
      content,
      line: lineOf(masked, open),
      effective: open < headEnd,
    })

    if (metas.length > limits.maxMetaTags) {
      truncated = { limit: 'maxMetaTags', value: limits.maxMetaTags, actual: metas.length }
      break
    }
  }

  return { metas, problems, truncated }
}

/** Does a directive source address this agent? `*` addresses every agent. */
export function addressesAgent(scope, agent) {
  if (scope === '*') return true
  return scope.toLowerCase() === String(agent).toLowerCase()
}

/**
 * Reduce the directive sources that address one agent to an indexing verdict.
 *
 * `sources` are already filtered to this agent and ordered header-first, then
 * document order. The first blocking directive is reported as the one that
 * decided it — with a header and a meta element saying different things, the
 * restrictive one wins, which is what the indexers do and what an auditor must
 * assume.
 */
export function decideIndexing(sources) {
  const blocking = sources.filter((source) =>
    source.directives.some((directive) => BLOCKING_DIRECTIVES.includes(directive.name)),
  )
  const timeDependent = sources.filter((source) =>
    source.directives.some((directive) => TIME_DEPENDENT_DIRECTIVES.includes(directive.name)),
  )
  const permitting = sources.filter(
    (source) =>
      !source.directives.some((directive) => BLOCKING_DIRECTIVES.includes(directive.name)) &&
      source.directives.some((directive) => directive.name === 'index' || directive.name === 'all'),
  )

  if (blocking.length > 0) {
    return {
      state: 'blocked',
      winner: blocking[0],
      conflicting: permitting.length > 0 ? permitting[0] : null,
      timeDependent: timeDependent.length > 0 ? timeDependent[0] : null,
    }
  }
  if (timeDependent.length > 0) {
    return { state: 'time-dependent', winner: timeDependent[0], conflicting: null, timeDependent: timeDependent[0] }
  }
  return { state: 'indexable', winner: null, conflicting: null, timeDependent: null }
}
