/**
 * robots-policy-auditor
 *
 * Evaluate a local robots.txt, captured `X-Robots-Tag` headers and captured
 * HTML robots directives against a supplied agent/URL list, report which rule
 * decided each outcome, and keep crawl permission and indexing strictly apart.
 *
 * The tool never fetches anything. Header and HTML evidence arrives as an
 * imported capture, and a URL the capture does not cover has an *unknown*
 * indexing state, which is reported as unverified and never as a pass.
 */

import { readFile, realpath, stat } from 'node:fs/promises'
import { basename, dirname, isAbsolute, relative, resolve, sep } from 'node:path'

import {
  addressesAgent,
  decideIndexing,
  extractMetaRobots,
  parseXRobotsTag,
} from './directives.mjs'
import { CONFIG_SCHEMA_VERSION, buildReport, excerpt, makeFinding, parseFailureDetail } from './report.mjs'
import { decideCrawl, parseRobotsTxt } from './robots-txt.mjs'

export {
  BLOCKING_DIRECTIVES,
  TIME_DEPENDENT_DIRECTIVES,
  addressesAgent,
  decideIndexing,
  extractMetaRobots,
  parseXRobotsTag,
} from './directives.mjs'
export {
  CONFIG_SCHEMA_VERSION,
  REPORT_SCHEMA_VERSION,
  RULE_SEVERITY,
  SEVERITIES,
  TOOL_ID,
  buildReport,
  byCodeUnit,
  comparePointers,
  excerpt,
  exitCodeFor,
  formatReport,
  makeFinding,
  parseFailureDetail,
  severityOf,
  sortFindings,
} from './report.mjs'
export {
  decideCrawl,
  extractProductToken,
  matchTargetOf,
  normalizePattern,
  normalizePercentEncoding,
  octetLength,
  parseRobotsTxt,
  patternMatches,
  selectGroups,
} from './robots-txt.mjs'

/**
 * Bounds are part of the contract, not a safety net.
 *
 * Every limit is enforced, overridable by name, and reported by name when it is
 * hit. Exceeding one produces a finding and an incomplete run — never a quietly
 * shorter answer. `maxRobotsBytes` is 500 KiB because that is the size RFC 9309
 * requires a crawler to parse at least; bytes past it are not enforced by the
 * crawlers either, so they must not be treated as policy here.
 */
export const DEFAULT_LIMITS = Object.freeze({
  maxRobotsBytes: 512000,
  maxRobotsLines: 10000,
  maxGroups: 1000,
  maxRulesPerGroup: 5000,
  maxChecks: 5000,
  maxCaptureEntries: 5000,
  maxHtmlBytes: 1048576,
  maxMetaTags: 500,
  maxHeaderValues: 50,
})

export const LIMIT_NAMES = Object.freeze(Object.keys(DEFAULT_LIMITS))

export const CRAWL_PERMISSIONS = Object.freeze(['allow', 'disallow'])
export const INDEX_STATES = Object.freeze(['indexable', 'blocked'])

const CONFIG_KEYS = new Set(['schemaVersion', 'site', 'robotsTxt', 'checks', 'capture', 'limits'])
const SITE_KEYS = new Set(['origin'])
const CHECK_KEYS = new Set(['userAgent', 'url', 'expect', 'note'])
const EXPECT_KEYS = new Set(['crawl', 'index'])
const RESPONSE_KEYS = new Set(['url', 'status', 'headers', 'html', 'note'])

/**
 * A problem with the configuration or with an input document's shape, rather
 * than with the site being audited.
 *
 * These are refusals: the run never had a subject it could trust, so it emits
 * no report at all. An input that exists but could not be read or decoded is a
 * different thing entirely and becomes an `incomplete` report instead.
 */
export class ConfigError extends Error {
  constructor(message, rule = null) {
    super(message)
    this.name = 'ConfigError'
    this.rule = rule
  }
}

function isRecord(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value)
}

function toPosix(value) {
  return value.split(sep).join('/')
}

function rejectUnknownKeys(record, allowed, label) {
  for (const key of Object.keys(record)) {
    if (allowed.has(key)) continue
    throw new ConfigError(
      `${label} has the unknown key "${String(key).slice(0, 40)}". Allowed keys: ${[...allowed].join(', ')}.`,
      'unknown-key',
    )
  }
}

/** A line-oriented location pointer. Zero padding keeps report order readable without a locale. */
function linePointer(line) {
  return `/line/${String(line).padStart(4, '0')}`
}

function escapes(from, target) {
  const rel = relative(from, target)
  return rel === '' || rel === '..' || rel.startsWith(`..${sep}`) || isAbsolute(rel)
}

/**
 * The real path a target would have once every symbolic link on the way to it
 * has been followed.
 *
 * `realpath` needs the whole path to exist, but a capture that names a file
 * which was never written must still reach the report as `input-unreadable`
 * rather than as a refusal. So the deepest existing ancestor is resolved for
 * real and the missing segments are appended literally: a link anywhere along
 * the existing part is still followed, and a missing leaf keeps the location
 * its parent gives it.
 */
async function realPathOf(target, describe) {
  const tail = []
  let current = target
  for (;;) {
    try {
      const real = await realpath(current)
      return tail.length === 0 ? real : resolve(real, ...tail)
    } catch (error) {
      if (error.code !== 'ENOENT' && error.code !== 'ENOTDIR') {
        throw new ConfigError(
          `${describe} could not be resolved (${error.code ?? 'unknown error'}).`,
          'input-unresolvable',
        )
      }
      const parent = dirname(current)
      if (parent === current) return target
      tail.unshift(basename(current))
      current = parent
    }
  }
}

/**
 * Resolve a path declared by an input document, refusing to leave the input root.
 *
 * Configuration and captures are data, and data does not choose which files this
 * tool opens. Spelling is not the only way out of a tree, so the lexical check
 * is not the boundary: a symbolic link planted inside the root points wherever
 * it likes, and following one would read a file no input had the right to name
 * and echo its content into the report. The resolved path is therefore confined
 * again after every link on it has been followed, against the *real* path of the
 * root — the root itself may sit behind a link, as `/var` does on macOS.
 */
export async function resolveWithin(root, realRoot, candidate, label) {
  if (typeof candidate !== 'string' || candidate.trim() === '') {
    throw new ConfigError(`${label} must be a non-empty relative path.`, 'input-not-relative')
  }
  if (isAbsolute(candidate)) {
    throw new ConfigError(
      `${label} must be relative to the input root, but "${excerpt(candidate).slice(0, 80)}" is absolute.`,
      'input-not-relative',
    )
  }
  const resolved = resolve(root, candidate)
  if (escapes(root, resolved)) {
    throw new ConfigError(
      `${label} resolves outside the input root: "${excerpt(candidate).slice(0, 80)}".`,
      'input-outside-root',
    )
  }
  const real = await realPathOf(resolved, `${label} ("${excerpt(candidate).slice(0, 80)}")`)
  if (escapes(realRoot, real)) {
    throw new ConfigError(
      `${label} leaves the input root through a symbolic link: "${excerpt(candidate).slice(0, 80)}". Nothing was read from it.`,
      'input-escapes-root',
    )
  }
  return resolved
}

function assertOrigin(value, label) {
  let url
  try {
    url = new URL(value)
  } catch {
    throw new ConfigError(`${label} must be an absolute http(s) URL, got "${excerpt(value).slice(0, 80)}".`)
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new ConfigError(`${label} must use http or https, got "${url.protocol.slice(0, -1)}".`)
  }
  if (url.pathname !== '/' || url.search !== '' || url.hash !== '') {
    throw new ConfigError(
      `${label} must be a bare origin such as https://example.com, got "${excerpt(value).slice(0, 80)}".`,
    )
  }
  return url.origin
}

/** Merge declared limits over the defaults, rejecting names that do not exist. */
export function validateLimits(overrides = {}) {
  if (!isRecord(overrides)) throw new ConfigError('limits must be an object.')
  const limits = { ...DEFAULT_LIMITS }
  for (const [name, value] of Object.entries(overrides)) {
    if (!Object.hasOwn(DEFAULT_LIMITS, name)) {
      throw new ConfigError(
        `Unknown limit "${String(name).slice(0, 40)}". Known limits: ${LIMIT_NAMES.join(', ')}.`,
        'unknown-limit',
      )
    }
    if (!Number.isInteger(value) || value < 1) {
      throw new ConfigError(`limits.${name} must be a positive integer.`)
    }
    limits[name] = value
  }
  return Object.freeze(limits)
}

export function validateConfig(document) {
  if (!isRecord(document)) throw new ConfigError('The config must be a JSON object.')
  rejectUnknownKeys(document, CONFIG_KEYS, 'The config')
  if (document.schemaVersion !== CONFIG_SCHEMA_VERSION) {
    throw new ConfigError(`Unsupported config schemaVersion: ${JSON.stringify(document.schemaVersion ?? null)}.`)
  }
  if (!isRecord(document.site)) throw new ConfigError('The config is missing its site object.')
  rejectUnknownKeys(document.site, SITE_KEYS, 'config.site')
  const origin = assertOrigin(document.site.origin, 'site.origin')

  if (typeof document.robotsTxt !== 'string' || document.robotsTxt.trim() === '') {
    throw new ConfigError('The config must name a robots.txt file in "robotsTxt".')
  }
  if (typeof document.checks !== 'string' || document.checks.trim() === '') {
    throw new ConfigError('The config must name a checks document in "checks".')
  }
  if (document.capture !== undefined && typeof document.capture !== 'string') {
    throw new ConfigError('config.capture must be a relative path or be omitted.')
  }

  return {
    schemaVersion: CONFIG_SCHEMA_VERSION,
    site: { origin },
    robotsTxt: document.robotsTxt,
    checks: document.checks,
    capture: document.capture ?? null,
    limits: document.limits ?? {},
  }
}

export function validateChecks(document) {
  if (!isRecord(document)) throw new ConfigError('The checks document must be a JSON object.')
  rejectUnknownKeys(document, new Set(['schemaVersion', 'checks']), 'The checks document')
  if (document.schemaVersion !== CONFIG_SCHEMA_VERSION) {
    throw new ConfigError(`Unsupported checks schemaVersion: ${JSON.stringify(document.schemaVersion ?? null)}.`)
  }
  if (!Array.isArray(document.checks)) throw new ConfigError('The checks document must declare a checks array.')

  return document.checks.map((entry, index) => {
    const label = `checks[${index}]`
    if (!isRecord(entry)) throw new ConfigError(`${label} must be an object.`)
    rejectUnknownKeys(entry, CHECK_KEYS, label)
    if (typeof entry.userAgent !== 'string' || entry.userAgent.trim() === '') {
      throw new ConfigError(`${label}.userAgent must be a non-empty string.`)
    }
    if (typeof entry.url !== 'string' || entry.url.trim() === '') {
      throw new ConfigError(`${label}.url must be a non-empty string.`)
    }
    let expect = null
    if (entry.expect !== undefined) {
      if (!isRecord(entry.expect)) throw new ConfigError(`${label}.expect must be an object.`)
      rejectUnknownKeys(entry.expect, EXPECT_KEYS, `${label}.expect`)
      if (entry.expect.crawl !== undefined && !CRAWL_PERMISSIONS.includes(entry.expect.crawl)) {
        throw new ConfigError(`${label}.expect.crawl must be one of ${CRAWL_PERMISSIONS.join(', ')}.`)
      }
      if (entry.expect.index !== undefined && !INDEX_STATES.includes(entry.expect.index)) {
        throw new ConfigError(`${label}.expect.index must be one of ${INDEX_STATES.join(', ')}.`)
      }
      expect = { crawl: entry.expect.crawl ?? null, index: entry.expect.index ?? null }
    }
    return { index, userAgent: entry.userAgent, url: entry.url, expect }
  })
}

/**
 * The capture key for a URL: origin, path and query.
 *
 * The fragment is dropped because it never reaches a server, so it cannot
 * change which headers or which document were returned.
 */
export function captureKey(url) {
  return `${url.origin}${url.pathname}${url.search}`
}

/**
 * Validate an imported capture.
 *
 * Only `x-robots-tag` is read out of the headers. Every other header is
 * discarded here, at the boundary, so a capture that happens to contain a
 * cookie or an authorization header cannot reach the report through any later
 * code path.
 */
export function validateCapture(document) {
  if (!isRecord(document)) throw new ConfigError('The capture must be a JSON object.')
  rejectUnknownKeys(document, new Set(['schemaVersion', 'capturedAt', 'responses']), 'The capture')
  if (document.schemaVersion !== CONFIG_SCHEMA_VERSION) {
    throw new ConfigError(`Unsupported capture schemaVersion: ${JSON.stringify(document.schemaVersion ?? null)}.`)
  }
  if (!Array.isArray(document.responses)) throw new ConfigError('The capture must declare a responses array.')

  const responses = document.responses.map((entry, index) => {
    const label = `responses[${index}]`
    if (!isRecord(entry)) throw new ConfigError(`${label} must be an object.`)
    rejectUnknownKeys(entry, RESPONSE_KEYS, label)
    if (typeof entry.url !== 'string' || entry.url.trim() === '') {
      throw new ConfigError(`${label}.url must be a non-empty string.`)
    }
    let url
    try {
      url = new URL(entry.url)
    } catch {
      throw new ConfigError(`${label}.url is not an absolute URL: "${excerpt(entry.url).slice(0, 80)}".`)
    }
    if (entry.status !== undefined && (!Number.isInteger(entry.status) || entry.status < 100 || entry.status > 599)) {
      throw new ConfigError(`${label}.status must be an HTTP status code when present.`)
    }
    if (entry.html !== undefined && typeof entry.html !== 'string') {
      throw new ConfigError(`${label}.html must be a relative path when present.`)
    }

    const headerValues = []
    const declaresHeaders = entry.headers !== undefined
    if (entry.headers !== undefined) {
      if (!isRecord(entry.headers)) throw new ConfigError(`${label}.headers must be an object.`)
      for (const [name, value] of Object.entries(entry.headers)) {
        if (name.toLowerCase() !== 'x-robots-tag') continue
        const values = Array.isArray(value) ? value : [value]
        for (const item of values) {
          if (typeof item !== 'string') {
            throw new ConfigError(`${label}.headers["${name.slice(0, 40)}"] must hold strings.`)
          }
          headerValues.push(item)
        }
      }
    }

    return {
      index,
      url: entry.url,
      key: captureKey(url),
      status: entry.status ?? 200,
      declaresHeaders,
      headerValues,
      html: entry.html ?? null,
    }
  })

  const seen = new Map()
  for (const response of responses) {
    if (seen.has(response.key)) {
      throw new ConfigError(
        `The capture declares two responses for the same URL (responses[${seen.get(response.key)}] and responses[${response.index}]). Which one applies would be ambiguous.`,
        'ambiguous-capture',
      )
    }
    seen.set(response.key, response.index)
  }

  return responses
}

/**
 * Read a file with its byte limit applied and decode it as strict UTF-8.
 *
 * The decoder is fatal on purpose. Inferring "not UTF-8" from a replacement
 * character in already-decoded text is how undecodable bytes get reported as a
 * pass: a file may legitimately contain U+FFFD, and a file of undecodable bytes
 * produces the same character. The only sound test is whether the decode
 * succeeded.
 */
async function readTextBounded(file, maxBytes, limitName) {
  let info
  try {
    info = await stat(file)
  } catch (error) {
    return { state: 'unreadable', detail: error.code ?? 'unknown error' }
  }
  if (!info.isFile()) return { state: 'unreadable', detail: 'not a regular file' }
  if (info.size > maxBytes) {
    return { state: 'too-large', detail: `${info.size} bytes, above the ${limitName} limit of ${maxBytes}` }
  }
  let bytes
  try {
    bytes = await readFile(file)
  } catch (error) {
    return { state: 'unreadable', detail: error.code ?? 'unknown error' }
  }
  let text
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes)
  } catch {
    return { state: 'not-utf8', detail: `${bytes.length} bytes could not be decoded as UTF-8` }
  }
  return { state: 'ok', text: text.startsWith('\uFEFF') ? text.slice(1) : text, bytes: info.size }
}

/**
 * Read a JSON input and decode it as strict UTF-8.
 *
 * The decoder is fatal for the same reason the one above it is. `readFile(file,
 * 'utf8')` is lossy: it turns an undecodable byte into U+FFFD and hands back a
 * string that parses, so a capture whose `noindex` carries one stray byte
 * becomes an unrecognised directive and the URL it protects is reported
 * indexable — an unread input reaching a pass. JSON is defined as UTF-8
 * (RFC 8259 section 8.1), so a document that does not decode was never read.
 */
async function readJsonDocument(file, label) {
  let bytes
  try {
    bytes = await readFile(file)
  } catch (error) {
    return { state: 'unreadable', detail: `${label} could not be read (${error.code ?? 'unknown error'})` }
  }
  let text
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes)
  } catch {
    return {
      state: 'not-utf8',
      detail: `${label} is not valid UTF-8 (${bytes.length} bytes could not be decoded), so it was not parsed`,
    }
  }
  try {
    return { state: 'ok', document: JSON.parse(text) }
  } catch (error) {
    return { state: 'unreadable', detail: `${label} is not valid JSON: ${excerpt(parseFailureDetail(error)).slice(0, 120)}` }
  }
}

function describeRule(rule) {
  if (rule === null) return 'no rule matched'
  const type = rule.type === 'allow' ? 'Allow' : 'Disallow'
  return `${type}: ${rule.raw} (line ${rule.line}, ${rule.octets} octet${rule.octets === 1 ? '' : 's'})`
}

function describeSource(source) {
  if (source === null || source === undefined) return 'none'
  if (source.kind === 'header') return `X-Robots-Tag "${source.content}" (${source.file})`
  return `meta robots "${source.content}" (${source.file} line ${source.line})`
}

/**
 * Audit one configuration.
 *
 * Returns a report; throws `ConfigError` when the run had no trustworthy
 * subject at all. Every status the report can carry is decided in one place,
 * `buildReport`, from the findings and the `incomplete` flag assembled here.
 */
export async function auditRobotsPolicy({ configFile, limits: limitOverrides = {} } = {}) {
  if (typeof configFile !== 'string' || configFile.trim() === '') {
    throw new ConfigError('A config file path is required.')
  }
  const configPath = resolve(configFile)
  const configRead = await readJsonDocument(configPath, 'The config')
  if (configRead.state !== 'ok') throw new ConfigError(configRead.detail)

  const config = validateConfig(configRead.document)
  const limits = validateLimits({ ...config.limits, ...limitOverrides })

  const root = dirname(configPath)
  let realRoot
  try {
    realRoot = await realpath(root)
  } catch (error) {
    throw new ConfigError(`The input root could not be resolved (${error.code ?? 'unknown error'}).`, 'input-unresolvable')
  }

  const robotsPath = await resolveWithin(root, realRoot, config.robotsTxt, 'config.robotsTxt')
  const checksPath = await resolveWithin(root, realRoot, config.checks, 'config.checks')
  const capturePath =
    config.capture === null ? null : await resolveWithin(root, realRoot, config.capture, 'config.capture')

  const robotsFile = toPosix(relative(root, robotsPath))
  const checksFile = toPosix(relative(root, checksPath))
  const captureFile = capturePath === null ? null : toPosix(relative(root, capturePath))

  const findings = []
  let incomplete = false

  // --- robots.txt ---------------------------------------------------------
  const robotsRead = await readTextBounded(robotsPath, limits.maxRobotsBytes, 'maxRobotsBytes')
  let groups = []
  if (robotsRead.state === 'unreadable') {
    incomplete = true
    findings.push(
      makeFinding('input-unreadable', `robots.txt could not be read (${robotsRead.detail}).`, { file: robotsFile }, {
        suggestion: 'point config.robotsTxt at the robots.txt this site actually serves',
      }),
    )
  } else if (robotsRead.state === 'too-large') {
    incomplete = true
    findings.push(
      makeFinding('input-too-large', `robots.txt is ${robotsRead.detail}, so it was not parsed.`, { file: robotsFile }, {
        suggestion: 'raise limits.maxRobotsBytes only if the crawlers you target parse that far',
      }),
    )
  } else if (robotsRead.state === 'not-utf8') {
    incomplete = true
    findings.push(
      makeFinding('input-not-utf8', `robots.txt is not valid UTF-8 (${robotsRead.detail}), so it was not parsed.`, {
        file: robotsFile,
      }, { suggestion: 'RFC 9309 requires UTF-8; re-encode the file' }),
    )
  } else {
    const parsed = parseRobotsTxt(robotsRead.text, limits)
    groups = parsed.groups
    for (const problem of parsed.problems) {
      findings.push(
        makeFinding(problem.ruleId, problem.message, { file: robotsFile, pointer: linePointer(problem.line) }, {
          evidence: problem.evidence,
        }),
      )
    }
    if (parsed.truncated !== null) {
      incomplete = true
      findings.push(
        makeFinding(
          'limit-exceeded',
          `robots.txt exceeded the ${parsed.truncated.limit} limit of ${parsed.truncated.value} (reached ${parsed.truncated.actual}), so parsing stopped and the decisions below are incomplete.`,
          { file: robotsFile },
          { suggestion: `raise limits.${parsed.truncated.limit} or shorten the file` },
        ),
      )
    }
  }

  // --- checks -------------------------------------------------------------
  const checksRead = await readJsonDocument(checksPath, 'The checks document')
  if (checksRead.state !== 'ok') {
    findings.push(
      checksRead.state === 'not-utf8'
        ? makeFinding('input-not-utf8', `${checksRead.detail}.`, { file: checksFile }, {
            suggestion: 'JSON is UTF-8 by definition; re-encode the checks document',
          })
        : makeFinding('input-unreadable', `${checksRead.detail}.`, { file: checksFile }, {
            suggestion: 'point config.checks at a readable JSON checks document',
          }),
    )
    return buildReport({
      findings,
      checked: 0,
      incomplete: true,
      summary: { allowed: 0, disallowed: 0, indexBlocked: 0, indexUnverified: 0 },
    })
  }
  const checks = validateChecks(checksRead.document)
  if (checks.length > limits.maxChecks) {
    findings.push(
      makeFinding(
        'limit-exceeded',
        `The checks document declares ${checks.length} checks, above the maxChecks limit of ${limits.maxChecks}. None were evaluated.`,
        { file: checksFile },
        { suggestion: 'raise limits.maxChecks or split the checks document' },
      ),
    )
    return buildReport({
      findings,
      checked: 0,
      incomplete: true,
      summary: { allowed: 0, disallowed: 0, indexBlocked: 0, indexUnverified: 0 },
    })
  }

  // --- capture ------------------------------------------------------------
  const capture = new Map()
  let captureLoaded = false
  if (capturePath !== null) {
    const captureRead = await readJsonDocument(capturePath, 'The capture')
    if (captureRead.state !== 'ok') {
      incomplete = true
      findings.push(
        captureRead.state === 'not-utf8'
          ? makeFinding('input-not-utf8', `${captureRead.detail}.`, { file: captureFile }, {
              suggestion: 'JSON is UTF-8 by definition; re-capture or re-encode the capture',
            })
          : makeFinding('input-unreadable', `${captureRead.detail}.`, { file: captureFile }, {
              suggestion: 'point config.capture at a readable JSON capture, or remove it',
            }),
      )
    } else {
      const responses = validateCapture(captureRead.document)
      if (responses.length > limits.maxCaptureEntries) {
        incomplete = true
        findings.push(
          makeFinding(
            'limit-exceeded',
            `The capture declares ${responses.length} responses, above the maxCaptureEntries limit of ${limits.maxCaptureEntries}. None of them were read.`,
            { file: captureFile },
            { suggestion: 'raise limits.maxCaptureEntries or split the capture' },
          ),
        )
        responses.length = 0
      } else {
        captureLoaded = true
      }
      for (const response of responses) {
        const sources = []
        // Evidence this entry declared and this run never got to read. It is
        // not the same as evidence that was read and said nothing, and the two
        // must not decide the same way.
        const unread = []

        if (response.headerValues.length > limits.maxHeaderValues) {
          incomplete = true
          unread.push('its X-Robots-Tag values were above the maxHeaderValues limit')
          findings.push(
            makeFinding(
              'limit-exceeded',
              `responses[${response.index}] declares ${response.headerValues.length} X-Robots-Tag values, above the maxHeaderValues limit of ${limits.maxHeaderValues}. Its indexing directives were not read.`,
              { file: captureFile, pointer: `/responses/${response.index}` },
              { suggestion: 'raise limits.maxHeaderValues or trim the capture' },
            ),
          )
        } else {
          response.headerValues.forEach((value, order) => {
            const parsedHeader = parseXRobotsTag(value)
            for (const problem of parsedHeader.problems) {
              findings.push(
                makeFinding(
                  'unknown-index-directive',
                  `The X-Robots-Tag on responses[${response.index}] names "${excerpt(problem.name).slice(0, 40)}", which no major indexer defines. A misspelled directive is silently ignored, so it removes nothing from an index.`,
                  { file: captureFile, pointer: `/responses/${response.index}/headers/x-robots-tag/${order}` },
                  { evidence: problem.raw, suggestion: 'correct the directive name or delete it' },
                ),
              )
            }
            sources.push({
              kind: 'header',
              agent: parsedHeader.agent,
              directives: parsedHeader.directives,
              content: excerpt(value).slice(0, 80),
              file: captureFile,
              pointer: `/responses/${response.index}/headers/x-robots-tag/${order}`,
              line: null,
            })
          })
        }

        if (response.html !== null) {
          const htmlPath = await resolveWithin(root, realRoot, response.html, `capture responses[${response.index}].html`)
          const htmlFile = toPosix(relative(root, htmlPath))
          const htmlRead = await readTextBounded(htmlPath, limits.maxHtmlBytes, 'maxHtmlBytes')
          if (htmlRead.state === 'unreadable') {
            incomplete = true
            unread.push('its captured document could not be read')
            findings.push(
              makeFinding('input-unreadable', `The captured document could not be read (${htmlRead.detail}).`, {
                file: htmlFile,
              }, { suggestion: `check capture responses[${response.index}].html` }),
            )
          } else if (htmlRead.state === 'too-large') {
            incomplete = true
            unread.push('its captured document is above the maxHtmlBytes limit')
            findings.push(
              makeFinding('input-too-large', `The captured document is ${htmlRead.detail}, so its robots meta elements were not read.`, {
                file: htmlFile,
              }, { suggestion: 'raise limits.maxHtmlBytes or capture a smaller document' }),
            )
          } else if (htmlRead.state === 'not-utf8') {
            incomplete = true
            unread.push('its captured document is not valid UTF-8')
            findings.push(
              makeFinding('input-not-utf8', `The captured document is not valid UTF-8 (${htmlRead.detail}), so its robots meta elements were not read.`, {
                file: htmlFile,
              }, { suggestion: 're-capture the document as UTF-8' }),
            )
          } else {
            const extracted = extractMetaRobots(htmlRead.text, limits)
            for (const problem of extracted.problems) {
              findings.push(
                makeFinding(
                  'unknown-index-directive',
                  `A robots meta element names "${excerpt(problem.name).slice(0, 40)}", which no major indexer defines. A misspelled directive is silently ignored, so it removes nothing from an index.`,
                  { file: htmlFile, pointer: linePointer(problem.line) },
                  { evidence: problem.raw, suggestion: 'correct the directive name or delete it' },
                ),
              )
            }
            if (extracted.truncated !== null) {
              incomplete = true
              unread.push(`its captured document was truncated at the ${extracted.truncated.limit} limit`)
              findings.push(
                makeFinding(
                  'limit-exceeded',
                  `The captured document exceeded the ${extracted.truncated.limit} limit of ${extracted.truncated.value}, so its remaining meta elements were not read.`,
                  { file: htmlFile },
                  { suggestion: `raise limits.${extracted.truncated.limit}` },
                ),
              )
            }
            for (const meta of extracted.metas) {
              if (!meta.effective) {
                findings.push(
                  makeFinding(
                    'meta-outside-head',
                    `A robots meta element appears after the document head, where the major indexers do not read it. It is treated here as having no effect.`,
                    { file: htmlFile, pointer: linePointer(meta.line) },
                    { evidence: meta.content, suggestion: 'move the element into <head>' },
                  ),
                )
                continue
              }
              sources.push({
                kind: 'meta',
                agent: meta.agent,
                directives: meta.directives,
                content: excerpt(meta.content).slice(0, 80),
                file: htmlFile,
                pointer: linePointer(meta.line),
                line: meta.line,
              })
            }
          }
        }

        // A response entry that declares neither a headers object nor a
        // document says nothing about indexing. Silence is not evidence of
        // absence, so it is treated as unverified rather than as "no
        // directives were served". An explicit `"headers": {}` is the way to
        // state that the response carried none.
        const declaresEvidence = response.declaresHeaders || response.html !== null
        capture.set(response.key, { response, sources, declaresEvidence, unread })
      }
    }
  }

  // --- decisions ----------------------------------------------------------
  let checked = 0
  let allowed = 0
  let disallowed = 0
  let indexBlocked = 0
  let indexUnverified = 0

  for (const check of checks) {
    const pointer = `/checks/${check.index}`
    let url
    try {
      url = new URL(check.url)
    } catch {
      incomplete = true
      findings.push(
        makeFinding(
          'check-unevaluable',
          `checks[${check.index}] does not declare an absolute URL, so no rule could be applied to it.`,
          { file: checksFile, pointer },
          { evidence: check.url, suggestion: 'use an absolute URL such as https://example.com/path' },
        ),
      )
      continue
    }
    if (url.origin !== config.site.origin) {
      incomplete = true
      findings.push(
        makeFinding(
          'check-unevaluable',
          `checks[${check.index}] names the origin ${excerpt(url.origin).slice(0, 60)}, which this robots.txt does not govern. A robots.txt applies only to its own origin.`,
          { file: checksFile, pointer },
          { evidence: check.url, suggestion: `audit that origin with its own robots.txt, or correct the URL` },
        ),
      )
      continue
    }

    const crawl = decideCrawl(groups, check.userAgent, url)
    checked += 1
    if (crawl.permission === 'allow') allowed += 1
    else disallowed += 1

    const found = capture.get(captureKey(url)) ?? null
    const entry = found !== null && found.declaresEvidence ? found : null
    const applicable =
      entry === null ? [] : entry.sources.filter((source) => addressesAgent(source.agent, check.userAgent))
    const indexing = entry === null ? { state: 'unknown', winner: null, conflicting: null } : decideIndexing(applicable)

    // Evidence that was declared but never read — a document that is missing,
    // undecodable or above its byte limit, header values or meta elements
    // bounded out — cannot show that a URL is indexable. "No directive was
    // found" and "no directive was looked at" are different answers, and
    // reporting the second as the first invents both an indexing verdict and
    // the expectation mismatch that follows from it. A directive that *was*
    // read and says noindex still decides: nothing unread could lift it.
    const unreadEvidence = entry !== null && entry.unread.length > 0 && indexing.state === 'indexable'
    const indexState = unreadEvidence ? 'unknown' : indexing.state
    if (indexState === 'unknown') {
      indexUnverified += 1
      incomplete = true
      findings.push(
        makeFinding(
          'indexing-unverified',
          unreadEvidence
            ? `The captured response for ${excerpt(captureKey(url)).slice(0, 80)} was not fully read (${entry.unread.join('; ')}), so the indexing directives for "${excerpt(check.userAgent).slice(0, 40)}" are unknown. Evidence nobody read cannot show a URL is indexable.`
            : found === null
              ? `No captured response covers ${excerpt(captureKey(url)).slice(0, 80)}, so the indexing directives for "${excerpt(check.userAgent).slice(0, 40)}" are unknown. Crawl permission below is decided; indexing is not.`
              : `The captured response for ${excerpt(captureKey(url)).slice(0, 80)} declares neither headers nor a document, so it states nothing about indexing for "${excerpt(check.userAgent).slice(0, 40)}". Silence is not evidence that no directive was served.`,
          { file: checksFile, pointer },
          {
            suggestion: unreadEvidence
              ? 'make that evidence readable, or raise the limit the finding above names, then run again'
              : found !== null
                ? 'declare "headers": {} on that response to state that it carried no X-Robots-Tag, or capture its document'
                : captureLoaded
                  ? 'add this URL to the capture, header and document alike'
                  : 'supply config.capture with the response headers and documents for these URLs',
          },
        ),
      )
    } else if (indexState === 'time-dependent') {
      indexUnverified += 1
      incomplete = true
      findings.push(
        makeFinding(
          'indexing-unverified',
          `The indexing directive for "${excerpt(check.userAgent).slice(0, 40)}" depends on the current time, and this tool has no clock, so whether the URL is indexable cannot be decided here.`,
          { file: checksFile, pointer },
          {
            evidence: describeSource(indexing.winner),
            suggestion: 'decide unavailable_after against your own reference time',
          },
        ),
      )
    } else if (indexState === 'blocked') {
      indexBlocked += 1
    }

    if (indexing.conflicting !== null && indexState === 'blocked') {
      findings.push(
        makeFinding(
          'directive-conflict',
          `Two indexing directives addressing "${excerpt(check.userAgent).slice(0, 40)}" disagree. The restrictive one is assumed to win, which is what the indexers do, but the disagreement is itself a defect.`,
          { file: checksFile, pointer },
          {
            evidence: `blocking: ${describeSource(indexing.winner)}; permitting: ${describeSource(indexing.conflicting)}`,
            suggestion: 'serve one directive for this URL',
          },
        ),
      )
    }

    const indexLabel =
      indexState === 'blocked'
        ? 'blocked'
        : indexState === 'indexable'
          ? 'indexable'
          : 'unverified'

    findings.push(
      makeFinding(
        'crawl-decision',
        `crawl=${crawl.permission} index=${indexLabel} for "${excerpt(check.userAgent).slice(0, 40)}" at ${excerpt(url.pathname + url.search).slice(0, 80)}.`,
        { file: checksFile, pointer },
        {
          evidence:
            `crawl: ${describeRule(crawl.rule)} in the ${crawl.agentMatch === 'specific' ? 'agent' : crawl.agentMatch === 'global' ? 'global "*"' : 'absent'} group` +
            `${crawl.groupAgents.length > 0 ? ` [${crawl.groupAgents.join(' ')}]` : ''}; index: ${describeSource(indexing.winner)}`,
        },
      ),
    )

    if (crawl.permission === 'disallow' && indexState === 'blocked') {
      findings.push(
        makeFinding(
          'noindex-behind-disallow',
          `This URL is disallowed for "${excerpt(check.userAgent).slice(0, 40)}" and also carries a noindex directive. A crawler that obeys the disallow never fetches the response, so it never sees the directive: the noindex cannot take effect while the disallow stands.`,
          { file: checksFile, pointer },
          {
            evidence: `crawl: ${describeRule(crawl.rule)}; index: ${describeSource(indexing.winner)}`,
            suggestion: 'allow crawling of this URL so the noindex can be read, or remove the noindex and accept that the URL may be indexed from external links',
          },
        ),
      )
    }

    if (crawl.permission === 'disallow' && indexState === 'indexable') {
      findings.push(
        makeFinding(
          'disallow-is-not-deindex',
          `This URL is disallowed for "${excerpt(check.userAgent).slice(0, 40)}" and carries no indexing directive. Disallow withholds the content, not the URL: it can still be indexed from external links, so this is not a guarantee of removal from an index.`,
          { file: checksFile, pointer },
          {
            evidence: `crawl: ${describeRule(crawl.rule)}`,
            suggestion: 'to keep a URL out of an index, allow crawling and serve noindex on the response',
          },
        ),
      )
    }

    if (check.expect !== null && check.expect.crawl !== null && check.expect.crawl !== crawl.permission) {
      findings.push(
        makeFinding(
          'crawl-expectation-mismatch',
          `checks[${check.index}] expects crawl=${check.expect.crawl} for "${excerpt(check.userAgent).slice(0, 40)}", but the rules decide crawl=${crawl.permission}.`,
          { file: checksFile, pointer },
          {
            evidence: `${describeRule(crawl.rule)}`,
            suggestion: 'change the rule or change the expectation, and record which was wrong',
          },
        ),
      )
    }

    if (check.expect !== null && check.expect.index !== null) {
      if (indexState === 'unknown' || indexState === 'time-dependent') {
        // The unverified finding above already says why, and claiming a
        // mismatch against evidence that was never obtained would be a
        // fabricated failure.
      } else if (check.expect.index !== indexState) {
        findings.push(
          makeFinding(
            'index-expectation-mismatch',
            `checks[${check.index}] expects index=${check.expect.index} for "${excerpt(check.userAgent).slice(0, 40)}", but the captured directives decide index=${indexState}.`,
            { file: checksFile, pointer },
            {
              evidence: `index: ${describeSource(indexing.winner)}`,
              suggestion: 'change the served directive or change the expectation',
            },
          ),
        )
      }
    }
  }

  if (checked === 0 && checks.length === 0) {
    findings.push(
      makeFinding(
        'no-evidence',
        'The checks document declares no checks, so this run decided nothing. An audit of nothing is not a passing audit.',
        { file: checksFile },
        { suggestion: 'declare at least one agent/URL pair to check' },
      ),
    )
  }

  return buildReport({
    findings,
    checked,
    incomplete,
    summary: { allowed, disallowed, indexBlocked, indexUnverified },
  })
}
