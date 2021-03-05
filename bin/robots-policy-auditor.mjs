#!/usr/bin/env node

import { ConfigError, DEFAULT_LIMITS, LIMIT_NAMES, auditRobotsPolicy, exitCodeFor, formatReport } from '../src/index.mjs'

const HELP = `robots-policy-auditor

Evaluate a local robots.txt, captured X-Robots-Tag headers and captured HTML
robots directives against a supplied agent/URL list. Reports which rule decided
each outcome and keeps crawl permission separate from indexing.

Usage:
  robots-policy-auditor --config FILE [--json] [--limit NAME=VALUE]...

Options:
  --config FILE        Audit configuration (JSON). Its directory is the input
                       root, and every path it names must stay inside that root
  --json               Machine mode: suppress the human summary on stderr
  --limit NAME=VALUE   Override one documented limit. Known limits:
                       ${LIMIT_NAMES.map((name) => `${name} (${DEFAULT_LIMITS[name]})`).join(', ')}
  -h, --help           Show this help

Streams:
  stdout  the JSON report and nothing else, so it can be piped to a parser.
          An invalid configuration writes nothing at all to stdout
  stderr  the human summary, usage errors and diagnostics

Nothing is fetched. Header and document evidence comes from the imported
capture, so a URL the capture does not cover is reported "indexing unverified"
and the run is incomplete rather than a pass.

Crawl permission and indexing are separate: a disallowed URL can still be
indexed from external links, so this tool never reports a disallow as a
guarantee of removal from an index.

Exit codes:
  0  every check was decided and every expectation held
  1  the policy was evaluated and at least one expectation or interaction failed
  2  invalid configuration, unreadable input, unverified evidence, or a limit
     that was exceeded (status "incomplete" - never reported as a pass)
`

function parseArguments(argv) {
  if (argv.includes('-h') || argv.includes('--help')) return { help: true }
  const options = { config: null, json: false, limits: {} }

  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index]
    const takeValue = (name) => {
      const value = argv[index + 1]
      if (value === undefined) throw new Error(`${name} requires a value`)
      index += 1
      return value
    }
    if (argument === '--json') {
      options.json = true
    } else if (argument === '--config') {
      options.config = takeValue('--config')
    } else if (argument === '--limit') {
      const raw = takeValue('--limit')
      const separator = raw.indexOf('=')
      if (separator === -1) throw new Error('--limit expects NAME=VALUE')
      const name = raw.slice(0, separator)
      const value = raw.slice(separator + 1)
      if (!LIMIT_NAMES.includes(name)) {
        throw new Error(`unknown limit "${name.slice(0, 40)}". Known limits: ${LIMIT_NAMES.join(', ')}`)
      }
      if (!/^[0-9]+$/.test(value) || Number(value) < 1) {
        throw new Error(`--limit ${name} requires a positive integer`)
      }
      options.limits[name] = Number(value)
    } else {
      throw new Error(`unknown option "${String(argument).slice(0, 40)}"`)
    }
  }

  if (options.config === null) throw new Error('--config is required')
  return options
}

async function main(argv) {
  let options
  try {
    options = parseArguments(argv)
  } catch (error) {
    process.stderr.write(`${error.message}\n\n${HELP}`)
    return 2
  }
  if (options.help) {
    process.stderr.write(HELP)
    return 0
  }

  let report
  try {
    report = await auditRobotsPolicy({ configFile: options.config, limits: options.limits })
  } catch (error) {
    if (!(error instanceof ConfigError)) throw error
    // A configuration refusal means the run never had a subject, so there is
    // nothing to report about and stdout stays empty.
    process.stderr.write(`robots-policy-auditor: ${error.message}\n`)
    return 2
  }

  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`)
  if (!options.json) process.stderr.write(formatReport(report))
  return exitCodeFor(report)
}

process.exitCode = await main(process.argv.slice(2))
