# Robots Policy Auditor

Evaluate a local `robots.txt`, captured `X-Robots-Tag` headers and captured HTML robots directives
against a supplied agent/URL list. Reports **which rule won**, with the line it came from, and keeps
crawl permission and indexing strictly apart.

- **Repository:** [edilec/robots-policy-auditor](https://github.com/edilec/robots-policy-auditor)
- **Area:** SEO & Search
- **License:** MIT

## Why the two axes are separate

`robots.txt` decides whether an agent may **fetch** a URL. `X-Robots-Tag` and `<meta name=robots>`
decide what an indexer may do with a response it has **already fetched**. Treating those as one
thing is the most common robots mistake there is, and it fails in both directions:

- A `Disallow` withholds the content, not the URL. A disallowed URL can still be indexed, described
  from external links to it. **Disallow is not de-indexing**, and this tool never reports it as
  such.
- An indexing directive is delivered *in the response*, so an agent that obeys a `Disallow` never
  fetches the response and never sees the directive. A `noindex` behind a `Disallow` cannot take
  effect — reported here as `noindex-behind-disallow`.

## Install and run

Node 22 or newer. No runtime dependencies, no dev dependencies, nothing to install.

```sh
node bin/robots-policy-auditor.mjs --config examples/clean/robots-audit.config.json
node bin/robots-policy-auditor.mjs --config examples/broken/robots-audit.config.json --json
node bin/robots-policy-auditor.mjs --help
```

`stdout` carries the JSON report and nothing else, so it can be piped straight into a parser.
`stderr` carries the human summary and any diagnostics. `--json` suppresses the summary.

## Input

One config file. Its directory is the **input root**, and every path it names must stay inside that
root — checked lexically and again against the real path after symbolic links are followed.

```json
{
  "schemaVersion": "1",
  "site": { "origin": "https://example.com" },
  "robotsTxt": "robots.txt",
  "checks": "checks.json",
  "capture": "capture.json"
}
```

The checks document is the agent/URL list. `expect` is optional; without it the decision is
reported but nothing is held to account.

```json
{
  "schemaVersion": "1",
  "checks": [
    {
      "userAgent": "GPTBot",
      "url": "https://example.com/search?q=shoes",
      "expect": { "crawl": "disallow", "index": "indexable" }
    }
  ]
}
```

The capture is the only source of indexing evidence. **Nothing is ever fetched**: there is no
network path in this tool. A capture is recorded elsewhere and read here as a file.

```json
{
  "schemaVersion": "1",
  "responses": [
    { "url": "https://example.com/offers", "headers": { "X-Robots-Tag": "noindex" } },
    { "url": "https://example.com/drafts/plan", "html": "capture/plan.html" },
    { "url": "https://example.com/search/help", "headers": {} }
  ]
}
```

An explicit `"headers": {}` states that the response carried no `X-Robots-Tag`. An entry that
declares neither headers nor a document states nothing, and is reported unverified — silence is not
evidence of absence. Only `x-robots-tag` is read; every other header is discarded at the boundary,
so a capture containing a cookie or an authorization header cannot leak into a report.

Unknown keys are **refused**, not ignored, in every input document. A one-character typo must not
turn a real failure into a green run.

## Output

```json
{
  "schemaVersion": "1",
  "tool": "robots-policy-auditor",
  "status": "pass",
  "summary": { "checked": 7, "errors": 0, "warnings": 0, "allowed": 4, "disallowed": 3,
               "indexBlocked": 1, "indexUnverified": 0 },
  "findings": [
    {
      "ruleId": "crawl-decision",
      "severity": "info",
      "message": "crawl=disallow index=indexable for \"GPTBot\" at /checks/2.",
      "location": { "file": "checks.json", "pointer": "/checks/2" },
      "evidence": "crawl: Disallow: /search (line 5, 7 octets) in the global \"*\" group [*]; index: none"
    }
  ]
}
```

Every decision names the rule that won, its line in `robots.txt`, its octet length and the group it
came from. Exit codes: `0` decided and passing, `1` decided and failing, `2` invalid configuration,
unreadable input, unverified evidence, or a limit exceeded.
Control and bidirectional-formatting characters from input are replaced before any finding or
diagnostic reaches JSON stdout or human stderr; an ordinary unknown directive is still reported.
An agent name consisting only of invisible characters is unevaluable: no crawl decision is made,
and the report is incomplete. Default-ignorable characters are rendered as spaces in diagnostics.

## Matching

RFC 9309, implemented as specified and documented rule by rule in
[`docs/robots-rules.md`](./docs/robots-rules.md):

- group selection by product token, compared case-insensitively and **in full** — not as a prefix;
- groups naming the same token are merged, and a specific group **replaces** the global `*` group
  rather than adding to it;
- an agent named by no group falls back to `*`, and with no `*` group either it is unrestricted;
- the most specific match wins, measured in octets of the rule pattern, and an `Allow` beats a
  `Disallow` of equal length;
- `*` matches any sequence, a trailing `$` anchors the end, and percent-encoding is normalized on
  both sides before comparison.

## Limits and non-goals

**This tool cannot conclude:**

- **That a URL is or is not in a search index.** It reads local files. Whether a given index holds
  a URL today is not visible from here, and no arrangement of directives guarantees it. The tool
  reports what the directives *say*, never what an index *contains*.
- **That a crawler obeys any of this.** RFC 9309 is voluntary. The tool reports what a compliant
  agent would do. A non-compliant one does as it likes — `Disallow` is not access control, and a
  URL that must stay private needs authentication, not a robots rule.
- **That the captured evidence is current.** A capture is a recording made elsewhere at some past
  moment. This tool cannot verify it and will not fetch to check. A URL the capture does not cover
  is reported unverified, and an unverified run is `incomplete`, never a pass. Evidence a capture
  declares but this tool could not read in full — a missing or oversized document, header values
  bounded out — is unverified for the same reason: it is not evidence that a URL is indexable.
- **That an agent name in a check is a real crawler.** Names are supplied by the operator and
  matched literally; a typo yields a correct decision for an agent that does not exist.
- **Anything about another origin.** A `robots.txt` governs its own origin only. A check naming a
  different origin is reported unevaluable rather than answered.
- **Anything about redirects, status codes or `rel=canonical`.** A capture's `status` is recorded
  but decides nothing.
- **That a `meta robots` element outside the head has no effect.** It is *treated* as ineffective,
  because that is the conservative reading, but an indexer may differ.

**Also deliberately absent:** any clock. `unavailable_after` makes indexability time-dependent, and
a report that changed with the hour could not be compared between runs, so such a URL is reported
unverified rather than guessed at.

## Determinism

Two runs over identical inputs produce byte-identical stdout. Nothing consults the clock, a locale,
a random source or filesystem enumeration order. Ordering is by UTF-16 code unit — never
`localeCompare`, whose collation varies with the ICU data in a given Node build.

## Verification

```sh
npm run check    # lint, tests, the clean example, and a packaging dry run
```

## Repository layout

- `src/` — implementation: `robots-txt.mjs` (RFC 9309 parsing and matching), `directives.mjs`
  (indexing directives), `report.mjs` (envelope, severity table, ordering), `index.mjs` (the audit)
- `bin/` — the command line interface
- `test/` — deterministic tests and fixtures
- `examples/` — a clean input set and a deliberately broken one
- `docs/` — the rule catalog, matching rules, refusals and limits

## License

MIT. See [LICENSE](./LICENSE).
