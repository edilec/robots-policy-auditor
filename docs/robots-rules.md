# Rule catalog, matching rules and limits

This document is the reference for what `robots-policy-auditor` evaluates, what each rule means,
and what the tool refuses to claim. Rule ids are stable: renaming one is a breaking change and is
recorded in the changelog. The severity column here is asserted against the `RULE_SEVERITY` table
in `src/report.mjs` in both directions, so the shipped catalog and this document cannot drift
apart.

## The two axes

The whole point of this tool is that **crawl permission and indexing are different questions**,
decided by different files, and confusing them is the most common robots mistake there is.

| Axis | Decided by | Question it answers |
| --- | --- | --- |
| Crawl permission | `robots.txt` | May this agent *fetch* this URL? |
| Indexing | `X-Robots-Tag` response header, `<meta name=robots>` in the response body | May an indexer *keep* what it fetched? |

A `Disallow` withholds the content, not the URL. A URL that is disallowed can still appear in a
search index, described from external links to it, because the indexer never needed the content to
learn the URL exists. So this tool never reports a disallow as removal from an index, and says so
in the report itself (`disallow-is-not-deindex`).

The practical consequence runs the other way too. An indexing directive is delivered *in the
response*, so an agent that obeys a `Disallow` never fetches the response and never sees the
directive. A `noindex` behind a `Disallow` cannot take effect, which is reported as
`noindex-behind-disallow`.

## What is read

| Input | Required | What is taken from it |
| --- | --- | --- |
| `robotsTxt` | yes | groups, `Allow` / `Disallow` rules, `Sitemap` declarations, syntax problems |
| `checks` | yes | the agent/URL pairs to decide, and the expectations to hold them to |
| `capture` | no | `X-Robots-Tag` values and captured HTML documents, per URL |

Nothing is fetched. There is no network path in this tool at all. Header and document evidence
reaches it only as an imported capture recorded elsewhere, and a URL the capture does not cover has
an **unknown** indexing state, reported as `indexing-unverified` — which makes the run `incomplete`,
never a pass.

Only `x-robots-tag` is read out of a capture's headers. Every other header is discarded while the
capture is being validated, before any code that could place it in a report can see it.

Every input is decoded as strict UTF-8 — the JSON documents exactly as much as `robots.txt` and the
captured pages. A decoder that replaces an undecodable byte instead of failing would turn a capture
carrying one stray byte into a `noindex` nobody can recognise, and the URL it protects would be
reported indexable by a run that read nothing. A file that does not decode reports `input-not-utf8`
and the run is `incomplete`.

## Group selection (RFC 9309 section 2.2.1)

1. A group is one or more consecutive `User-agent` lines followed by its rules. A `User-agent` line
   that follows a rule line opens a *new* group.
2. A group's product token is the leading run of letters, `-` and `_` in the `User-agent` value, so
   `ExampleBot/2.0 (+https://example.com/bot)` names the token `ExampleBot`.
3. The agent being checked matches a token when the two are equal, compared case-insensitively.
   Matching is **not** by prefix or substring: a group for `Example` does not govern `ExampleBot`.
4. Every group naming a matching token is merged, in file order. A repeated token is reported as
   `duplicate-group`.
5. An agent matched by no group falls back to the groups naming `*`. An agent matched by neither is
   unrestricted, and the report says the decision came from no group at all.
6. A specific group **replaces** the global one; it does not add to it. An agent with its own group
   is not subject to the `*` rules, which is the behaviour most often assumed backwards.
7. `*` is the global token only when it stands alone or is followed by whitespace. `*bot` names no
   usable token and is reported as `invalid-user-agent`.

## Rule matching (RFC 9309 sections 2.2.2 and 2.2.3)

- A rule is matched against the URL's **path and query** together, so `Disallow: /search` matches
  `/search?q=shoes`.
- `*` matches any sequence of characters. A trailing `$` anchors the end of the path; a `$`
  anywhere else is a literal character.
- The most specific match wins, and "most specific" means the rule pattern with the most **octets**
  — the pattern as written, wildcards included, measured after normalization.
- When an `Allow` and a `Disallow` match with the same octet length, the `Allow` wins, whichever
  was written first. Two rules of the same type and length say the same thing, so the earlier line
  is reported as the winner and the order stays stable.
- With no matching rule, the URL is crawlable. That is the default the protocol specifies.
- `Disallow:` and `Allow:` with an empty value place no restriction and grant nothing. They are
  valid, and neither becomes a rule.
- A rule value beginning with neither `/` nor `*` is undefined by RFC 9309 and is reported as
  `invalid-rule-path` rather than guessed at.

### Percent-encoding

Both sides of a comparison are normalized before matching: percent-escapes of unreserved
characters (`A-Z a-z 0-9 - . _ ~`) are decoded, every other escape keeps its escape with uppercase
hex digits, and a literal non-ASCII character in a rule is percent-encoded. So `Disallow: /café/`
and `Disallow: /caf%C3%A9/` both match `https://example.com/café/menu`, while `/a%2Fb` and `/a/b`
stay distinct — `%2F` is a reserved octet and decoding it would change what the rule means.

## Indexing directives

A directive source is either an `X-Robots-Tag` header value or a robots `<meta>` element in the
captured document.

- A header value may be scoped to one agent, as in `X-Robots-Tag: googlebot: noindex`. A directive
  name that itself contains a colon, such as `unavailable_after:`, is not mistaken for an agent.
- A meta element's `name` is either `robots`, addressing every indexer, or a product token
  addressing one. `http-equiv` is deliberately not read: the major indexers do not honour a robots
  directive delivered that way, and honouring it here would report a page as blocked when it is not.
- Comments and the bodies of `script` and `style` elements are blanked out before extraction, so a
  directive quoted in a comment or a template string is not mistaken for a live one.
- A robots meta element after the document head is reported as `meta-outside-head` and treated as
  having **no effect**. That is the conservative reading: the risk being warned about is a page
  staying in an index, so a directive that may be ignored must not be counted as one that removed
  it.
- `noindex` and `none` block indexing. Anything else recognised does not. A name that no major
  indexer defines is reported as `unknown-index-directive`, because a misspelled directive is
  silently ignored by the indexer and therefore removes nothing.
- With a blocking and a permitting directive both addressing the same agent, the restrictive one is
  assumed to win — which is what the indexers do — and the disagreement is reported as
  `directive-conflict`.
- `unavailable_after` makes indexability depend on the current time. This tool has no clock, by
  design, because a report that changed with the hour could not be compared between runs. Such a
  URL is reported `indexing-unverified` rather than guessed at.

## Rule catalog

| Rule | Severity | What it means |
| --- | --- | --- |
| `check-unevaluable` | error | A check names no absolute URL, or an origin this robots.txt does not govern. It could not be decided, so the run is incomplete. |
| `crawl-decision` | info | The decision for one agent/URL pair, with the rule that won, its line, its octet length and the group it came from. |
| `crawl-expectation-mismatch` | error | A check declared `expect.crawl` and the rules decided the other way. |
| `directive-conflict` | warning | A blocking and a permitting indexing directive both address this agent. The restrictive one is assumed to win. |
| `disallow-is-not-deindex` | info | A disallowed URL carries no indexing directive. It can still be indexed from external links; this is not removal from an index. |
| `duplicate-group` | info | One product token heads more than one group. The records are merged, as RFC 9309 requires. |
| `empty-group` | info | A group declares no rule, so every URL is crawlable for the agents it names. |
| `index-expectation-mismatch` | error | A check declared `expect.index` and the captured directives decided the other way. |
| `indexing-unverified` | warning | The indexing axis could not be decided: no capture covers the URL, the capture entry states nothing, or the directive depends on the time. The run is incomplete. |
| `input-not-utf8` | error | A file's bytes could not be decoded as UTF-8, so it was not parsed. |
| `input-too-large` | error | A file exceeded its byte limit, so it was not parsed. |
| `input-unreadable` | error | A declared file could not be read or was not valid JSON. |
| `invalid-rule-path` | warning | A rule value begins with neither `/` nor `*`, which RFC 9309 does not define. The rule is ignored. |
| `invalid-user-agent` | warning | A `User-agent` line names no usable product token, so the group it opens can never be selected. |
| `limit-exceeded` | error | A documented limit was reached. Parsing stopped; nothing was silently truncated. |
| `malformed-line` | warning | A non-empty, non-comment line has no `:` separator and declares no directive. |
| `meta-outside-head` | warning | A robots meta element appears after the head, where the major indexers do not read it. It is treated as having no effect. |
| `no-evidence` | error | Nothing was decided, so nothing was verified. A run that checked zero URLs is never a pass. |
| `noindex-behind-disallow` | error | A URL is disallowed and also carries a noindex. An agent that obeys the disallow never fetches the response, so it never sees the directive. |
| `nonstandard-directive` | info | A directive outside RFC 9309, such as `crawl-delay`. It was read and takes no part in any decision. |
| `robots-txt-noindex` | warning | `noindex` appears in robots.txt. It is not part of RFC 9309, the major crawlers do not honour it, and it removes nothing from an index. |
| `rule-outside-group` | warning | An `allow` or `disallow` line appears before any `user-agent` line, so it belongs to no group and is ignored. |
| `unknown-directive` | warning | An unrecognised robots.txt directive that no crawler is required to act on. |
| `unknown-index-directive` | warning | An indexing directive name no major indexer defines. A misspelling here is silently ignored and removes nothing. |

## Refusals

A refusal is different from a finding. A finding describes the site being audited; a refusal says
the run never had a subject it could trust. A refusal writes **nothing to stdout** and exits 2,
because emitting a report about a run that never started would be worse than emitting none.

| Refusal | Cause |
| --- | --- |
| unknown key | Any input document carries a key the schema does not define. A one-character typo must not turn a real failure into a green run. |
| unknown limit | A limit name that does not exist. |
| schema violation | A wrong `schemaVersion`, a wrong type, or an expectation value outside the documented set. |
| ambiguous capture | Two capture entries for the same URL. Which one applies would be a guess. |
| input not relative | A declared path is absolute. |
| input outside root | A declared path resolves outside the input root. |
| input escapes root | A declared path leaves the input root through a symbolic link. Nothing is read from it. |
| input unresolvable | A path could not be resolved at all, for example through a link cycle. |

Path confinement is checked twice: lexically, and again against the **real** path after every
symbolic link on it has been followed, compared with the real path of the root itself. A lexical
check alone is not confinement — a link planted inside the root points wherever it likes.

## Limits

Every limit is enforced, overridable by name in `config.limits` or with `--limit NAME=VALUE`, and
reported by name when it is reached. Exceeding one makes the run `incomplete`; nothing is ever
silently truncated. The two byte limits report `input-too-large`, because the file was rejected
before it was parsed at all; the seven counting limits report `limit-exceeded`, because parsing
began and stopped.

| Limit | Default | What it bounds |
| --- | ---: | --- |
| `maxRobotsBytes` | 512000 | Bytes of robots.txt read; reports `input-too-large`. 500 KiB is the size RFC 9309 requires a crawler to parse at least, so bytes past it are not policy anywhere. |
| `maxRobotsLines` | 10000 | Lines parsed from robots.txt. |
| `maxGroups` | 1000 | Groups parsed from robots.txt. |
| `maxRulesPerGroup` | 5000 | Rules parsed within one group. |
| `maxChecks` | 5000 | Checks evaluated in one run. |
| `maxCaptureEntries` | 5000 | Responses read from one capture. |
| `maxHtmlBytes` | 1048576 | Bytes of one captured document; reports `input-too-large`. |
| `maxMetaTags` | 500 | Meta elements extracted from one captured document. |
| `maxHeaderValues` | 50 | `X-Robots-Tag` values read from one response. |

Evidence excerpts are bounded at 200 characters and stripped of control characters. Input content
is data: it is never emitted at full length and never placed where it could be mistaken for an
instruction.

## Report shape and determinism

The report follows the Edilec tool report contract: `schemaVersion`, `tool`, `status`, `summary`
and `findings`. The summary carries `checked`, `errors`, `warnings`, and the tool-specific counts
`allowed`, `disallowed`, `indexBlocked` and `indexUnverified`.

Findings are ordered by `location.file`, then `location.pointer`, then `ruleId`, then `message`.
The last two make the order total, so two findings sharing a location never depend on the order
they were produced in. Comparison is by UTF-16 code unit — never `localeCompare`, whose collation
depends on ICU data that differs between Node builds — except that all-digit pointer segments are
compared numerically, so `/checks/2` precedes `/checks/10`. Line-oriented pointers are written
`/line/0007`, zero-padded, so they read in order too.

Two runs over identical inputs produce byte-identical stdout. Nothing in the tool consults the
clock, a locale, a random source or filesystem enumeration order.

## Status and exit codes

| Status | Exit | When |
| --- | ---: | --- |
| `pass` | 0 | At least one check was decided and no error-severity finding was produced. |
| `fail` | 1 | The policy was evaluated and at least one error-severity finding was produced. |
| `incomplete` | 2 | Evidence was missing, undecodable or bounded out — or nothing was checked. |

`incomplete` wins over everything. `checked == 0` is never a pass: a run that decided nothing has
proved nothing, and it reports `no-evidence` and exits 2.

## What this tool cannot conclude

- **That a URL is or is not in a search index.** It reads local files. Whether a given index
  contains a URL today is not visible from here, and no arrangement of directives guarantees it.
- **That a crawler obeys any of this.** RFC 9309 is voluntary. The tool reports what a compliant
  agent would do; a non-compliant one does whatever it likes, and a disallowed URL is not access
  control.
- **That the captured evidence is what the server serves now.** A capture is a recording made
  elsewhere at some past moment. The tool cannot verify it, will not fetch to check it, and treats
  a URL it does not cover as unverified.
- **That an agent name in a check is a real crawler.** Agent names are supplied by the operator and
  matched literally. A typo produces a decision for an agent that does not exist, and the decision
  will be correct for that nonexistent agent.
- **Anything about robots.txt files at other origins or other ports.** A robots.txt governs its own
  origin only; a check naming another origin is reported unevaluable rather than answered.
- **Anything about redirects, status codes or `rel=canonical`.** A capture's `status` is recorded
  but takes no part in a decision; how an indexer treats a 404 or a redirect is out of scope.
