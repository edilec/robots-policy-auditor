# Changelog

All notable changes to this project are documented in this file.

## Unreleased

### Added

- RFC 9309 group selection and rule matching: product tokens compared case-insensitively and in
  full rather than by prefix, groups naming the same token merged, a specific group replacing the
  global `*` group rather than adding to it, an unmatched agent falling back to `*`, the most
  specific match winning by octet length, and an `Allow` beating a `Disallow` of equal length
  whichever was written first;
- `*` and trailing `$` matching without building a regular expression from input, and
  percent-encoding normalized on both sides so a rule written `/café/` and one written
  `/caf%C3%A9/` decide the same URL while `/a%2Fb` and `/a/b` stay distinct;
- a decision record for every agent/URL pair naming the rule that won, its line, its octet length
  and the group it came from — the winning rule is part of the answer, not a debugging aid;
- a separate indexing axis read from captured `X-Robots-Tag` values and robots `<meta>` elements,
  with agent-scoped directives on both, comment and `script` / `style` masking, and a robots meta
  element outside the head reported and treated as having no effect;
- `noindex-behind-disallow`, which reports a noindex an obedient agent can never fetch, and
  `disallow-is-not-deindex`, which states plainly that a disallowed URL can still be indexed from
  external links — this tool never reports a disallow as removal from an index;
- robots.txt hygiene rules: rules before any user-agent line, unusable product tokens, rule paths
  beginning with neither `/` nor `*`, `noindex` in robots.txt, malformed lines, unknown and
  non-standard directives, empty groups and duplicate groups;
- `unknown-index-directive`, because a misspelled directive is silently ignored by an indexer and
  therefore removes nothing, and `directive-conflict` when a blocking and a permitting directive
  address the same agent;
- an imported capture as the only source of indexing evidence, with no network path in the tool at
  all; a URL the capture does not cover, an entry that declares neither headers nor a document, and
  a time-dependent `unavailable_after` are each reported `indexing-unverified`, which makes the run
  `incomplete` rather than a pass;
- only `x-robots-tag` read from a capture's headers, with every other header discarded at the
  validation boundary so it cannot reach a report;
- one frozen `ruleId -> severity` table that every finding's severity is taken from, asserted
  against the documented catalog in both directions, throwing on an unknown rule;
- confinement of every declared path to the input root, checked lexically and again against the
  real path after symbolic links are followed, so neither a relative traversal nor a link planted
  inside the root can read outside it;
- strict UTF-8 decoding, so undecodable bytes are reported rather than inferred from a replacement
  character in already-decoded text;
- nine explicit limits, each overridable in `config.limits` or with `--limit NAME=VALUE`, each
  reported by name when reached, and each making the run `incomplete` instead of truncating;
- unknown keys refused in every input document, and unknown limit names refused, rather than
  silently ignored;
- a CLI with `--help`, `--json` and `--limit`, the report on stdout, the human summary on stderr,
  an empty stdout on a configuration refusal, and exit codes 0 / 1 / 2;
- runnable clean and deliberately broken example input sets; the clean set demonstrates longest
  match, the equal-length `Allow`, end anchoring, the unknown-agent fallback and a specific group
  displacing the global one, and the broken set spreads its findings over three files so the
  documented finding order is demonstrated as well as the rules;
- the rule catalog, matching rules, refusals, limits, report shape, determinism guarantee and an
  explicit statement of what the tool cannot conclude, in `docs/robots-rules.md`.

No release has been published.
