# Aidecis ledger verifier

A small, open-source program that checks a full export of an Aidecis environment without any Aidecis system. A client
or its auditor can run it on their own machine, with no internet connection.

Licence: MIT (see LICENSE). One file, `verify.mjs`, with no dependencies: it uses only what ships with Node.js 18 or later.

## Run it

```sh
node verify.mjs aidecis-export-<environment>-<time>.tar.gz
```

It also reads a `.tar` or a folder you unpacked the export into. Options:

| Option | What it does |
|---|---|
| `--audit-head <hex>` | Also checks that the audit log ends at this hash, one you hold from earlier (the app shows it, and every export states it) |
| `--admin-head <hex>` | The same for the administration log |
| `--run-head <hex>` | The same for the run ledger |
| `--json` | The result as JSON instead of text |

Exit code: 0 when every check passes, 1 when one fails, 2 when the export cannot be read.

## What it checks

1. Files: every file in `manifest.json` is present, has the SHA-256 the manifest gives, and no other file is in the
   export.
2. Rows: every table file holds the number of rows the manifest gives, and every row belongs to the environment the
   manifest names.
3. Hash chains: the audit log (`audit_events`), the administration log (`admin_events`) and the run ledger
   (`run_events`). Each event's hash is recomputed from its content and the hash of the event before it, from 64 zeros
   at the start. A changed, removed, added or reordered event breaks the chain at that event. The last hash (the head)
   must equal the head in the manifest, and the head you give, if any.

## The hashing rules

These are the rules the Aidecis server uses to write the logs; every export's manifest states them too.

- Audit log and administration log: SHA-256 (hex) of `JSON.stringify([prev_hash, decision_id, id, at, kind, actor,
  actor_type, text, detail or null])`, with `at` as ISO 8601 in UTC with milliseconds (`2026-10-29T14:05:00.000Z`).
- Run ledger: SHA-256 (hex) of the canonical JSON of `[prev_hash, run_id, id, at, kind, from_state, to_state, actor,
  actor_type, detail]`. Canonical JSON is JSON with the keys of every object sorted and no spaces; `at` as above.
- Events are taken in order of `seq`. The first event's `prev_hash` is 64 zeros.
- Files: SHA-256 (hex) of the bytes of the file.

## What a pass means, and what it does not

A pass means the files match the manifest and the three chains are intact from their first event to their head.

- The chains protect the audit log, the administration log and the run ledger event by event. Someone who changes an
  event cannot hide it without recomputing every later hash, and then the head changes.
- That is why the head matters: compare it with a head you wrote down or kept from an earlier export. The same head,
  or a later export whose chain contains it, means nothing before it was rewritten.
- The other tables (decisions, policies, settings and so on) are protected by the SHA-256 in the manifest only. That
  protects against damage and against changes after the export, as long as you keep the manifest, or the SHA-256 of
  the archive shown when you downloaded it, apart from the files.

## Tests

`node --test test.mjs` builds a small synthetic export, checks that it passes, and checks that each of these fails: a
changed byte, an edited audit event, a removed run event, a row of another environment, an extra file and a head that
differs from the one you hold. The forged cases fix up the file hashes in the manifest first, as a careful forger
would, so they show that the hash chains catch what the manifest alone cannot. CI runs the tests on Node.js 18, 20 and
22. The Aidecis app also runs this verifier on real exports in its own test suite.

## Where it comes from

Aidecis is the decision intelligence and control layer for consequential supply-chain decisions
([aidecis.com](https://www.aidecis.com/)). This verifier is part of its continuity package: a client owns its decision
record and can check it without Aidecis. A copy of this file is also included in every export. To report a problem,
open an issue in this repository.
