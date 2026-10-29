#!/usr/bin/env node
// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Aidecis
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
// documentation files (the "Software"), to deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to the following conditions: the above copyright
// notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND (see LICENSE next to this file).

/**
 * Aidecis ledger verifier: checks a full export of an Aidecis environment without any Aidecis system.
 *
 * It needs Node.js 18 or later and nothing else (no packages, no network). It reads the export (the .tar.gz as
 * downloaded, a .tar, or a folder it was unpacked into) and checks:
 *   1. every file listed in manifest.json is present, has the SHA-256 the manifest gives, and no data file is unlisted;
 *   2. every table file holds the number of rows the manifest gives, and every row belongs to the exported environment;
 *   3. the hash chains of the audit log, the administration log and the run ledger: each event's hash is recomputed
 *      from its content and the hash of the event before it, exactly as the Aidecis server computes it, and the last
 *      hash (the head) is compared with the manifest and, when given, with a head you hold yourself.
 *
 * Usage: node verify.mjs <export.tar.gz | export.tar | folder> [--audit-head <hex>] [--admin-head <hex>] [--run-head <hex>] [--json]
 * Exit code 0 when every check passes, 1 when one fails, 2 when the export cannot be read.
 */

import { createHash } from 'node:crypto'
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, relative, sep } from 'node:path'
import { gunzipSync } from 'node:zlib'
import { fileURLToPath } from 'node:url'

export const VERSION = '1.0.0'
export const FORMAT = 'aidecis.tenant-export v1'
const GENESIS = '0'.repeat(64)

const sha256 = (data) => createHash('sha256').update(data).digest('hex')

// ---------------------------------------------------------------- hashing rules (same as the Aidecis server)

/**
 * Audit log and administration log (server/audit.ts): SHA-256 of the JSON array
 * [previous hash, subject id, event id, time, kind, actor, actor type, text, detail or null],
 * where the time is ISO 8601 in UTC with milliseconds.
 */
export function logEventHash(prev, row) {
  const at = new Date(row.at).toISOString()
  return sha256(JSON.stringify([prev, row.decision_id, row.id, at, row.kind, row.actor, row.actor_type, row.text, row.detail ?? null]))
}

/** Canonical JSON with object keys sorted, as server/run-ledger.ts canonical(). */
export function canonical(v) {
  if (Array.isArray(v)) return `[${v.map(canonical).join(',')}]`
  if (v && typeof v === 'object') return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canonical(v[k])}`).join(',')}}`
  return JSON.stringify(v ?? null)
}

/**
 * Run ledger (server/run-ledger.ts): SHA-256 of the canonical JSON of
 * [previous hash, run id, event id, time, kind, from state, to state, actor, actor type, detail].
 */
export function runEventHash(prev, row) {
  const at = new Date(row.at).toISOString()
  return sha256(canonical([prev, row.run_id, row.id, at, row.kind, row.from_state, row.to_state, row.actor, row.actor_type, row.detail]))
}

const CHAINS = [
  { table: 'audit_events', label: 'Audit log', hash: logEventHash, flag: 'audit-head' },
  { table: 'admin_events', label: 'Administration log', hash: logEventHash, flag: 'admin-head' },
  { table: 'run_events', label: 'Run ledger', hash: runEventHash, flag: 'run-head' },
]

/** Walks one chain in sequence order from the genesis hash; reports the first event that does not hold. */
export function walkChain(rows, hash) {
  const sorted = [...rows].sort((a, b) => (BigInt(a.seq) < BigInt(b.seq) ? -1 : BigInt(a.seq) > BigInt(b.seq) ? 1 : 0))
  let prev = GENESIS
  for (const r of sorted) {
    if (r.prev_hash !== prev) return { ok: false, events: sorted.length, head: prev, brokenAt: { seq: String(r.seq), id: r.id, why: 'its previous hash does not point at the event before it (an event was removed, added or reordered)' } }
    const expected = hash(prev, r)
    if (r.hash !== expected) return { ok: false, events: sorted.length, head: prev, brokenAt: { seq: String(r.seq), id: r.id, why: 'its content does not match its hash (the event was changed)' } }
    prev = r.hash
  }
  return { ok: true, events: sorted.length, head: prev }
}

// ---------------------------------------------------------------- reading the export

/** Reads a POSIX (ustar) tar archive into a map of path to bytes; only regular files. */
export function readTar(buf) {
  const files = new Map()
  let off = 0
  const str = (b) => { const i = b.indexOf(0); return (i < 0 ? b : b.subarray(0, i)).toString('utf8') }
  while (off + 512 <= buf.length) {
    const h = buf.subarray(off, off + 512)
    if (h.every((x) => x === 0)) break
    const name = str(h.subarray(0, 100))
    const prefix = str(h.subarray(345, 500))
    const size = parseInt(str(h.subarray(124, 136)).trim() || '0', 8)
    const type = String.fromCharCode(h[156] || 48)
    const sum = parseInt(str(h.subarray(148, 156)).trim() || '0', 8)
    let actual = 0
    for (let i = 0; i < 512; i++) actual += i >= 148 && i < 156 ? 32 : h[i]
    if (Number.isNaN(size) || sum !== actual) throw new Error(`The archive is damaged at byte ${off} (a header does not check out).`)
    off += 512
    if (type === '0') files.set(prefix ? `${prefix}/${name}` : name, Buffer.from(buf.subarray(off, off + size)))
    off += Math.ceil(size / 512) * 512
  }
  return files
}

function readFolder(dir) {
  const files = new Map()
  const walk = (d) => {
    for (const e of readdirSync(d, { withFileTypes: true })) {
      const p = join(d, e.name)
      if (e.isDirectory()) walk(p)
      else if (e.isFile()) files.set(relative(dir, p).split(sep).join('/'), readFileSync(p))
    }
  }
  walk(dir)
  return files
}

/** Loads an export from a .tar.gz, a .tar or a folder; returns the files relative to the folder holding manifest.json. */
export function loadExport(path) {
  let files
  if (statSync(path).isDirectory()) files = readFolder(path)
  else {
    let buf = readFileSync(path)
    if (buf[0] === 0x1f && buf[1] === 0x8b) buf = gunzipSync(buf)
    files = readTar(buf)
  }
  const manifestPath = [...files.keys()].filter((p) => p === 'manifest.json' || p.endsWith('/manifest.json')).sort((a, b) => a.length - b.length)[0]
  if (!manifestPath) throw new Error('No manifest.json found: this is not an Aidecis export.')
  const root = manifestPath.slice(0, -'manifest.json'.length)
  const out = new Map()
  for (const [p, b] of files) if (p.startsWith(root)) out.set(p.slice(root.length), b)
  return out
}

// ---------------------------------------------------------------- checks

/**
 * Verifies an export already loaded with loadExport. `expect` may hold heads you hold yourself:
 * { 'audit-head': hex, 'admin-head': hex, 'run-head': hex }.
 */
export function verifyFiles(files, expect = {}) {
  const checks = []
  const add = (ok, name, text) => checks.push({ ok, name, text })
  let manifest
  try {
    manifest = JSON.parse(files.get('manifest.json').toString('utf8'))
  } catch {
    add(false, 'manifest', 'manifest.json is not valid JSON.')
    return { ok: false, manifest: null, checks }
  }
  if (manifest.format !== FORMAT) add(false, 'format', `Unknown format "${manifest.format}"; this verifier reads "${FORMAT}".`)
  else add(true, 'format', FORMAT)

  // 1. Files and their hashes.
  const listed = new Map((manifest.files ?? []).map((f) => [f.path, f]))
  const missing = [...listed.keys()].filter((p) => !files.has(p))
  const unlisted = [...files.keys()].filter((p) => p !== 'manifest.json' && !listed.has(p))
  add(missing.length === 0 && unlisted.length === 0, 'files',
    missing.length || unlisted.length
      ? [missing.length ? `missing: ${missing.join(', ')}` : '', unlisted.length ? `not in the manifest: ${unlisted.join(', ')}` : ''].filter(Boolean).join('; ')
      : `${listed.size} files listed, all present, none unlisted`)
  const badHash = [...listed.values()].filter((f) => files.has(f.path) && sha256(files.get(f.path)) !== f.sha256).map((f) => f.path)
  add(badHash.length === 0, 'hashes', badHash.length ? `SHA-256 differs from the manifest for: ${badHash.join(', ')}` : `${listed.size - missing.length} of ${listed.size} files match their SHA-256`)

  // 2. Rows: counts and environment.
  const tenantId = manifest.environment?.id
  const rowsOf = new Map()
  const countErrors = []
  const foreign = []
  for (const f of listed.values()) {
    if (f.format !== 'json' || !f.table || !files.has(f.path)) continue
    let rows
    try {
      rows = JSON.parse(files.get(f.path).toString('utf8'))
      if (!Array.isArray(rows)) throw new Error('not an array')
    } catch {
      countErrors.push(`${f.path} is not a JSON array`)
      continue
    }
    rowsOf.set(f.table, rows)
    if (rows.length !== f.rows) countErrors.push(`${f.path} has ${rows.length} rows, the manifest says ${f.rows}`)
    const other = rows.filter((r) => 'tenant_id' in r && r.tenant_id !== tenantId).length
    if (other) foreign.push(`${f.table}: ${other}`)
  }
  add(countErrors.length === 0, 'rows', countErrors.length ? countErrors.join('; ') : `${rowsOf.size} tables, row counts match the manifest`)
  add(!!tenantId && foreign.length === 0, 'environment', !tenantId ? 'the manifest names no environment' : foreign.length ? `rows of another environment in ${foreign.join(', ')}` : `every row belongs to environment ${tenantId}`)

  // 3. Hash chains.
  const chains = {}
  for (const ch of CHAINS) {
    const rows = rowsOf.get(ch.table)
    const stated = manifest.chains?.[ch.table]
    if (!rows) { add(false, ch.table, `${ch.label}: data/${ch.table}.json is missing`); continue }
    const r = walkChain(rows, ch.hash)
    chains[ch.table] = r
    if (!r.ok) { add(false, ch.table, `${ch.label}: chain broken at event ${r.brokenAt.seq} (${r.brokenAt.id}): ${r.brokenAt.why}`); continue }
    const problems = []
    if (!stated) problems.push('the manifest states no head')
    else {
      if (stated.head !== r.head) problems.push(`head ${short(r.head)} differs from the manifest's ${short(stated.head)}`)
      if (stated.events !== r.events) problems.push(`${r.events} events, the manifest says ${stated.events}`)
    }
    const mine = expect[ch.flag]
    if (mine && mine.toLowerCase() !== r.head) problems.push(`head ${short(r.head)} differs from the head you gave (${short(mine)})`)
    add(problems.length === 0, ch.table, problems.length ? `${ch.label}: ${problems.join('; ')}` : `${ch.label}: ${r.events} events, chain intact, head ${r.head}${mine ? ' (matches the head you gave)' : ''}`)
  }
  return { ok: checks.every((c) => c.ok), manifest, checks, chains }
}

const short = (h) => (h ? `${String(h).slice(0, 12)}…` : 'none')

export function verifyExport(path, expect = {}) {
  return verifyFiles(loadExport(path), expect)
}

export function report(path, result) {
  const m = result.manifest
  const lines = [`Aidecis ledger verifier ${VERSION}`, `Export: ${path}`]
  if (m) lines.push(`Environment: ${m.environment?.subdomain ?? '?'} (${m.environment?.name ?? '?'}), exported ${m.createdAt ?? '?'} by ${m.exportedBy ?? '?'}`)
  lines.push('')
  for (const c of result.checks) lines.push(`${c.ok ? 'PASS' : 'FAIL'}  ${c.name}: ${c.text}`)
  lines.push('', `RESULT: ${result.ok ? 'PASS' : 'FAIL'}`)
  if (result.ok) lines.push('The files match the manifest and the three hash chains are intact. Compare the heads with a head you hold from earlier (for example the one shown in the app or in an earlier export) to know that nothing was cut off or rewritten as a whole.')
  return lines.join('\n')
}

// ---------------------------------------------------------------- command line

function main(argv) {
  const args = argv.slice(2)
  const expect = {}
  let json = false
  let path
  for (let i = 0; i < args.length; i++) {
    const a = args[i]
    if (a === '--json') json = true
    else if (a === '--help' || a === '-h') path = undefined
    else if (a.startsWith('--') && CHAINS.some((c) => `--${c.flag}` === a)) expect[a.slice(2)] = args[++i] ?? ''
    else if (!path) path = a
  }
  if (!path || args.includes('--help') || args.includes('-h')) {
    console.log('Usage: node verify.mjs <export.tar.gz | export.tar | folder> [--audit-head <hex>] [--admin-head <hex>] [--run-head <hex>] [--json]')
    return args.includes('--help') || args.includes('-h') ? 0 : 2
  }
  let result
  try {
    result = verifyExport(path, expect)
  } catch (e) {
    console.error(`Cannot read the export: ${e.message}`)
    return 2
  }
  if (json) console.log(JSON.stringify({ ok: result.ok, checks: result.checks, chains: result.chains ?? {} }, null, 2))
  else console.log(report(path, result))
  return result.ok ? 0 : 1
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) process.exitCode = main(process.argv)
