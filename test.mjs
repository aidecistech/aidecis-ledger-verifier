// SPDX-License-Identifier: MIT
// Self-contained test: builds a small synthetic export, checks that it passes, then tampers with it in several ways
// and checks that each one fails. Run with: node --test test.mjs
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { logEventHash, runEventHash, verifyFiles, FORMAT } from './verify.mjs'

const sha256 = (b) => createHash('sha256').update(b).digest('hex')
const T = '00000000-0000-4000-8000-000000000001'
const OTHER = '00000000-0000-4000-8000-000000000002'
const GENESIS = '0'.repeat(64)

function chain(rows, hash) {
  let prev = GENESIS
  return rows.map((r, i) => { const row = { ...r, seq: String(i + 1), prev_hash: prev }; row.hash = hash(prev, row); prev = row.hash; return row })
}

function makeExport() {
  const at = (m) => new Date(Date.UTC(2026, 9, 29, 10, m)).toISOString()
  const audit = chain([
    { tenant_id: T, decision_id: 'DEC-1', id: 'e1', at: at(0), kind: 'proposed', actor: 'Agent', actor_type: 'agent', text: 'Expedite proposed', detail: { amount: 1200 } },
    { tenant_id: T, decision_id: 'DEC-1', id: 'e2', at: at(5), kind: 'approved', actor: 'Logistics manager', actor_type: 'person', text: 'Approved on the brief', detail: null },
  ], logEventHash)
  const admin = chain([
    { tenant_id: T, decision_id: 'admin', id: 'a1', at: at(1), kind: 'admin', actor: 'Administrator', actor_type: 'person', text: 'Export downloaded', detail: null },
  ], logEventHash)
  const runs = chain([
    { tenant_id: T, run_id: 'RUN-1', id: 'r1', at: at(0), kind: 'opened', from_state: null, to_state: 'open', actor: 'Orchestrator', actor_type: 'system', detail: { b: 2, a: 1 } },
    { tenant_id: T, run_id: 'RUN-1', id: 'r2', at: at(6), kind: 'closed', from_state: 'open', to_state: 'closed', actor: 'Orchestrator', actor_type: 'system', detail: {} },
  ], runEventHash)
  const decisions = [{ tenant_id: T, id: 'DEC-1', title: 'Expedite a late inbound shipment' }]
  const tables = { audit_events: audit, admin_events: admin, run_events: runs, decisions }
  const files = new Map()
  const listed = []
  for (const [table, rows] of Object.entries(tables)) {
    const path = `data/${table}.json`
    const buf = Buffer.from(JSON.stringify(rows))
    files.set(path, buf)
    listed.push({ path, table, format: 'json', rows: rows.length, sha256: sha256(buf) })
  }
  const head = (rows) => ({ head: rows.at(-1).hash, events: rows.length })
  const manifest = { format: FORMAT, environment: { id: T, subdomain: 'example', name: 'Example' }, createdAt: at(7), exportedBy: 'test',
    files: listed, chains: { audit_events: head(audit), admin_events: head(admin), run_events: head(runs) } }
  files.set('manifest.json', Buffer.from(JSON.stringify(manifest)))
  return { files, manifest, tables }
}

// Rewrites one table and fixes up its file hash in the manifest, as a careful forger would.
function forge(ex, table, change) {
  const rows = structuredClone(ex.tables[table])
  change(rows)
  const buf = Buffer.from(JSON.stringify(rows))
  ex.files.set(`data/${table}.json`, buf)
  const m = structuredClone(ex.manifest)
  const f = m.files.find((x) => x.table === table)
  f.sha256 = sha256(buf); f.rows = rows.length
  ex.files.set('manifest.json', Buffer.from(JSON.stringify(m)))
  return ex
}
const failed = (r) => r.checks.filter((c) => !c.ok).map((c) => c.name)

test('an untouched export passes', () => {
  const ex = makeExport()
  const r = verifyFiles(ex.files, { 'audit-head': ex.manifest.chains.audit_events.head })
  assert.equal(r.ok, true, JSON.stringify(r.checks))
})

test('a changed byte fails on its file hash', () => {
  const ex = makeExport()
  const b = Buffer.from(ex.files.get('data/decisions.json')); b[b.length - 3] ^= 1
  ex.files.set('data/decisions.json', b)
  assert.deepEqual(failed(verifyFiles(ex.files)).includes('hashes'), true)
})

test('an edited audit event fails on its chain, even with the manifest hash fixed up', () => {
  const r = verifyFiles(forge(makeExport(), 'audit_events', (rows) => { rows[0].detail.amount = 120 }).files)
  assert.deepEqual(failed(r), ['audit_events'])
})

test('a removed run event fails on its chain', () => {
  const r = verifyFiles(forge(makeExport(), 'run_events', (rows) => { rows.splice(0, 1) }).files)
  assert.ok(failed(r).includes('run_events'))
})

test('a row of another environment fails', () => {
  const r = verifyFiles(forge(makeExport(), 'decisions', (rows) => { rows.push({ tenant_id: OTHER, id: 'DEC-9', title: 'x' }) }).files)
  assert.deepEqual(failed(r), ['environment'])
})

test('an extra file fails', () => {
  const ex = makeExport()
  ex.files.set('data/extra.json', Buffer.from('[]'))
  assert.ok(failed(verifyFiles(ex.files)).includes('files'))
})

test('a head you hold that differs fails', () => {
  const ex = makeExport()
  assert.ok(failed(verifyFiles(ex.files, { 'run-head': 'f'.repeat(64) })).includes('run_events'))
})
