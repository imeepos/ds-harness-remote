#!/usr/bin/env node
/**
 * M0 契约门禁：把"上界"与"映射完备"变成可执行断言。
 *
 * 只读，不改任何源码。失败时退出码 1，并写出 contract/report.json。
 *
 * 用法：node contract/check.mjs [--json <path>]
 */
import { readdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const root = join(here, '..')
const outIndex = process.argv.indexOf('--json')
const reportPath = outIndex === -1 ? join(here, 'report.json') : process.argv[outIndex + 1]

const readJson = (p) => JSON.parse(readFileSync(join(root, p), 'utf8'))
const readText = (p) => readFileSync(join(root, p), 'utf8')

const verbs = readJson('contract/verbs.json')
const codes = readJson('contract/codes.json')
const state = readJson('contract/state.json')
const bounds = readJson('contract/bounds.json')

const contract = { verbs, codes, state, bounds }
const checks = []
const record = (id, title, status, detail, extra = {}) => checks.push({ id, title, status, detail, ...extra })
const pass = (id, title, detail, extra) => record(id, title, 'pass', detail, extra)
const fail = (id, title, detail, extra) => record(id, title, 'fail', detail, extra)

const srcDir = join(root, 'src')
const srcFiles = readdirSync(srcDir).filter((f) => f.endsWith('.ts'))
const srcText = Object.fromEntries(srcFiles.map((f) => [f, readFileSync(join(srcDir, f), 'utf8')]))
const allSrc = Object.values(srcText).join('\n')
const serverText = srcText['server.ts'] ?? ''
const gatewayText = srcText['gateway.ts'] ?? ''

// ── 上界 ────────────────────────────────────────────────────────────────────────
{
  const limit = bounds.bounds.verbs.limit
  const actual = verbs.verbs.length
  actual === limit
    ? pass('B1', 'verbs = 9', `${actual}`)
    : fail('B1', 'verbs = 9', `verbs.json 有 ${actual} 个动词，上界 ${limit}`, { actual, expected: limit })
}
{
  const limit = bounds.bounds.internalCodes.limit
  const actual = codes.internal.length
  actual === limit
    ? pass('B2', 'internal codes = 12', `${actual}`)
    : fail('B2', 'internal codes = 12', `codes.json 有 ${actual} 个内部码，上界 ${limit}`, { actual, expected: limit })
  const ids = codes.internal.map((c) => c.id)
  new Set(ids).size === ids.length
    ? pass('B3', 'internal codes unique', `${ids.length}`)
    : fail('B3', 'internal codes unique', '内部码存在重复', { ids })
}
{
  const machines = ['control', 'link', 'token'].filter((k) => state[k] !== undefined)
  machines.length === bounds.bounds.stateMachines.limit
    ? pass('B4', 'state machines = 3', machines.join(','))
    : fail('B4', 'state machines = 3', `state.json 只包含 ${machines.join(',')}`, { machines })
}
{
  const total = verbs.verbs.reduce((n, v) => n + v.routes.length, 0) + verbs.nonVerbs.routes.length
  total <= bounds.routes.limit
    ? pass('B5', 'routes <= limit', `${total} <= ${bounds.routes.limit}`)
    : fail('B5', 'routes <= limit', `${total} > ${bounds.routes.limit}`, { total })
  if (bounds.bounds.decisionEntryPoints.current > 0) {
    // 本版的两个判定点：授权（GrantStore.authorize）与租约（LeaseRegistry.allows）。
    // 只数实现（行尾有 `{`），不数接口声明。
    const authorize = allSrc.match(/^ {2}authorize\([^\n]*\{\s*$/gm) ?? []
    const allows = allSrc.match(/^ {2}allows\([^\n]*\{\s*$/gm) ?? []
    const total = authorize.length + allows.length
    total === bounds.bounds.decisionEntryPoints.current
      ? pass('B6', `decision entry points = ${bounds.bounds.decisionEntryPoints.current}`, `authorize×${authorize.length} allows×${allows.length}`)
      : fail('B6', `decision entry points = ${bounds.bounds.decisionEntryPoints.current}`, `实际 ${total}（authorize×${authorize.length} allows×${allows.length}）`, { total })
  } else {
    record('B6', 'decision entry points', 'skip', 'current=0，尚未引入判定点')
  }
}

// ── 映射完备性：REST ────────────────────────────────────────────────────────────
{
  const declared = new Set(verbs.verbs.flatMap((v) => v.routes.filter((r) => !r.source).map((r) => r.path)))
  const nonVerbs = new Set(verbs.nonVerbs.routes.map((r) => r.path))
  const literals = new Set([...serverText.matchAll(/'(\/api\/v1[^']*)'/g)].map((m) => m[1]))
  const unknown = [...literals].filter((p) => !declared.has(p) && !nonVerbs.has(p))
  unknown.length === 0
    ? pass('T1', 'every /api/v1 literal is classified', `${literals.size} 个字面量全部命中表格`)
    : fail('T1', 'every /api/v1 literal is classified', `未分类：${unknown.join(', ')}`, { unknown })
  const missing = [...declared].filter((p) => !serverText.includes(`'${p}'`))
  missing.length === 0
    ? pass('T2', 'every declared route exists in server.ts', `${declared.size} 条`)
    : fail('T2', 'every declared route exists in server.ts', `表格声明但代码中没有：${missing.join(', ')}`, { missing })
}
{
  const param = verbs.verbs.flatMap((v) => v.routes.filter((r) => r.source))
  const missing = param.filter((r) => !serverText.includes(r.source)).map((r) => r.path)
  missing.length === 0
    ? pass('T3', 'every parameterized route exists', `${param.length} 条`)
    : fail('T3', 'every parameterized route exists', `未找到 source 片段：${missing.join(', ')}`, { missing })
}

// ── 映射完备性：control frame ───────────────────────────────────────────────────
{
  const allowed = new Set([
    ...verbs.verbs.flatMap((v) => v.frames),
    ...verbs.nonVerbs.frames,
  ])
  const found = new Set()
  for (const m of gatewayText.matchAll(/frame\.type\s*===\s*'([a-z][a-z.]*)'/g)) found.add(m[1])
  for (const m of gatewayText.matchAll(/createControlFrame\('([a-z][a-z.]*)'/g)) found.add(m[1])
  const prefixes = [...new Set([...gatewayText.matchAll(/frame\.type\.startsWith\('([a-z][a-z.]*\.)'\)/g)].map((m) => m[1]))]
  const unknown = [...found].filter((f) => !allowed.has(f))
  unknown.length === 0
    ? pass('T4', 'every frame literal is classified', `${found.size} 个字面量；前缀 ${prefixes.join(',') || '无'}`)
    : fail('T4', 'every frame literal is classified', `未分类：${unknown.join(', ')}`, { unknown })
  const prefixOrphans = prefixes.filter((p) => ![...allowed].some((f) => f.startsWith(p)))
  prefixOrphans.length === 0
    ? pass('T5', 'every frame prefix maps to declared frames', prefixes.join(',') || '无前缀')
    : fail('T5', 'every frame prefix maps to declared frames', `前缀无对应帧：${prefixOrphans.join(', ')}`, { prefixOrphans })
  const undeclared = [...allowed].filter((f) => {
    if (found.has(f)) return false
    return !prefixes.some((p) => f.startsWith(p))
  })
  undeclared.length === 0
    ? pass('T6', 'every declared frame exists in gateway', `${allowed.size} 个帧`)
    : fail('T6', 'every declared frame exists in gateway', `表格声明但代码中没有：${undeclared.join(', ')}`, { undeclared })
}

// ── 码空间 ──────────────────────────────────────────────────────────────────────
{
  const wire = new Set(codes.wire.codes)
  const internalWire = codes.internal.flatMap((c) => c.wire)
  const badInternal = internalWire.filter((c) => !wire.has(c))
  badInternal.length === 0
    ? pass('C1', 'internal wire codes ⊆ protocol §23', `${internalWire.length} 个映射`)
    : fail('C1', 'internal wire codes ⊆ protocol §23', `越界：${badInternal.join(', ')}`, { badInternal })
  const badOnly = codes.wireOnly.codes.filter((c) => !wire.has(c))
  badOnly.length === 0
    ? pass('C2', 'wireOnly ⊆ protocol §23', `${codes.wireOnly.codes.length} 个`)
    : fail('C2', 'wireOnly ⊆ protocol §23', `越界：${badOnly.join(', ')}`, { badOnly })
  const used = new Set([...allSrc.matchAll(/new ApiError\('([A-Z_]+)'/g)].map((m) => m[1]))
  const unknown = [...used].filter((c) => !wire.has(c))
  unknown.length === 0
    ? pass('C3', 'every ApiError code is a protocol wire code', `${used.size} 种码，${(allSrc.match(/new ApiError\(/g) ?? []).length} 处`)
    : fail('C3', 'every ApiError code is a protocol wire code', `新造码：${unknown.join(', ')}`, { unknown })
  const internalUsed = [...used].filter((c) => codes.internal.some((i) => i.id === c))
  record('C4', 'internals stay internal', 'info', `线上使用内部码：${internalUsed.join(', ') || '无'}`)
}

// ── 表格自洽 ────────────────────────────────────────────────────────────────────
{
  const tableFrames = new Set([...verbs.verbs.flatMap((v) => v.frames), ...verbs.nonVerbs.frames])
  const usedInState = new Set(
    ['control', 'link'].flatMap((k) =>
      (state[k].transitions ?? []).map((t) => t.on).filter((on) => on && on !== 'other' && on !== 'frame'),
    ),
  )
  const missing = [...usedInState].filter((f) => !tableFrames.has(f))
  missing.length === 0
    ? pass('S1', 'state transitions only use declared frames', `${usedInState.size} 个转移`)
    : fail('S1', 'state transitions only use declared frames', `未声明：${missing.join(', ')}`, { missing })
  const loadBearing = state.orderPairs.pairs.filter((p) => p.kind === 'load-bearing')
  const tested = loadBearing.filter((p) => p.test)
  record('S2', 'load-bearing order pairs pinned by tests', tested.length === loadBearing.length ? 'pass' : 'info',
    `${tested.length}/${loadBearing.length} 已有测试`)
}

// ── I10：判定不得读取实际路径 ───────────────────────────────────────────────────
{
  const files = Object.entries(srcText)
  const violations = []
  for (const [name, text] of files) {
    for (const [index, line] of text.split(/\r?\n/).entries()) {
      // 允许转发 transport.selected（那是数据面搬运动作），
      // 但同一行里不允许出现任何"拒绝"语义：一旦出现就是拿实际路径做授权。
      if (line.includes('transport.selected') && /return false|return undefined|throw new|this\.deny\(/.test(line)) {
        violations.push(`${name}:${index + 1}`)
      }
      // 租约上的实际路径只允许被回执/日志模块读取。
      if (line.includes('lease.transport') && name !== 'receipt.ts') violations.push(`${name}:${index + 1}`)
    }
  }
  violations.length === 0
    ? pass('D1', 'I10: no decision reads the selected transport', 'src 中无判定读取实际路径')
    : fail('D1', 'I10: no decision reads the selected transport', `违规：${violations.join(', ')}`, { violations })
}

// ── 报告 ────────────────────────────────────────────────────────────────────────
const failed = checks.filter((c) => c.status === 'fail')
const report = {
  registry: 'DSH-R contract gate',
  generatedAt: new Date().toISOString(),
  summary: {
    total: checks.length,
    passed: checks.filter((c) => c.status === 'pass').length,
    failed: failed.length,
    skipped: checks.filter((c) => c.status === 'skip').length,
    info: checks.filter((c) => c.status === 'info').length,
  },
  checks,
}
writeFileSync(reportPath, `${JSON.stringify(report, null, 2)}\n`)

for (const c of checks) {
  const mark = c.status === 'pass' ? 'PASS' : c.status === 'fail' ? 'FAIL' : c.status === 'skip' ? 'SKIP' : 'INFO'
  console.log(`${mark}  ${c.id.padEnd(3)} ${c.title}  —  ${c.detail}`)
}
console.log(`\n${report.summary.passed}/${report.summary.total} passed, ${failed.length} failed — report: ${reportPath}`)
process.exit(failed.length === 0 ? 0 : 1)
