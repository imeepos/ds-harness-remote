#!/usr/bin/env node
/**
 * M0 等价性门禁：基线用例清单 + 测试文件不可篡改。
 *
 * 断言：
 *   K1 基线清单里每一个用例名都仍然存在
 *   K2 每个存在的基线用例都通过
 *   K3 用例总数不少于基线
 *   K4 apps/server/tests 下的既有文件没有被修改或删除（新增文件允许）
 *
 * 环境级 EPERM（Windows 文件锁/杀软）单独记录并重试一次，重试会写进报告。
 *
 * 用法：node contract/corpus.mjs [--json <path>]
 */
import { execFileSync } from 'node:child_process'
import { createRequire } from 'node:module'
import { readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const root = join(here, '..')
const repo = join(root, '..', '..')
const require = createRequire(join(root, 'package.json'))
const vitest = require.resolve('vitest/vitest.mjs')
const outIndex = process.argv.indexOf('--json')
const reportPath = outIndex === -1 ? join(here, 'corpus-report.json') : process.argv[outIndex + 1]

const baseline = JSON.parse(readFileSync(join(here, 'baseline-tests.json'), 'utf8'))
const expected = new Set(baseline.names)
const checks = []
const record = (id, title, status, detail, extra = {}) => checks.push({ id, title, status, detail, ...extra })

function runSuite() {
  const out = join(tmpdir(), `dsh-corpus-${process.pid}-${Date.now()}.json`)
  let output = ''
  let code = 0
  try {
    output = execFileSync(process.execPath, [vitest, 'run', '--reporter=json', `--outputFile=${out}`], {
      cwd: root,
      encoding: 'utf8',
      stdio: 'pipe',
    })
  } catch (error) {
    output = `${error.stdout ?? ''}${error.stderr ?? ''}`
    code = error.status ?? 1
  }
  let parsed
  try {
    parsed = JSON.parse(readFileSync(out, 'utf8'))
  } catch {
    parsed = undefined
  }
  return { code, output, parsed }
}

let attempt = 1
let run = runSuite()
let hits = (run.parsed?.testResults ?? []).flatMap((f) => (f.assertionResults ?? []).map((a) => ({ file: f.name, name: a.fullName ?? a.title, status: a.status })))
const envFlake = hits.some((h) => h.status !== 'passed' && /EPERM|EBUSY|resource busy/i.test(JSON.stringify(run.parsed ?? {})))
if (run.code !== 0 && envFlake) {
  attempt = 2
  run = runSuite()
  hits = (run.parsed?.testResults ?? []).flatMap((f) => (f.assertionResults ?? []).map((a) => ({ file: f.name, name: a.fullName ?? a.title, status: a.status })))
}

if (!run.parsed) {
  record('K0', 'suite produces a JSON report', 'fail', `vitest 未能产出报告（exit ${run.code}）：${run.output.split('\n').slice(-4).join(' | ')}`)
} else {
  record('K0', 'suite produces a JSON report', 'pass', `attempts=${attempt}`)
  const present = new Map(hits.map((h) => [h.name, h]))
  const missing = [...expected].filter((n) => !present.has(n))
  missing.length === 0
    ? record('K1', 'every baseline test still exists', 'pass', `${expected.size} 个`)
    : record('K1', 'every baseline test still exists', 'fail', `缺失 ${missing.length} 个：${missing.slice(0, 5).join(' | ')}`, { missing })

  const notPassed = [...expected].filter((n) => present.has(n) && present.get(n).status !== 'passed')
  notPassed.length === 0
    ? record('K2', 'every baseline test passes', 'pass', `${expected.size}/${expected.size}`)
    : record('K2', 'every baseline test passes', 'fail', `${notPassed.length} 个未通过：${notPassed.join(' | ')}`, { notPassed })

  hits.length >= baseline.count
    ? record('K3', 'test count not reduced', 'pass', `${hits.length} >= ${baseline.count}`)
    : record('K3', 'test count not reduced', 'fail', `${hits.length} < ${baseline.count}`)
}

// 既有测试文件不可修改/删除
try {
  const status = execFileSync('git', ['-C', repo, 'status', '--porcelain', '--', 'apps/server/tests'], { encoding: 'utf8' })
  const changed = status
    .split('\n')
    .map((l) => l.trimEnd())
    .filter(Boolean)
    .filter((l) => !l.startsWith('??'))
  changed.length === 0
    ? record('K4', 'baseline test files untouched', 'pass', '只有新增文件')
    : record('K4', 'baseline test files untouched', 'fail', `被修改或删除：${changed.join(' | ')}`, { changed })
} catch (error) {
  record('K4', 'baseline test files untouched', 'fail', `git 查询失败：${String(error).slice(0, 120)}`)
}

const failed = checks.filter((c) => c.status === 'fail')
const report = {
  registry: 'DSH-R corpus gate',
  generatedAt: new Date().toISOString(),
  summary: {
    total: checks.length,
    passed: checks.filter((c) => c.status === 'pass').length,
    failed: failed.length,
    attempts: attempt,
    envRetry: attempt > 1,
  },
  checks,
}
writeFileSync(reportPath, `${JSON.stringify(report, null, 2)}\n`)

for (const c of checks) console.log(`${c.status === 'pass' ? 'PASS' : 'FAIL'}  ${c.id} ${c.title}  —  ${c.detail}`)
console.log(`\n${report.summary.passed}/${report.summary.total} passed, ${failed.length} failed — report: ${reportPath}`)
process.exit(failed.length === 0 ? 0 : 1)
