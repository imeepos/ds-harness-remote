#!/usr/bin/env node
/**
 * 消融门禁：删掉一条检查，必须有一个具名测试变红。
 *
 * mutations.json 每条：{ id, title, file, find, replace, testFile, testName }
 * 执行：替换源码（find 必须唯一命中）→ 跑指定用例 → 断言失败 → 还原。
 * 崩溃恢复：任何 *.ablate-bak 残留会在下次启动时自动还原。
 *
 * 用法：node contract/ablate.mjs [--json <path>]
 */
import { execFileSync } from 'node:child_process'
import { createRequire } from 'node:module'
import { existsSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const root = join(here, '..')
const require = createRequire(join(root, 'package.json'))
const vitest = require.resolve('vitest/vitest.mjs')
const outIndex = process.argv.indexOf('--json')
const reportPath = outIndex === -1 ? join(here, 'ablate-report.json') : process.argv[outIndex + 1]

const registry = JSON.parse(readFileSync(join(here, 'mutations.json'), 'utf8'))
const checks = []
const record = (id, title, status, detail, extra = {}) => checks.push({ id, title, status, detail, ...extra })

function restoreLeftovers() {
  for (const dir of [join(root, 'src'), join(root, 'contract')]) {
    if (!existsSync(dir)) continue
    for (const name of readdirSync(dir)) {
      if (!name.endsWith('.ablate-bak')) continue
      const target = join(dir, name.slice(0, -'.ablate-bak'.length))
      writeFileSync(target, readFileSync(join(dir, name)))
      rmSync(join(dir, name))
      record('R0', 'restored leftover backup', 'info', target)
    }
  }
}

function runTest(testFile, testName) {
  try {
    execFileSync(process.execPath, [vitest, 'run', testFile, '--reporter=dot', '-t', testName], {
      cwd: root,
      encoding: 'utf8',
      stdio: 'pipe',
    })
    return { failed: false }
  } catch (error) {
    return { failed: true, output: `${error.stdout ?? ''}${error.stderr ?? ''}` }
  }
}

restoreLeftovers()
const mutations = registry.mutations ?? []
if (mutations.length === 0) {
  record('A0', 'mutation registry', 'skip', '尚未登记消融点（M0 基线；S1/S2 后必须 >= 5）')
}

for (const m of mutations) {
  const file = join(root, m.file)
  const original = readFileSync(file, 'utf8')
  const count = original.split(m.find).length - 1
  if (count !== 1) {
    record(m.id, m.title ?? m.id, 'fail', `find 片段命中 ${count} 次（必须恰好 1 次）：${m.file}`)
    continue
  }
  writeFileSync(join(root, `${m.file}.ablate-bak`), original)
  try {
    writeFileSync(file, original.replace(m.find, m.replace))
    const result = runTest(m.testFile, m.testName)
    result.failed
      ? record(m.id, m.title ?? m.id, 'pass', `删掉检查后 "${m.testName}" 失败（已被发现）`)
      : record(m.id, m.title ?? m.id, 'fail', `删掉检查后测试仍然通过 —— 该检查没有被测试承重`)
  } finally {
    writeFileSync(file, original)
    rmSync(join(root, `${m.file}.ablate-bak`))
  }
}

const failed = checks.filter((c) => c.status === 'fail')
const passed = checks.filter((c) => c.status === 'pass')
const report = {
  registry: 'DSH-R ablation gate',
  generatedAt: new Date().toISOString(),
  summary: { total: checks.length, passed: passed.length, failed: failed.length, mutations: mutations.length },
  checks,
}
writeFileSync(reportPath, `${JSON.stringify(report, null, 2)}\n`)
for (const c of checks) console.log(`${c.status.toUpperCase().padEnd(4)}  ${c.id} ${c.title}  —  ${c.detail}`)
console.log(`\n${passed.length}/${checks.length} discovered, ${failed.length} missed — report: ${reportPath}`)
process.exit(failed.length === 0 ? 0 : 1)
