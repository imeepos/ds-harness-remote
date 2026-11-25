#!/usr/bin/env node
/**
 * 回执校验工具。
 *
 * 校验两件事：
 *   1. 形状：字段与类型符合 contract/grants.schema.json 的 Receipt 定义（这里手写等价检查，不引依赖）；
 *   2. 绑定：grantDigest 与 grants.json 里那条委托重新计算出的摘要一致。
 *
 * 它**不**验证签名：当前回执是 server-attested（由已认证控制通道提交并由 Server 搬运计数），
 * 不是密码学签名。真正的第三方可验需要给设备增加独立签名密钥（Ed25519），见 03-acceptance.md。
 *
 * 用法：
 *   node contract/verify-receipt.mjs <receipts.json> [grants.json]
 *   两个文件都接受 {"items":[...]} 或裸数组。
 */
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'

const [receiptPath, grantsPath, devicePath] = process.argv.slice(2)
if (receiptPath === undefined) {
  console.error('usage: node contract/verify-receipt.mjs <receipts.json> [grants.json] [device.json]')
  process.exit(2)
}

const load = path => {
  const value = JSON.parse(readFileSync(path, 'utf8'))
  return Array.isArray(value) ? value : value.items
}

const digest = grant => createHash('sha256')
  .update(JSON.stringify([grant.id, grant.issuer, grant.subject, grant.resource, [...grant.verbs].sort(), grant.expiresAt]))
  .digest('base64url')

const checks = []
const check = (id, ok, detail) => { checks.push({ id, ok, detail }) }

const receipts = load(receiptPath)
const grants = grantsPath === undefined ? undefined : load(grantsPath)
const byId = new Map((grants ?? []).map(grant => [grant.id, grant]))
// 设备登记里发布的回执公钥：有它就能把"自签"变成"登记过的钥匙签"。
const registeredKey = devicePath === undefined ? undefined : JSON.parse(readFileSync(devicePath, 'utf8')).receiptSigningKey

check('R1', Array.isArray(receipts) && receipts.length > 0, `receipts=${receipts?.length ?? 0}`)
for (const [index, receipt] of (receipts ?? []).entries()) {
  const ok = typeof receipt.connectionId === 'string' && receipt.connectionId.length > 0
    && typeof receipt.grantId === 'string' && receipt.grantId.length > 0
    && typeof receipt.clientDeviceId === 'string' && typeof receipt.hostDeviceId === 'string'
    && Number.isSafeInteger(receipt.startedAt) && Number.isSafeInteger(receipt.endedAt)
    && receipt.endedAt >= receipt.startedAt
    && typeof receipt.counters === 'object' && receipt.counters !== null
    && Number.isSafeInteger(receipt.counters.frames) && Number.isSafeInteger(receipt.counters.bytes)
    && (receipt.attestedBy === 'server' || receipt.attestedBy === 'host+server')
  check(`S${index + 1}`, ok, ok ? receipt.connectionId : 'shape mismatch')
  if (grants === undefined) continue
  const grant = byId.get(receipt.grantId)
  if (grant === undefined) {
    check(`D${index + 1}`, receipt.grantDigest === undefined, 'grant no longer stored; digest must be absent')
  } else {
    check(`D${index + 1}`, receipt.grantDigest === digest(grant), receipt.grantDigest === digest(grant)
      ? `digest matches grant ${grant.id}`
      : `digest mismatch for ${grant.id}`)
  }
  if (receipt.sig === undefined) continue
  // 签名回执：验证 Ed25519 覆盖的规范输入，并打印 signer 指纹供带外比对。
  const signingInput = JSON.stringify([receipt.connectionId, receipt.grantId, receipt.clientDeviceId, receipt.hostDeviceId,
    receipt.startedAt, receipt.endedAt, receipt.counters.frames, receipt.counters.bytes])
  let valid = false
  try {
    const { ed25519 } = await import('@noble/curves/ed25519.js')
    valid = ed25519.verify(Buffer.from(receipt.sig, 'base64url'), new TextEncoder().encode(signingInput), Buffer.from(receipt.signer, 'base64url'))
  } catch {
    valid = false
  }
  check(`V${index + 1}`, valid, valid ? `signature valid; signer=${receipt.signer}` : 'signature invalid')
  if (registeredKey !== undefined) {
    check(`K${index + 1}`, receipt.signer === registeredKey,
      receipt.signer === registeredKey ? 'signer matches the registered device key' : 'signer does not match the registered device key')
  }
}

const failed = checks.filter(entry => !entry.ok)
for (const entry of checks) console.log(`${entry.ok ? 'PASS' : 'FAIL'}  ${entry.id}  ${entry.detail}`)
console.log(`\n${checks.length - failed.length}/${checks.length} checks passed`)
console.log('注意：本工具验证"形状 + 与委托的绑定"，不验证签名（见 03-acceptance.md 的阻塞说明）。')
process.exit(failed.length === 0 ? 0 : 1)
