import { afterEach, describe, expect, it } from 'vitest'
import { createPublicKey, verify as verifyWithKey } from 'node:crypto'
import { mkdtempSync, rmSync, statSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { ReceiptSigner } from '../src/receipt-signer.js'

const dirs: string[] = []
const temp = () => {
  const dir = mkdtempSync(join(tmpdir(), 'dsh-receipt-key-'))
  dirs.push(dir)
  return dir
}

afterEach(() => {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true })
})

/** Ed25519 SPKI DER 前缀 + 32 字节原始公钥。 */
const spki = (raw: Buffer) => Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), raw])

describe('receipt signing key', () => {
  it('creates a private key once and reuses it', () => {
    const dir = temp()
    const first = ReceiptSigner.load(dir)
    const second = ReceiptSigner.load(dir)
    expect(first.publicKey).toBe(second.publicKey)
    expect(first.publicKey).toHaveLength(43)
    if (process.platform !== 'win32') {
      const mode = statSync(join(dir, ReceiptSigner.FILE_NAME)).mode & 0o777
      expect(mode & 0o077).toBe(0)
    }
  })

  it('produces a signature that verifies against the published public key', () => {
    const signer = ReceiptSigner.load(temp())
    const input = ReceiptSigner.signingInput({
      connectionId: 'c-1',
      grantId: 'g-1',
      clientDeviceId: 'client-1',
      hostDeviceId: 'host-1',
      startedAt: 1_800_000_000_000,
      endedAt: 1_800_000_030_000,
      counters: { frames: 3, bytes: 4 },
    })
    const signature = signer.sign(input)
    expect(signature).toHaveLength(86)
    const ok = verifyWithKey(null, Buffer.from(input, 'utf8'),
      createPublicKey({ key: spki(Buffer.from(signer.publicKey, 'base64url')), format: 'der', type: 'spki' }),
      Buffer.from(signature, 'base64url'))
    expect(ok).toBe(true)
  })

  it('bounds the signed payload to identifiers and counters', () => {
    const input = ReceiptSigner.signingInput({
      connectionId: 'c-1',
      grantId: 'g-1',
      clientDeviceId: 'client-1',
      hostDeviceId: 'host-1',
      startedAt: 1,
      endedAt: 2,
      counters: { frames: 3, bytes: 4 },
    })
    expect(JSON.parse(input)).toEqual(['c-1', 'g-1', 'client-1', 'host-1', 1, 2, 3, 4])
    expect(input).not.toContain('prompt')
    expect(input).not.toContain('body')
  })
})
