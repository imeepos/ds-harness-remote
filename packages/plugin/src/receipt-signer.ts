import { createPrivateKey, createPublicKey, generateKeyPairSync, sign as signWithKey } from 'node:crypto'
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

/**
 * 回执签名密钥（opt-in）。
 *
 * 与 Noise 身份分开：设备身份是 X25519（只能做密钥协商），签名需要 Ed25519。
 * 只在 `grants.receiptSigning` 打开时创建，默认不产生任何文件，因此不改变既有安装的
 * 身份目录、迁移白名单与钉扎规则。
 *
 * 文件权限 0600；私钥不出本机。
 */
export class ReceiptSigner {
  private constructor(
    private readonly keyPem: string,
    /** 32 字节 Ed25519 公钥的 base64url。 */
    readonly publicKey: string,
  ) {}

  static readonly FILE_NAME = 'receipt-signing.key.pem'

  static load(directory: string): ReceiptSigner {
    const file = join(directory, ReceiptSigner.FILE_NAME)
    if (existsSync(file)) {
      const keyPem = readFileSync(file, 'utf8')
      return new ReceiptSigner(keyPem, ReceiptSigner.publicKeyOf(keyPem))
    }
    mkdirSync(directory, { recursive: true, mode: 0o700 })
    const { privateKey } = generateKeyPairSync('ed25519')
    const keyPem = privateKey.export({ format: 'pem', type: 'pkcs8' }).toString()
    writeFileSync(file, keyPem, { mode: 0o600 })
    try {
      chmodSync(file, 0o600)
    } catch {
      // Windows 上 chmod 语义有限；文件已按 0600 创建。
    }
    return new ReceiptSigner(keyPem, ReceiptSigner.publicKeyOf(keyPem))
  }

  /** SPKI DER 的末 32 字节就是 Ed25519 原始公钥。 */
  private static publicKeyOf(keyPem: string): string {
    const der = createPublicKey(createPrivateKey(keyPem)).export({ format: 'der', type: 'spki' })
    return Buffer.from(der.subarray(der.length - 32)).toString('base64url')
  }

  /**
   * 规范签名输入：与 contract/verify-receipt.mjs 完全一致的数组形式，
   * 避免键序、空白与浮点格式带来的歧义。
   */
  static signingInput(receipt: {
    connectionId: string
    grantId: string
    clientDeviceId: string
    hostDeviceId: string
    startedAt: number
    endedAt: number
    counters: { frames: number; bytes: number }
  }): string {
    return JSON.stringify([
      receipt.connectionId,
      receipt.grantId,
      receipt.clientDeviceId,
      receipt.hostDeviceId,
      receipt.startedAt,
      receipt.endedAt,
      receipt.counters.frames,
      receipt.counters.bytes,
    ])
  }

  sign(input: string): string {
    return signWithKey(null, Buffer.from(input, 'utf8'), createPrivateKey(this.keyPem)).toString('base64url')
  }
}
