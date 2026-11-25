import { createHash, randomUUID } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs'
import { dirname } from 'node:path'
import { z } from 'zod'
import { ApiError } from './store.js'

/**
 * Grant = 静态授权；Lease（见 lease.ts）= 它在一条连接上的实例。
 *
 * 硬规则：expiresAt 必填。没有 TTL 的授权无法被撤销通道覆盖，等于永久后门。
 *
 * 本模块不判定"该不该"，只回答"这份授权是否覆盖这次动作"。判定结论由调用方
 * 翻译成既有的 12 个内部码（见 contract/codes.json），不新增码。
 */

export const GRANT_VERBS = [
  'register',
  'attach',
  'link.request',
  'link.accept',
  'frame.forward',
  'ice.issue',
  'revoke',
  'directory.read',
  'directory.write',
] as const
export type GrantVerb = (typeof GRANT_VERBS)[number]

const ULID = /^[0-9A-HJKMNP-TV-Z]{26}$/u
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu
const deviceRef = z.string().refine((value) => value === '*' || ULID.test(value) || UUID.test(value), {
  message: 'device reference must be a ULID, UUID or "*"',
})
const verbSchema = z.enum(GRANT_VERBS)
const transportSchema = z.enum(['lan', 'p2p', 'turn', 'relay'])
const executionScopeSchema = z.string().trim().min(1).max(64).regex(/^[a-z][a-z0-9]*([.:][a-z0-9*_-]+){0,3}$/u)

export const MIN_GRANT_TTL_MS = 60_000
export const MAX_GRANT_TTL_MS = 30 * 86_400_000

const grantInputSchema = z
  .object({
    subject: deviceRef,
    resource: deviceRef,
    verbs: z.array(verbSchema).min(1).max(GRANT_VERBS.length),
    executionScopes: z.array(executionScopeSchema).max(32).optional(),
    constraints: z
      .object({
        transports: z.array(transportSchema).min(1).max(4).optional(),
        sessionBudget: z.number().int().min(1).max(10_000).optional(),
        maxConcurrent: z.number().int().min(1).max(16).optional(),
      })
      .strict()
      .optional(),
    expiresAt: z.number().int().positive(),
  })
  .strict()

export const grantRequestSchema = z.object({ v: z.literal(1), grant: grantInputSchema }).strict()
export type GrantRequest = z.infer<typeof grantRequestSchema>

const savedGrantSchema = grantInputSchema.extend({
  id: z.string(),
  issuer: z.string(),
  issuedAt: z.number().int().nonnegative(),
  state: z.enum(['active', 'revoked', 'exhausted', 'expired']),
  /** 已建立的会话数；额度用尽由 authorize 的用量判断体现，不改 state（避免把当前租约判死）。 */
  sessionsUsed: z.number().int().nonnegative().optional(),
})
export type Grant = z.infer<typeof savedGrantSchema>

const stateSchema = z.object({
  version: z.literal(1),
  grants: z.record(z.string(), savedGrantSchema),
})

/** Host 在 hello.capabilities 里声明该能力后，才承接执行级收窄。 */
export const GRANTS_CAPABILITY = 'grants.v1'

/** 隐式全通授权：默认配置下它让新代码路径退化为旧行为（逐字节一致）。 */
export const IMPLICIT_GRANT_ID = 'implicit-all-pass'
const IMPLICIT_GRANT: Grant = {
  id: IMPLICIT_GRANT_ID,
  issuer: '*',
  subject: '*',
  resource: '*',
  verbs: [...GRANT_VERBS],
  issuedAt: 0,
  expiresAt: Number.MAX_SAFE_INTEGER,
  state: 'active',
}

export interface GrantLookup {
  /** 返回覆盖该动作的授权；未命中返回 undefined。 */
  authorize(subject: string, resource: string, verb: GrantVerb, now?: number): Grant | undefined
  get(id: string): Grant | undefined
  /** 建立会话前消耗一次额度（可选：纯查询实现可省略）。 */
  consume?(id: string, now?: number): Grant
}

function specificity(grant: Grant): number {
  // 精确匹配优先于通配；同类再比剩余寿命。
  return (grant.subject === '*' ? 0 : 2) + (grant.resource === '*' ? 0 : 1)
}

/**
 * 单进程授权存储。与 Store 一样：原子写、只落公开字段、不落任何明文秘密。
 */
export class GrantStore implements GrantLookup {
  private state: z.infer<typeof stateSchema>
  private readonly implicit: boolean
  private readonly now: () => number

  constructor(
    private readonly file: string | undefined,
    readonly issuer: string,
    options: { now?: () => number; implicitAllPass?: boolean } = {},
  ) {
    this.now = options.now ?? Date.now
    this.implicit = options.implicitAllPass !== false
    const previous = file !== undefined && existsSync(file) ? stateSchema.parse(JSON.parse(readFileSync(file, 'utf8'))) : undefined
    this.state = previous ?? { version: 1, grants: {} }
  }

  private save(): void {
    if (this.file === undefined) return
    mkdirSync(dirname(this.file), { recursive: true, mode: 0o700 })
    const tmp = `${this.file}.tmp`
    writeFileSync(tmp, JSON.stringify(this.state), { mode: 0o600 })
    renameSync(tmp, this.file)
  }

  list(): Grant[] {
    return Object.values(this.state.grants).sort((a, b) => b.issuedAt - a.issuedAt)
  }

  get(id: string): Grant | undefined {
    return this.state.grants[id]
  }

  issue(input: GrantRequest, options: { executionScopesAllowed?: boolean } = {}): Grant {
    const now = this.now()
    const grantInput = input.grant
    if (grantInput.expiresAt <= now + MIN_GRANT_TTL_MS) throw new ApiError('INVALID_MESSAGE')
    if (grantInput.expiresAt > now + MAX_GRANT_TTL_MS) throw new ApiError('INVALID_MESSAGE')
    const verbs = [...new Set(grantInput.verbs)]
    // 未协商能力的主机不得获得执行级范围：拒绝签发，而不是签了当没看见。
    if ((grantInput.executionScopes?.length ?? 0) > 0 && options.executionScopesAllowed !== true) {
      throw new ApiError('CAPABILITY_NOT_SUPPORTED')
    }
    if (Object.values(this.state.grants).filter((g) => g.state === 'active').length >= 4096) throw new ApiError('RATE_LIMITED')
    const grant: Grant = {
      id: randomUUID(),
      issuer: this.issuer,
      subject: grantInput.subject,
      resource: grantInput.resource,
      verbs,
      ...(grantInput.executionScopes === undefined ? {} : { executionScopes: [...new Set(grantInput.executionScopes)] }),
      ...(grantInput.constraints === undefined ? {} : { constraints: grantInput.constraints }),
      issuedAt: now,
      expiresAt: grantInput.expiresAt,
      state: 'active',
    }
    this.state.grants[grant.id] = grant
    this.save()
    return grant
  }

  revoke(id: string): Grant {
    const grant = this.state.grants[id]
    if (grant === undefined) throw new ApiError('DEVICE_NOT_FOUND', 404)
    if (grant.state === 'active') {
      grant.state = 'revoked'
      this.save()
    }
    return grant
  }

  /** 额度耗尽：不改 revoked，保留"为什么失效"的区分。 */
  exhaust(id: string): void {
    const grant = this.state.grants[id]
    if (grant === undefined || grant.state !== 'active') return
    grant.state = 'exhausted'
    this.save()
  }

  /** 到期只是读时判定，不改状态；状态由 tick 或下次读取时收敛。 */
  private live(grant: Grant, now: number): boolean {
    return grant.state === 'active' && grant.expiresAt > now
  }

  /** 额度：未配置即无限；已用满则不再授权新会话（但已发放的租约不受影响）。 */
  private budgetLeft(grant: Grant): boolean {
    const budget = grant.constraints?.sessionBudget
    return budget === undefined || (grant.sessionsUsed ?? 0) < budget
  }

  /**
   * 建立一个会话前消耗一次额度。必须在建链之前调用：它把"能建几次"从
   * 静态字段变成有状态的计数，且与授权记录一起原子落盘。
   */
  consume(id: string, now = this.now()): Grant {
    const grant = this.state.grants[id]
    if (grant === undefined || !this.live(grant, now)) throw new ApiError('MEMBERSHIP_REQUIRED')
    if (!this.budgetLeft(grant)) throw new ApiError('RATE_LIMITED')
    grant.sessionsUsed = (grant.sessionsUsed ?? 0) + 1
    this.save()
    return grant
  }

  /** 显式委托一旦存在，隐式全通即关闭：空表 = 旧行为，非空表 = 委托是唯一权威。 */
  private implicitActive(): boolean {
    return this.implicit && Object.keys(this.state.grants).length === 0
  }

  authorize(subject: string, resource: string, verb: GrantVerb, now = this.now()): Grant | undefined {
    const matches = Object.values(this.state.grants).filter(
      (grant) =>
        this.live(grant, now) &&
        this.budgetLeft(grant) &&
        (grant.subject === '*' || grant.subject === subject) &&
        (grant.resource === '*' || grant.resource === resource) &&
        grant.verbs.includes(verb),
    )
    if (matches.length > 0) {
      matches.sort((a, b) => specificity(b) - specificity(a) || b.expiresAt - a.expiresAt)
      return matches[0]
    }
    return this.implicitActive() ? IMPLICIT_GRANT : undefined
  }

  /** 诊断：当前是否存在显式委托（存在即隐式全通已关闭）。 */
  isExplicit(): boolean {
    return Object.keys(this.state.grants).length > 0
  }

  /** 仅用于诊断与对账：稳定摘要，不含时间与状态。 */
  digest(grant: Grant): string {
    const canonical = JSON.stringify([grant.id, grant.issuer, grant.subject, grant.resource, [...grant.verbs].sort(), grant.expiresAt])
    return createHash('sha256').update(canonical).digest('base64url')
  }
}
