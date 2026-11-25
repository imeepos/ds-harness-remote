import type { Grant, GrantVerb } from './grants.js'

/**
 * Lease = Grant 在一条连接上的实例。
 *
 * I13 连接 ⊆ 授权：每次 frame.forward / ice.issue 都必须命中一个未过期的租约。
 * I14 授权 ⊆ 连接：授权失效时，引用它的租约必须结束，且只经由 endLease 一个出口。
 *
 * 本类不判定"该不该"（那是 GrantStore 的事），只维护"这条连接此刻还剩什么"。
 */

export type LeaseTransport = 'lan' | 'p2p' | 'turn' | 'relay'

export interface Lease {
  connectionId: string
  grantId: string
  clientDeviceId: string
  hostDeviceId: string
  verbs: GrantVerb[]
  startedAt: number
  expiresAt: number
  /** 只记录，不参与判定（I10）。 */
  transport?: LeaseTransport
}

/** 单条租约的硬上限：再长的授权也不让一条连接活过 12 小时。 */
export const MAX_LEASE_MS = 12 * 3_600_000

export interface LeaseStart {
  connectionId: string
  grant: Pick<Grant, 'id' | 'verbs' | 'expiresAt' | 'constraints'>
  clientDeviceId: string
  hostDeviceId: string
}

export interface LeaseEnd {
  lease: Lease
  reason: string
}

export class LeaseRegistry {
  private readonly byConnection = new Map<string, Lease>()

  constructor(private readonly now: () => number = Date.now) {}

  start(input: LeaseStart): Lease {
    const startedAt = this.now()
    const expiresAt = Math.min(input.grant.expiresAt, startedAt + MAX_LEASE_MS)
    const verbs = input.grant.verbs.filter((verb): verb is GrantVerb => input.grant.verbs.includes(verb))
    const lease: Lease = {
      connectionId: input.connectionId,
      grantId: input.grant.id,
      clientDeviceId: input.clientDeviceId,
      hostDeviceId: input.hostDeviceId,
      verbs,
      startedAt,
      expiresAt,
    }
    this.byConnection.set(lease.connectionId, lease)
    return lease
  }

  get(connectionId: string): Lease | undefined {
    return this.byConnection.get(connectionId)
  }

  allows(connectionId: string, deviceId: string, verb: GrantVerb, now = this.now()): boolean {
    const lease = this.byConnection.get(connectionId)
    if (lease === undefined || lease.expiresAt <= now) return false
    if (lease.clientDeviceId !== deviceId && lease.hostDeviceId !== deviceId) return false
    return lease.verbs.includes(verb)
  }

  /** 同一授权下、排除某客户端后的活动租约数（并发位判定）。 */
  countForGrant(grantId: string, exceptClient?: string, now = this.now()): number {
    let count = 0
    for (const lease of this.byConnection.values()) {
      if (lease.grantId !== grantId) continue
      if (lease.expiresAt <= now) continue
      if (exceptClient !== undefined && lease.clientDeviceId === exceptClient) continue
      count += 1
    }
    return count
  }

  expired(now = this.now()): Lease[] {
    return [...this.byConnection.values()].filter((lease) => lease.expiresAt <= now)
  }

  /** 唯一出口：结束租约，返回被结束的对象供调用方断链与记账。 */
  end(connectionId: string, reason: string): LeaseEnd | undefined {
    const lease = this.byConnection.get(connectionId)
    if (lease === undefined) return undefined
    this.byConnection.delete(connectionId)
    return { lease, reason }
  }

  endByGrant(grantId: string, reason: string): LeaseEnd[] {
    const ended: LeaseEnd[] = []
    for (const [connectionId, lease] of [...this.byConnection]) {
      if (lease.grantId !== grantId) continue
      this.byConnection.delete(connectionId)
      ended.push({ lease, reason })
    }
    return ended
  }

  list(): Lease[] {
    return [...this.byConnection.values()]
  }

  size(): number {
    return this.byConnection.size
  }
}
