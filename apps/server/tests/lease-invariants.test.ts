import { describe, expect, it } from 'vitest'
import { randomUUID } from 'node:crypto'
import { GRANT_VERBS, GrantStore, type Grant } from '../src/grants.js'
import { LeaseRegistry } from '../src/leases.js'

/**
 * I13 连接 ⊆ 授权、I14 授权 ⊆ 连接 的属性测试。
 *
 * 用一个最小模型穷举交错：签发 / 撤销 / 时间前进 / 建租约 / 结束租约，
 * 每一步之后都断言两条不变量。模型里少了"到期扫描"或"撤销级联"，
 * I14 会立刻失败——这就是它们的杀死测试。
 */

function mulberry32(seed: number) {
  let a = seed >>> 0
  return () => {
    a = (a + 0x6d2b79f5) >>> 0
    let t = a
    t = Math.imul(t ^ (t >>> 15), t | 1)
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61)
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

const HOSTS = Array.from({ length: 3 }, () => randomUUID())
const CLIENTS = Array.from({ length: 3 }, () => randomUUID())
const BASE = 1_800_000_000_000

describe('I13/I14 over interleavings', () => {
  it('holds for every reachable state of a randomized model', () => {
    for (let seed = 1; seed <= 40; seed += 1) {
      const random = mulberry32(seed)
      const clock = { now: BASE + Math.floor(random() * 1_000_000) }
      const store = new GrantStore(undefined, 'owner@example.com', { now: () => clock.now, implicitAllPass: false })
      const leases = new LeaseRegistry(() => clock.now)
      const live: Grant[] = []

      const check = (step: number): void => {
        for (const lease of leases.list()) {
          const grant = store.get(lease.grantId)
          expect(grant, `I13: lease ${step} references a missing grant`).toBeDefined()
          expect(grant!.state, `I13: lease ${step} references a revoked grant`).toBe('active')
          expect(grant!.expiresAt, `I13: lease ${step} outlived its grant`).toBeGreaterThan(clock.now)
          expect(lease.expiresAt, `I13: lease ${step} expiry exceeds grant`).toBeLessThanOrEqual(grant!.expiresAt)
          for (const verb of lease.verbs) expect(grant!.verbs, `I13: lease ${step} widened scope`).toContain(verb)
        }
        for (const grant of live) {
          const dead = grant.state !== 'active' || grant.expiresAt <= clock.now
          if (!dead) continue
          const still = leases.list().some((lease) => lease.grantId === grant.id)
          expect(still, `I14: grant ${grant.id} is dead but still has a lease at step ${step}`).toBe(false)
        }
      }

      for (let step = 0; step < 160; step += 1) {
        const roll = random()
        if (roll < 0.3 || live.length === 0) {
          const grant = store.issue(
            {
              v: 1,
              grant: {
                subject: CLIENTS[Math.floor(random() * CLIENTS.length)]!,
                resource: HOSTS[Math.floor(random() * HOSTS.length)]!,
                verbs: [...GRANT_VERBS],
                expiresAt: clock.now + 60_000 + Math.floor(random() * 600_000),
              },
            },
            { executionScopesAllowed: true },
          )
          live.push(grant)
        } else if (roll < 0.45) {
          const grant = live[Math.floor(random() * live.length)]!
          if (grant.state === 'active') {
            store.revoke(grant.id)
            leases.endByGrant(grant.id, 'revoked')
          }
        } else if (roll < 0.6) {
          clock.now += Math.floor(random() * 180_000)
          for (const lease of leases.expired(clock.now)) leases.end(lease.connectionId, 'expired')
        } else if (roll < 0.85) {
          const grant = live[Math.floor(random() * live.length)]!
          const authorized = store.authorize(grant.subject === '*' ? '' : grant.subject, grant.resource === '*' ? '' : grant.resource, 'link.request', clock.now)
          if (authorized !== undefined) {
            if (authorized.id !== 'implicit-all-pass') store.consume(authorized.id, clock.now)
            leases.start({
              connectionId: randomUUID(),
              grant: authorized,
              clientDeviceId: authorized.subject === '*' ? CLIENTS[0]! : authorized.subject,
              hostDeviceId: authorized.resource === '*' ? HOSTS[0]! : authorized.resource,
            })
          }
        } else {
          const all = leases.list()
          if (all.length > 0) leases.end(all[Math.floor(random() * all.length)]!.connectionId, 'manual')
        }
        check(step)
      }
    }
  })

  it('refuses to widen: a lease never carries verbs its grant lacks', () => {
    const clock = { now: BASE }
    const store = new GrantStore(undefined, 'owner@example.com', { now: () => clock.now, implicitAllPass: false })
    const leases = new LeaseRegistry(() => clock.now)
    const grant = store.issue(
      {
        v: 1,
        grant: { subject: CLIENTS[0]!, resource: HOSTS[0]!, verbs: ['link.request'], expiresAt: clock.now + 600_000 },
      },
      { executionScopesAllowed: true },
    )
    const lease = leases.start({ connectionId: randomUUID(), grant, clientDeviceId: CLIENTS[0]!, hostDeviceId: HOSTS[0]! })
    expect(lease.verbs).toEqual(['link.request'])
    expect(leases.allows(lease.connectionId, CLIENTS[0]!, 'frame.forward', clock.now)).toBe(false)
    expect(leases.allows(lease.connectionId, HOSTS[0]!, 'ice.issue', clock.now)).toBe(false)
  })

  it('caps a lease at 12h even when the grant is longer', () => {
    const clock = { now: BASE }
    const store = new GrantStore(undefined, 'owner@example.com', { now: () => clock.now, implicitAllPass: false })
    const leases = new LeaseRegistry(() => clock.now)
    const grant = store.issue(
      {
        v: 1,
        grant: { subject: CLIENTS[0]!, resource: HOSTS[0]!, verbs: ['link.request'], expiresAt: clock.now + 86_400_000 },
      },
      { executionScopesAllowed: true },
    )
    const lease = leases.start({ connectionId: randomUUID(), grant, clientDeviceId: CLIENTS[0]!, hostDeviceId: HOSTS[0]! })
    expect(lease.expiresAt).toBe(clock.now + 12 * 3_600_000)
  })
})
