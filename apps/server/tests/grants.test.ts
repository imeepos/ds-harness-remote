import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { randomUUID } from 'node:crypto'
import { once } from 'node:events'
import { WebSocket } from 'ws'
import { createControlFrame } from '@dsh-remote/protocol'
import { generateKeyPair } from '../../../packages/crypto/src/index.js'
import { createRemoteServer, type Config } from '../src/server.js'

const account = 'owner@example.com'
const password = 'local-test-password'
let app: ReturnType<typeof createRemoteServer>
let dir: string
let base: string
let accountToken: string
const sockets: WebSocket[] = []

async function request(path: string, method = 'GET', body?: unknown, token?: string) {
  const response = await fetch(`${base}/api/v1${path}`, {
    method,
    headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  })
  return { status: response.status, data: await response.json() }
}

async function start(configOverrides: Partial<Config> = {}) {
  app = createRemoteServer({
    account,
    password,
    dataFile: join(dir, 'state.json'),
    publicUrl: 'http://localhost:8080',
    ...configOverrides,
  })
  app.server.listen(0, '127.0.0.1')
  await once(app.server, 'listening')
  base = `http://127.0.0.1:${(app.server.address() as { port: number }).port}`
  const login = await request('/auth/login', 'POST', { email: account, password })
  accountToken = login.data.token
}

async function device(role: 'host' | 'client' = 'client') {
  const keys = generateKeyPair()
  const descriptor = { deviceId: randomUUID(), identityKey: keys.publicKey, name: `${role}-device`, role, platform: 'linux', clientVersion: '0.6.7' }
  const result = await request('/devices/register', 'POST', { v: 1, device: descriptor }, accountToken)
  expect(result.status).toBe(200)
  return { ...descriptor, keys, ...result.data }
}

class Wire {
  messages: any[] = []
  waiters: (() => void)[] = []
  constructor(readonly ws: WebSocket) {
    ws.on('message', (raw) => {
      this.messages.push(JSON.parse(raw.toString()))
      for (const notify of this.waiters.splice(0)) notify()
    })
  }
  send(type: Parameters<typeof createControlFrame>[0], payload: unknown) {
    this.ws.send(JSON.stringify(createControlFrame(type, payload)))
  }
  async next(type: string): Promise<any> {
    const until = Date.now() + 3000
    while (Date.now() < until) {
      const index = this.messages.findIndex((m) => m.type === type)
      if (index >= 0) return this.messages.splice(index, 1)[0].payload
      await new Promise<void>((resolve) => {
        const timer = setTimeout(resolve, 50)
        this.waiters.push(() => {
          clearTimeout(timer)
          resolve()
        })
      })
    }
    throw new Error(`Missing frame ${type}`)
  }
}

const capabilities = ['transport.p2p', 'transport.relay', 'grants.v1']

async function socket(d: Awaited<ReturnType<typeof device>>, overrides: Record<string, unknown> = {}) {
  const ws = new WebSocket(`${base.replace('http:', 'ws:')}/ws/v1/connect`)
  sockets.push(ws)
  const wire = new Wire(ws)
  await once(ws, 'open')
  wire.send('hello', { role: d.role, deviceId: d.deviceId, accessToken: d.accessToken, protocols: [1], capabilities, clientVersion: d.clientVersion, ...overrides })
  return wire
}

async function grant(input: Record<string, unknown>) {
  return request('/grants', 'POST', { v: 1, grant: { verbs: ['link.request', 'frame.forward', 'ice.issue', 'directory.read'], expiresAt: Date.now() + 600_000, ...input } }, accountToken)
}

beforeEach(async () => {
  dir = mkdtempSync(join(tmpdir(), 'dsh-grants-'))
  await start()
})

afterEach(async () => {
  for (const ws of sockets.splice(0)) ws.close()
  await app.close()
  rmSync(dir, { recursive: true, force: true })
})

describe('grant-bound sessions', () => {
  it('keeps the implicit all-pass path when no grant exists', async () => {
    const host = await device('host')
    const client = await device()
    const hostWire = await socket(host)
    const clientWire = await socket(client)
    await hostWire.next('hello.ack')
    await clientWire.next('hello.ack')
    clientWire.send('connect.request', { hostDeviceId: host.deviceId, preferredTransports: ['relay'] })
    const incoming = await hostWire.next('connect.incoming')
    expect(incoming.authorization).toBe('account')
    expect(app.grants.isExplicit()).toBe(false)
  })

  it('issues, lists and revokes a grant through the account token', async () => {
    const host = await device('host')
    const client = await device()
    const created = await grant({ subject: client.deviceId, resource: host.deviceId })
    expect(created.status).toBe(200)
    expect(created.data).toMatchObject({ subject: client.deviceId, resource: host.deviceId, state: 'active', issuer: account })
    expect(typeof created.data.id).toBe('string')
    expect(created.data.expiresAt).toBeGreaterThan(Date.now())

    const list = await request('/grants', 'GET', undefined, accountToken)
    expect(list.status).toBe(200)
    expect(list.data.items).toHaveLength(1)
    expect(list.data.items[0].id).toBe(created.data.id)

    const revoked = await request(`/grants/${created.data.id}`, 'DELETE', undefined, accountToken)
    expect(revoked.status).toBe(200)
    expect(revoked.data.status).toBe('revoked')
    expect(revoked.data.grant.state).toBe('revoked')

    const after = await request('/grants', 'GET', undefined, accountToken)
    expect(after.data.items[0].state).toBe('revoked')
  })

  it('rejects grants without a TTL, with an unknown device, or beyond the upper bound', async () => {
    const host = await device('host')
    const client = await device()

    const noTtl = await request('/grants', 'POST', { v: 1, grant: { subject: client.deviceId, resource: host.deviceId, verbs: ['link.request'] } }, accountToken)
    expect(noTtl.status).toBe(400)

    const tooSoon = await grant({ subject: client.deviceId, resource: host.deviceId, expiresAt: Date.now() + 1000 })
    expect(tooSoon.status).toBe(400)

    const tooLong = await grant({ subject: client.deviceId, resource: host.deviceId, expiresAt: Date.now() + 31 * 86_400_000 })
    expect(tooLong.status).toBe(400)

    const unknown = await grant({ subject: randomUUID(), resource: host.deviceId })
    expect(unknown.status).toBe(404)
    expect(unknown.data.error.code).toBe('DEVICE_NOT_FOUND')

    const requiresAccount = await request('/grants', 'POST', { v: 1, grant: { subject: client.deviceId, resource: host.deviceId, verbs: ['link.request'], expiresAt: Date.now() + 60_000 } })
    expect(requiresAccount.status).toBe(401)
  })

  it('scopes link.request to an explicit grant without tearing down the control channel', async () => {
    const allowedHost = await device('host')
    const deniedHost = await device('host')
    const client = await device()
    await grant({ subject: client.deviceId, resource: allowedHost.deviceId })

    const allowedWire = await socket(allowedHost)
    const deniedWire = await socket(deniedHost)
    const clientWire = await socket(client)
    await allowedWire.next('hello.ack')
    await deniedWire.next('hello.ack')
    await clientWire.next('hello.ack')

    clientWire.send('connect.request', { hostDeviceId: deniedHost.deviceId, preferredTransports: ['relay'] })
    const denied = await clientWire.next('error')
    expect(denied.code).toBe('MEMBERSHIP_REQUIRED')
    expect(deniedWire.messages.find((m) => m.type === 'connect.incoming')).toBeUndefined()
    expect(clientWire.ws.readyState).toBe(WebSocket.OPEN)

    clientWire.send('connect.request', { hostDeviceId: allowedHost.deviceId, preferredTransports: ['relay'] })
    const incoming = await allowedWire.next('connect.incoming')
    allowedWire.send('connect.accepted', { connectionId: incoming.connectionId })
    const accepted = await clientWire.next('connect.accepted')
    expect(accepted.connectionId).toBe(incoming.connectionId)
  })

  it('revokes only the connections that referenced the grant', async () => {
    const host = await device('host')
    const first = await device()
    const second = await device()
    const firstGrant = await grant({ subject: first.deviceId, resource: host.deviceId })
    await grant({ subject: second.deviceId, resource: host.deviceId })

    const hostWire = await socket(host)
    const firstWire = await socket(first)
    const secondWire = await socket(second)
    await hostWire.next('hello.ack')
    await firstWire.next('hello.ack')
    await secondWire.next('hello.ack')

    firstWire.send('connect.request', { hostDeviceId: host.deviceId, preferredTransports: ['relay'] })
    const firstIncoming = await hostWire.next('connect.incoming')
    hostWire.send('connect.accepted', { connectionId: firstIncoming.connectionId })
    await firstWire.next('connect.accepted')

    secondWire.send('connect.request', { hostDeviceId: host.deviceId, preferredTransports: ['relay'] })
    const secondIncoming = await hostWire.next('connect.incoming')
    hostWire.send('connect.accepted', { connectionId: secondIncoming.connectionId })
    await secondWire.next('connect.accepted')

    const revoked = await request(`/grants/${firstGrant.data.id}`, 'DELETE', undefined, accountToken)
    expect(revoked.status).toBe(200)

    // 被撤销的那条链路以 connectionId 作用域报错；另一条不受影响。
    const scoped = await firstWire.next('error')
    expect(scoped.connectionId).toBe(firstIncoming.connectionId)
    expect(scoped.code).toBe('AUTH_INVALID')
    expect(secondWire.messages.find((m) => m.type === 'error')).toBeUndefined()
  })

  it('persists grants across a restart and keeps revocations', async () => {
    const host = await device('host')
    const client = await device()
    const created = await grant({ subject: client.deviceId, resource: host.deviceId })
    await app.close()

    await start({ dataFile: join(dir, 'state.json') })
    const list = await request('/grants', 'GET', undefined, accountToken)
    expect(list.data.items).toHaveLength(1)
    expect(list.data.items[0].id).toBe(created.data.id)

    await request(`/grants/${created.data.id}`, 'DELETE', undefined, accountToken)
    await app.close()
    await start({ dataFile: join(dir, 'state.json') })
    const after = await request('/grants', 'GET', undefined, accountToken)
    expect(after.data.items[0].state).toBe('revoked')
  })

  it('refuses execution scopes unless the host is online and advertises grants.v1', async () => {
    const host = await device('host')
    const client = await device()

    const offline = await grant({ subject: client.deviceId, resource: host.deviceId, executionScopes: ['session:read'] })
    expect(offline.status).toBe(400)
    expect(offline.data.error.code).toBe('CAPABILITY_NOT_SUPPORTED')

    const hostWire = await socket(host, { capabilities: ['transport.relay'] })
    await hostWire.next('hello.ack')
    const withoutCapability = await grant({ subject: client.deviceId, resource: host.deviceId, executionScopes: ['session:read'] })
    expect(withoutCapability.status).toBe(400)
    expect(withoutCapability.data.error.code).toBe('CAPABILITY_NOT_SUPPORTED')

    const capableHost = await device('host')
    const capableWire = await socket(capableHost)
    await capableWire.next('hello.ack')
    const allowed = await grant({ subject: client.deviceId, resource: capableHost.deviceId, executionScopes: ['session:read'] })
    expect(allowed.status).toBe(200)
    expect(allowed.data.executionScopes).toEqual(['session:read'])
  })

  it('hands the covering grants to the host when it resolves its peer', async () => {
    const host = await device('host')
    const client = await device()
    const hostWire = await socket(host)
    await hostWire.next('hello.ack')
    const created = await grant({ subject: client.deviceId, resource: host.deviceId, executionScopes: ['session:read'] })
    expect(created.status).toBe(200)

    const detail = await request(`/devices/${client.deviceId}`, 'GET', undefined, host.accessToken)
    expect(detail.status).toBe(200)
    expect(detail.data.grants).toHaveLength(1)
    expect(detail.data.grants[0]).toMatchObject({ id: created.data.id, executionScopes: ['session:read'] })

    // 反方向（client 查 host）不暴露执行范围：收窄只对被执行的一方有意义。
    const reverse = await request(`/devices/${host.deviceId}`, 'GET', undefined, client.accessToken)
    expect(reverse.status).toBe(200)
    expect(reverse.data.grants).toBeUndefined()

    // 撤销后不再下发。
    await request(`/grants/${created.data.id}`, 'DELETE', undefined, accountToken)
    const after = await request(`/devices/${client.deviceId}`, 'GET', undefined, host.accessToken)
    expect(after.data.grants).toBeUndefined()
  })
})
