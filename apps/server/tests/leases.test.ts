import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { randomUUID } from 'node:crypto'
import { once } from 'node:events'
import { WebSocket } from 'ws'
import { createControlFrame } from '@dsh-remote/protocol'
import { generateKeyPair, NoiseIkSession, createNoisePrologue, toBase64Url, fromBase64Url } from '../../../packages/crypto/src/index.js'
import { createRemoteServer, type Config } from '../src/server.js'

const account = 'owner@example.com'
const password = 'local-test-password'
let app: ReturnType<typeof createRemoteServer>
let dir: string
let base: string
let accountToken: string
const sockets: WebSocket[] = []
const clock = { now: 1_800_000_000_000 }

async function request(path: string, method = 'GET', body?: unknown, token?: string) {
  const response = await fetch(`${base}/api/v1${path}`, {
    method,
    headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  })
  return { status: response.status, data: await response.json() }
}

async function start(overrides: Partial<Config> = {}) {
  app = createRemoteServer({
    account,
    password,
    dataFile: join(dir, 'state.json'),
    publicUrl: 'http://localhost:8080',
    now: () => clock.now,
    ...overrides,
  })
  app.server.listen(0, '127.0.0.1')
  await once(app.server, 'listening')
  base = `http://127.0.0.1:${(app.server.address() as { port: number }).port}`
  accountToken = (await request('/auth/login', 'POST', { email: account, password })).data.token
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
  readonly closed: Promise<number>
  constructor(readonly ws: WebSocket) {
    this.closed = new Promise((resolve) => ws.once('close', (code) => resolve(code as number)))
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

/** 每个设备只允许一条控制连接（I6），因此同一设备的所有链路复用同一条 socket。 */
async function online(d: Awaited<ReturnType<typeof device>>) {
  const wire = await socket(d)
  await wire.next('hello.ack')
  return wire
}

async function connect(hostWire: Wire, clientWire: Wire, hostDeviceId: string, transports: string[] = ['relay']) {
  clientWire.send('connect.request', { hostDeviceId, preferredTransports: transports })
  const incoming = await hostWire.next('connect.incoming')
  hostWire.send('connect.accepted', { connectionId: incoming.connectionId })
  await clientWire.next('connect.accepted')
  return incoming.connectionId as string
}

/** 走完 Noise 握手，把链路推到 ready —— 只有 ready 阶段才会转发 relay 帧。 */
async function handshake(
  hostWire: Wire,
  clientWire: Wire,
  host: Awaited<ReturnType<typeof device>>,
  client: Awaited<ReturnType<typeof device>>,
  connectionId: string,
) {
  const prologue = createNoisePrologue(connectionId, host.deviceId, client.deviceId)
  const initiator = new NoiseIkSession({ role: 'initiator', localPrivateKey: client.keys.privateKey, localPublicKey: client.identityKey, remotePublicKey: host.identityKey, prologue })
  const responder = new NoiseIkSession({ role: 'responder', localPrivateKey: host.keys.privateKey, localPublicKey: host.identityKey, remotePublicKey: client.identityKey, prologue })
  clientWire.send('secure.handshake', { connectionId, targetDeviceId: host.deviceId, step: 1, data: toBase64Url(initiator.writeHandshake()) })
  responder.readHandshake(fromBase64Url((await hostWire.next('secure.handshake')).data))
  hostWire.send('secure.handshake', { connectionId, targetDeviceId: client.deviceId, step: 2, data: toBase64Url(responder.writeHandshake()) })
  initiator.readHandshake(fromBase64Url((await clientWire.next('secure.handshake')).data))
}

async function grant(input: Record<string, unknown>) {
  return request(
    '/grants',
    'POST',
    { v: 1, grant: { verbs: ['link.request', 'frame.forward', 'ice.issue', 'directory.read'], expiresAt: clock.now + 600_000, ...input } },
    accountToken,
  )
}

beforeEach(async () => {
  dir = mkdtempSync(join(tmpdir(), 'dsh-leases-'))
  clock.now = 1_800_000_000_000
  await start()
})

afterEach(async () => {
  for (const ws of sockets.splice(0)) ws.close()
  await app.close()
  rmSync(dir, { recursive: true, force: true })
})

describe('lease lifecycle', () => {
  it('revocation race: revoking one grant kills only its link', async () => {
    const host = await device('host')
    const first = await device()
    const second = await device()
    const firstGrant = await grant({ subject: first.deviceId, resource: host.deviceId })
    await grant({ subject: second.deviceId, resource: host.deviceId })

    const hostWire = await online(host)
    const firstWire = await online(first)
    const secondWire = await online(second)
    const firstConnection = await connect(hostWire, firstWire, host.deviceId)
    const secondConnection = await connect(hostWire, secondWire, host.deviceId)

    const revoked = await request(`/grants/${firstGrant.data.id}`, 'DELETE', undefined, accountToken)
    expect(revoked.status).toBe(200)

    const scoped = await firstWire.next('error')
    expect(scoped.connectionId).toBe(firstConnection)
    expect(scoped.code).toBe('AUTH_INVALID')
    expect(secondConnection).not.toBe(firstConnection)
    expect(secondWire.messages.find((m) => m.type === 'error')).toBeUndefined()
  })

  it('expiry race: a frame arriving after the lease clock expires is not forwarded', async () => {
    const host = await device('host')
    const client = await device()
    await grant({ subject: client.deviceId, resource: host.deviceId, expiresAt: clock.now + 61_000 })

    const hostWire = await online(host)
    const clientWire = await online(client)
    const connectionId = await connect(hostWire, clientWire, host.deviceId)
    await handshake(hostWire, clientWire, host, client, connectionId)

    // 时钟越过授权到期点：下一帧必须被拒，不能"最后再放一帧"。
    clock.now += 62_000
    clientWire.send('relay', { connectionId, targetDeviceId: host.deviceId, counter: 1, ciphertext: 'AAAA' })
    const scoped = await clientWire.next('error')
    expect(scoped.connectionId).toBe(connectionId)
    expect(hostWire.messages.find((m) => m.type === 'relay')).toBeUndefined()
  })

  it('expiry sweep: an idle link is closed within one sweep even without traffic', async () => {
    const host = await device('host')
    const client = await device()
    await grant({ subject: client.deviceId, resource: host.deviceId, expiresAt: clock.now + 61_000 })

    const hostWire = await online(host)
    const clientWire = await online(client)
    const connectionId = await connect(hostWire, clientWire, host.deviceId)

    // 不发送任何帧，只把时钟推过到期点：扫描（≤1s）必须把链路收掉。
    clock.now += 62_000
    const scoped = await clientWire.next('error')
    expect(scoped.connectionId).toBe(connectionId)
    expect(scoped.code).toBe('AUTH_INVALID')
    expect(hostWire.messages.find((m) => m.type === 'error' && m.payload?.connectionId === connectionId)).toBeDefined()
  })

  it('double-open: the same client reconnecting replaces the previous lease', async () => {
    const host = await device('host')
    const client = await device()
    await grant({ subject: client.deviceId, resource: host.deviceId })

    const hostWire = await online(host)
    const firstWire = await online(client)
    const firstConnection = await connect(hostWire, firstWire, host.deviceId)

    const secondWire = await socket(client)
    await secondWire.next('hello.ack')
    // 被替换的一端收到的是关闭帧 4003（不是 error 帧）：它已经从 peers 里移除。
    expect(await firstWire.closed).toBe(4003)

    const secondConnection = await connect(hostWire, secondWire, host.deviceId)
    expect(secondConnection).not.toBe(firstConnection)
  })

  it('budget exhaustion: sessionBudget refuses the next session', async () => {
    const host = await device('host')
    const client = await device()
    await grant({ subject: client.deviceId, resource: host.deviceId, constraints: { sessionBudget: 1 } })

    const hostWire = await online(host)
    const firstWire = await online(client)
    await connect(hostWire, firstWire, host.deviceId)

    const secondWire = await socket(client)
    await secondWire.next('hello.ack')
    secondWire.send('connect.request', { hostDeviceId: host.deviceId, preferredTransports: ['relay'] })
    const denied = await secondWire.next('error')
    expect(denied.code).toBe('MEMBERSHIP_REQUIRED')
    expect(hostWire.messages.find((m) => m.type === 'connect.incoming')).toBeUndefined()
  })

  it('emits a server-attested receipt when a link ends', async () => {
    const host = await device('host')
    const client = await device()
    const created = await grant({ subject: client.deviceId, resource: host.deviceId })
    const hostWire = await online(host)
    const clientWire = await online(client)
    const connectionId = await connect(hostWire, clientWire, host.deviceId)
    await handshake(hostWire, clientWire, host, client, connectionId)

    clientWire.send('relay', { connectionId, targetDeviceId: host.deviceId, counter: 1, ciphertext: 'AAAA' })
    await hostWire.next('relay')

    await request(`/grants/${created.data.id}`, 'DELETE', undefined, accountToken)

    const list = await request('/receipts', 'GET', undefined, accountToken)
    expect(list.status).toBe(200)
    const receipt = list.data.items.find((item: { connectionId: string }) => item.connectionId === connectionId)
    // 两帧 Noise 握手 + 一帧 relay；字节数只算 relay 密文长度。
    expect(receipt).toMatchObject({ attestedBy: 'server', grantId: created.data.id, counters: { frames: 3, bytes: 4 } })
    expect(typeof receipt.grantDigest).toBe('string')
    expect(receipt.grantDigest).toHaveLength(43)
    expect(receipt.endedAt).toBeGreaterThanOrEqual(receipt.startedAt)
    // 回执里不得出现任何业务内容。
    expect(JSON.stringify(receipt)).not.toContain('AAAA')
  })

  it('accepts a host-signed receipt only when it matches the server witness', async () => {
    const host = await device('host')
    const client = await device()
    const created = await grant({ subject: client.deviceId, resource: host.deviceId })
    const hostWire = await online(host)
    const clientWire = await online(client)
    const connectionId = await connect(hostWire, clientWire, host.deviceId)
    await handshake(hostWire, clientWire, host, client, connectionId)
    clientWire.send('relay', { connectionId, targetDeviceId: host.deviceId, counter: 1, ciphertext: 'AAAA' })
    await hostWire.next('relay')
    await request(`/grants/${created.data.id}`, 'DELETE', undefined, accountToken)
    const witness = (await request('/receipts', 'GET', undefined, accountToken)).data.items
      .find((item: { connectionId: string }) => item.connectionId === connectionId)

    const { ed25519 } = await import('@noble/curves/ed25519.js')
    const seed = ed25519.utils.randomSecretKey()
    const body = {
      connectionId,
      grantId: witness.grantId,
      clientDeviceId: client.deviceId,
      hostDeviceId: host.deviceId,
      startedAt: witness.startedAt,
      endedAt: witness.endedAt,
      counters: witness.counters,
    }
    const signingInput = JSON.stringify([body.connectionId, body.grantId, body.clientDeviceId, body.hostDeviceId,
      body.startedAt, body.endedAt, body.counters.frames, body.counters.bytes])
    const toB64 = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64url')
    const signature = ed25519.sign(new TextEncoder().encode(signingInput), seed)
    const payload = { ...body, signer: toB64(ed25519.getPublicKey(seed)), sig: toB64(signature) }

    const tampered = await request('/receipts', 'POST', { v: 1, receipt: { ...payload, grantId: 'other-grant' } }, host.accessToken)
    expect(tampered.status).toBe(400)

    // 未登记公钥时，签名回执不被接受（防自签）。
    const unpublished = await request('/receipts', 'POST', { v: 1, receipt: payload }, host.accessToken)
    expect(unpublished.status).toBe(401)
    expect(unpublished.data.error.code).toBe('AUTH_INVALID')

    const registered = await request('/devices/self/receipt-key', 'POST', { v: 1, receiptSigningKey: payload.signer }, host.accessToken)
    expect(registered.status).toBe(200)

    // 登记后，公钥出现在设备详情里，供第三方核对。
    const clientDetail = await request(`/devices/${host.deviceId}`, 'GET', undefined, client.accessToken)
    expect(clientDetail.data.receiptSigningKey).toBe(payload.signer)

    // 换一把钥匙（未登记）同样被拒。
    const otherSeed = ed25519.utils.randomSecretKey()
    const otherSig = ed25519.sign(new TextEncoder().encode(signingInput), otherSeed)
    const wrongKey = await request('/receipts', 'POST', { v: 1, receipt: { ...payload, signer: toB64(ed25519.getPublicKey(otherSeed)), sig: toB64(otherSig) } }, host.accessToken)
    expect(wrongKey.status).toBe(401)

    const accepted = await request('/receipts', 'POST', { v: 1, receipt: payload }, host.accessToken)
    expect(accepted.status).toBe(200)
    expect(accepted.data.attestedBy).toBe('host+server')
    expect(accepted.data.sig).toBe(payload.sig)
  })

  it('transport constraint narrows the negotiated set instead of denying everything', async () => {
    const host = await device('host')
    const other = await device('host')
    const client = await device()
    await grant({ subject: client.deviceId, resource: host.deviceId, constraints: { transports: ['turn'] } })
    await grant({ subject: client.deviceId, resource: other.deviceId, constraints: { transports: ['relay'] } })

    const hostWire = await online(host)
    const otherWire = await online(other)
    const clientWire = await online(client)

    clientWire.send('connect.request', { hostDeviceId: host.deviceId, preferredTransports: ['relay'] })
    const denied = await clientWire.next('error')
    expect(denied.code).toBe('CAPABILITY_NOT_SUPPORTED')
    expect(hostWire.messages.find((m) => m.type === 'connect.incoming')).toBeUndefined()
    // 拒绝是请求级的：控制通道仍然可用。
    expect(clientWire.ws.readyState).toBe(WebSocket.OPEN)

    const connectionId = await connect(otherWire, clientWire, other.deviceId)
    expect(connectionId).toBeTruthy()
  })
})
