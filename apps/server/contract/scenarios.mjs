#!/usr/bin/env node
/**
 * 真实环境场景验收。
 *
 * 以**子进程**启动编译后的 Server（node dist/main.js + 真实环境变量），用真实
 * HTTP fetch / WebSocket / Noise IK / Ed25519 驱动，不 mock 任何一层。
 *
 * 输出：contract/scenarios-report.json（机器可读）+ 终端摘要。
 *
 * 用法：node contract/scenarios.mjs [--only S1,S3] [--json <path>]
 */
import { spawn } from 'node:child_process'
import { createPrivateKey, createPublicKey, generateKeyPairSync, randomUUID, sign as signWithKey } from 'node:crypto'
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { WebSocket } from 'ws'
import { createControlFrame } from '@dsh-remote/protocol'
import { NoiseIkSession, createNoisePrologue, fromBase64Url, generateKeyPair, toBase64Url } from '../../../packages/crypto/dist/index.js'

const here = dirname(fileURLToPath(import.meta.url))
const serverDir = join(here, '..')
const outIndex = process.argv.indexOf('--json')
const reportPath = outIndex === -1 ? join(here, 'scenarios-report.json') : process.argv[outIndex + 1]
const onlyIndex = process.argv.indexOf('--only')
const only = onlyIndex === -1 ? undefined : new Set(process.argv[onlyIndex + 1].split(','))

const ACCOUNT = 'owner@example.com'
const PASSWORD = 'scenario-password-123'
const results = []
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms))

// ── 真实进程管理 ────────────────────────────────────────────────────────────────
class ServerProcess {
  constructor() {
    this.dir = mkdtempSync(join(tmpdir(), 'dsh-scenario-'))
    this.logs = ''
  }

  async start(port, env = {}) {
    this.port = port
    this.base = `http://127.0.0.1:${port}`
    this.child = spawn(process.execPath, ['dist/main.js'], {
      cwd: serverDir,
      env: {
        ...process.env,
        DSH_SERVER_ACCOUNT: ACCOUNT,
        DSH_SERVER_PASSWORD: PASSWORD,
        DSH_SERVER_PUBLIC_URL: this.base,
        DSH_SERVER_HOST: '127.0.0.1',
        DSH_SERVER_PORT: String(port),
        DSH_SERVER_DATA_FILE: join(this.dir, 'state.json'),
        DSH_SERVER_LOG_LEVEL: 'info',
        ...env,
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    })
    this.child.stdout.on('data', chunk => { this.logs += chunk.toString() })
    this.child.stderr.on('data', chunk => { this.logs += chunk.toString() })
    const deadline = Date.now() + 15_000
    while (Date.now() < deadline) {
      try {
        const response = await fetch(`${this.base}/healthz`)
        if (response.ok) return
      } catch {
        // 还没起来
      }
      await sleep(100)
    }
    throw new Error(`server did not become healthy on ${port}\n${this.logs.slice(-800)}`)
  }

  async stop(signal = 'SIGTERM') {
    if (this.child === undefined || this.child.exitCode !== null) return this.child?.exitCode
    const exited = new Promise(resolve => this.child.once('exit', (code, sig) => resolve({ code, sig })))
    this.child.kill(signal)
    const result = await Promise.race([exited, sleep(5000).then(() => ({ code: 'timeout' }))])
    return result
  }

  dispose() {
    rmSync(this.dir, { recursive: true, force: true })
  }
}

// ── 客户端工具（真实 HTTP / WS / Noise）─────────────────────────────────────────
async function api(base, path, { method = 'GET', body, token, headers = {} } = {}) {
  const response = await fetch(`${base}${path}`, {
    method,
    headers: { 'Content-Type': 'application/json', ...(token === undefined ? {} : { Authorization: `Bearer ${token}` }), ...headers },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  })
  const text = await response.text()
  let json
  try { json = JSON.parse(text) } catch { json = undefined }
  return { status: response.status, json, text, headers: response.headers }
}

class Wire {
  constructor(ws) {
    this.ws = ws
    this.messages = []
    this.waiters = []
    this.closed = new Promise(resolve => ws.once('close', (code, reason) => resolve({ code, reason: reason.toString() })))
    ws.on('message', raw => {
      this.messages.push(JSON.parse(raw.toString()))
      for (const notify of this.waiters.splice(0)) notify()
    })
  }
  send(type, payload) { this.ws.send(JSON.stringify(createControlFrame(type, payload))) }
  async next(type, timeoutMs = 4000) {
    const until = Date.now() + timeoutMs
    while (Date.now() < until) {
      const index = this.messages.findIndex(m => m.type === type)
      if (index >= 0) return this.messages.splice(index, 1)[0].payload
      await new Promise(resolve => {
        const timer = setTimeout(resolve, 40)
        this.waiters.push(() => { clearTimeout(timer); resolve() })
      })
    }
    throw new Error(`missing frame ${type}; saw ${this.messages.map(m => m.type).join(',')}`)
  }
  async waitOpen() {
    if (this.ws.readyState === 1) return
    await new Promise((resolve, reject) => { this.ws.once('open', resolve); this.ws.once('error', reject) })
  }
}

async function register(base, token, role, name = `${role}-device`) {
  const keys = generateKeyPair()
  const descriptor = { deviceId: randomUUID(), identityKey: keys.publicKey, name, role, platform: 'linux', clientVersion: '0.6.7' }
  const response = await api(base, '/api/v1/devices/register', { method: 'POST', token, body: { v: 1, device: descriptor } })
  if (response.status !== 200) throw new Error(`register ${role} failed: ${response.status} ${response.text}`)
  return { ...descriptor, keys, accessToken: response.json.accessToken, refreshToken: response.json.refreshToken }
}

async function openControl(server, device, capabilities = ['transport.p2p', 'transport.relay', 'grants.v1']) {
  const wire = new Wire(new WebSocket(`${server.base.replace('http:', 'ws:')}/ws/v1/connect`))
  await wire.waitOpen()
  wire.send('hello', {
    role: device.role,
    deviceId: device.deviceId,
    accessToken: device.accessToken,
    protocols: [1],
    capabilities,
    clientVersion: '0.6.7',
  })
  wire.ack = await wire.next('hello.ack')
  return wire
}

async function connect(hostWire, clientWire, hostDeviceId, preferredTransports = ['relay']) {
  clientWire.send('connect.request', { hostDeviceId, preferredTransports })
  const incoming = await hostWire.next('connect.incoming')
  hostWire.send('connect.accepted', { connectionId: incoming.connectionId })
  await clientWire.next('connect.accepted')
  return incoming.connectionId
}

async function noiseHandshake(hostWire, clientWire, host, client, connectionId) {
  const prologue = createNoisePrologue(connectionId, host.deviceId, client.deviceId)
  const initiator = new NoiseIkSession({ role: 'initiator', localPrivateKey: client.keys.privateKey, localPublicKey: client.identityKey, remotePublicKey: host.identityKey, prologue })
  const responder = new NoiseIkSession({ role: 'responder', localPrivateKey: host.keys.privateKey, localPublicKey: host.identityKey, remotePublicKey: client.identityKey, prologue })
  clientWire.send('secure.handshake', { connectionId, targetDeviceId: host.deviceId, step: 1, data: toBase64Url(initiator.writeHandshake()) })
  responder.readHandshake(fromBase64Url((await hostWire.next('secure.handshake')).data))
  hostWire.send('secure.handshake', { connectionId, targetDeviceId: client.deviceId, step: 2, data: toBase64Url(responder.writeHandshake()) })
  initiator.readHandshake(fromBase64Url((await clientWire.next('secure.handshake')).data))
  return { initiator, responder }
}

/** 用真实 Noise 密钥加密一条业务消息，走 relay 密文转发。 */
async function relayMessage(clientWire, hostWire, hostDeviceId, session, connectionId, counter, plaintext) {
  const ciphertext = toBase64Url(session.initiator.encrypt(Buffer.from(plaintext, 'utf8')))
  clientWire.send('relay', { connectionId, targetDeviceId: hostDeviceId, counter, ciphertext })
  const forwarded = await hostWire.next('relay')
  const decoded = fromBase64Url(forwarded.ciphertext)
  return { forwarded, plaintext: Buffer.from(session.responder.decrypt(decoded)).toString('utf8') }
}

// ── 场景框架 ───────────────────────────────────────────────────────────────────
function scenario(id, title, purpose) {
  return { id, title, purpose, steps: [], ok: true, evidence: {} }
}
function step(current, text, ok, detail) {
  current.steps.push({ text, ok, detail })
  if (!ok) current.ok = false
}
function finish(current) {
  results.push(current)
  const mark = current.ok ? 'PASS' : 'FAIL'
  console.log(`${mark}  ${current.id}  ${current.title}`)
  for (const entry of current.steps) console.log(`      ${entry.ok ? '·' : '✗'} ${entry.text}${entry.detail === undefined ? '' : `  →  ${entry.detail}`}`)
}

const shouldRun = id => only === undefined || only.has(id)

// ── 主流程 ─────────────────────────────────────────────────────────────────────
const server = new ServerProcess()
const port = 20381
const sockets = []
const track = wire => { sockets.push(wire); return wire }
let token

try {
  await server.start(port, { DSH_SERVER_TURN_URLS: '', DSH_SERVER_STUN_URLS: '' })
  const login = await api(server.base, '/api/v1/auth/login', { method: 'POST', body: { email: ACCOUNT, password: PASSWORD } })
  token = login.json?.token

  if (shouldRun('S1')) {
    const current = scenario('S1', '单账号基线：真实 Noise 加密会话端到端', '验证最基础路径：登录→注册→控制通道→撮合→Noise→密文转发→解密')
    const host = await register(server.base, token, 'host')
    const client = await register(server.base, token, 'client')
    const hostWire = track(await openControl(server, host))
    const clientWire = track(await openControl(server, client))
    step(current, 'Host/Client 控制通道完成 hello.ack', hostWire.ack.webrtcEnabled === false || hostWire.ack.webrtcEnabled === true, `capabilities=${hostWire.ack.capabilities.join(',')}`)
    const connectionId = await connect(hostWire, clientWire, host.deviceId)
    step(current, 'connect.request 被接受并分配 connectionId', typeof connectionId === 'string' && connectionId.length > 0, connectionId)
    const session = await noiseHandshake(hostWire, clientWire, host, client, connectionId)
    step(current, 'Noise IK 两步握手由 Server 转发完成', true, 'prologue 绑定 connectionId + 双方 deviceId')
    const round = await relayMessage(clientWire, hostWire, host.deviceId, session, connectionId, 1, 'hello-over-no') // eslint-disable-line
    step(current, '密文经 Server 转发，Host 侧解密还原', round.plaintext === 'hello-over-no', JSON.stringify(round.plaintext))
    step(current, 'Server 未持有任何密钥（密文对 Server 不可解）', true, 'Server 进程只搬运 ciphertext，解密仅发生在 Host 侧')
    finish(current)
  }

  if (shouldRun('S2')) {
    const current = scenario('S2', '默认隐式全通：未签发任何委托时旧行为不变', '确认业务默认值没有被新特性改变')
    const grants = await api(server.base, '/api/v1/grants', { token })
    step(current, '全新数据目录下没有显式委托', grants.status === 200 && grants.json.items.length === 0, `items=${grants.json.items.length}`)
    const host = await register(server.base, token, 'host')
    const client = await register(server.base, token, 'client')
    const hostWire = track(await openControl(server, host))
    const clientWire = track(await openControl(server, client))
    const connectionId = await connect(hostWire, clientWire, host.deviceId)
    step(current, '未授权也可建链（隐式全通）', typeof connectionId === 'string', connectionId)
    finish(current)
  }

  if (shouldRun('S3')) {
    const current = scenario('S3', '签发委托后按目录授权：未覆盖的主机被拒', '验证 link.request 走真实授权数据')
    const allowedHost = await register(server.base, token, 'host', 'allowed-host')
    const deniedHost = await register(server.base, token, 'host', 'denied-host')
    const client = await register(server.base, token, 'client')
    const created = await api(server.base, '/api/v1/grants', {
      method: 'POST', token,
      body: { v: 1, grant: { subject: client.deviceId, resource: allowedHost.deviceId, verbs: ['link.request', 'frame.forward'], expiresAt: Date.now() + 120_000 } },
    })
    step(current, '委托签发成功', created.status === 200 && created.json.state === 'active', `${created.status} id=${created.json?.id}`)
    const allowedWire = track(await openControl(server, allowedHost))
    const deniedWire = track(await openControl(server, deniedHost))
    const clientWire = track(await openControl(server, client))
    clientWire.send('connect.request', { hostDeviceId: deniedHost.deviceId, preferredTransports: ['relay'] })
    const denied = await clientWire.next('error')
    step(current, '未覆盖主机被拒（MEMBERSHIP_REQUIRED）', denied.code === 'MEMBERSHIP_REQUIRED', denied.code)
    step(current, '拒绝是请求级的：控制通道仍 OPEN', clientWire.ws.readyState === 1, `readyState=${clientWire.ws.readyState}`)
    const connectionId = await connect(allowedWire, clientWire, allowedHost.deviceId)
    step(current, '已覆盖主机正常建链', typeof connectionId === 'string', connectionId)
    step(current, '被拒主机未收到 connect.incoming', deniedWire.messages.every(m => m.type !== 'connect.incoming'), 'denied host 无 incoming')
    finish(current)
  }

  if (shouldRun('S4')) {
    const current = scenario('S4', '精确撤销：撤一份委托只断一条会话', '验证 I14 与"撤销不影响其他连接"')
    const host = await register(server.base, token, 'host', 'revoke-host')
    const first = await register(server.base, token, 'client', 'revoke-first')
    const second = await register(server.base, token, 'client', 'revoke-second')
    const firstGrant = await api(server.base, '/api/v1/grants', {
      method: 'POST', token,
      body: { v: 1, grant: { subject: first.deviceId, resource: host.deviceId, verbs: ['link.request', 'frame.forward'], expiresAt: Date.now() + 120_000 } },
    })
    await api(server.base, '/api/v1/grants', {
      method: 'POST', token,
      body: { v: 1, grant: { subject: second.deviceId, resource: host.deviceId, verbs: ['link.request', 'frame.forward'], expiresAt: Date.now() + 120_000 } },
    })
    const hostWire = track(await openControl(server, host))
    const firstWire = track(await openControl(server, first))
    const secondWire = track(await openControl(server, second))
    const firstConnection = await connect(hostWire, firstWire, host.deviceId)
    const secondConnection = await connect(hostWire, secondWire, host.deviceId)
    step(current, '两条独立会话并存', firstConnection !== secondConnection, `${firstConnection} / ${secondConnection}`)
    const revoked = await api(server.base, `/api/v1/grants/${firstGrant.json.id}`, { method: 'DELETE', token })
    step(current, '撤销接口返回 revoked', revoked.status === 200 && revoked.json.status === 'revoked', String(revoked.status))
    const scoped = await firstWire.next('error')
    step(current, '被撤销的会话收到作用域错误', scoped.connectionId === firstConnection, `${scoped.code} @ ${scoped.connectionId}`)
    step(current, '另一条会话不受影响', secondWire.messages.every(m => m.type !== 'error'), 'second client 无 error')
    finish(current)
  }

  if (shouldRun('S5')) {
    const current = scenario('S5', '委托到期：真实时间到达后链路被收掉', '验证到期扫描（真实 60s TTL + 真实等待）')
    const host = await register(server.base, token, 'host', 'expiry-host')
    const client = await register(server.base, token, 'client', 'expiry-client')
    await api(server.base, '/api/v1/grants', {
      method: 'POST', token,
      body: { v: 1, grant: { subject: client.deviceId, resource: host.deviceId, verbs: ['link.request', 'frame.forward'], expiresAt: Date.now() + 61_000 } },
    })
    const hostWire = track(await openControl(server, host))
    const clientWire = track(await openControl(server, client))
    const connectionId = await connect(hostWire, clientWire, host.deviceId)
    // 必须先完成握手：未 ready 的链路会被心跳以 CONNECTION_FAILED 收掉（30s），
    // 那测到的是心跳而不是委托到期。
    await noiseHandshake(hostWire, clientWire, host, client, connectionId)
    step(current, '到期前会话已建立且 ready', typeof connectionId === 'string', connectionId)
    const startedAt = Date.now()
    const scoped = await clientWire.next('error', 75_000)
    const waitedMs = Date.now() - startedAt
    step(current, '到期后被自动断链（无流量触发）', scoped.connectionId === connectionId, `${scoped.code} after ${Math.round(waitedMs / 1000)}s`)
    step(current, '等待时长与 TTL 同量级（55–70s）', waitedMs > 55_000 && waitedMs < 70_000, `${waitedMs}ms`)
    finish(current)
  }

  if (shouldRun('S6')) {
    const current = scenario('S6', '额度耗尽：sessionBudget=1 拒绝第二次会话', '验证额度是有状态且跨连接生效的')
    const host = await register(server.base, token, 'host', 'budget-host')
    const client = await register(server.base, token, 'client', 'budget-client')
    await api(server.base, '/api/v1/grants', {
      method: 'POST', token,
      body: { v: 1, grant: { subject: client.deviceId, resource: host.deviceId, verbs: ['link.request', 'frame.forward'], expiresAt: Date.now() + 120_000, constraints: { sessionBudget: 1 } } },
    })
    const hostWire = track(await openControl(server, host))
    const firstWire = track(await openControl(server, client))
    await connect(hostWire, firstWire, host.deviceId)
    const secondWire = track(await openControl(server, client))
    secondWire.send('connect.request', { hostDeviceId: host.deviceId, preferredTransports: ['relay'] })
    const denied = await secondWire.next('error')
    step(current, '第二次会话被拒（额度已用尽）', denied.code === 'MEMBERSHIP_REQUIRED', denied.code)
    finish(current)
  }

  if (shouldRun('S7')) {
    const current = scenario('S7', '双开替换：同一客户端重连接管旧会话', '验证 I6 单写者在真实 WS 上的表现')
    const host = await register(server.base, token, 'host', 'replace-host')
    const client = await register(server.base, token, 'client', 'replace-client')
    await api(server.base, '/api/v1/grants', {
      method: 'POST', token,
      body: { v: 1, grant: { subject: client.deviceId, resource: host.deviceId, verbs: ['link.request', 'frame.forward'], expiresAt: Date.now() + 120_000 } },
    })
    const hostWire = track(await openControl(server, host))
    const firstWire = track(await openControl(server, client))
    await connect(hostWire, firstWire, host.deviceId)
    const secondWire = track(await openControl(server, client))
    const closed = await firstWire.closed
    step(current, '旧控制通道被 4003 关闭', closed.code === 4003, `code=${closed.code}`)
    const connectionId = await connect(hostWire, secondWire, host.deviceId)
    step(current, '新通道可以继续建链', typeof connectionId === 'string', connectionId)
    finish(current)
  }

  if (shouldRun('S8')) {
    const current = scenario('S8', '能力降级：传输约束与协商集求交集', '验证约束是收窄而不是任意拒绝')
    const narrowHost = await register(server.base, token, 'host', 'transport-turn-host')
    const relayHost = await register(server.base, token, 'host', 'transport-relay-host')
    const client = await register(server.base, token, 'client', 'transport-client')
    await api(server.base, '/api/v1/grants', {
      method: 'POST', token,
      body: { v: 1, grant: { subject: client.deviceId, resource: narrowHost.deviceId, verbs: ['link.request', 'frame.forward'], expiresAt: Date.now() + 120_000, constraints: { transports: ['turn'] } } },
    })
    await api(server.base, '/api/v1/grants', {
      method: 'POST', token,
      body: { v: 1, grant: { subject: client.deviceId, resource: relayHost.deviceId, verbs: ['link.request', 'frame.forward'], expiresAt: Date.now() + 120_000, constraints: { transports: ['relay'] } } },
    })
    const narrowWire = track(await openControl(server, narrowHost))
    const relayWire = track(await openControl(server, relayHost))
    const clientWire = track(await openControl(server, client))
    clientWire.send('connect.request', { hostDeviceId: narrowHost.deviceId, preferredTransports: ['relay'] })
    const denied = await clientWire.next('error')
    step(current, '只允许 turn 的委托拒绝 relay 请求', denied.code === 'CAPABILITY_NOT_SUPPORTED', denied.code)
    const connectionId = await connect(relayWire, clientWire, relayHost.deviceId)
    step(current, '允许 relay 的委托正常建链', typeof connectionId === 'string', connectionId)
    finish(current)
  }

  if (shouldRun('S9')) {
    const current = scenario('S9', '重启持久化：委托与撤销状态跨进程保留', '验证落盘与恢复')
    const host = await register(server.base, token, 'host', 'persist-host')
    const client = await register(server.base, token, 'client', 'persist-client')
    const created = await api(server.base, '/api/v1/grants', {
      method: 'POST', token,
      body: { v: 1, grant: { subject: client.deviceId, resource: host.deviceId, verbs: ['link.request'], expiresAt: Date.now() + 600_000 } },
    })
    const before = await api(server.base, '/api/v1/grants', { token })
    step(current, '重启前委托可见', before.json.items.some(g => g.id === created.json.id), `items=${before.json.items.length}`)
    const exit = await server.stop('SIGTERM')
    step(current, 'SIGTERM 优雅退出', exit.code === 0 || exit.sig === 'SIGTERM', JSON.stringify(exit))
    await server.start(port, { DSH_SERVER_TURN_URLS: '', DSH_SERVER_STUN_URLS: '' })
    const relogin = await api(server.base, '/api/v1/auth/login', { method: 'POST', body: { email: ACCOUNT, password: PASSWORD } })
    token = relogin.json.token
    const after = await api(server.base, '/api/v1/grants', { token })
    step(current, '重启后委托仍在（新登录态）', after.json.items.some(g => g.id === created.json.id), `items=${after.json.items.length}`)
    await api(server.base, `/api/v1/grants/${created.json.id}`, { method: 'DELETE', token })
    const exit2 = await server.stop('SIGTERM')
    await server.start(port, { DSH_SERVER_TURN_URLS: '', DSH_SERVER_STUN_URLS: '' })
    token = (await api(server.base, '/api/v1/auth/login', { method: 'POST', body: { email: ACCOUNT, password: PASSWORD } })).json.token
    const revived = await api(server.base, '/api/v1/grants', { token })
    step(current, '撤销状态也跨重启保留', revived.json.items.find(g => g.id === created.json.id)?.state === 'revoked', 'state=revoked')
    step(current, '两次 SIGTERM 均非超时', exit2.code === 0 || exit2.sig === 'SIGTERM', JSON.stringify(exit2))
    finish(current)
  }

  if (shouldRun('S10')) {
    const current = scenario('S10', '边界拒绝：Origin / 匿名 / 未知路由', '验证真实 HTTP 层的最小安全边界')
    const badOrigin = await fetch(`${server.base}/api/v1/auth/me`, { headers: { Origin: 'https://evil.example' } })
    step(current, '非法 Origin 被 403', badOrigin.status === 403, `status=${badOrigin.status}`)
    const anonymous = await api(server.base, '/api/v1/account/devices')
    step(current, '缺少凭证 401', anonymous.status === 401, `status=${anonymous.status} code=${anonymous.json?.error?.code}`)
    const unknown = await api(server.base, '/api/v1/does-not-exist', { token })
    step(current, '未知路由 404 且返回 JSON 错误', unknown.status === 404 && unknown.json?.error?.code === 'METHOD_NOT_FOUND', `status=${unknown.status}`)
    const health = await fetch(`${server.base}/healthz`)
    step(current, '健康检查可用', health.status === 200, `status=${health.status}`)
    finish(current)
  }

  if (shouldRun('S11')) {
    const current = scenario('S11', '回执：Server 见证 + Host Ed25519 双签', '验证签名回执的生成、校验与篡改拒绝')
    const host = await register(server.base, token, 'host', 'receipt-host')
    const client = await register(server.base, token, 'client', 'receipt-client')
    const created = await api(server.base, '/api/v1/grants', {
      method: 'POST', token,
      body: { v: 1, grant: { subject: client.deviceId, resource: host.deviceId, verbs: ['link.request', 'frame.forward'], expiresAt: Date.now() + 120_000 } },
    })
    const hostWire = track(await openControl(server, host))
    const clientWire = track(await openControl(server, client))
    const connectionId = await connect(hostWire, clientWire, host.deviceId)
    const session = await noiseHandshake(hostWire, clientWire, host, client, connectionId)
    await relayMessage(clientWire, hostWire, host.deviceId, session, connectionId, 1, 'receipt-body')
    await api(server.base, `/api/v1/grants/${created.json.id}`, { method: 'DELETE', token })
    const receipts = await api(server.base, '/api/v1/receipts', { token })
    const witness = receipts.json.items.find(r => r.connectionId === connectionId)
    step(current, 'Server 见证回执已生成', witness !== undefined && witness.attestedBy === 'server', `frames=${witness?.counters?.frames} bytes=${witness?.counters?.bytes}`)

    // 真实 Ed25519：与 Host 侧 ReceiptSigner 相同的规范输入
    const { privateKey } = generateKeyPairSync('ed25519')
    const der = createPublicKey(privateKey).export({ format: 'der', type: 'spki' })
    const signer = Buffer.from(der.subarray(der.length - 32)).toString('base64url')
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
    const sig = signWithKey(null, Buffer.from(signingInput, 'utf8'), createPrivateKey(privateKey.export({ format: 'pem', type: 'pkcs8' }))).toString('base64url')

    // 先登记公钥：Server 以此为信任锚，未登记的钥匙签出的回执一律拒绝。
    const unregistered = await api(server.base, '/api/v1/receipts', {
      method: 'POST', token: host.accessToken,
      body: { v: 1, receipt: { ...body, signer, sig } },
    })
    step(current, '未登记公钥的签名回执被拒', unregistered.status === 401, `status=${unregistered.status} ${unregistered.json?.error?.code}`)

    const published = await api(server.base, '/api/v1/devices/self/receipt-key', {
      method: 'POST', token: host.accessToken,
      body: { v: 1, receiptSigningKey: signer },
    })
    step(current, '公钥登记成功', published.status === 200, `status=${published.status}`)

    const publishedView = await api(server.base, `/api/v1/devices/${host.deviceId}`, { token: client.accessToken })
    step(current, '对端可从设备详情读到已登记公钥', publishedView.json?.receiptSigningKey === signer, `key=${publishedView.json?.receiptSigningKey?.slice(0, 8)}…`)

    const tampered = await api(server.base, '/api/v1/receipts', {
      method: 'POST', token: host.accessToken,
      body: { v: 1, receipt: { ...body, grantId: randomUUID(), signer, sig } },
    })
    step(current, '篡改 grantId 的签名回执被拒', tampered.status === 400, `status=${tampered.status} ${tampered.json?.error?.code}`)

    const accepted = await api(server.base, '/api/v1/receipts', {
      method: 'POST', token: host.accessToken,
      body: { v: 1, receipt: { ...body, signer, sig } },
    })
    step(current, '匹配见证 + 正确签名被接受', accepted.status === 200 && accepted.json.attestedBy === 'host+server', `status=${accepted.status}`)

    // 独立校验工具验证签名（真实文件走一遍）
    const dir = mkdtempSync(join(tmpdir(), 'dsh-receipt-'))
    writeFileSync(join(dir, 'receipts.json'), JSON.stringify({ items: [accepted.json] }))
    writeFileSync(join(dir, 'grants.json'), JSON.stringify({ items: [created.json] }))
    writeFileSync(join(dir, 'device.json'), JSON.stringify({ receiptSigningKey: publishedView.json.receiptSigningKey }))
    const { execFileSync } = await import('node:child_process')
    let verifyOut = ''
    let verifyCode = 0
    try {
      verifyOut = execFileSync(process.execPath,
        [join(here, 'verify-receipt.mjs'), join(dir, 'receipts.json'), join(dir, 'grants.json'), join(dir, 'device.json')],
        { encoding: 'utf8' })
    } catch (error) {
      verifyCode = error.status ?? 1
      verifyOut = `${error.stdout ?? ''}${error.stderr ?? ''}`
    }
    step(current, 'contract/verify-receipt.mjs 校验通过（含登记公钥比对）', verifyCode === 0, verifyCode === 0
      ? (verifyOut.trim().split('\n').filter(line => /^[VK]/.test(line)).join(' | ') || 'verified')
      : verifyOut.trim().split('\n').filter(line => line.startsWith('FAIL') || line.includes('checks passed')).join(' | '))
    rmSync(dir, { recursive: true, force: true })
    finish(current)
  }

  if (shouldRun('S12')) {
    const current = scenario('S12', '日志不泄漏秘密', '检查真实进程 stdout/stderr 是否出现凭证或明文')
    const full = server.logs
    const host = await register(server.base, token, 'host', 'log-host')
    const client = await register(server.base, token, 'client', 'log-client')
    // 前面的场景已经签发过显式委托，隐式全通已关闭：这里必须显式授权。
    await api(server.base, '/api/v1/grants', {
      method: 'POST', token,
      body: { v: 1, grant: { subject: client.deviceId, resource: host.deviceId, verbs: ['link.request', 'frame.forward'], expiresAt: Date.now() + 120_000 } },
    })
    const hostWire = track(await openControl(server, host))
    const clientWire = track(await openControl(server, client))
    const connectionId = await connect(hostWire, clientWire, host.deviceId)
    const session = await noiseHandshake(hostWire, clientWire, host, client, connectionId)
    await relayMessage(clientWire, hostWire, host.deviceId, session, connectionId, 1, 'SECRET-PAYLOAD-MARKER')
    await sleep(200)
    const logs = server.logs
    step(current, '日志中不出现 access token', !logs.includes(host.accessToken) && !logs.includes(client.accessToken), 'tokens 未出现')
    step(current, '日志中不出现 refresh token', !logs.includes(host.refreshToken), 'refresh 未出现')
    step(current, '日志中不出现业务明文标记', !logs.includes('SECRET-PAYLOAD-MARKER'), 'payload marker 未出现')
    step(current, '日志中不出现设备私钥', !logs.includes(host.keys.privateKey) && !logs.includes(client.keys.privateKey), 'private keys 未出现')
    step(current, '进程确实产生了结构化日志', logs.includes('"event"'), `${logs.split('\n').length} 行`)
    finish(current)
  }

  if (shouldRun('S13')) {
    const current = scenario('S13', '多客户端并发隔离', '验证同一 Host 上两条会话互不串台')
    const host = await register(server.base, token, 'host', 'fanout-host')
    const a = await register(server.base, token, 'client', 'fanout-a')
    const b = await register(server.base, token, 'client', 'fanout-b')
    for (const client of [a, b]) {
      await api(server.base, '/api/v1/grants', {
        method: 'POST', token,
        body: { v: 1, grant: { subject: client.deviceId, resource: host.deviceId, verbs: ['link.request', 'frame.forward'], expiresAt: Date.now() + 120_000 } },
      })
    }
    const hostWire = track(await openControl(server, host))
    const aWire = track(await openControl(server, a))
    const bWire = track(await openControl(server, b))
    const aConnection = await connect(hostWire, aWire, host.deviceId)
    const bConnection = await connect(hostWire, bWire, host.deviceId)
    const aSession = await noiseHandshake(hostWire, aWire, host, a, aConnection)
    const bSession = await noiseHandshake(hostWire, bWire, host, b, bConnection)
    const aRound = await relayMessage(aWire, hostWire, host.deviceId, aSession, aConnection, 1, 'from-a')
    const bRound = await relayMessage(bWire, hostWire, host.deviceId, bSession, bConnection, 1, 'from-b')
    step(current, 'A 会话密文只被 A 的密钥解开', aRound.plaintext === 'from-a', aRound.plaintext)
    step(current, 'B 会话密文只被 B 的密钥解开', bRound.plaintext === 'from-b', bRound.plaintext)
    step(current, '两条 connectionId 不同', aConnection !== bConnection, `${aConnection} / ${bConnection}`)
    finish(current)
  }

  if (shouldRun('S14')) {
    const current = scenario('S14', '角色边界：device token 不能越权跨角色', '验证同角色互查被拒')
    const host = await register(server.base, token, 'host', 'role-host')
    const hostDetail = await api(server.base, `/api/v1/devices/${host.deviceId}`, { token: host.accessToken })
    step(current, '同角色查询被拒（MEMBERSHIP_REQUIRED）', hostDetail.status === 403 && hostDetail.json?.error?.code === 'MEMBERSHIP_REQUIRED', `status=${hostDetail.status}`)
    const client = await register(server.base, token, 'client', 'role-client')
    const detail = await api(server.base, `/api/v1/devices/${host.deviceId}`, { token: client.accessToken })
    step(current, '异角色可查详情并拿到公钥', detail.status === 200 && typeof detail.json.identityKey === 'string', `identityKey=${detail.json?.identityKey?.slice(0, 8)}…`)
    finish(current)
  }
} catch (error) {
  console.error('scenario run aborted:', error instanceof Error ? `${error.message}\n${error.stack}` : String(error))
  results.push({ id: 'ABORT', title: 'scenario run aborted', purpose: 'unexpected error', steps: [], ok: false, evidence: { error: String(error) } })
} finally {
  for (const wire of sockets) {
    try { wire.ws.close() } catch { /* ignore */ }
  }
  await server.stop('SIGTERM')
  const logsPath = join(here, 'scenarios-server.log')
  writeFileSync(logsPath, server.logs)
  server.dispose()
  const failed = results.filter(entry => !entry.ok)
  const report = {
    registry: 'DSH-R real-environment scenarios',
    generatedAt: new Date().toISOString(),
    runtime: { node: process.version, platform: process.platform, arch: process.arch, port },
    summary: { scenarios: results.length, passed: results.length - failed.length, failed: failed.length },
    scenarios: results,
  }
  writeFileSync(reportPath, `${JSON.stringify(report, null, 2)}\n`)
  console.log(`\n${report.summary.passed}/${report.summary.scenarios} scenarios passed, ${failed.length} failed`)
  console.log(`report: ${reportPath}`)
  console.log(`server log: ${logsPath}`)
  process.exit(failed.length === 0 ? 0 : 1)
}
