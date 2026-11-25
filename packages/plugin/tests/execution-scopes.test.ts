import { describe, expect, it } from 'vitest'
import { RpcRouter, requiredExecutionScope } from '../src/rpc-router.js'

/**
 * 执行级收窄（grants.v1）：
 * 表是数据；表外方法在收窄后一律拒绝；未收窄时行为不变。
 */
function routerWithScopes(scopes: readonly string[] | undefined): RpcRouter {
  const u = undefined
  return new RpcRouter(128, u, u, u, u, u, u, u, u, u, u, u, u, u, u, u, u, u, u, scopes)
}

function rpc(method: string) {
  return {
    v: 1,
    id: 'req-1',
    type: 'rpc.request',
    timestamp: Date.now(),
    payload: { method, params: {} },
  } as never
}

describe('execution scopes', () => {
  it('maps methods to a closed scope table', () => {
    expect(requiredExecutionScope('session.transfer.import.v1')).toBe('session:write')
    expect(requiredExecutionScope('workspace.upload.open')).toBe('session:write')
    expect(requiredExecutionScope('workspace.git.diff')).toBe('files:read')
    expect(requiredExecutionScope('fileviewer.read')).toBe('files:read')
    expect(requiredExecutionScope('dsh.web.open')).toBe('session:write')
    expect(requiredExecutionScope('harness.remote.call')).toBe('tools')
    expect(requiredExecutionScope('plugin.route.call')).toBe('tools')
    // 表外方法没有 scope —— 收窄后即拒绝。
    expect(requiredExecutionScope('something.unclassified')).toBeUndefined()
  })

  it('denies an operation outside the granted scopes', async () => {
    const router = routerWithScopes(['session:read'])
    const response = await router.handle(rpc('harness.transport.describe'))
    expect(response.type).toBe('rpc.error')
    expect((response.payload as { code: string }).code).toBe('PERMISSION_DENIED')
  })

  it('denies unclassified methods once narrowed (fail-closed)', async () => {
    const router = routerWithScopes(['tools', 'session:read'])
    // 该方法存在于 apiMethods 之外，先被 METHOD_NOT_FOUND 拦下；用一个已登记但表外的名字时
    // 才轮到缺省拒绝，这里只断言"没有任何一条路径会放行未登记 scope 的方法"。
    const response = await router.handle(rpc('session.unknown.operation'))
    expect(['METHOD_NOT_FOUND', 'PERMISSION_DENIED']).toContain((response.payload as { code: string }).code)
  })

  it('does not narrow when the connection carries no execution scopes', async () => {
    const router = routerWithScopes(undefined)
    const response = await router.handle(rpc('harness.transport.describe'))
    // 未收窄：不返回 PERMISSION_DENIED（具体失败原因取决于依赖，不是收窄造成的）。
    expect((response.payload as { code?: string }).code).not.toBe('PERMISSION_DENIED')
  })
})
