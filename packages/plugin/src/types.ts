import type { RemoteMessage, SameLinkIpv6Pair } from '@dsh-remote/protocol'

export interface AuthenticatedPeerChannel {
  /**
   * Attestation supplied by the Noise/control-plane integration. Implementors
   * must expose this channel only after both the Noise IK transcript and the
   * Server membership for this exact connection have been verified.
   */
  readonly security: {
    protocol: 'Noise_IK_25519_ChaChaPoly_SHA256'
    connectionId: string
    membershipId: string
  }
  readonly peerDeviceId: string
  readonly peerIdentityKey: string
  /**
   * 本连接的执行级范围（来自 Server 下发的 grants.executionScopes）。
   * 缺省表示"未收窄"：旧 Server 不下发、或覆盖该关系的委托没有 executionScopes。
   */
  readonly executionScopes?: readonly string[]
  readonly sameLinkIpv6Endpoints?: (pair?: SameLinkIpv6Pair) => Promise<string[]>
  readonly lanWebAddress?: (pair?: SameLinkIpv6Pair) => Promise<string | undefined>
  readonly mode?: 'LAN' | 'P2P' | 'TURN' | 'Relay'
  readonly createTransportUpgradeHost?: (publishEvent: (message: RemoteMessage) => Promise<void>) => import('./transport-upgrade.js').TransportUpgradeHost | undefined
  send(message: RemoteMessage): Promise<void>
  onMessage(handler: (message: RemoteMessage) => void): () => void
  close(code?: string): Promise<void>
}
