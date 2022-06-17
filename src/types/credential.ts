export interface StoredCredential {
  user_id: string
  // User visible identifier.
  credentialID: string // roaming authenticator's credential id,
  credentialPublicKey: string // public key,
  counter: number // previous counter,
  aaguid?: string // AAGUID,
  registered?: number // registered epoc time,
  user_verifying: boolean // user verifying authenticator,
  authenticatorAttachment: "platform" | "cross-platform" | "undefined" // authenticator attachment,
  transports?: AuthenticatorTransport[] // list of transports,
  browser?: string
  os?: string
  platform?: string
  last_used?: number // last used epoc time,
  clientExtensionResults?: any
}
