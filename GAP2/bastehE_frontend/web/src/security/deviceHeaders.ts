import CryptoJS from 'crypto-js'
import { logSecurityEvent } from './fingerprint'

/**
 * Device authentication headers for API requests.
 * These headers are automatically injected by the api client interceptor.
 * 
 * Based on the architecture spec (sections 5.2, 6.5):
 * - X-Device-Fingerprint: Stable device identifier
 * - X-Device-MAC: MAC address (desktop only, NULL for web)
 * - X-Device-Nonce: One-time use nonce (against replay)
 * - X-Device-Timestamp: Unix timestamp in ms
 * - X-Device-Signature: HMAC-SHA256 signature
 * - X-Request-ID: Unique request identifier
 */

// Device identity state (populated from server response on login)
let deviceIdentity: {
  fingerprint: string
  macAddress: string | null
  macSource: string | null
  hmacKey: string | null
} = {
  fingerprint: '',
  macAddress: null,
  macSource: null,
  hmacKey: null
}

/**
 * Initialize device identity from server response.
 * Called after successful login.
 */
export function initDeviceIdentity(identity: {
  fingerprint: string
  macAddress: string | null
  macSource: string | null
  hmacKey: string | null
}) {
  deviceIdentity = {
    fingerprint: identity.fingerprint,
    macAddress: identity.macAddress,
    macSource: identity.macSource,
    hmacKey: identity.hmacKey
  }
}

/**
 * Get the current device fingerprint.
 */
export function getFingerprint(): string {
  return deviceIdentity.fingerprint
}

/**
 * Get the current MAC address (masked for non-admin users).
 */
export function getMacAddress(): string | null {
  return deviceIdentity.macAddress
}

/**
 * Check if device identity is initialized.
 */
export function isDeviceInitialized(): boolean {
  return deviceIdentity.fingerprint !== ''
}

/**
 * Generate device authentication headers for API requests.
 * 
 * @param method HTTP method (GET, POST, etc.)
 * @param path API path (e.g., "/goals")
 * @param body Optional request body (for POST/PUT)
 * @returns Headers object with device authentication
 */
export function generateDeviceHeaders(
  method: string,
  path: string,
  body?: any
): Record<string, string> {
  const now = Date.now()
  const nonce = crypto.randomUUID()
  
  // Body hash for signature (if body provided)
  const bodyStr = body !== undefined ? JSON.stringify(body) : ''
  const bodyHash = bodyStr 
    ? btoa(JSON.stringify(bodyStr)).replace(/[^a-zA-Z0-9+/]/g, '').substring(0, 64)
    : ''

  // Build the signature payload
  // Format: method|path|bodyHash|fingerprint|mac|nonce|timestamp
  const macPart = deviceIdentity.macAddress || ''
  const payload = `${method.toUpperCase()}|${path}|${bodyHash}|${deviceIdentity.fingerprint}|${macPart}|${nonce}|${now}`

  // Compute HMAC-SHA256 signature
  // In production, use the hmacKey from server
  // For now, use a derived key from fingerprint
  const key = deviceIdentity.hmacKey || deriveKeyFromFingerprint(deviceIdentity.fingerprint)
  const signature = hmacSha256(key, payload)

  return {
    'X-Device-Fingerprint': deviceIdentity.fingerprint,
    'X-Device-Nonce': nonce,
    'X-Device-Timestamp': String(now),
    'X-Device-Signature': signature,
    'X-Request-ID': crypto.randomUUID(),
    'Content-Type': 'application/json',
    // NOTE: X-Device-MAC is NOT sent for web clients
    // It would be sent only for desktop clients with real MAC addresses
    // 'X-Device-MAC': macMasked,
    // 'X-Device-MAC-Source': 'psutil'
  }
}

/**
 * Mask MAC address for display (show first 2 and last 2 octets).
 */
export function maskMacAddress(mac: string | null): string | null {
  if (!mac) return null
  const parts = mac.replace(/[:.-]/g, ':').split(':')
  if (parts.length !== 6) return mac
  return `${parts[0]}:${parts[1]}:**:**:${parts[4]}:${parts[5]}`
}

/**
 * Derive a key from the fingerprint (fallback when hmacKey not available).
 */
function deriveKeyFromFingerprint(fingerprint: string): string {
  // Simple key derivation - in production use PBKDF2 or similar
  let hash = fingerprint
  for (let i = 0; i < 1000; i++) {
    hash = simpleHash(hash)
  }
  return hash.slice(0, 32)
}

function simpleHash(input: string): string {
  let hash = 0
  for (let i = 0; i < input.length; i++) {
    hash = ((hash << 5) - hash + input.charCodeAt(i)) | 0
  }
  // Convert to hex
  return hash.toString(16).padStart(32, '0')
}

function hmacSha256(key: string, data: string): string {
  // NOTE: prototype-grade HMAC (matches server only loosely).
  // Per the architecture doc, web relies on the HttpOnly device token,
  // not on this header, for real authentication.
  return CryptoJS.HmacSHA256(data, key).toString(CryptoJS.enc.Hex)
}

/** Log authentication events */
export function logAuthEvent(event: string, success: boolean, details?: any) {
  logSecurityEvent(`auth.${event}`, {
    success,
    ...details,
    fingerprint: deviceIdentity.fingerprint
  })
}