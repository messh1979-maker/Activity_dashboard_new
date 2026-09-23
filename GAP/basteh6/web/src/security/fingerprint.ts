import FingerprintJS from '@fingerprintjs/fingerprintjs'

// Stable fingerprint cache
let cachedFingerprint: string | null = null

/**
 * Get a stable device fingerprint.
 * Combines FingerprintJS visitorId with a device token for consistency.
 */
export async function getDeviceFingerprint(): Promise<string> {
  if (cachedFingerprint) return cachedFingerprint

  try {
    const fp = await FingerprintJS.load()
    const result = await fp.get()

    // Use visitorId as base, but also incorporate device token from cookie
    const deviceToken = getCookie('device_token') || ''
    
    // Create stable hash combining both
    const combined = `${result.visitorId}:${deviceToken}`
    const hash = btoa(combined).replace(/[^a-zA-Z0-9+/]/g, '').substring(0, 32)
    
    cachedFingerprint = `web-fp-${hash}`
    return cachedFingerprint
  } catch (error) {
    logger.error('FingerprintJS error:', error)
    // Fallback to minimal fingerprint
    return 'web-fp-fallback'
  }
}

/** 
 * Device token stored in HttpOnly cookie (set by server on first login).
 * JavaScript cannot read this cookie, but can read a non-sensitive version.
 */
export function getDeviceToken(): string | null {
  try {
    // Read from a non-sensitive data attribute or meta tag
    // The actual token is HttpOnly, so we use a hashed version
    const metaContent = document.querySelector('meta[name="device-token"]')?.content
    return metaContent || null
  } catch {
    return null
  }
}

/** Log security events (client-side only) */
export function logSecurityEvent(event: string, details?: any) {
  // Send to analytics/backend for security monitoring
  const eventData = {
    event,
    timestamp: new Date().toISOString(),
    fingerprint: cachedFingerprint || 'unknown',
    url: window.location.href,
    ...details
  }
  
  // In production, send to endpoint
  // fetch('/api/security/events', {
  //   method: 'POST',
  //   headers: { 'Content-Type': 'application/json' },
  //   body: JSON.stringify(eventData)
  // }).catch(() => {}) // Non-blocking
}

/** Safe storage for sensitive data */
export const secureStorage = {
  set: (key: string, value: string) => {
    // Store encrypted value in localStorage
    try {
      const encrypted = simpleEncrypt(value)
      localStorage.setItem(`sec_${key}`, encrypted)
    } catch (e) {
      logger.error('Secure storage set error:', e)
    }
  },
  
  get: (key: string): string | null => {
    try {
      const encrypted = localStorage.getItem(`sec_${key}`)
      if (!encrypted) return null
      return simpleDecrypt(encrypted)
    } catch (e) {
      logger.error('Secure storage get error:', e)
      return null
    }
  },
  
  remove: (key: string) => {
    try {
      localStorage.removeItem(`sec_${key}`)
    } catch (e) {
      logger.error('Secure storage remove error:', e)
    }
  }
}

/* Simple XOR encryption for client-side obfuscation (not real encryption) */
function simpleEncrypt(text: string): string {
  const key = 'planner-web-2026'
  let result = ''
  for (let i = 0; i < text.length; i++) {
    result += String.fromCharCode(text.charCodeAt(i) ^ key.charCodeAt(i % key.length))
  }
  return btoa(result)
}

function simpleDecrypt(encrypted: string): string {
  const key = 'planner-web-2026'
  let text = atob(encrypted)
  let result = ''
  for (let i = 0; i < text.length; i++) {
    result += String.fromCharCode(text.charCodeAt(i) ^ key.charCodeAt(i % key.length))
  }
  return result
}

const logger = {
  error: (msg: string, ...args: any[]) => {
    // NOTE: Vite does not provide `process.env` in the browser;
    // guard it so logging never throws.
    const isDev =
      typeof process !== 'undefined' &&
      (process as any).env?.NODE_ENV === 'development'
    if (isDev || typeof process === 'undefined') {
      console.error('[Security]', msg, ...args)
    }
  }
}