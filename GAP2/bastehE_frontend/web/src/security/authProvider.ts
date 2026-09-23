import { create } from 'zustand'
import { persist, createJSONStorage } from 'zustand/middleware'
import { apiRef as api } from '../api/client'
import {
  initDeviceIdentity,
  getMacAddress,
  isDeviceInitialized,
  generateDeviceHeaders,
  logAuthEvent
} from '../security/deviceHeaders'
import { secureStorage } from '../security/fingerprint'
import type { User } from '../types'

// Auth state interface
interface AuthState {
  user: User | null
  token: string | null
  refreshToken: string | null
  isAuthenticated: boolean
  isLoading: boolean
  mfaRequired: boolean
  mfaMethod: string | null
  login: (credentials: LoginCredentials) => Promise<void>
  refreshToken: () => Promise<void>
  logout: () => Promise<void>
  forceLogout: () => void
  verifyMFA: (code: string) => Promise<void>
  enrollMFA: (secret: string) => Promise<{ qrUrl: string; secret: string }>
  register: (credentials: RegisterCredentials) => Promise<void>
  getDevices: () => Promise<DeviceInfo[]>
  trustDevice: (deviceId: string) => Promise<void>
  untrustDevice: (deviceId: string) => Promise<void>
  init: () => Promise<void>
}

// Login credentials
interface LoginCredentials {
  identifier: string  // username or national ID
  password: string
  rememberMe?: boolean
}

/** Registration credentials */
interface RegisterCredentials {
  nationalId: string
  username: string
  password: string
  displayName: string
  email?: string
  mobile?: string
}

/** Device info */
interface DeviceInfo {
  id: string
  label: string
  platform: string
  isTrusted: boolean
  lastSeen: string
}

/** MFA enrollment result */
interface MfaEnrollResult {
  qrUrl: string
  secret: string
}

/** Auth store */
export const useAuth = create<AuthState>()(
  persist(
    (set, get) => ({
      user: null,
      token: null,
      refreshToken: null,
      isAuthenticated: false,
      isLoading: true,
      mfaRequired: false,
      mfaMethod: null,

      // Login
      login: async (credentials: LoginCredentials) => {
        set({ isLoading: true, mfaRequired: false })
        
        try {
          const response = await api.post('/auth/login', {
            identifier: credentials.identifier,
            password: credentials.password,
            remember_me: credentials.rememberMe ?? false
          })
          
          const data = response.data
          
          if (data.mfa_required) {
            // MFA required - store challenge info
            set({
              mfaRequired: true,
              mfaMethod: data.mfa_method,
              user: data.user
            })
            return
          }
          
          // Successful login - no MFA
          set({
            user: data.user,
            token: data.tokens.access_token,
            refreshToken: data.tokens.refresh_token,
            isAuthenticated: true,
            isLoading: false,
            mfaRequired: false
          })
          
          // Initialize device identity
          if (data.device) {
            initDeviceIdentity({
              fingerprint: data.device.fingerprint,
              macAddress: data.device.mac_address,
              macSource: data.device.mac_source,
              hmacKey: data.device.hmac_key
            })
          }
          
          // Store tokens securely
          secureStorage.set('access_token', data.tokens.access_token)
          secureStorage.set('refresh_token', data.tokens.refresh_token)
          
          // Log auth event
          logAuthEvent('login', true, {
            method: credentials.identifier.includes('@') ? 'email' : 'national_id'
          })
          
        } catch (error: any) {
          set({ isLoading: false })
          throw error
        }
      },

      // Verify MFA
      verifyMFA: async (code: string) => {
        set({ isLoading: true, mfaRequired: false })
        
        try {
          const response = await api.post('/auth/mfa/verify', {
            mfa_token: code,
            mfa_method: get().mfaMethod
          })
          
          const data = response.data
          
          set({
            user: data.user,
            token: data.tokens.access_token,
            refreshToken: data.tokens.refresh_token,
            isAuthenticated: true,
            isLoading: false,
            mfaRequired: false,
            mfaMethod: null
          })
          
          // Initialize device identity
          if (data.device) {
            initDeviceIdentity({
              fingerprint: data.device.fingerprint,
              macAddress: data.device.mac_address,
              macSource: data.device.mac_source,
              hmacKey: data.device.hmac_key
            })
          }
          
          secureStorage.set('access_token', data.tokens.access_token)
          secureStorage.set('refresh_token', data.tokens.refresh_token)
          
          logAuthEvent('mfa_verify', true)
          
        } catch (error: any) {
          set({ isLoading: false })
          throw error
        }
      },

      // Logout
      logout: async () => {
        try {
          await api.post('/auth/logout')
        } catch (error) {
          // Ignore logout errors
        }
        
        // Clear secure storage
        secureStorage.remove('access_token')
        secureStorage.remove('refresh_token')
        
        // Clear auth state
        set({
          user: null,
          token: null,
          refreshToken: null,
          isAuthenticated: false,
          isLoading: false,
          mfaRequired: false,
          mfaMethod: null
        })
        
        // Remove tokens from session storage
        sessionStorage.removeItem('user')
        
        // Navigate to login
        // In real app: navigate('/login')
      },

      // Force logout without API call (e.g. refresh failed in interceptor)
      forceLogout: () => {
        secureStorage.remove('access_token')
        secureStorage.remove('refresh_token')
        sessionStorage.removeItem('user')
        set({
          user: null,
          token: null,
          refreshToken: null,
          isAuthenticated: false,
          isLoading: false,
          mfaRequired: false,
          mfaMethod: null
        })
      },

      // Get devices
      getDevices: async () => {
        try {
          const response = await api.get('/auth/devices')
          return response.data.items || []
        } catch (error) {
          console.error('Get devices error:', error)
          return []
        }
      },

      // Trust device
      trustDevice: async (deviceId: string) => {
        try {
          await api.post(`/auth/devices/${deviceId}/trust`, {
            mfa_satisfied: get().mfaMethod !== null
          })
          // Update local state
          set(state => ({
            user: state.user
              ? { ...state.user, trusted_devices: [...(state.user.trusted_devices || []), deviceId] }
              : null
          }))
        } catch (error) {
          console.error('Trust device error:', error)
        }
      },

      // Untrust device
      untrustDevice: async (deviceId: string) => {
        try {
          await api.post(`/auth/devices/${deviceId}/untrust`)
          set(state => ({
            user: state.user
              ? { ...state.user, trusted_devices: state.user.trusted_devices?.filter(d => d !== deviceId) || [] }
              : null
          }))
        } catch (error) {
          console.error('Untrust device error:', error)
        }
      },

      // Initial load - check auth state
      init: async () => {
        set({ isLoading: true })

        // Check if we have stored tokens
        const storedRefresh = secureStorage.get('refresh_token')

        if (!storedRefresh) {
          // No refresh token: do NOT trust the persisted isAuthenticated flag.
          // Otherwise the UI gets stuck on a dead dashboard after the
          // tokens were cleared (expired session, another tab logged out).
          get().forceLogout()
          return
        }

        try {
          // Validate + rotate via refresh (works even if access token expired)
          const response = await api.post('/auth/refresh', {
            refresh_token: storedRefresh
          }, { skipAuth: true } as any)

          const data = response.data

          secureStorage.set('access_token', data.tokens.access_token)
          secureStorage.set('refresh_token', data.tokens.refresh_token)

          set({
            user: data.user,
            token: data.tokens.access_token,
            refreshToken: data.tokens.refresh_token,
            isAuthenticated: true,
            isLoading: false
          })

          // Initialize device identity
          if (data.device) {
            initDeviceIdentity({
              fingerprint: data.device.fingerprint,
              macAddress: data.device.mac_address,
              macSource: data.device.mac_source,
              hmacKey: data.device.hmac_key
            })
          }

        } catch (error) {
          // Refresh token invalid - clear and login required
          get().forceLogout()
        }
      }
    }),
    {
      name: 'auth-storage',
      storage: createJSONStorage(() => localStorage)
    }
  )
)

export default useAuth
