import axios, { AxiosInstance, AxiosRequestConfig, CanceledError } from 'axios'
import { getFingerprint, getMacAddress, isDeviceInitialized, generateDeviceHeaders } from '../security/deviceHeaders'
import { secureStorage } from '../security/fingerprint'
import type { AxiosRequestConfig as AxiosConfig } from 'axios'

// Base API URL
const API_BASE_URL = import.meta.env.VITE_API_BASE || 'https://api.corp.local/api/v1'

// Request interface to include device headers
interface RequestConfig extends AxiosConfig {
  skipAuth?: boolean
  skipDeviceHeaders?: boolean
}

/** API client instance */
let api: AxiosInstance | null = null

/** Initialize API client with auth interceptors */
export function initApiClient(): AxiosInstance {
  if (api) return api
  
  api = axios.create({
    baseURL: API_BASE_URL,
    timeout: 30_000,
    withCredentials: true, // For cookie-based refresh tokens
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/json',
    },
  })
  
  // Attach device headers to every request
  api.interceptors.request.use(
    async (config: RequestConfig) => {
      // Check if device identity is initialized
      if (!isDeviceInitialized() && !config.skipAuth) {
        // If not initialized and not skipping auth, we need to handle this
        // In practice, this would happen after login
        console.debug('Device identity not initialized - adding minimal headers')
      }
      
      // Generate device authentication headers if not skipped
      if (!config.skipDeviceHeaders && !config.skipAuth) {
        const headers = generateDeviceHeaders(
          config.method?.toUpperCase() || 'GET',
          config.url || '',
          config.data
        )
        
        // Merge headers with existing ones
        config.headers = {
          ...config.headers,
          ...headers,
          // Remove X-Device-MAC for web clients (would be set for desktop)
          ...(getMacAddress() ? { 'X-Device-MAC': getMacAddress() } : {}),
        }
      }
      
      // Add auth token if available
      const token = secureStorage.get('access_token')
      if (token && !config.headers?.Authorization) {
        config.headers.Authorization = `Bearer ${token}`
      }
      
      // Add request ID if not present
      if (!config.headers?.['X-Request-ID']) {
        config.headers['X-Request-ID'] = crypto.randomUUID()
      }
      
      return config
    },
    (error) => {
      return Promise.reject(error)
    }
  )
  
  // Handle token refresh on 401
  // Single-flight: concurrent 401s share one refresh call so the rotated
  // refresh token is not consumed twice (second use => 401 REVOKED).
  let refreshPromise: Promise<{ access: string; refresh: string }> | null = null

  function doRefresh(): Promise<{ access: string; refresh: string }> {
    if (!refreshPromise) {
      const refreshToken = secureStorage.get('refresh_token')
      if (!refreshToken) {
        return Promise.reject(new Error('no refresh token'))
      }
      refreshPromise = (async () => {
        try {
          const response = await api!.post('/auth/refresh', {
            refresh_token: refreshToken
          })
          const data = response.data
          // Update tokens
          secureStorage.set('access_token', data.tokens.access_token)
          secureStorage.set('refresh_token', data.tokens.refresh_token)
          return { access: data.tokens.access_token, refresh: data.tokens.refresh_token }
        } finally {
          refreshPromise = null
        }
      })()
    }
    return refreshPromise
  }

  api.interceptors.response.use(
    (response) => response,
    async (error) => {
      const originalRequest = error.config as RequestConfig & { _retry?: boolean }
      const failedUrl = String(originalRequest?.url || '')
      const isAuthCall = failedUrl.includes('/auth/refresh') || failedUrl.includes('/auth/login')

      // If 401 and not already retried (never retry the auth calls themselves)
      if (error.response?.status === 401 && !originalRequest._retry && !isAuthCall) {
        originalRequest._retry = true
        
        try {
          // Try to refresh token (single-flight across concurrent 401s)
          const { access } = await doRefresh()
          
          // Retry original request with new token.
          // NOTE: axios already serialized originalRequest.data to a JSON
          // string on the first attempt; re-dispatching would stringify it
          // AGAIN (422 dict_type on the server). Bypass re-transform.
          originalRequest.headers.Authorization = `Bearer ${access}`
          
          // Also regenerate device headers
          const headers = generateDeviceHeaders(
            originalRequest.method?.toUpperCase() || 'GET',
            originalRequest.url || '',
            originalRequest.data
          )
          originalRequest.headers = {
            ...originalRequest.headers,
            ...headers,
          }
          
          return api({
            ...originalRequest,
            transformRequest: [(data) => data],
          })
        } catch (refreshError) {
          // Refresh failed - clear tokens and notify the app shell
          // (client.ts cannot import the auth store: authProvider imports this
          // module, so we signal via a DOM event instead of a direct call).
          secureStorage.remove('access_token')
          secureStorage.remove('refresh_token')
          sessionStorage.removeItem('user')
          if (typeof window !== 'undefined') {
            window.dispatchEvent(new CustomEvent('auth:expired'))
          }

          // Navigate to login
          // In real app: navigate('/login')
          return Promise.reject(refreshError)
        }
      }

      // No refresh token stored: nothing to recover with. Notify shell too.
      if (error.response?.status === 401 && !isAuthCall) {
        if (typeof window !== 'undefined') {
          window.dispatchEvent(new CustomEvent('auth:expired'))
        }
      }
      
      return Promise.reject(error)
    }
  )
  
  return api
}

/** Get the API client instance */
export function getApi(): AxiosInstance {
  if (!api) {
    return initApiClient()
  }
  return api
}

/** Simple API helper functions */
export const apiRef = {
  get: <T>(url: string, config?: RequestConfig) => 
    getApi().get<T, T>(url, config),
  
  post: <T, D = any>(url: string, data?: D, config?: RequestConfig) => 
    getApi().post<T, T>(url, data, config),
  
  put: <T, D = any>(url: string, data?: D, config?: RequestConfig) => 
    getApi().put<T, T>(url, data, config),
  
  delete: <T>(url: string, config?: RequestConfig) => 
    getApi().delete<T, T>(url, config),
  
  patch: <T, D = any>(url: string, data?: D, config?: RequestConfig) => 
    getApi().patch<T, T>(url, data, config),
  
  // File upload with progress
  upload: <T>(url: string, file: File, onProgress?: (progress: number) => void) => {
    const formData = new FormData()
    formData.append('file', file)
    
    return getApi().post<T, any>(url, formData, {
      onUploadProgress: (progressEvent) => {
        if (onProgress && progressEvent.total) {
          const progress = Math.round((progressEvent.loaded * 100) / progressEvent.total)
          onProgress(progress)
        }
      }
    })
  },
  
  // Download file
  download: (url: string) => {
    return getApi().get(url, {
      responseType: 'blob',
      headers: {
        'X-Requested-With': ' XMLHttpRequest'
      }
    })
  },
}

export default apiRef