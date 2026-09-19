import { useState, useEffect, useCallback } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { useQueryClient } from '@tanstack/react-query'
import { api } from '../api/client'
import { logger } from '../security/sanitize'

/** Hook for managing widget layout persistence */
export function useLayoutPersistence(userId: string) {
  const [layout, setLayout] = useState<any>([])

  // Load saved layout from localStorage
  useEffect(() => {
    try {
      const saved = localStorage.getItem(`layout_${userId}`)
      if (saved) {
        setLayout(JSON.parse(saved))
      }
    } catch (e) {
      logger.error('Layout persistence load error:', e)
    }
  }, [userId])

  // Save layout on change
  useEffect(() => {
    try {
      localStorage.setItem(`layout_${userId}`, JSON.stringify(layout))
    } catch (e) {
      logger.error('Layout persistence save error:', e)
    }
  }, [layout, userId])

  const setLayoutConfig = (newLayout: any) => {
    setLayout(newLayout)
  }

  const resetLayout = () => {
    setLayout([])
    try {
      localStorage.removeItem(`layout_${userId}`)
    } catch (e) {
      logger.error('Layout reset error:', e)
    }
  }

  return { layout, setLayoutConfig, resetLayout }
}

/** Hook for managing widget settings (clock, etc.) */
export function useWidgetSettings(userId: string) {
  const [widgets, setWidgets] = useState<Record<string, any>>({})

  useEffect(() => {
    try {
      const saved = localStorage.getItem(`widgets_${userId}`)
      if (saved) {
        setWidgets(JSON.parse(saved))
      }
    } catch (e) {
      logger.error('Widget settings load error:', e)
    }
  }, [userId])

  useEffect(() => {
    try {
      localStorage.setItem(`widgets_${userId}`, JSON.stringify(widgets))
    } catch (e) {
      logger.error('Widget settings save error:', e)
    }
  }, [widgets, userId])

  const updateWidget = (key: string, config: any) => {
    setWidgets(prev => ({
      ...prev,
      [key]: { ...prev[key], ...config, updatedAt: new Date().toISOString() }
    }))
  }

  const resetWidgets = () => {
    setWidgets({})
    try {
      localStorage.removeItem(`widgets_${userId}`)
    } catch (e) {
      logger.error('Widget reset error:', e)
    }
  }

  return { widgets, updateWidget, resetWidgets }
}

/** Hook for managing permissions */
export function usePermissionCache() {
  const [permissions, setPermissions] = useState<Set<string>>(new Set())
  const { user } = useAuth()

  // Load permissions from API on mount
  useEffect(() => {
    if (!user) return

    const loadPermissions = async () => {
      try {
        const response = await api.get('/rbac/permissions')
        const data = response.data
        
        const permSet = new Set(data.permissions || [])
        setPermissions(permSet)
        
        // Cache for 5 minutes
      } catch (error) {
        logger.error('Permission cache load error:', error)
      }
    }

    loadPermissions()
  }, [user?.id])

  const hasPermission = (code: string): boolean => {
    return permissions.has(code)
  }

  const hasAnyPermission = (codes: string[]): boolean => {
    return codes.some(code => permissions.has(code))
  }

  const hasAllPermissions = (codes: string[]): boolean => {
    return codes.every(code => permissions.has(code))
  }

  const getVisibleSections = (sections: Record<string, string>): Record<string, boolean> => {
    const result: Record<string, boolean> = {}
    for (const [section, requiredPerm] of Object.entries(sections)) {
      result[section] = permissions.has(requiredPerm)
    }
    return result
  }

  return {
    hasPermission,
    hasAnyPermission,
    hasAllPermissions,
    getVisibleSections,
    permissions: Array.from(permissions)
  }
}

/** Hook for managing device identity */
export function useDeviceIdentity() {
  const [initialized, setInitialized] = useState(false)
  const { getFingerprint, getMacAddress, isDeviceInitialized: checkInitialized } = useSecurity()

  useEffect(() => {
    if (!initialized && checkInitialized()) {
      setInitialized(true)
    }
  }, [initialized, checkInitialized])

  return { initialized, fingerprint: useSecurity().getFingerprint() }
}

/** Security hook */
useSecurity: () => ({
  getFingerprint,
  getMacAddress,
  isDeviceInitialized,
  initDeviceIdentity
}) = useAuth()

/** Hook for managing toast notifications */
export function useToast() {
  const [toasts, setToasts] = useState<Toast[]>([])

  const addToast = (toast: Toast) => {
    const id = crypto.randomUUID()
    setToasts(prev => [...prev, { ...toast, id }])
    
    // Auto-remove after duration
    setTimeout(() => {
      setToasts(prev => prev.filter(t => t.id !== id))
    }, toast.duration ?? 5000)
  }

  const removeToast = (id: string) => {
    setToasts(prev => prev.filter(t => t.id !== id))
  }

  return { toasts, addToast, removeToast }
}

interface Toast {
  id: string
  title: string
  description?: string
  variant?: 'default' | 'destructive' | 'secondary'
  duration?: number
  action?: {
    label: string
    onClick: () => void
  }
}

/** Hook for managing user settings */
export function useUserSettings() {
  const [settings, setSettings] = useState<Record<string, any>>({})

  useEffect(() => {
    try {
      const saved = localStorage.getItem('user_settings')
      if (saved) {
        setSettings(JSON.parse(saved))
      }
    } catch (e) {
      logger.error('User settings load error:', e)
    }
  }, [])

  useEffect(() => {
    try {
      localStorage.setItem('user_settings', JSON.stringify(settings))
    } catch (e) {
      logger.error('User settings save error:', e)
    }
  }, [settings])

  const updateSetting = (key: string, value: any) => {
    setSettings(prev => ({
      ...prev,
      [key]: value
    }))
  }

  const resetSettings = () => {
    setSettings({})
    try {
      localStorage.removeItem('user_settings')
    } catch (e) {
      logger.error('User settings reset error:', e)
    }
  }

  return { settings, updateSetting, resetSettings }
}