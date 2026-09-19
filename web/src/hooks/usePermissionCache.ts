import { useEffect, useState } from 'react'
import { useAuth } from '../security/authProvider'
import { api } from '../api/client'
import { logger } from '../security/sanitize'

export function usePermissionCache() {
  const [permissions, setPermissions] = useState<Set<string>>(new Set())
  const { user } = useAuth()

  useEffect(() => {
    if (!user) return

    const loadPermissions = async () => {
      try {
        const response = await api.get('/rbac/permissions')
        const data = response.data
        
        if (data && Array.isArray(data.permissions)) {
          const permSet = new Set(data.permissions)
          setPermissions(permSet)
        }
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