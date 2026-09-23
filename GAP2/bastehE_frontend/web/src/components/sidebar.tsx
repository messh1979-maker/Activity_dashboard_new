import React from 'react'
import { Link } from 'react-router-dom'
import { useAuth } from '../security/authProvider'
import { usePermissionCache } from '../hooks/usePermissionCache'

/** Sidebar navigation for the dashboard */
export const Sidebar: React.FC<{ user?: User }> = ({ user }) => {
  const { isAuthenticated } = useAuth()
  const { hasPermission } = usePermissionCache()
  const navigate = useNavigate()

  // Navigation items with permissions
  const navItems = [
    { key: 'dashboard', label: 'داشبورد', icon: 'Layout', requiredPerm: undefined },
    { key: 'goals', label: 'اهداف', icon: 'TrendingUp', requiredPerm: 'goal.view' },
    { key: 'calendar', label: 'تقویم', icon: 'Calendar', requiredPerm: 'calendar.view' },
    { key: 'inbox', label: 'کارتابل', icon: 'MessageSquare', requiredPerm: 'inbox.view' },
    { key: 'chat', label: 'چت', icon: 'MessageCircle', requiredPerm: 'chat.view' },
    { key: 'reports', label: 'گزارش‌ها', icon: 'BarChart3', requiredPerm: 'report.view' },
    { key: 'widgets', label: 'ویجت‌ها', icon: 'Widgets', requiredPerm: 'widgets.manage' },
    { key: 'group-manager', label: 'مدیریت گروه', icon: 'Users', requiredPerm: 'group.manage' },
    { key: 'profile', label: 'پروفایل', icon: 'User', requiredPerm: undefined },
    { key: 'settings', label: 'تنظیمات', icon: 'Settings', requiredPerm: 'settings.manage' },
  ]

  return (
    <nav className="rtl bg-white dark:bg-gray-900 h-screen w-64 shadow-lg border2 border-gray-200 dark:border-gray-700 flex-shrink-0">
      <div className="p-4 border-b border-gray-200 dark:border-gray-700">
        <h2 className="text-lg font-bold text-gray-900 dark:text-white">
          {user?.display_name || 'کاربر'}
        </h2>
        <p className="text-sm text-gray-500 dark:text-gray-400">
          {user?.username || ''}
        </p>
      </div>
      
      <ul className="mt-4 space-y-1 max-h-screen overflow-y-auto">
        {navItems.map((item) => {
          const isVisible = !item.requiredPerm || hasPermission(item.requiredPerm)
          
          if (!isVisible) return null
          
          const isActive = item.key === 'dashboard' // Simplified active check
          
          return (
            <li key={item.key} className={`transition-colors duration-200 ${
              isActive 
                ? 'bg-gray-100 dark:bg-gray-800' 
                : 'hover:bg-gray-50 dark:hover:bg-gray-800'}
              rounded-md px-3 py-2 flex items-center gap-3`}
            >
              <Link
                to={`/${item.key}`}
                className="flex items-center gap-2 text-sm text-gray-700 dark:text-gray-300 hover:text-primary transition-colors"
                onClick={() => navigate(`/${item.key}`)}
              >
                <svg className="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" d={item.icon} />
                </svg>
                <span>{item.label}</span>
              </Link>
            </li>
          )
        })}
      </ul>
      
      <div className="mt-6 p-3 border-t border-gray-200 dark:border-gray-700">
        <button
          onClick={() => {
            // Logout
            useAuth.getState().logout()
            navigate('/login')
          }
          className="w-full py-2 rounded-md bg-red-100 text-red-800 text-sm font-medium hover:bg-red-200 dark:bg-red-900 dark:hover:bg-red-200 transition-colors"
        >
          خروج
        </button>
      </div>
    </nav>
  )
}

/** User type import */
import type { User } from '../types'