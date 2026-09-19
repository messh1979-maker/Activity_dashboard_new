import React from 'react'
import { useQuery } from '@tanstack/react-query'
import { useAuth } from '../security/authProvider'
import { usePermissionCache } from '../hooks/usePermissionCache'
import { useWidgetSettings } from '../hooks/useWidgetSettings'
import ClockWidget from '../widgets/clock_widget'
import GoalsProgressWidget from '../widgets/dashboard/goals_progress_widget'
import QuickActionsWidget from '../widgets/dashboard/quick_actions_widget'
import {Sidebar} from '../components/sidebar'
import {useLayoutPersistence} from '../hooks/useLayoutPersistence'

/** Main dashboard layout with RTL support */
export const DashboardLayout: React.FC = () => {
  const { user, isAuthenticated } = useAuth()
  const { hasPermission } = usePermissionCache()
  const { savedLayouts, setLayout, resetLayout } = useLayoutPersistence(user?.id || '')
  const { widgets, updateWidget } = useWidgetSettings(user?.id || '')
  
  // Default layout configuration
  const [layoutConfig, setLayoutConfig] = React.useState({
    blocks: [
      { key: 'clock', x: 0, y: 0, w: 2, h: 2, config: {} },
      { key: 'goals', x: 2, y: 0, w: 6, h: 4, config: {} },
      { key: 'quick-actions', x: 8, y: 0, w: 4, h: 3, config: {} },
      { key: 'recent-activity', x: 0, y: 4, w: 12, h: 3, config: {} },
    ]
  })
  
  // Apply saved layout on mount
  React.useEffect(() => {
    if (savedLayouts && savedLayouts.layout) {
      setLayoutConfig(savedLayouts.layout)
    }
  }, [savedLayouts])
  
  return (
    <div className="rtl min-h-screen bg-gray-50 dark:bg-gray-900">
      <Sidebar user={user} />
      
      <main className="flex-1 p-6 overflow-x-auto">
        <header className="mb-6">
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
            {user?.display_name || 'سامانه مدیریت اهداف'}
          </h1>
          <p className="text-gray-600 dark:text-gray-300">
            خوش آمدید، {user?.display_name || ''}
          </p>
        </header>
        
        {/* Widget grid */}
        <div className="grid grid-cols-1 gap-6 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 xl:grid-cols-6">
          {/* Clock widget - always visible */}
          <div className="rtl">
            <ClockWidget
              cfg={layoutConfig.blocks.find(b => b.key === 'clock')?.config || {}}
              style={{ bg: '#1a202c', fg: '#edf2f7', font_family: 'Vazirmatn', font_size: 14 }}
              onSettingsChanged={(settings) => {
                // Save widget settings
                updateWidget('clock', settings)
              }}
            />
          </div>
          
          {/* Goals progress widget */}
          <GoalsProgressWidget
            userInfo={user}
            authState={{ isAuthenticated }}
            onProgressUpdate={(data) => {
              updateWidget('goals', data)
            }}
          />
          
          {/* Quick actions */}
          <QuickActionsWidget
            authState={{ isAuthenticated }}
            onActionTriggered={(action) => {
              // Handle quick action
              console.log('Action triggered:', action)
            }}
          />
          
          {/* Recent activity */}
          <div className="rtl rounded-lg border p-4 bg-white dark:bg-gray-800 shadow-sm">
            <h2 className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-4">
              فعالیت‌های اخیر
            </h2>
            <p className="text-muted-foreground text-sm">
              فعالیت‌های اخیر نمایش داده می‌شود هنا
            </p>
          </div>
        </div>
      </main>
    </div>
  )
}