import { useCallback, useEffect, useState } from 'react'
import { apiRef as api } from '../api/client'

const BASE = '/reporting/dashboard'

export interface DashStats {
  goals_active: number
  goals_completed: number
  goals_total: number
  tasks_open: number
  inbox_pending: number
  groups_count: number
  rooms_count: number
}

export interface DashGoal {
  id: string
  title: string
  description?: string | null
  status: string
  progress_pct: number
  due_date?: string | null
  created_at: string
}

export interface DashTask {
  id: string
  title: string
  status: string
  priority: string
  due_date?: string | null
  goal_title?: string | null
}

export interface DashInbox {
  id: string
  title: string
  message?: string | null
  item_type: string
  priority: string
  action_state: string
  created_at: string
  sender_name?: string | null
}

export interface DashGroup {
  id: string
  name: string
  is_manager: boolean
}

export interface DashboardSummary {
  stats: DashStats
  recent_goals: DashGoal[]
  open_tasks: DashTask[]
  pending_inbox: DashInbox[]
  my_groups: DashGroup[]
  my_rooms: { id: string; title: string; linked_type?: string | null }[]
}

const EMPTY: DashboardSummary = {
  stats: {
    goals_active: 0,
    goals_completed: 0,
    goals_total: 0,
    tasks_open: 0,
    inbox_pending: 0,
    groups_count: 0,
    rooms_count: 0,
  },
  recent_goals: [],
  open_tasks: [],
  pending_inbox: [],
  my_groups: [],
  my_rooms: [],
}

function unwrap<T>(res: any): T | null {
  const d = res?.data ?? res
  return (d?.data ?? d ?? null) as T | null
}

export function useDashboard() {
  const [summary, setSummary] = useState<DashboardSummary>(EMPTY)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const refresh = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await api.get(`${BASE}/summary`)
      const data = unwrap<DashboardSummary>(res)
      if (data) setSummary({ ...EMPTY, ...data })
      else setError('دریافت اطلاعات داشبورد ناموفق بود.')
    } catch {
      setError('ارتباط با سرور برقرار نشد.')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void refresh()
  }, [refresh])

  const createGoal = useCallback(
    async (title: string, description?: string) => {
      await api.post(`${BASE}/goals`, { title, description })
      await refresh()
    },
    [refresh],
  )

  const actOnInbox = useCallback(
    async (id: string, action: 'accepted' | 'rejected') => {
      await api.post(`${BASE}/inbox/${id}/act`, { action })
      await refresh()
    },
    [refresh],
  )

  return { summary, loading, error, refresh, createGoal, actOnInbox }
}
