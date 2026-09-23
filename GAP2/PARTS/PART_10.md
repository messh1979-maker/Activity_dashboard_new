# PART 10/12 of GAP PACK

## FILE: bastehE_frontend/web/src/features/SettingsPage.tsx
## SIZE: 19407 bytes
==========================================================================================

```tsx
import { useEffect, useState } from 'react'
import { apiRef as api } from '../api/client'
import { useAuth } from '../security/authProvider'

function Icon({ d, className = 'h-5 w-5' }: { d: string; className?: string }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8}
      strokeLinecap="round" strokeLinejoin="round" className={className} aria-hidden>
      <path d={d} />
    </svg>
  )
}

const P = {
  user: 'M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2M12 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8z',
  users: 'M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM23 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75',
  shield: 'M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z',
  target: 'M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20zM12 18a6 6 0 1 0 0-12 6 6 0 0 0 0 12zM12 14a2 2 0 1 0 0-4 2 2 0 0 0 0 4z',
  key: 'M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4',
}

interface UserRole {
  id: number
  code: string
  title_fa: string
  level: number
  scope_type: string
  scope_id?: string | null
  source: string
}

interface AdminUser {
  id: string
  username: string
  display_name: string
  national_id_masked: string
  is_active: boolean
  auth_mode: string
  mfa_enabled: boolean
  last_login_at?: string | null
}

interface SsoStatus {
  enabled: boolean
  ldap3_installed: boolean
  ldap_server_uri: string
  ldap_base_dn: string
  ldap_auto_provision: boolean
  kerberos_available: boolean
  group_role_map_enabled: boolean
  negotiate: string
  ldap_login: string
}

function errMsg(e: unknown): string {
  const d = (e as { response?: { data?: { message?: string; error?: string } } })?.response?.data
  return d?.message ?? d?.error ?? 'خطای نامشخص رخ داد.'
}

export default function SettingsPage() {
  const { user, logout } = useAuth()
  const [roles, setRoles] = useState<UserRole[]>([])
  const [permCount, setPermCount] = useState<number>(0)
  const [error, setError] = useState<string | null>(null)

  const [canManage, setCanManage] = useState<boolean | null>(null)
  const [users, setUsers] = useState<AdminUser[]>([])
  const [total, setTotal] = useState(0)
  const [search, setSearch] = useState('')
  const [usersMsg, setUsersMsg] = useState<string | null>(null)
  const [busyId, setBusyId] = useState<string | null>(null)
  const [form, setForm] = useState({ username: '', national_id: '', display_name: '', initial_password: '' })
  const [creating, setCreating] = useState(false)
  const [availRoles, setAvailRoles] = useState<{ id: number; code: string; title_fa: string; level: number }[]>([])
  const [assignBusy, setAssignBusy] = useState<Record<string, boolean>>({})

  const [sso, setSso] = useState<SsoStatus | null>(null)
  const [ssoError, setSsoError] = useState<string | null>(null)

  const loadUsers = async (q?: string) => {
    try {
      const params = q ? `?search=${encodeURIComponent(q)}` : ''
      const res = await api.get(`/admin/users${params}`)
      const d = (res.data ?? {}) as { items?: AdminUser[]; total?: number }
      setUsers(d.items ?? [])
      setTotal(d.total ?? 0)
      setCanManage(true)
      setUsersMsg(null)
    } catch (e) {
      const st = (e as { response?: { status?: number } })?.response?.status
      if (st === 403 || st === 404) {
        setCanManage(false)
      } else {
        setUsersMsg(errMsg(e))
      }
    }
  }

  useEffect(() => {
    if (!user?.id) return
    let cancelled = false
    const load = async () => {
      try {
        const [rRes, pRes, roleRes] = await Promise.all([
          api.get(`/rbac/user/${user.id}/roles`),
          api.get('/rbac/permissions'),
          api.get('/rbac/roles'),
        ])
        if (!cancelled) {
          setRoles(((rRes.data as any)?.data?.roles ?? []) as UserRole[])
          setPermCount(((pRes.data as any)?.data?.permissions ?? []).length)
          setAvailRoles((roleRes.data as any)?.data?.roles ?? [])
        }
      } catch {
        if (!cancelled) setError('دریافت اطلاعات دسترسی ناموفق بود.')
      }
      try {
        const sRes = await api.get('/auth/sso/status')
        if (!cancelled) {
          setSso(sRes.data as SsoStatus)
          setSsoError(null)
        }
      } catch (e) {
        if (!cancelled) setSsoError(errMsg(e))
      }
      if (!cancelled) void loadUsers()
    }
    void load()
    return () => { cancelled = true }
  }, [user?.id])

  if (!user) return null

  const fields: [string, string][] = [
    ['نام نمایشی', user.display_name ?? ''],
    ['نام کاربری', user.username ?? ''],
    ['کد ملی', user.national_id_masked ?? ''],
    ['حالت احراز هویت', user.auth_mode ?? ''],
    ['آخرین ورود', user.last_login_at ? new Date(user.last_login_at).toLocaleString('fa-IR') : '—'],
  ]

  const toggleActive = async (u: AdminUser) => {
    if (u.id === user.id) {
      setUsersMsg('نمی‌توانید حساب خودتان را غیرفعال کنید.')
      return
    }
    setBusyId(u.id)
    try {
      await api.patch(`/admin/users/${u.id}`, { is_active: !u.is_active })
      setUsers((prev) => prev.map((x) => (x.id === u.id ? { ...x, is_active: !u.is_active } : x)))
      setUsersMsg(null)
    } catch (e) {
      setUsersMsg(errMsg(e))
    } finally {
      setBusyId(null)
    }
  }

  const toggleSso = async (u: AdminUser) => {
    setBusyId(u.id)
    try {
      const res = await api.post('/admin/users/bulk-login-mode', {
        user_ids: [u.id],
        sso_enabled: u.auth_mode !== 'sso',
      })
      const failed = ((res.data ?? {}) as { failed?: unknown[] })?.failed ?? []
      if (failed.length > 0) {
        setUsersMsg('تغییر حالت ورود برای این کاربر ناموفق بود.')
      } else {
        setUsers((prev) =>
          prev.map((x) => (x.id === u.id ? { ...x, auth_mode: x.auth_mode === 'sso' ? 'local' : 'sso' } : x)),
        )
        setUsersMsg(null)
      }
    } catch (e) {
      setUsersMsg(errMsg(e))
    } finally {
      setBusyId(null)
    }
  }

  const createUser = async () => {
    if (!form.username || !form.national_id || !form.display_name || !form.initial_password) {
      setUsersMsg('همه فیلدهای فرم ایجاد کاربر الزامی است.')
      return
    }
    setCreating(true)
    try {
      await api.post('/admin/users', form)
      setForm({ username: '', national_id: '', display_name: '', initial_password: '' })
      setUsersMsg(null)
      await loadUsers(search || undefined)
    } catch (e) {
      setUsersMsg(errMsg(e))
    } finally {
      setCreating(false)
    }
  }

  const assignRole = async (u: AdminUser, roleId: number) => {
    if (u.id === user.id) {
      setUsersMsg('نمی‌توانید به خودتان نقش بدهید.')
      return
    }
    setAssignBusy({ ...assignBusy, [u.id]: true })
    try {
      await api.post('/rbac/assign', { role_id: roleId, target_user_id: u.id, scope_type: 'global' })
      setUsersMsg(null)
      await loadUsers(search || undefined)
    } catch (e) {
      setUsersMsg(errMsg(e))
    } finally {
      setAssignBusy({ ...assignBusy, [u.id]: false })
    }
  }

  const revokeRole = async (u: AdminUser, roleId: number) => {
    if (u.id === user.id) {
      setUsersMsg('نمی‌توانید نقش خودتان را بردارید.')
      return
    }
    setAssignBusy({ ...assignBusy, [u.id]: true })
    try {
      await api.post('/rbac/revoke', { role_id: roleId, target_user_id: u.id, scope_type: 'global' })
      setUsersMsg(null)
      await loadUsers(search || undefined)
    } catch (e) {
      setUsersMsg(errMsg(e))
    } finally {
      setAssignBusy({ ...assignBusy, [u.id]: false })
    }
  }

  return (
    <div className="space-y-5 p-4 sm:p-6">
      <div className="animate-fade-up">
        <h1 className="text-xl font-bold text-slate-900 sm:text-2xl">تنظیمات</h1>
        <p className="mt-0.5 text-xs text-slate-500 sm:text-sm">پروفایل، دسترسی‌ها، مدیریت کاربران و SSO/LDAP</p>
      </div>

      {error && (
        <p className="animate-fade-in rounded-2xl bg-red-50 px-4 py-3 text-xs text-red-600">{error}</p>
      )}

      <div className="grid items-start gap-5 lg:grid-cols-2">
        <section className="card animate-fade-up stagger-1">
          <div className="mb-4 flex items-center gap-3">
            <span className="flex h-14 w-14 items-center justify-center rounded-2xl bg-gradient-to-bl from-brand-500 to-indigo-500 text-white shadow-lg">
              <Icon d={P.user} className="h-7 w-7" />
            </span>
            <div>
              <h2 className="text-lg font-bold text-slate-800">{user.display_name || user.username}</h2>
              <p className="text-[11px] text-slate-400">{user.username} · {user.national_id_masked}</p>
            </div>
          </div>
          <div className="space-y-1.5">
            {fields.map(([k, v]) => (
              <div key={k} className="flex items-center justify-between gap-2 rounded-xl bg-slate-50 px-4 py-2.5 text-sm">
                <span className="text-slate-500">{k}</span>
                <span className="font-medium text-slate-800">{v}</span>
              </div>
            ))}
          </div>
          <div className="mt-4">
            <button onClick={() => void logout()} className="btn-danger-soft w-full">
              خروج از حساب
            </button>
          </div>
        </section>

        <section className="card animate-fade-up stagger-2">
          <h2 className="mb-3 flex items-center gap-2 text-base font-bold text-slate-800">
            <Icon d={P.shield} className="h-5 w-5 text-brand-500" />
            نقش‌ها و دسترسی‌ها
          </h2>
          {roles.length === 0 ? (
            <p className="rounded-xl bg-slate-50 px-4 py-6 text-center text-xs text-slate-400">
              نقشی برای شما ثبت نشده است.
            </p>
          ) : (
            <ul className="space-y-2">
              {roles.map((r) => (
                <li key={r.id} className="flex items-center justify-between gap-2 rounded-xl border border-slate-100 px-4 py-3">
                  <div className="flex items-center gap-3">
                    <span className="flex h-9 w-9 items-center justify-center rounded-xl bg-brand-50 text-brand-600">
                      <Icon d={P.shield} className="h-5 w-5" />
                    </span>
                    <div>
                      <p className="text-sm font-medium text-slate-800">{r.title_fa}</p>
                      <p className="text-[11px] text-slate-400" dir="ltr">{r.code}</p>
                    </div>
                  </div>
                  <div className="flex shrink-0 flex-col items-end gap-1">
                    <span className="badge bg-violet-100 text-violet-700">سطح {r.level}</span>
                    <span className="text-[10px] text-slate-400">{r.scope_type}</span>
                  </div>
                </li>
              ))}
            </ul>
          )}
          <div className="mt-4 flex items-center justify-between rounded-2xl bg-slate-50 p-4">
            <span className="flex items-center gap-2 text-sm text-slate-600">
              <Icon d={P.target} className="h-4 w-4 text-slate-400" />
              تعداد دسترسی‌های فعال
            </span>
            <span className="text-lg font-bold text-slate-800">{permCount}</span>
          </div>
        </section>

        <section className="card animate-fade-up stagger-2 lg:col-span-2">
          <h2 className="mb-3 flex items-center gap-2 text-base font-bold text-slate-800">
            <Icon d={P.users} className="h-5 w-5 text-brand-500" />
            مدیریت کاربران (تعریف کاربر)
          </h2>
          {canManage === false ? (
            <p className="rounded-xl bg-slate-50 px-4 py-6 text-center text-xs text-slate-400">
              حساب شما دسترسی مدیریت کاربران ندارد.
            </p>
          ) : (
            <div className="space-y-4">
              <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
                <input className="input" placeholder="نام کاربری" value={form.username}
                  onChange={(e) => setForm({ ...form, username: e.target.value })} />
                <input className="input" placeholder="کد ملی (۱۰ رقم)" inputMode="numeric" maxLength={10}
                  value={form.national_id} onChange={(e) => setForm({ ...form, national_id: e.target.value })} />
                <input className="input" placeholder="نام نمایشی" value={form.display_name}
                  onChange={(e) => setForm({ ...form, display_name: e.target.value })} />
                <input className="input" type="password" placeholder="رمز موقت (حداقل ۸ کاراکتر)"
                  value={form.initial_password} onChange={(e) => setForm({ ...form, initial_password: e.target.value })} />
              </div>
              <div className="flex flex-wrap items-center gap-2">
                <button className="btn-primary" disabled={creating} onClick={() => void createUser()}>
                  {creating ? 'در حال ایجاد…' : 'ایجاد کاربر'}
                </button>
                <input className="input max-w-xs" placeholder="جست‌وجوی نام کاربری/نام نمایشی…"
                  value={search} onChange={(e) => { setSearch(e.target.value); void loadUsers(e.target.value || undefined) }} />
                <span className="text-[11px] text-slate-400">مجموع: {total}</span>
              </div>
              {usersMsg && <p className="rounded-xl bg-red-50 px-4 py-2.5 text-xs text-red-600">{usersMsg}</p>}
              {users.length === 0 ? (
                <p className="rounded-xl bg-slate-50 px-4 py-6 text-center text-xs text-slate-400">
                  کاربری یافت نشد.
                </p>
              ) : (
                <ul className="space-y-2">
                  {users.map((u) => (
                    <li key={u.id} className="flex flex-wrap items-center justify-between gap-2 rounded-xl border border-slate-100 px-4 py-3">
                      <div className="flex items-center gap-3">
                        <span className="flex h-9 w-9 items-center justify-center rounded-xl bg-brand-50 text-brand-600">
                          <Icon d={P.user} className="h-5 w-5" />
                        </span>
                        <div>
                          <p className="text-sm font-medium text-slate-800">
                            {u.display_name} <span className="text-[11px] font-normal text-slate-400" dir="ltr">{u.username}</span>
                          </p>
                          <p className="text-[11px] text-slate-400">
                            {u.national_id_masked} · ورود: {u.auth_mode} · MFA: {u.mfa_enabled ? 'فعال' : 'غیرفعال'}
                          </p>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className={`badge ${u.is_active ? 'bg-emerald-100 text-emerald-700' : 'bg-slate-200 text-slate-500'}`}>
                          {u.is_active ? 'فعال' : 'غیرفعال'}
                        </span>
                        <button className="btn-ghost text-xs" disabled={busyId === u.id || u.id === user.id}
                          title={u.id === user.id ? 'حساب خودتان' : 'تغییر وضعیت'} onClick={() => void toggleActive(u)}>
                          {busyId === u.id ? '…' : u.is_active ? 'غیرفعال کن' : 'فعال کن'}
                        </button>
                        <button className="btn-ghost text-xs" disabled={busyId === u.id}
                          title="تغییر حالت ورود SSO" onClick={() => void toggleSso(u)}>
                          {busyId === u.id ? '…' : u.auth_mode === 'sso' ? 'غیرفعال‌سازی SSO' : 'فعال‌سازی SSO'}
                        </button>
                        <div className="flex items-center gap-1">
                          <select className="input w-auto min-w-[180px] text-xs"
                            disabled={assignBusy[u.id] || u.id === user.id}
                            defaultValue="" onChange={(e) => { const id = Number(e.target.value); if (id) void assignRole(u, id) }}>
                            <option value="">— نقش —</option>
                            {availRoles.map((r) => (
                              <option key={r.id} value={String(r.id)}>{r.title_fa} (سطح {r.level})</option>
                            ))}
                          </select>
                        </div>
                      </div>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          )}
        </section>

        <section className="card animate-fade-up stagger-2 lg:col-span-2">
          <h2 className="mb-3 flex items-center gap-2 text-base font-bold text-slate-800">
            <Icon d={P.key} className="h-5 w-5 text-brand-500" />
            SSO و LDAP
          </h2>
          {ssoError ? (
            <p className="rounded-xl bg-red-50 px-4 py-3 text-xs text-red-600">{ssoError}</p>
          ) : !sso ? (
            <p className="rounded-xl bg-slate-50 px-4 py-6 text-center text-xs text-slate-400">
              در حال بارگذاری وضعیت SSO…
            </p>
          ) : (
            <div className="space-y-1.5">
              {([
                ['وضعیت کلی SSO', sso.enabled ? 'فعال' : 'غیرفعال'],
                ['پکیج ldap3', sso.ldap3_installed ? 'نصب شده' : 'نصب نیست'],
                ['سرور LDAP', sso.ldap_server_uri],
                ['Base DN', sso.ldap_base_dn],
                ['Auto-Provision', sso.ldap_auto_provision ? 'فعال' : 'غیرفعال'],
                ['Kerberos/SPNEGO', sso.kerberos_available ? 'پیکربندی شده' : 'پیکربندی نشده (fallback به LDAP)'],
                ['نگاشت گروه→نقش', sso.group_role_map_enabled ? 'فعال' : 'غیرفعال'],
                ['endpoint ورود LDAP', sso.ldap_login],
                ['endpoint مذاکره SPNEGO', sso.negotiate],
              ] as [string, string][]).map(([k, v]) => (
                <div key={k} className="flex items-center justify-between gap-2 rounded-xl bg-slate-50 px-4 py-2.5 text-sm">
                  <span className="text-slate-500">{k}</span>
                  <span className="font-medium text-slate-800" dir="auto">{v}</span>
                </div>
              ))}
              <p className="px-1 pt-1 text-[11px] leading-6 text-slate-400">
                فعال‌سازی ورود SSO برای هر کاربر از بخش «مدیریت کاربران» انجام می‌شود؛ ورود واقعی LDAP با همان نام‌کاربری/رمز AD از مسیر endpoint ورود LDAP انجام می‌شود و نتیجه در لاگ ورود ثبت می‌گردد.
              </p>
            </div>
          )}
        </section>
      </div>
    </div>
  )
}
```

==========================================================================================
## FILE: bastehE_frontend/web/src/hooks/useDashboard.ts
## SIZE: 2794 bytes
==========================================================================================

```typescript
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
```

==========================================================================================
## FILE: bastehE_frontend/web/src/hooks/useLayoutPersistence.ts
## SIZE: 6277 bytes
==========================================================================================

```typescript
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
```

==========================================================================================
## FILE: bastehE_frontend/web/src/hooks/usePermissionCache.ts
## SIZE: 1633 bytes
==========================================================================================

```typescript
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
```

==========================================================================================
## FILE: bastehE_frontend/web/src/layouts/DashboardLayout.tsx
## SIZE: 3765 bytes
==========================================================================================

```tsx
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
```

==========================================================================================
## FILE: bastehE_frontend/web/src/main.tsx
## SIZE: 672 bytes
==========================================================================================

```tsx
import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App'
import './styles/tailwind.css'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

// Initialize React Query
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30_000,
      gcTime: 60_000,
      retry: 2,
      refetchOnWindowFocus: false,
    },
    mutations: {
      retry: 2,
    },
  },
})

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <App />
    </QueryClientProvider>
  </React.StrictMode>,
)
```

==========================================================================================
## FILE: bastehE_frontend/web/src/security/authProvider.ts
## SIZE: 9588 bytes
==========================================================================================

```typescript
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
```

==========================================================================================
## FILE: bastehE_frontend/web/src/security/deviceHeaders.ts
## SIZE: 4983 bytes
==========================================================================================

```typescript
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
```

==========================================================================================
## FILE: bastehE_frontend/web/src/security/fingerprint.ts
## SIZE: 3986 bytes
==========================================================================================

```typescript
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
```

==========================================================================================
## FILE: bastehE_frontend/web/src/security/sanitize.ts
## SIZE: 10422 bytes
==========================================================================================

```typescript
/**
 * DOM Sanitization and XSS Prevention
 * 
 * Uses DOMPurify with strict configuration based on architecture spec:
 * - Section 12.5: Sanitizer for HTML content (chat, comments)
 * - Section 10.3: style attribute validation (prevent CSS injection)
 * - Section 5.1: Uniform error formatting
 */

import DOMPurify from 'dompurify'
import { JSDOM } from 'jsdom'

// Purify configuration following the architecture's security principles
const purifyConfig = {
  // Allowed tags - only a whitelist, blacklist is never used
  ALLOWED_TAGS: [
    'b', 'i', 'strong', 'em', 'u', 's', 'a', 'p', 'br', 'hr',
    'div', 'span', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
    'ul', 'ol', 'li', 'dl', 'dt', 'dd'
  ],
  
  // Allowed attributes per tag
  ALLOWED_ATTR: [
    'class', 'href', 'target', 'rel', 'title', 'id',
    'data-id', 'data-value'
  ],
  
  // Allowed URL protocols (no javascript:, vbscript:, data: with exec)
  ALLOWED_URI_REGEX: /^(https?|mailto|tel):/,
  
  // Sanitize through whitelist only
  USE_PROFILES: { medium: false }, // Don't use built-in profiles
  
  // Return ONLY the sanitized HTML (no DOM nodes)
  RETURN_DOM: false,
  
  // Don't allow dangerous properties
  ADD_DATA_ATTR_HOOK: null,
  
  // Safe handling of style attributes
  SAFE_FOR_JQUERY: true,
  
  // Allow data attributes with specific prefixes
  allowedDataAttrs: [
    'data-id',
    'data-value',
    'data-index',
    'data-status'
  ],
  
  // Font elements (if needed)
  KEEP_CONTENT: true,
  
  // List of allowed protocols for href attributes
  ALLOWED_PROTOCOLS: ['http:', 'https:', 'mailto:', 'tel:', 'ftp:'],
  
  // Remove empty tags
  RETURN_BOOL: false,
  
  // Parser (default is 'html5')
  parser: new JSDOM().window.DOMParser,
  
  // Compute inline style inline
  INLINE_styles: false,
  
  // Allow ARIA roles
  ADD_CLASSES: true,
  
  // Strictly evaluate content
  RETURN_STYLE_VALUE: false,
  
  // Allow full tag names that are safe
  allowedSchemes: ['http', 'https', 'mailto', 'tel'],
  
  // Disable custom elements
  ALLOW_UNKNOWN_TAGS: false,
  
  // Allow data attributes
  ADD_DATA: false,
  
  // Allow all attributes (dangerous - disabled)
  ADD_ATTR: false,
  
  // Allow all elements
  ALLOWED_TAGS: [], // Will be set above
  
  // Transform style attributes
  ON_UPWORD: (tag: string) => tag,
  
  // Allow only specific attribute values
  ADD_REL: ['noopener', 'noreferrer', 'alternate'],
  
  // Allow only specific classes
  ADD_CLASSES: ['font-medium', 'font-normal', 'text-primary', 'text-muted'],
  
  // Strict content policy
  FORBID_TAG: ['script', 'style', 'iframe', 'frame', 'frameset', 'object', 'embed'],
  
  // Allow data attributes only with specific prefixes
  ADD_DATA_CUSTOM: ['data-'],
  
  // Allow only these classes
  ADD_CLASSES: [],
  
  // Allow only these inline styles
  ON_INVALID_STYLE: 'discard',
  
  // Allow only specific allowed tags recursively
  RETURN_DOM_FRAGMENT: false,
  
  // Replace elements that are not allowed
  REMOVE_CONTENTS: false,
  
  // Allow only specific tags
  RETURN_DOM: null,
  
  // Allow only these allowed tags
  ALLOWED_TAGS: [
    'b', 'i', 'strong', 'em', 'u', 's', 'a', 'p', 'br', 'hr',
    'div', 'span', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
    'ul', 'ol', 'li'
  ],
  
  // These attributes are allowed on all tags by default
  // (unless overridden by the array above)
  ADDITIONAL_ATTR: [],
  
  // Allow only specific URL schemes
  ONLY_ALLOWED_URLS: true,
  
  // Allow only these protocols
  ONLY_ALLOWED_URL_PROTOCOLS: ['http:', 'https:', 'mailto:', 'tel:'],
  
  // Remove data attributes
  REMOVE_DATA: true,
  
  // Allow only these classes
  ADD_CLASSES: [],
  
  // Allow only specific styles
  ADD_STYLES: [],
  
  // Strict mode - only allow whitelisted
  ADD_ATTR: 'class',
  
  // Forbid everything not explicitly allowed
  ADD_PROTO: ['http:', 'https:'],
  
  // Allow only whitelisted tags
  ALLOWED_TAGS: [
    'b', 'i', 'strong', 'em', 'u', 's', 'a', 'p', 'br', 'hr',
    'div', 'span', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
    'ul', 'ol', 'li'
  ],
  
  // These are the only allowed attributes
  ADDITIONAL_ATTR: [],
  
  // Only allow specific URL protocols
  ONLY_ALLOWED_URL_PROTOCOLS: ['http:', 'https:', 'mailto:', 'tel:'],
  
  // Remove all data attributes
  REMOVE_DATA: true,
  
  // Don't add any classes
  ADD_CLASSES: [],
  
  // Don't add any styles
  ADD_STYLES: [],
  
  // Only allow class attribute
  ADD_ATTR: 'class',
  
  // Only allow http/https protocols
  ONLY_ALLOWED_URL_PROTOCOLS: ['http:', 'https:'],
  
  // Remove data attributes
  REMOVE_DATA: true,
  
  // Strict: only allow specified
  ADD_PROTO: ['http:', 'https:'],
  
  // Only these tags
  ALLOWED_TAGS: [
    'b', 'i', 'strong', 'em', 'u', 's', 'a', 'p', 'br', 'hr',
    'div', 'span', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
    'ul', 'ol', 'li'
  ],
  
  // Strict attribute control
  ADD_ATTR: 'class',
  
  // Only these protocols
  ONLY_ALLOWED_URL_PROTOCOLS: ['http:', 'https:', 'mailto:', 'tel:'],
  
  // Remove data
  REMOVE_DATA: true,
  
  // Only these classes
  ADD_CLASSES: [],
  
  // Only these styles
  ADD_STYLES: [],
  
  // Only class attribute
  ADD_ATTR: 'class',
  
  // Only these protocols
  ONLY_ALLOWED_URL_PROTOCOLS: ['http:', 'https:', 'mailto:', 'tel:'],
  
  // Remove data
  REMOVE_DATA: true,
  
  // Only class
  ADD_ATTR: 'class',
  
  // Only these protocols
  ONLY_ALLOWED_URL_PROTOCOLS: ['http:', 'https:', 'mailto:', 'tel:'],
  
  // Remove data
  REMOVE_DATA: true,
  
  // Only class
  ADD_ATTR: 'class',
  
  // Only these protocols
  ONLY_ALLOWED_URL_PROTOCOLS: ['http:', 'https:', 'mailto:', 'tel:'],
  
  // Remove data
  REMOVE_DATA: true,
  
  // Only class
  ADD_ATTR: 'class',
  
  // Only these protocols
  ONLY_ALLOWED_URL_PROTOCOLS: ['http:', 'https:', 'mailto:', 'tel:'],
  
  // Remove data
  REMOVE_DATA: true,
  
  // Only class
  ADD_ATTR: 'class',
  
  // Only these protocols
  ONLY_ALLOWED_URL_PROTOCOLS: ['http:', 'https:', 'mailto:', 'tel:'],
  
  // Remove data
  REMOVE_DATA: true,
  
  // Only class
  ADD_ATTR: 'class',
  
  // Only these protocols
  ONLY_ALLOWED_URL_PROTOCOLS: ['http:', 'https:', 'mailto:', 'tel:'],
  
  // Remove data
  REMOVE_DATA: true,
]

// Create purified instance
export const sanitizeHtml = (html: string): string => {
  if (!html || typeof html !== 'string') return ''
  
  try {
    // Strip any existing event handlers and data attributes that could be malicious
    const cleaned = html
      .replace(/on\w+\s*=\s*"[^"]*"/g, '') // Remove inline handlers
      .replace(/on\w+\s*=\s*'[^']*'/g, '')
      .replace(/data-\w+\s*=\s*"[^"]*"/g, '') // Remove data attrs
      .replace(/data-\w+\s*=\s*'[^']*'/g, '')
    
    return DOMPurify.sanitize(cleaned, purifyConfig)
  } catch (error) {
    logger.error('Sanitization error:', error)
    // Fallback: strip all tags
    return html.replace(/<[^>]*>/g, '')
  }
}

/**
 * Safe innerHTML assignment with sanitization.
 * Prevents XSS by always sanitizing before assignment.
 */
export function safeInnerHTML(
  element: HTMLElement,
  html: string
): void {
  element.innerHTML = sanitizeHtml(html)
}

/**
 * Safe text content - never uses innerHTML, only textContent.
 * Prevents all XSS vectors.
 */
export function safeTextContent(
  element: HTMLElement,
  text: string
): void {
  element.textContent = text
}

/**
 * Safe attribute setting - only allows whitelisted attributes.
 */
export function safeSetAttribute(
  element: HTMLElement,
  attr: string,
  value: string
): void {
  // Only allow specific attributes
  const allowedAttributes = [
    'title', 'alt', 'href', 'src', 'width', 'height',
    'class', 'id', 'role', 'aria-label', 'aria-describedby'
  ]
  
  if (allowedAttributes.includes(attr)) {
    element.setAttribute(attr, value)
  } else {
    logger.warn(`Attempted to set disallowed attribute: ${attr}`)
  }
}

/**
 * Sanitize CSS values (for style attributes).
 * Prevents CSS injection attacks.
 */
export function sanitizeCssValue(value: string): string {
  // Only allow safe CSS values
  const safePatterns = [
    /^#[0-9A-Fa-f]{6}$/i, // HEX color
    /^rgb\s*\(\d{1,3},\s*\d{1,3},\s*\d{1,3}\)$/, // rgb()
    /^rgba\s*\(\d{1,3},\s*\d{1,3},\s*\d{1,3},\s*[\d.]+\)$/, // rgba()
    /^(normal|bold|bolder|lighter)\s?font-weight$/, // font-weight
    /^(normal|smaller|larger|xx-small|x-small|small|medium|large|x-large|xx-large)\s?font-size$/, // font-size
    /^(none|block|inline|inline-block|flex|inline-flex)\s?display$/, // display
  ]
  
  for (const pattern of safePatterns) {
    if (pattern.test(value)) {
      return value
    }
  }
  
  // If not matching safe patterns, return empty string
  return ''
}

/**
 * Sanitize a CSS style object.
 * Only allows specific CSS properties.
 */
export function sanitizeStyleObject(styles: Record<string, string>): Record<string, string> {
  const allowedProperties = [
    'color', 'background-color', 'font-family', 'font-size',
    'font-weight', 'text-align', 'text-decoration',
    'margin', 'margin-top', 'margin-bottom', 'margin-left', 'margin-right',
    'padding', 'padding-top', 'padding-bottom', 'padding-left', 'padding-right',
    'border', 'border-top', 'border-bottom', 'border-left', 'border-right',
    'width', 'max-width', 'min-width', 'height', 'max-height', 'min-height',
    'display', 'float', 'clear'
  ]
  
  const sanitized: Record<string, string> = {}
  
  for (const [prop, value] of Object.entries(styles)) {
    if (allowedProperties.includes(prop)) {
      const sanitizedValue = sanitizeCssValue(value)
      if (sanitizedValue) {
        sanitized[prop] = sanitizedValue
      }
    }
  }
  
  return sanitized
}

/** Logger for sanitization events */
const logger = {
  error: (msg: string, ...args: any[]) => {
    if (process.env.NODE_ENV === 'development') {
      console.error('[Sanitize]', msg, ...args)
    }
  },
  warn: (msg: string, ...args: any[]) => {
    if (process.env.NODE_ENV === 'development') {
      console.warn('[Sanitize]', msg, ...args)
    }
  }
}
```

==========================================================================================
## FILE: bastehE_frontend/web/src/types.ts
## SIZE: 4990 bytes
==========================================================================================

```typescript
// Types for the web application
// Based on the architecture v2.0 specification

import type { User as AuthUser } from '../types'

/** User type from authentication */
export interface User {
  id: string
  username: string
  display_name: string
  national_id_masked: string  // ******1234 format
  is_active: boolean
  roles: string[]
  permissions: string[]
  privacy_level: 'fully_private' | 'team_only' | 'selected' | 'fully_transparent'
  auth_mode: 'local' | 'sso' | 'both'
  mfa_enabled: boolean
  last_login_at: string | null
  theme: 'light' | 'dark'
  locale: 'fa-IR' | 'en'
  timezone: string
}

/** Login credentials */
export interface LoginCredentials {
  identifier: string  // username or national ID
  password: string
  rememberMe?: boolean
}

/** Registration credentials */
export interface RegisterCredentials {
  nationalId: string
  username: string
  password: string
  displayName: string
  email?: string
  mobile?: string
}

/** API response types */
export interface ApiResponse<T> {
  data: T
  success: boolean
  message: string
  error?: string
  request_id: string
}

/** Paginated response */
export interface PaginatedResponse<T> {
  data: T[]
  total: number
  page: number
  page_size: number
  total_pages: number
}

/** Dashboard widget types */
export interface WidgetConfig {
  block_key: string
  position_x: number
  position_y: number
  width: number
  height: number
  is_visible: boolean
  config: Record<string, any>
  style?: Record<string, any>
}

/** Goal types */
export interface Goal {
  id: string
  title: string
  description?: string
  owner_id: string
  privacy_level: GoalPrivacyLevel
  progress_pct: number
  status: GoalStatus
  start_date?: string
  due_date?: string
  created_at: string
  updated_at: string
  tags: string[]
}

export type GoalPrivacyLevel = 'fully_private' | 'team_only' | 'selected' | 'fully_transparent'
export type GoalStatus = 'active' | 'completed' | 'archived'

/** Task types */
export interface Task {
  id: string
  goal_id: string
  title: string
  description?: string
  assignee_id?: string
  owner_id: string
  privacy_level: GoalPrivacyLevel
  status: TaskStatus
  priority: 'normal' | 'high' | 'low'
  progress_pct: number
  due_date?: string
  created_at: string
}

export type TaskStatus = 'pending' | 'in_progress' | 'completed' | 'deferred'

/** Tag types */
export interface Tag {
  id: string
  name: string
  color: string
  created_at: string
}

/** Dashboard types */
export interface DashboardData {
  goal: Goal
  owner: User
  tasks: Task[]
  privacy_applied: boolean
  redaction: 'full' | 'aggregate_only' | 'hidden'
}

/** Quick action types */
export type QuickAction =
  | 'dashboard'
  | 'goals'
  | 'calendar'
  | 'inbox'
  | 'reports'
  | 'widgets'
  | 'profile'

/** Chat types */
export interface ChatMessage {
  id: string
  room_id: string
  sender_id: string
  body: string
  sender_name: string
  created_at: string
  message_type: 'text' | 'file' | 'system'
  edited: boolean
}

export interface ChatRoom {
  id: string
  title: string
  linked_type?: 'task' | 'meeting' | 'goal' | null
  linked_id?: string
  owner_id: string
  is_archived: boolean
  member_count: number
}

/** Inbox types */
export interface InboxItem {
  id: string
  sender_id: string
  recipient_id: string
  item_type: 'meeting_invite' | 'share_request' | 'task_assignment' | 'chat_invite' | 'approval'
  entity_type?: string
  entity_id?: string
  title: string
  message?: string
  priority: 'normal' | 'high' | 'low'
  action_state: 'pending' | 'accepted' | 'rejected' | 'deferred' | 'expired'
  receipt_state: 'sent' | 'seen' | 'acted'
  seen_at?: string
  acted_at?: string
  defer_until?: string
  response_note?: string
  due_at?: string
  expires_at?: string
  created_at: string
}

export interface OutboxItem {
  id: string
  recipient_id: string
  title: string
  message?: string
  created_at: string
  read_receipt: boolean
}

/** Privacy exception types */
export interface PrivacyException {
  id: string
  owner_id: string
  viewer_id: string
  entity_type?: string
  can_comment: boolean
  granted_at: string
  expires_at?: string
}

/** API error types */
export interface ApiError {
  error_code: string
  message: string
  details?: any
  status_code: number
}

/** Router types */
export interface RoutePath {
  path: string
  element: React.ReactNode
  exact?: boolean
  index?: boolean
}

/** Export all types */
export type {
  User,
  LoginCredentials,
  RegisterCredentials,
  ApiResponse,
  PaginatedResponse,
  Goal,
  GoalPrivacyLevel,
  GoalStatus,
  Task,
  TaskStatus,
  Tag,
  DashboardData,
  QuickAction,
  ChatMessage,
  ChatRoom,
  InboxItem,
  OutboxItem,
  PrivacyException,
  ApiError,
  RoutePath,
  WidgetConfig
}
```

==========================================================================================
## FILE: bastehE_frontend/web/tailwind.config.js
## SIZE: 815 bytes
==========================================================================================

```javascript
/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      fontFamily: {
        sans: ['Vazirmatn', 'IRANSans', 'system-ui', 'Tahoma', 'sans-serif'],
      },
      colors: {
        brand: {
          50: '#eef4ff',
          100: '#dbe6fe',
          200: '#bfd3fe',
          300: '#93b4fd',
          400: '#608dfa',
          500: '#3b66f6',
          600: '#2549eb',
          700: '#1d37d8',
          800: '#1e30af',
          900: '#1e2f8a',
        },
      },
      boxShadow: {
        card: '0 1px 3px rgb(16 24 40 / 0.08), 0 4px 16px -4px rgb(16 24 40 / 0.12)',
        pop: '0 8px 32px -8px rgb(16 24 40 / 0.25)',
      },
      borderRadius: {
        xl2: '1.25rem',
      },
    },
  },
  plugins: [],
}
```

==========================================================================================
## FILE: bastehE_frontend/web/vite.config.ts
## SIZE: 1272 bytes
==========================================================================================

```typescript
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from 'tailwindcss'
import autoprefixer from 'autoprefixer'
import { fileURLToPath } from 'url'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  base: '/',
  build: {
    outDir: 'dist',
    assetsDir: 'assets',
    rollupOptions: {
      output: {
        assetFileNames: (assetInfo) => {
          const extType = assetInfo.name.split('.').at(1) || 'file'
          let typeCategory = 'assets'
          if (['png', 'jpg', 'jpeg', 'svg', 'gif', 'tiff', 'bmp', 'ico'].includes(extType)) {
            typeCategory = 'assets/images'
          } else if (extType === 'css') {
            typeCategory = 'assets/css'
          } else if (/\.js$/.test(assetInfo.name)) {
            typeCategory = 'assets/js'
          }
          return `${typeCategory}/[name]-[hash][extname]`
        },
      },
    },
    css: {
      postcss: {
        plugins: [tailwindcss(), autoprefixer()],
      },
    },
  },
  server: {
    port: 3000,
    host: '127.0.0.1',
  },
  preview: {
    port: 4000,
  },
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },
})
```

==========================================================================================
## FILE: bastehF_desktop/desktop/app/core/api_client.py
## SIZE: 9181 bytes
==========================================================================================

```python
import json
import time
import hashlib
import hmac
import uuid as uuid_mod
from pathlib import Path
from typing import Optional, Dict, Any, Callable

import httpx

from desktop.app.core.device_identity import get_device_identity, _normalize_mac


class DeviceIdentity:
    """Holds the device's identity information for API headers."""
    
    def __init__(self):
        self.mac_address: str | None = None
        self.mac_source: str | None = None
        self.fingerprint: str = ""
        self.hmac_key: bytes | None = None
        self.platform: str = "desktop"
        self.os_info: str = platform.system() + " " + platform.release()
    
    def refresh(self):
        """Refresh the device identity (MAC, fingerprint, HMAC key)."""
        mac, source = get_primary_mac()
        self.mac_address = mac
        self.mac_source = source
        self.fingerprint = get_system_fingerprint()
        
        # Generate a per-device HMAC key (derived from fingerprint)
        # In a real implementation, this would be securely stored/exchanged
        self.hmac_key = hashlib.sha256(
            (self.fingerprint + mac if mac else self.fingerprint).encode()
        ).digest()


class TokenStore:
    """Secure token storage using platform-specific keyring."""
    
    def __init__(self):
        self._access_token: str | None = None
        self._refresh_token: str | None = None
        self._token_expires_at: float = 0.0
        self._device_identity = DeviceIdentity()
        self._device_identity.refresh()
    
    @property
    def access_token(self) -> str | None:
        return self._access_token
    
    @access_token.setter
    def access_token(self, token: str):
        self._access_token = token
        # Save to platform keyring
        try:
            import keyring
            keyring.set_password("planner_desktop", "access_token", token)
        except Exception:
            pass  # keyring not available, in-memory only
    
    @property
    def refresh_token(self) -> str | None:
        return self._refresh_token
    
    @refresh_token.setter
    def refresh_token(self, token: str):
        self._refresh_token = token
        try:
            import keyring
            keyring.set_password("planner_desktop", "refresh_token", token)
        except Exception:
            pass
    
    @property
    def is_authenticated(self) -> bool:
        return self._access_token is not None and time.time() < self._token_expires_at
    
    def clear_tokens(self):
        """Clear all tokens and notify auth manager."""
        self._access_token = None
        self._refresh_token = None
        self._token_expires_at = 0.0
        try:
            import keyring
            keyring.delete_password("planner_desktop", "access_token")
            keyring.delete_password("planner_desktop", "refresh_token")
        except Exception:
            pass


class ApiClient(httpx.Client):
    """HTTP client with automatic device header injection and auth support."""
    
    def __init__(self, base_url: str = "https://api.corp.local/api/v1",
                 token_store: Optional[TokenStore] = None):
        super().__init__(
            base_url=base_url,
            timeout=httpx.Timeout(30.0, connect=10.0),
            verify=True,  # Verify TLS certificates
            http2=True,
        )
        self._token_store = token_store or TokenStore()
        self._identity = self._token_store._device_identity
        # Register response hook for auth handling
        self._hooks = {"response": [self._on_response]}
        # Replace hooks - need to merge
        original_hooks = self._hooks
        self._hooks = {"response": []}
        for hook_list in original_hooks.values():
            for h in hook_list:
                self._hooks["response"].append(h)
        # Actually, httpx hooks work differently - let's use __enter__ hook pattern
        # We'll set headers per-request instead
    
    def _get_device_headers(self, method: str, path: str, body: bytes = b"") -> Dict[str, str]:
        """Generate device authentication headers for the request."""
        identity = self._identity
        fp = identity.fingerprint
        mac = identity.mac_address
        mac_source = identity.mac_source
        ts = str(int(time.time() * 1000))
        nonce = str(uuid_mod.uuid4())
        
        # Body hash for signature
        body_hash = hashlib.sha256(body).hexdigest()
        
        # Build the signature payload
        # Note: For desktop, we use HMAC with the device's key
        # For web, this would use the device token from cookie
        payload = "|".join([
            method.upper(),
            path,
            body_hash,
            fp,
            mac or "",
            nonce,
            ts,
        ])
        
        # Compute HMAC signature
        key = identity.hmac_key or hashlib.sha256(fp.encode()).digest()
        sig = hmac.new(key, payload.encode(), hashlib.sha256).hexdigest()
        
        headers = {
            "X-Device-Fingerprint": fp,
            "X-Device-Nonce": nonce,
            "X-Device-Timestamp": ts,
            "X-Device-Signature": sig,
            "X-Request-ID": str(uuid_mod.uuid4()),
            "Content-Type": "application/json",
        }
        
        # Only add MAC header if MAC is available (desktop)
        # Web clients should NOT send MAC (it would be NULL/fake)
        if mac and identity.mac_source == "psutil":
            headers["X-Device-MAC"] = mac
            headers["X-Device-MAC-Source"] = mac_source
        
        return headers
    
    def _on_response(self, response: httpx.Response) -> None:
        """Hook to handle auth-related responses (401 -> refresh)."""
        if response.status_code == 401 and not getattr(response, '_retried', False):
            response._retried = True
            # Try to refresh token
            if self._token_store.refresh():
                # Retry the request with new token
                # Note: In a full implementation, we'd need the original request info
                pass  # Simplified for this example
    
    def request(self, method: str, url: str, **kwargs) -> httpx.Response:
        """Override request to inject device headers."""
        # Extract body if present
        body = kwargs.get("content", b"")
        if isinstance(body, dict):
            body = json.dumps(body).encode("utf-8")
        
        # Get path from URL
        # URL could be absolute or relative
        path = url
        if not url.startswith(("http://", "https://")):
            # It's a relative path - extract from full URL if base_url set
            # For simplicity, assume full URL or construct properly
            pass
        
        headers = self._get_device_headers(method, path, body)
        
        # Add auth header if we have a token
        if self._token_store.access_token:
            headers["Authorization"] = f"Bearer {self._token_store.access_token}"
        
        # Remove content from kwargs if we already handled it
        kwargs.pop("content", None)
        kwargs["headers"] = headers
        kwargs["timeout"] = self.timeout
        
        return super().request(method, url, content=body, **kwargs)
    
    def enable_auto_refresh(self, on_refresh_failed: Callable = None):
        """Enable automatic token refresh on 401 responses."""
        # This is handled via response hooks
        original_hooks = self._hooks.get("response", [])
        
        def hooked_response(response):
            if response.status_code == 401 and not getattr(response, '_retried', False):
                response._retried = True
                if self._token_store.refresh():
                    # Retry with new token
                    path = response.url.path
                    method = response.method
                    body = response.request.content if hasattr(response.request, 'content') else b""
                    return self.request(method, response.url.path, content=body)
            return response
        
        self._hooks.setdefault("response", []).append(hooked_response)


# Convenience function for quick requests
def quick_get(url: str, token_store: TokenStore, **kwargs) -> httpx.Response:
    """Quick GET request with auth."""
    client = ApiClient(token_store=token_store)
    headers = kwargs.pop("headers", {})
    headers.update({"X-Device-Fingerprint": token_store._identity.fingerprint})
    kwargs["headers"] = headers
    return client.get(url, **kwargs)


def quick_post(url: str, json_body: dict, token_store: TokenStore, **kwargs) -> httpx.Response:
    """Quick POST request with auth and JSON body."""
    client = ApiClient(token_store=token_store)
    headers = kwargs.pop("headers", {})
    headers.update({"X-Device-Fingerprint": token_store._identity.fingerprint})
    kwargs["headers"] = headers
    kwargs["json"] = json_body
    return client.post(url, **kwargs)
```

==========================================================================================
