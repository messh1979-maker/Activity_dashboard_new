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