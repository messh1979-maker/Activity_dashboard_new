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
  shield: 'M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z',
  cog: 'M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z',
  target: 'M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20zM12 18a6 6 0 1 0 0-12 6 6 0 0 0 0 12zM12 14a2 2 0 1 0 0-4 2 2 0 0 0 0 4z',
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

export default function SettingsPage() {
  const { user, logout } = useAuth()
  const [roles, setRoles] = useState<UserRole[]>([])
  const [permCount, setPermCount] = useState<number>(0)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!user?.id) return
    let cancelled = false
    const load = async () => {
      try {
        const [rRes, pRes] = await Promise.all([
          api.get(`/rbac/user/${user.id}/roles`),
          api.get('/rbac/permissions'),
        ])
        if (!cancelled) {
          setRoles(((rRes.data as any)?.data?.roles ?? []) as UserRole[])
          setPermCount(((pRes.data as any)?.data?.permissions ?? []).length)
        }
      } catch {
        if (!cancelled) setError('دریافت اطلاعات دسترسی ناموفق بود.')
      }
    }
    void load()
    return () => {
      cancelled = true
    }
  }, [user?.id])

  if (!user) return null

  const fields: [string, string][] = [
    ['نام نمایشی', user.display_name ?? ''],
    ['نام کاربری', user.username ?? ''],
    ['کد ملی', user.national_id_masked ?? ''],
    ['حالت احراز هویت', user.auth_mode ?? ''],
    ['آخرین ورود', user.last_login_at ? new Date(user.last_login_at).toLocaleString('fa-IR') : '—'],
  ]

  return (
    <div className="space-y-5 p-4 sm:p-6">
      <div className="animate-fade-up">
        <h1 className="text-xl font-bold text-slate-900 sm:text-2xl">تنظیمات</h1>
        <p className="mt-0.5 text-xs text-slate-500 sm:text-sm">پروفایل و سطوح دسترسی شما</p>
      </div>

      {error && (
        <p className="animate-fade-in rounded-2xl bg-red-50 px-4 py-3 text-xs text-red-600">{error}</p>
      )}

      <div className="grid items-start gap-5 lg:grid-cols-2">
        {/* Profile */}
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
            <button
              onClick={() => void logout()}
              className="btn-danger-soft w-full"
            >
              خروج از حساب
            </button>
          </div>
        </section>

        {/* Access */}
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
      </div>
    </div>
  )
}