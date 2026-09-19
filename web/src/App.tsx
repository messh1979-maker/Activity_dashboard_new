import React, { useEffect, useMemo, useState } from 'react'
import {
  BrowserRouter,
  Routes,
  Route,
  Navigate,
  Link,
  useLocation,
  useNavigate,
} from 'react-router-dom'
import { useAuth } from './security/authProvider'
import DashboardPage from './features/DashboardPage'
import ChatPage from './features/ChatPage'
import InboxPage from './features/InboxPage'
import GroupsPage from './features/GroupsPage'
import ReportsPage from './features/ReportsPage'
import SettingsPage from './features/SettingsPage'

/* ---------------- Icons (inline SVG, no emoji) ---------------- */

function Icon({ d, className = 'h-5 w-5' }: { d: string; className?: string }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8}
      strokeLinecap="round" strokeLinejoin="round" className={className} aria-hidden>
      <path d={d} />
    </svg>
  )
}

const PATHS = {
  grid: 'M3 3h7v7H3zM14 3h7v7h-7zM3 14h7v7H3zM14 14h7v7h-7z',
  chat: 'M21 11.5a8.38 8.38 0 0 1-.9 3.8 8.5 8.5 0 0 1-7.6 4.7 8.38 8.38 0 0 1-3.8-.9L3 21l1.9-5.7a8.38 8.38 0 0 1-.9-3.8 8.5 8.5 0 0 1 4.7-7.6 8.38 8.38 0 0 1 3.8-.9h.5a8.48 8.48 0 0 1 8 8v.5z',
  inbox: 'M22 12h-6l-2 3h-4l-2-3H2M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z',
  users: 'M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM23 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75',
  chart: 'M18 20V10M12 20V4M6 20v-6',
  cog: 'M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z',
  logout: 'M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9',
  target: 'M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20zM12 18a6 6 0 1 0 0-12 6 6 0 0 0 0 12zM12 14a2 2 0 1 0 0-4 2 2 0 0 0 0 4z',
  lock: 'M5 11h14a2 2 0 0 1 2 2v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-7a2 2 0 0 1 2-2zM7 11V7a5 5 0 0 1 10 0v4',
  user: 'M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2M12 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8z',
  check: 'M20 6 9 17l-5-5',
}

/* ---------------- Login ---------------- */

function LoginPage() {
  const { login, isLoading } = useAuth()
  const [identifier, setIdentifier] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)
    try {
      await login({ identifier, password })
    } catch {
      setError('ورود ناموفق بود. مشخصات را بررسی کنید.')
    }
  }

  const features = useMemo(
    () => [
      { d: PATHS.target, t: 'اهداف و وظایف', s: 'تعریف، پیگیری پیشرفت و مدیریت مهلت‌ها' },
      { d: PATHS.users, t: 'گروه‌ها و حریم خصوصی', s: 'کار تیمی با کنترل دقیق دسترسی' },
      { d: PATHS.chart, t: 'گزارش و داشبورد', s: 'نمای زنده از عملکرد شما و تیم' },
    ],
    [],
  )

  return (
    <div className="flex min-h-screen bg-slate-100">
      {/* Brand panel */}
      <div className="relative hidden w-[44%] overflow-hidden bg-slate-900 lg:block">
        <div className="absolute inset-0 bg-gradient-to-bl from-brand-700 via-slate-900 to-slate-950" />
        <div
          className="absolute inset-0 opacity-[0.15]"
          style={{
            backgroundImage:
              'radial-gradient(circle at 25% 25%, #fff 1.5px, transparent 1.5px)',
            backgroundSize: '28px 28px',
          }}
        />
        <div className="absolute -left-24 -top-24 h-96 w-96 rounded-full bg-brand-500/30 blur-3xl" />
        <div className="absolute -bottom-32 -right-16 h-[28rem] w-[28rem] rounded-full bg-indigo-500/20 blur-3xl" />
        <div className="relative flex h-full flex-col justify-between p-12 text-white">
          <div className="animate-fade-up flex items-center gap-3">
            <div className="flex h-12 w-12 items-center justify-center rounded-2xl bg-white/15 text-white backdrop-blur">
              <Icon d={PATHS.target} className="h-7 w-7" />
            </div>
            <div>
              <p className="text-lg font-bold leading-6">سامانه مدیریت اهداف</p>
              <p className="text-xs text-slate-300">نسخه سازمانی</p>
            </div>
          </div>
          <div className="space-y-6">
            <h2 className="animate-fade-up stagger-1 text-3xl font-bold leading-[2.6rem]">
              مدیریت اهداف، برنامه‌ریزی و همکاری تیمی
            </h2>
            <p className="animate-fade-up stagger-2 max-w-md text-sm leading-7 text-slate-300">
              همه اهداف، وظایف، گفتگوها و پیگیری‌ها — یکجا، امن و یکپارچه.
            </p>
            <ul className="space-y-4 pt-2">
              {features.map((f, i) => (
                <li
                  key={f.t}
                  className={`animate-fade-up stagger-${i + 3} flex items-start gap-3`}
                >
                  <span className="mt-0.5 flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-white/10 text-brand-200">
                    <Icon d={f.d} className="h-5 w-5" />
                  </span>
                  <span>
                    <span className="block text-sm font-medium">{f.t}</span>
                    <span className="block text-xs text-slate-400">{f.s}</span>
                  </span>
                </li>
              ))}
            </ul>
          </div>
          <p className="text-[11px] text-slate-500">امنیت چندلایه · احراز هویت دو عاملی · ثبت وقایع</p>
        </div>
      </div>

      {/* Form panel */}
      <div className="flex flex-1 items-center justify-center p-6">
        <form
          onSubmit={onSubmit}
          className="animate-fade-up w-full max-w-md rounded-3xl bg-white p-8 shadow-pop sm:p-10"
        >
          <div className="mb-8 text-center lg:hidden">
            <div className="mx-auto mb-3 flex h-12 w-12 items-center justify-center rounded-2xl bg-gradient-to-l from-brand-600 to-brand-500 text-white">
              <Icon d={PATHS.target} className="h-7 w-7" />
            </div>
            <p className="font-bold">سامانه مدیریت اهداف</p>
          </div>
          <h1 className="text-2xl font-bold">ورود به سامانه</h1>
          <p className="mb-6 mt-1 text-sm text-slate-500">برای ادامه وارد حساب کاربری خود شوید</p>

          <label className="label" htmlFor="login-id">
            نام کاربری یا کد ملی
          </label>
          <div className="relative mb-4">
            <span className="pointer-events-none absolute right-3.5 top-1/2 -translate-y-1/2 text-slate-400">
              <Icon d={PATHS.user} className="h-5 w-5" />
            </span>
            <input
              id="login-id"
              className="input pr-11"
              placeholder="مثلاً ali.rezaei"
              value={identifier}
              onChange={(e) => setIdentifier(e.target.value)}
              autoComplete="username"
            />
          </div>

          <label className="label" htmlFor="login-pw">
            گذرواژه
          </label>
          <div className="relative mb-2">
            <span className="pointer-events-none absolute right-3.5 top-1/2 -translate-y-1/2 text-slate-400">
              <Icon d={PATHS.lock} className="h-5 w-5" />
            </span>
            <input
              id="login-pw"
              className="input pr-11"
              placeholder="گذرواژه خود را وارد کنید"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="current-password"
            />
          </div>

          {error && (
            <p className="animate-fade-in mb-2 rounded-xl bg-red-50 px-4 py-2.5 text-xs text-red-600">
              {error}
            </p>
          )}

          <button type="submit" disabled={isLoading} className="btn-primary mt-4 w-full py-3">
            {isLoading ? (
              <>
                <span className="h-4 w-4 animate-spin rounded-full border-2 border-white/40 border-t-white" />
                در حال ورود…
              </>
            ) : (
              'ورود'
            )}
          </button>
          <p className="mt-5 text-center text-[11px] leading-5 text-slate-400">
            حساب پیش‌فرض مدیر: admin / admin123
          </p>
        </form>
      </div>
    </div>
  )
}

/* ---------------- Shell ---------------- */

const NAV = [
  { to: '/dashboard', label: 'داشبورد', icon: PATHS.grid },
  { to: '/chat', label: 'گفتگوها', icon: PATHS.chat },
  { to: '/inbox', label: 'صندوق ورودی', icon: PATHS.inbox },
  { to: '/groups', label: 'گروه‌ها', icon: PATHS.users },
  { to: '/reports', label: 'گزارش‌ها', icon: PATHS.chart },
  { to: '/settings', label: 'تنظیمات', icon: PATHS.cog },
]

function Sidebar({ onNav }: { onNav?: () => void }) {
  const { user, logout } = useAuth()
  const { pathname } = useLocation()
  const navigate = useNavigate()

  const doLogout = async () => {
    await logout()
    navigate('/login', { replace: true })
    onNav?.()
  }

  return (
    <div className="flex h-full flex-col bg-slate-900 text-white">
      <div className="flex items-center gap-3 px-5 pb-6 pt-6">
        <div className="flex h-11 w-11 items-center justify-center rounded-2xl bg-gradient-to-l from-brand-500 to-indigo-500 shadow-lg shadow-brand-900/40">
          <Icon d={PATHS.target} className="h-6 w-6" />
        </div>
        <div className="min-w-0">
          <p className="truncate text-sm font-bold">سامانه مدیریت اهداف</p>
          <p className="text-[11px] text-slate-400">نسخه سازمانی</p>
        </div>
      </div>
      <nav className="flex-1 space-y-1 overflow-y-auto px-3">
        {NAV.map((n) => {
          const active = pathname === n.to || (n.to === '/dashboard' && pathname === '/')
          return (
            <Link
              key={n.to}
              to={n.to}
              onClick={onNav}
              className={`navlink ${active ? 'navlink-active' : ''}`}
            >
              <Icon d={n.icon} />
              <span>{n.label}</span>
            </Link>
          )
        })}
      </nav>
      <div className="border-t border-white/10 p-4">
        <div className="mb-3 flex items-center gap-3 rounded-xl bg-white/5 p-3">
          <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-gradient-to-l from-brand-400 to-indigo-400 text-sm font-bold">
            {(user?.display_name || user?.username || '?').slice(0, 1)}
          </div>
          <div className="min-w-0 flex-1">
            <p className="truncate text-sm font-medium">
              {user?.display_name || user?.username}
            </p>
            <p className="truncate text-[11px] text-slate-400" dir="ltr">
              {user?.national_id_masked}
            </p>
          </div>
        </div>
        <button onClick={() => void doLogout()} className="navlink w-full text-red-300 hover:text-red-200">
          <Icon d={PATHS.logout} />
          <span>خروج از حساب</span>
        </button>
      </div>
    </div>
  )
}

function Topbar({ onMenu }: { onMenu: () => void }) {
  const today = useMemo(
    () =>
      new Intl.DateTimeFormat('fa-IR', {
        weekday: 'long',
        day: 'numeric',
        month: 'long',
      }).format(new Date()),
    [],
  )
  return (
    <header className="sticky top-0 z-10 border-b border-slate-200/70 bg-white/80 backdrop-blur">
      <div className="flex items-center gap-3 px-4 py-3 sm:px-6">
        <button onClick={onMenu} className="btn-ghost p-2 lg:hidden" aria-label="menu">
          <svg viewBox="0 0 24 24" className="h-6 w-6" fill="none" stroke="currentColor"
            strokeWidth={2} strokeLinecap="round">
            <path d="M4 6h16M4 12h16M4 18h16" />
          </svg>
        </button>
        <div className="min-w-0 flex-1">
          <p className="truncate text-sm font-bold text-slate-800">سامانه مدیریت اهداف</p>
          <p className="text-[11px] text-slate-400">{today}</p>
        </div>
        <span className="badge bg-emerald-50 text-emerald-700">
          <span className="ml-1.5 h-2 w-2 rounded-full bg-emerald-500" />
          متصل
        </span>
      </div>
    </header>
  )
}

function Shell() {
  const [open, setOpen] = useState(false)
  return (
    <div className="flex min-h-screen bg-slate-100">
      <aside className="sticky top-0 hidden h-screen w-72 shrink-0 lg:block">
        <Sidebar />
      </aside>
      {open && (
        <div className="fixed inset-0 z-20 lg:hidden">
          <div className="animate-fade-in absolute inset-0 bg-slate-900/50" onClick={() => setOpen(false)} />
          <aside className="animate-fade-in absolute bottom-0 right-0 top-0 w-72">
            <Sidebar onNav={() => setOpen(false)} />
          </aside>
        </div>
      )}
      <div className="flex min-w-0 flex-1 flex-col">
        <Topbar onMenu={() => setOpen(true)} />
        <main className="flex-1">
          <Routes>
            <Route path="/dashboard" element={<DashboardPage />} />
            <Route path="/chat" element={<ChatPage />} />
            <Route path="/inbox" element={<InboxPage />} />
            <Route path="/groups" element={<GroupsPage />} />
            <Route path="/reports" element={<ReportsPage />} />
            <Route path="/settings" element={<SettingsPage />} />
            <Route path="/" element={<Navigate to="/dashboard" replace />} />
            <Route path="*" element={<Navigate to="/dashboard" replace />} />
          </Routes>
        </main>
      </div>
    </div>
  )
}

/* ---------------- App ---------------- */

function App() {
  const { isAuthenticated, isLoading, init } = useAuth()

  useEffect(() => {
    void init()
  }, [init])

  // When the API layer reports an unrecoverable 401 (refresh failed or no
  // refresh token), drop the persisted "authenticated" flag so the user is
  // sent back to the login page instead of a dead dashboard.
  useEffect(() => {
    const onExpired = () => {
      useAuth.getState().forceLogout()
    }
    window.addEventListener('auth:expired', onExpired)
    return () => window.removeEventListener('auth:expired', onExpired)
  }, [])

  if (isLoading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-slate-100">
        <div className="flex flex-col items-center gap-4">
          <div className="h-12 w-12 animate-spin rounded-full border-[3px] border-brand-200 border-t-brand-600" />
          <p className="text-sm text-slate-500">در حال بارگذاری…</p>
        </div>
      </div>
    )
  }

  return (
    <BrowserRouter>
      <Routes>
        {isAuthenticated ? (
          <Route path="/*" element={<Shell />} />
        ) : (
          <>
            <Route path="/login" element={<LoginPage />} />
            <Route path="*" element={<Navigate to="/login" replace />} />
          </>
        )}
      </Routes>
    </BrowserRouter>
  )
}

export default App
