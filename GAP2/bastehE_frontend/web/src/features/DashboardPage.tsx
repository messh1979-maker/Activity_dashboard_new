import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useAuth } from '../security/authProvider'
import { useDashboard } from '../hooks/useDashboard'

function Icon({ d, className = 'h-5 w-5' }: { d: string; className?: string }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8}
      strokeLinecap="round" strokeLinejoin="round" className={className} aria-hidden>
      <path d={d} />
    </svg>
  )
}

const P = {
  target: 'M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20zM12 18a6 6 0 1 0 0-12 6 6 0 0 0 0 12zM12 14a2 2 0 1 0 0-4 2 2 0 0 0 0 4z',
  check: 'M20 6 9 17l-5-5',
  inbox: 'M22 12h-6l-2 3h-4l-2-3H2M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z',
  list: 'M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01',
  users: 'M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM23 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75',
  chat: 'M21 11.5a8.38 8.38 0 0 1-.9 3.8 8.5 8.5 0 0 1-7.6 4.7 8.38 8.38 0 0 1-3.8-.9L3 21l1.9-5.7a8.38 8.38 0 0 1-.9-3.8 8.5 8.5 0 0 1 4.7-7.6 8.38 8.38 0 0 1 3.8-.9h.5a8.48 8.48 0 0 1 8 8v.5z',
  plus: 'M12 5v14M5 12h14',
  refresh: 'M23 4v6h-6M1 20v-6h6M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15',
  x: 'M18 6 6 18M6 6l12 12',
  clock: 'M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20zM12 6v6l4 2',
}

function StatCard({
  value,
  label,
  icon,
  grad,
  delay,
}: {
  value: number
  label: string
  icon: string
  grad: string
  delay: string
}) {
  return (
    <div className={`stat-card animate-fade-up ${delay} bg-gradient-to-bl ${grad}`}>
      <div
        className="pointer-events-none absolute inset-0 opacity-20"
        style={{
          backgroundImage: 'radial-gradient(circle at 80% 20%, #fff 1.5px, transparent 1.5px)',
          backgroundSize: '22px 22px',
        }}
      />
      <div className="relative flex items-start justify-between">
        <div>
          <p className="text-4xl font-bold leading-10">{value}</p>
          <p className="mt-1 text-sm text-white/85">{label}</p>
        </div>
        <span className="flex h-11 w-11 items-center justify-center rounded-2xl bg-white/20 backdrop-blur">
          <Icon d={icon} className="h-6 w-6" />
        </span>
      </div>
    </div>
  )
}

function Section({
  title,
  action,
  children,
  delay = '',
}: {
  title: string
  action?: React.ReactNode
  children: React.ReactNode
  delay?: string
}) {
  return (
    <section className={`card animate-fade-up ${delay}`}>
      <div className="mb-4 flex items-center justify-between">
        <h2 className="text-base font-bold text-slate-800">{title}</h2>
        {action}
      </div>
      {children}
    </section>
  )
}

function Empty({ text }: { text: string }) {
  return (
    <div className="rounded-xl bg-slate-50 px-4 py-6 text-center text-xs text-slate-400">
      {text}
    </div>
  )
}

const BAR_COLORS = ['bg-brand-500', 'bg-emerald-500', 'bg-violet-500', 'bg-amber-500', 'bg-sky-500']

export default function DashboardPage() {
  const { user } = useAuth()
  const { summary, loading, error, refresh, createGoal, actOnInbox } = useDashboard()
  const [title, setTitle] = useState('')
  const [desc, setDesc] = useState('')
  const [saving, setSaving] = useState(false)
  const [formError, setFormError] = useState(false)
  const [acting, setActing] = useState<string | null>(null)

  const onCreate = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!title.trim()) return
    setSaving(true)
    setFormError(false)
    try {
      await createGoal(title.trim(), desc.trim() || undefined)
      setTitle('')
      setDesc('')
    } catch {
      setFormError(true)
    } finally {
      setSaving(false)
    }
  }

  const onAct = async (id: string, action: 'accepted' | 'rejected') => {
    setActing(id)
    try {
      await actOnInbox(id, action)
    } finally {
      setActing(null)
    }
  }

  if (loading) {
    return (
      <div className="grid animate-pulse grid-cols-2 gap-4 p-6 md:grid-cols-4">
        {[1, 2, 3, 4].map((i) => (
          <div key={i} className="h-28 rounded-2xl bg-slate-200" />
        ))}
      </div>
    )
  }

  const s = summary.stats

  return (
    <div className="space-y-5 p-4 sm:p-6">
      {/* Header */}
      <div className="animate-fade-up flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-bold text-slate-900 sm:text-2xl">
            سلام، {user?.display_name || user?.username}
          </h1>
          <p className="mt-0.5 text-xs text-slate-500 sm:text-sm">نمای کلی فعالیت‌های امروز شما</p>
        </div>
        <button onClick={() => void refresh()} className="btn-ghost border border-slate-200 bg-white shadow-sm">
          <Icon d={P.refresh} className="h-4 w-4" />
          به‌روزرسانی
        </button>
      </div>

      {error && (
        <p className="animate-fade-in rounded-2xl bg-red-50 px-4 py-3 text-xs text-red-600">{error}</p>
      )}

      {/* Stats */}
      <div className="grid grid-cols-2 gap-4 xl:grid-cols-4">
        <StatCard value={s.goals_active} label="اهداف فعال" icon={P.target} grad="from-blue-600 to-indigo-500" delay="stagger-1" />
        <StatCard value={s.goals_completed} label="اهداف تکمیل‌شده" icon={P.check} grad="from-emerald-500 to-teal-500" delay="stagger-2" />
        <StatCard value={s.inbox_pending} label="در انتظار بررسی" icon={P.inbox} grad="from-amber-500 to-orange-500" delay="stagger-3" />
        <StatCard value={s.tasks_open} label="وظایف باز" icon={P.list} grad="from-violet-600 to-purple-500" delay="stagger-4" />
      </div>

      <div className="grid items-start gap-5 xl:grid-cols-2">
        {/* Goals */}
        <Section
          title="اهداف من"
          delay="stagger-2"
          action={
            <span className="badge bg-brand-50 text-brand-700">
              {summary.recent_goals.length} مورد
            </span>
          }
        >
          <form onSubmit={onCreate} className="mb-3 rounded-2xl bg-slate-50 p-3">
            <div className="flex gap-2">
              <input
                className="input border-0 bg-white shadow-sm"
                placeholder="عنوان هدف جدید…"
                value={title}
                onChange={(e) => setTitle(e.target.value)}
              />
              <button type="submit" disabled={saving || !title.trim()} className="btn-primary shrink-0 px-4">
                <Icon d={P.plus} className="h-4 w-4" />
                {saving ? '...' : 'افزودن'}
              </button>
            </div>
            <input
              className="input mt-2 border-0 bg-white text-xs shadow-sm"
              placeholder="توضیح (اختیاری)"
              value={desc}
              onChange={(e) => setDesc(e.target.value)}
            />
            {formError && <p className="mt-2 text-xs text-red-600">ایجاد هدف ناموفق بود.</p>}
          </form>
          {summary.recent_goals.length === 0 ? (
            <Empty text="هنوز هدفی ثبت نشده است." />
          ) : (
            <ul className="max-h-80 space-y-2.5 overflow-y-auto pl-1">
              {summary.recent_goals.map((g, i) => (
                <li
                  key={g.id}
                  className="card-hover rounded-2xl border border-slate-100 bg-white p-3.5 shadow-sm"
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="truncate text-sm font-medium text-slate-800">{g.title}</span>
                    {g.status === 'completed' ? (
                      <span className="badge shrink-0 bg-emerald-50 text-emerald-700">
                        <Icon d={P.check} className="ml-1 h-3 w-3" />
                        تکمیل‌شده
                      </span>
                    ) : (
                      <span className="badge shrink-0 bg-brand-50 text-brand-700">
                        {g.progress_pct}٪
                      </span>
                    )}
                  </div>
                  <div className="mt-2.5 h-2 overflow-hidden rounded-full bg-slate-100">
                    <div
                      className={`h-full rounded-full bg-gradient-to-l ${BAR_COLORS[i % BAR_COLORS.length]} transition-all duration-500`}
                      style={{ width: `${g.progress_pct}%` }}
                    />
                  </div>
                </li>
              ))}
            </ul>
          )}
        </Section>

        {/* Inbox */}
        <Section
          title="صندوق ورودی"
          delay="stagger-3"
          action={
            s.inbox_pending > 0 ? (
              <span className="badge bg-amber-50 text-amber-700">{s.inbox_pending} در انتظار</span>
            ) : undefined
          }
        >
          {summary.pending_inbox.length === 0 ? (
            <Empty text="صندوق ورودی_EMPTY" />
          ) : (
            <ul className="max-h-80 space-y-2.5 overflow-y-auto pl-1">
              {summary.pending_inbox.map((it) => (
                <li key={it.id} className="rounded-2xl border border-amber-100 bg-amber-50/50 p-3.5">
                  <div className="flex items-start justify-between gap-2">
                    <span className="text-sm font-medium text-slate-800">{it.title}</span>
                    <span className="badge shrink-0 bg-white text-slate-500 shadow-sm">{it.item_type}</span>
                  </div>
                  <p className="mt-1 text-[11px] text-slate-500">
                    {it.sender_name ? `از ${it.sender_name}` : ''}
                  </p>
                  {it.message && <p className="mt-1.5 text-xs leading-5 text-slate-600">{it.message}</p>}
                  <div className="mt-2.5 flex gap-2">
                    <button
                      disabled={acting === it.id}
                      onClick={() => void onAct(it.id, 'accepted')}
                      className="btn-success-soft disabled:opacity-50"
                    >
                      <Icon d={P.check} className="h-3.5 w-3.5" />
                      تأیید
                    </button>
                    <button
                      disabled={acting === it.id}
                      onClick={() => void onAct(it.id, 'rejected')}
                      className="btn-danger-soft disabled:opacity-50"
                    >
                      <Icon d={P.x} className="h-3.5 w-3.5" />
                      رد
                    </button>
                  </div>
                </li>
              ))}
            </ul>
          )}
          <Link to="/inbox" className="btn-ghost mt-3 w-full text-brand-600">
            مشاهده همه در صندوق ورودی
          </Link>
        </Section>

        {/* Tasks */}
        <Section title="وظایف باز من" delay="stagger-4">
          {summary.open_tasks.length === 0 ? (
            <Empty text="وظیفه بازی ندارید." />
          ) : (
            <ul className="max-h-72 space-y-2 overflow-y-auto pl-1">
              {summary.open_tasks.map((t) => (
                <li
                  key={t.id}
                  className="flex items-center justify-between gap-2 rounded-xl border border-slate-100 p-3 text-sm"
                >
                  <span className="flex min-w-0 items-center gap-2.5">
                    <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-violet-50 text-violet-600">
                      <Icon d={P.list} className="h-4 w-4" />
                    </span>
                    <span className="min-w-0">
                      <span className="block truncate font-medium text-slate-800">{t.title}</span>
                      {t.goal_title && (
                        <span className="block truncate text-[11px] text-slate-400">{t.goal_title}</span>
                      )}
                    </span>
                  </span>
                  <span
                    className={`badge shrink-0 ${
                      t.priority === 'high' ? 'bg-red-50 text-red-600' : 'bg-slate-100 text-slate-500'
                    }`}
                  >
                    <Icon d={P.clock} className="ml-1 h-3 w-3" />
                    {t.status}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </Section>

        {/* Groups & rooms */}
        <Section title="گروه‌ها و گفتگوها" delay="stagger-5">
          {summary.my_groups.length === 0 && summary.my_rooms.length === 0 ? (
            <Empty text="عضو هیچ گروه یا اتاقی نیستید." />
          ) : (
            <div className="space-y-4">
              {summary.my_groups.length > 0 && (
                <div>
                  <p className="mb-2 text-[11px] font-medium text-slate-400">
                    گروه‌ها و گفتگوها_L ({s.groups_count})
                  </p>
                  <div className="flex flex-wrap gap-2">
                    {summary.my_groups.map((g) => (
                      <span
                        key={g.id}
                        className="inline-flex items-center gap-1.5 rounded-xl bg-slate-100 px-3 py-1.5 text-xs font-medium text-slate-700"
                      >
                        <Icon d={P.users} className="h-3.5 w-3.5 text-slate-400" />
                        {g.name}
                        {g.is_manager && (
                          <span className="badge bg-violet-100 text-violet-700">مدیر</span>
                        )}
                      </span>
                    ))}
                  </div>
                </div>
              )}
              {summary.my_rooms.length > 0 && (
                <div>
                  <p className="mb-2 text-[11px] font-medium text-slate-400">
                    اتاق‌های گفتگو ({s.rooms_count})
                  </p>
                  <div className="flex flex-wrap gap-2">
                    {summary.my_rooms.map((r) => (
                      <Link
                        key={r.id}
                        to="/chat"
                        className="inline-flex items-center gap-1.5 rounded-xl bg-brand-50 px-3 py-1.5 text-xs font-medium text-brand-700 transition-colors hover:bg-brand-100"
                      >
                        <Icon d={P.chat} className="h-3.5 w-3.5" />
                        {r.title}
                      </Link>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
          <Link to="/chat" className="btn-ghost mt-4 w-full text-brand-600">
            رفتن به گفتگوها
          </Link>
        </Section>
      </div>
    </div>
  )
}
