# PART 9/12 of GAP PACK

## FILE: bastehE_frontend/web/src/features/ChatPage.tsx
## SIZE: 10256 bytes
==========================================================================================

```tsx
import { useCallback, useEffect, useRef, useState } from 'react'
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
  chat: 'M21 11.5a8.38 8.38 0 0 1-.9 3.8 8.5 8.5 0 0 1-7.6 4.7 8.38 8.38 0 0 1-3.8-.9L3 21l1.9-5.7a8.38 8.38 0 0 1-.9-3.8 8.5 8.5 0 0 1 4.7-7.6 8.38 8.38 0 0 1 3.8-.9h.5a8.48 8.48 0 0 1 8 8v.5z',
  plus: 'M12 5v14M5 12h14',
  send: 'M22 2 11 13M22 2l-7 20-4-9-9-4z',
  users: 'M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM23 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75',
}

interface ChatRoom {
  id: string
  title: string
  owner_id: string
  member_count: number
  is_archived: boolean
  linked_type?: string | null
  linked_id?: string | null
}

interface ChatMsg {
  id: string
  room_id: string
  sender_id: string
  body: string
  sender_name: string
  created_at: string
  message_type: string
  is_edited: boolean
}

function fmtTime(iso: string) {
  if (!iso) return ''
  try {
    return new Intl.DateTimeFormat('fa-IR', {
      hour: '2-digit',
      minute: '2-digit',
      day: '2-digit',
      month: '2-digit',
    }).format(new Date(iso))
  } catch {
    return ''
  }
}

export default function ChatPage() {
  const { user } = useAuth()
  const [rooms, setRooms] = useState<ChatRoom[]>([])
  const [selected, setSelected] = useState<string | null>(null)
  const [messages, setMessages] = useState<ChatMsg[]>([])
  const [title, setTitle] = useState('')
  const [body, setBody] = useState('')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [creating, setCreating] = useState(false)
  const [sending, setSending] = useState(false)
  const listRef = useRef<HTMLDivElement | null>(null)

  const loadRooms = useCallback(async () => {
    try {
      const res = await api.get('/chat/rooms')
      const data = (res.data as any)?.data?.rooms ?? []
      setRooms(data as ChatRoom[])
      if (data.length && !selected) setSelected(data[0].id)
    } catch {
      setError('دریافت اتاق‌های گفتگو ناموفق بود.')
    } finally {
      setLoading(false)
    }
  }, [selected])

  useEffect(() => {
    void loadRooms()
  }, [loadRooms])

  useEffect(() => {
    if (!selected) {
      setMessages([])
      return
    }
    let cancelled = false
    const load = async () => {
      try {
        const res = await api.get(`/chat/${selected}/messages`)
        const data = (res.data as any)?.data?.messages ?? []
        if (!cancelled) setMessages(data as ChatMsg[])
      } catch {
        if (!cancelled) setError('دریافت پیام‌ها ناموفق بود.')
      }
    }
    void load()
    const t = setInterval(load, 4000)
    return () => {
      cancelled = true
      clearInterval(t)
    }
  }, [selected])

  useEffect(() => {
    listRef.current?.scrollTo({ top: listRef.current.scrollHeight, behavior: 'smooth' })
  }, [messages])

  const onCreate = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!title.trim()) return
    setCreating(true)
    setError(null)
    try {
      const res = await api.post('/chat/rooms', { title: title.trim() })
      const roomId = (res.data as any)?.room_id
      setTitle('')
      await loadRooms()
      if (roomId) setSelected(roomId)
    } catch {
      setError('ایجاد اتاق گفتگو ناموفق بود.')
    } finally {
      setCreating(false)
    }
  }

  const onSend = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!selected || !body.trim()) return
    setSending(true)
    setError(null)
    try {
      await api.post(`/chat/${selected}/messages`, { body: body.trim() })
      setBody('')
      const res = await api.get(`/chat/${selected}/messages`)
      setMessages(((res.data as any)?.data?.messages ?? []) as ChatMsg[])
    } catch {
      setError('ارسال پیام ناموفق بود.')
    } finally {
      setSending(false)
    }
  }

  return (
    <div className="space-y-5 p-4 sm:p-6">
      <div className="animate-fade-up">
        <h1 className="text-xl font-bold text-slate-900 sm:text-2xl">گفتگوها</h1>
        <p className="mt-0.5 text-xs text-slate-500 sm:text-sm">اتاق‌های گفتگو و پیام‌های گروهی</p>
      </div>

      {error && (
        <p className="animate-fade-in rounded-2xl bg-red-50 px-4 py-3 text-xs text-red-600">{error}</p>
      )}

      <div className="grid items-start gap-5 lg:grid-cols-3">
        {/* Rooms */}
        <section className="card animate-fade-up stagger-1">
          <h2 className="mb-3 text-base font-bold text-slate-800">اتاق‌ها</h2>
          <form onSubmit={onCreate} className="mb-3 flex gap-2">
            <input
              className="input"
              placeholder="عنوان اتاق جدید…"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
            />
            <button type="submit" disabled={creating || !title.trim()} className="btn-primary shrink-0 px-4">
              <Icon d={P.plus} className="h-4 w-4" />
              {creating ? '...' : 'افزودن'}
            </button>
          </form>
          {loading ? (
            <p className="text-xs text-slate-400">در حال بارگذاری…</p>
          ) : rooms.length === 0 ? (
            <p className="rounded-xl bg-slate-50 px-4 py-6 text-center text-xs text-slate-400">
              هنوز اتاقی نساخته‌اید.
            </p>
          ) : (
            <ul className="max-h-[26rem] space-y-2 overflow-y-auto pl-1">
              {rooms.map((r) => (
                <li key={r.id} className="flex items-center justify-between gap-2">
                  <button
                    onClick={() => setSelected(r.id)}
                    className={`flex w-full items-center gap-3 rounded-xl px-3 py-2.5 text-right transition-colors ${
                      selected === r.id ? 'bg-brand-50 text-brand-700' : 'text-slate-700 hover:bg-slate-50'
                    }`}
                  >
                    <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-white text-brand-500 shadow-sm">
                      <Icon d={P.chat} className="h-5 w-5" />
                    </span>
                    <span className="min-w-0 flex-1">
                      <span className="block truncate text-sm font-medium">{r.title}</span>
                      <span className="block text-[11px] text-slate-400">
                        {r.member_count} عضو
                      </span>
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </section>

        {/* Messages */}
        <section className="card animate-fade-up stagger-2 lg:col-span-2">
          {!selected ? (
            <div className="flex flex-col items-center justify-center gap-3 py-16 text-center">
              <span className="flex h-14 w-14 items-center justify-center rounded-2xl bg-brand-50 text-brand-500">
                <Icon d={P.chat} className="h-7 w-7" />
              </span>
              <p className="text-sm text-slate-500">یک اتاق گفتگو را انتخاب کنید</p>
            </div>
          ) : (
            <>
              <div className="mb-3 flex items-center justify-between gap-2">
                <h2 className="truncate text-base font-bold text-slate-800">
                  {rooms.find((r) => r.id === selected)?.title ?? 'گفتگو'}
                </h2>
                <span className="badge shrink-0 bg-brand-50 text-brand-700">
                  {messages.length} پیام
                </span>
              </div>
              <div
                ref={listRef}
                className="h-[26rem] space-y-2.5 overflow-y-auto rounded-2xl bg-slate-50 p-3"
              >
                {messages.length === 0 ? (
                  <p className="py-16 text-center text-xs text-slate-400">پیامی در این گفتگو نیست.</p>
                ) : (
                  messages.map((m) => {
                    const mine = m.sender_id === user?.id
                    return (
                      <div key={m.id} className={`flex ${mine ? 'justify-start' : 'justify-end'}`}>
                        <div
                          className={`max-w-[80%] rounded-2xl px-3.5 py-2 shadow-sm ${
                            mine
                              ? 'bg-white text-slate-700 border border-slate-200'
                              : 'bg-gradient-to-l from-brand-600 to-brand-500 text-white'
                          }`}
                        >
                          <div className="mb-0.5 flex items-center gap-2 text-[10px] opacity-70">
                            <Icon d={P.users} className="h-3 w-3" />
                            <span>{mine ? 'شما' : (m.sender_name || m.sender_id.slice(0, 8))}</span>
                            <span>{fmtTime(m.created_at)}</span>
                          </div>
                          <p className="whitespace-pre-wrap break-words text-sm leading-6">{m.body}</p>
                        </div>
                      </div>
                    )
                  })
                )}
              </div>
              <form onSubmit={onSend} className="mt-3 flex gap-2">
                <input
                  className="input"
                  placeholder="پیام خود را بنویسید…"
                  value={body}
                  onChange={(e) => setBody(e.target.value)}
                />
                <button type="submit" disabled={sending || !body.trim()} className="btn-primary shrink-0 px-4">
                  <Icon d={P.send} className="h-4 w-4" />
                  {sending ? '...' : 'ارسال'}
                </button>
              </form>
            </>
          )}
        </section>
      </div>
    </div>
  )
}
```

==========================================================================================
## FILE: bastehE_frontend/web/src/features/DashboardPage.tsx
## SIZE: 14972 bytes
==========================================================================================

```tsx
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
```

==========================================================================================
## FILE: bastehE_frontend/web/src/features/GroupsPage.tsx
## SIZE: 14583 bytes
==========================================================================================

```tsx
import { useCallback, useEffect, useState } from 'react'
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
  users: 'M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM23 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75',
  plus: 'M12 5v14M5 12h14',
  lock: 'M5 11h14a2 2 0 0 1 2 2v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-7a2 2 0 0 1 2-2zM7 11V7a5 5 0 0 1 10 0v4',
  x: 'M18 6 6 18M6 6l12 12',
  check: 'M20 6 9 17l-5-5',
}

interface GroupRow {
  id: string
  name: string
  description?: string | null
  is_active: boolean
  member_count: number
  owner_id?: string | null
}

interface GroupMember {
  user_id: string
  is_manager: boolean
  joined_at: string
}

const PRIVACY_OPTIONS = [
  ['team_only', 'فقط تیم'],
  ['selected', 'افراد انتخاب‌شده'],
  ['fully_private', 'کاملاً خصوصی'],
  ['fully_transparent', 'کاملاً شفاف'],
] as const

export default function GroupsPage() {
  const { user } = useAuth()
  const [groups, setGroups] = useState<GroupRow[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  // Create form
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [privacy, setPrivacy] = useState<string>('team_only')
  const [creating, setCreating] = useState(false)

  // Selected group
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [members, setMembers] = useState<GroupMember[]>([])
  const [membersLoading, setMembersLoading] = useState(false)
  const [memberUid, setMemberUid] = useState('')
  const [adding, setAdding] = useState(false)

  // Users for dropdown (loaded once on mount)
  const [allUsers, setAllUsers] = useState<{ id: string; username: string; display_name: string; is_active: boolean }[]>([])
  const [usersLoading, setUsersLoading] = useState(false)

  const loadGroups = useCallback(async () => {
    setError(null)
    try {
      const res = await api.get('/groups/')
      setGroups(((res.data as any)?.data?.groups ?? []) as GroupRow[])
    } catch {
      setError('دریافت گروه‌ها ناموفق بود.')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void loadGroups()
  }, [loadGroups])

  const loadMembers = useCallback(async (gid: string) => {
    setMembersLoading(true)
    try {
      const res = await api.get(`/groups/${gid}/members`)
      setMembers(((res.data as any)?.data?.members ?? []) as GroupMember[])
    } catch {
      setError('دریافت اعضای گروه ناموفق بود.')
    } finally {
      setMembersLoading(false)
    }
  }, [])

  useEffect(() => {
    if (selectedId) {
      void loadMembers(selectedId)
    } else {
      setMembers([])
    }
  }, [selectedId, loadMembers])

  const loadUsers = useCallback(async () => {
    setUsersLoading(true)
    try {
      const res = await api.get('/admin/users')
      const d = res.data as { items?: { id: string; username: string; display_name: string; is_active: boolean }[] }
      const items = d?.items ?? []
      const sorted = [...items].sort((a, b) =>
        (a.display_name || a.username).localeCompare(b.display_name || b.username, 'fa')
      )
      setAllUsers(sorted)
    } catch {
      setAllUsers([])
    } finally {
      setUsersLoading(false)
    }
  }, [])

  useEffect(() => {
    void loadUsers()
  }, [loadUsers])

  const nonMembers = allUsers.filter((u) => !members.some((m) => m.user_id === u.id))
  const userNameOf = (uid: string): string => {
    const u = allUsers.find((x) => x.id === uid)
    return u ? u.display_name || u.username : uid
  }

  const onCreate = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!name.trim()) return
    setCreating(true)
    setError(null)
    try {
      await api.post('/groups/', {
        name: name.trim(),
        description: description.trim() || undefined,
        privacy_level: privacy,
      })
      setName('')
      setDescription('')
      await loadGroups()
    } catch (e) {
      const d = (e as { response?: { data?: { message?: string; error?: string } } })?.response?.data
      setError(d?.message ?? d?.error ?? 'ایجاد گروه ناموفق بود.')
    } finally {
      setCreating(false)
    }
  }

  const onAddMember = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!selectedId || !memberUid) return
    setAdding(true)
    setError(null)
    try {
      await api.post(`/groups/${selectedId}/members`, {
        user_id: memberUid,
        is_manager: false,
      })
      setMemberUid('')
      await loadMembers(selectedId)
    } catch (e) {
      const d = (e as { response?: { data?: { message?: string; error?: string } } })?.response?.data
      setError(d?.message ?? d?.error ?? 'افزودن عضو ناموفق بود. تنها مدیر گروه می‌تواند عضو اضافه کند.')
    } finally {
      setAdding(false)
    }
  }

  return (
    <div className="space-y-5 p-4 sm:p-6">
      <div className="animate-fade-up">
        <h1 className="text-xl font-bold text-slate-900 sm:text-2xl">گروه‌ها</h1>
        <p className="mt-0.5 text-xs text-slate-500 sm:text-sm">گروه‌های سازمانی و اعضای آن‌ها</p>
      </div>

      {error && (
        <p className="animate-fade-in rounded-2xl bg-red-50 px-4 py-3 text-xs text-red-600">{error}</p>
      )}

      <div className="grid items-start gap-5 lg:grid-cols-3">
        {/* List */}
        <section className="card animate-fade-up stagger-1 lg:col-span-2">
          <h2 className="mb-3 text-base font-bold text-slate-800">لیست گروه‌ها</h2>
          {loading ? (
            <p className="text-xs text-slate-400">در حال بارگذاری…</p>
          ) : groups.length === 0 ? (
            <p className="rounded-xl bg-slate-50 px-4 py-8 text-center text-xs text-slate-400">
              هنوز گروهی ساخته نشده است.
            </p>
          ) : (
            <ul className="space-y-2.5">
              {groups.map((g) => {
                const isSelected = selectedId === g.id
                const isOwner = g.owner_id && user?.id ? g.owner_id === user.id : false
                return (
                  <li
                    key={g.id}
                    className={`rounded-2xl border p-4 transition-colors ${
                      isSelected ? 'border-brand-200 bg-brand-50/40' : 'border-slate-100 bg-white'
                    }`}
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex items-center gap-3">
                        <span className="flex h-10 w-10 items-center justify-center rounded-xl bg-brand-50 text-brand-500">
                          <Icon d={P.users} className="h-5 w-5" />
                        </span>
                        <div>
                          <p className="font-medium text-slate-800">{g.name}</p>
                          {g.description && (
                            <p className="text-[11px] text-slate-400">{g.description}</p>
                          )}
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="badge bg-slate-100 text-slate-500">{g.member_count} عضو</span>
                        {isOwner && <span className="badge bg-violet-100 text-violet-700">مدیر</span>}
                        <button
                          onClick={() => setSelectedId(isSelected ? null : g.id)}
                          className={`rounded-lg px-3 py-1.5 text-xs font-medium transition-colors ${
                            isSelected
                              ? 'bg-brand-600 text-white'
                              : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
                          }`}
                        >
                          {isSelected ? 'بستن' : 'اعضا'}
                        </button>
                      </div>
                    </div>
                    {isSelected && (
                      <div className="mt-3 border-t border-slate-100 pt-3">
                        <p className="mb-2 text-[11px] font-medium text-slate-400">اعضای گروه</p>
                        {membersLoading ? (
                          <p className="text-xs text-slate-400">در حال بارگذاری…</p>
                        ) : members.length === 0 ? (
                          <p className="rounded-lg bg-slate-50 px-3 py-4 text-center text-xs text-slate-400">
                            عضوی در گروه نیست.
                          </p>
                        ) : (
                          <ul className="space-y-1.5">
                            {members.map((m) => (
                              <li
                                key={m.user_id}
                                className="flex items-center justify-between gap-2 rounded-xl bg-slate-50 px-3 py-2 text-xs"
                              >
                                <span className="min-w-0 truncate">
                                  <span className="font-medium text-slate-700">{userNameOf(m.user_id)}</span>
                                  <span className="mr-2 text-slate-400" dir="ltr">{m.user_id.slice(0, 8)}…</span>
                                </span>
                                <div className="flex shrink-0 items-center gap-2">
                                  {m.is_manager && (
                                    <span className="badge bg-violet-100 text-violet-700">مدیر</span>
                                  )}
                                  {m.user_id === user?.id && (
                                    <span className="badge bg-brand-50 text-brand-700">شما</span>
                                  )}
                                </div>
                              </li>
                            ))}
                          </ul>
                        )}
                        {isOwner && (
                          <form onSubmit={onAddMember} className="mt-3 flex flex-col sm:flex-row gap-2">
                            <div className="flex-1 flex flex-col gap-1">
                              <label className="text-[11px] text-slate-500">افزودن کاربر به گروه</label>
                              <select
                                className="input text-xs"
                                value={memberUid}
                                onChange={(e) => setMemberUid(e.target.value)}
                                disabled={adding || nonMembers.length === 0}
                              >
                                <option value="">— انتخاب از کاربران سیستم —</option>
                                {nonMembers.map((u) => (
                                  <option key={u.id} value={u.id}>
                                    {u.display_name || u.username}{u.is_active ? '' : ' (غیرفعال)'}
                                  </option>
                                ))}
                              </select>
                              {nonMembers.length === 0 && !usersLoading && (
                                <p className="text-[10px] text-slate-400">همه‌ی کاربران سیستم عضو این گروه هستند.</p>
                              )}
                              {usersLoading && <p className="text-[10px] text-slate-400">در حال بارگذاری کاربران…</p>}
                            </div>
                            <button
                              type="submit"
                              disabled={adding || !memberUid}
                              className="btn-ghost shrink-0 bg-brand-50 text-brand-700 hover:bg-brand-100 self-end"
                            >
                              <Icon d={P.plus} className="h-4 w-4" />
                              {adding ? '...' : 'افزودن'}
                            </button>
                          </form>
                        )}
                      </div>
                    )}
                  </li>
                )
              })}
            </ul>
          )}
        </section>

        {/* Create */}
        <section className="card animate-fade-up stagger-2">
          <h2 className="mb-3 flex items-center gap-2 text-base font-bold text-slate-800">
            <Icon d={P.plus} className="h-5 w-5 text-brand-500" />
            گروه جدید
          </h2>
          <form onSubmit={onCreate} className="space-y-4">
            <div>
              <label className="label" htmlFor="grp-name">نام گروه</label>
              <input
                id="grp-name"
                className="input"
                placeholder="مثلاً تیم توسعه"
                value={name}
                onChange={(e) => setName(e.target.value)}
              />
            </div>
            <div>
              <label className="label" htmlFor="grp-desc">توضیح</label>
              <input
                id="grp-desc"
                className="input"
                placeholder="توضیح (اختیاری)"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
              />
            </div>
            <div>
              <label className="label" htmlFor="grp-privacy">حریم خصوصی</label>
              <select
                id="grp-privacy"
                className="input"
                value={privacy}
                onChange={(e) => setPrivacy(e.target.value)}
              >
                {PRIVACY_OPTIONS.map(([v, l]) => (
                  <option key={v} value={v}>{l}</option>
                ))}
              </select>
            </div>
            <button type="submit" disabled={creating || !name.trim()} className="btn-primary w-full">
              <Icon d={P.check} className="h-4 w-4" />
              {creating ? '...' : 'ایجاد گروه'}
            </button>
          </form>
        </section>
      </div>
    </div>
  )
}
```

==========================================================================================
## FILE: bastehE_frontend/web/src/features/InboxPage.tsx
## SIZE: 12638 bytes
==========================================================================================

```tsx
import { useCallback, useEffect, useState } from 'react'
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
  inbox: 'M22 12h-6l-2 3h-4l-2-3H2M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z',
  check: 'M20 6 9 17l-5-5',
  x: 'M18 6 6 18M6 6l12 12',
  clock: 'M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20zM12 6v6l4 2',
  send: 'M22 2 11 13M22 2l-7 20-4-9-9-4z',
  plus: 'M12 5v14M5 12h14',
  list: 'M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01',
}

type Tab = 'inbox' | 'outbox' | 'compose'

interface InboxRow {
  id: string
  sender_id: string
  recipient_id: string
  item_type: string
  entity_type?: string | null
  entity_id?: string | null
  title: string
  message?: string | null
  priority: string
  action_state: string
  receipt_state: string
  seen_at?: string | null
  acted_at?: string | null
  response_note?: string | null
  created_at: string
}

interface OutboxRow {
  id: string
  recipient_id: string
  item_type: string
  title: string
  message?: string | null
  created_at: string
  read_receipt: boolean
}

function fmt(iso: string) {
  if (!iso) return ''
  try {
    return new Intl.DateTimeFormat('fa-IR', {
      day: '2-digit',
      month: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
    }).format(new Date(iso))
  } catch {
    return ''
  }
}

const ITEM_TYPES: Record<string, string> = {
  meeting_invite: 'دعوت به نشست',
  share_request: 'درخواست دسترسی',
  task_assignment: 'تعیین وظیفه',
  chat_invite: 'دعوت به گفتگو',
  approval: 'تأیید درخواست',
}

const ACTION_TINT: Record<string, string> = {
  pending: 'bg-amber-50 text-amber-700',
  accepted: 'bg-emerald-50 text-emerald-700',
  rejected: 'bg-red-50 text-red-600',
  deferred: 'bg-sky-50 text-sky-700',
  expired: 'bg-slate-100 text-slate-500',
}

export default function InboxPage() {
  const { user } = useAuth()
  const [tab, setTab] = useState<Tab>('inbox')
  const [items, setItems] = useState<InboxRow[]>([])
  const [outbox, setOutbox] = useState<OutboxRow[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [acting, setActing] = useState<string | null>(null)

  // Compose form
  const [recipientId, setRecipientId] = useState('')
  const [itemType, setItemType] = useState('task_assignment')
  const [title, setTitle] = useState('')
  const [message, setMessage] = useState('')
  const [priority, setPriority] = useState('normal')
  const [sending, setSending] = useState(false)

  const refresh = useCallback(async () => {
    if (!user?.id) return
    setError(null)
    try {
      const [inRes, outRes] = await Promise.all([
        api.get(`/inbox/${user.id}`),
        api.get('/inbox/outbox'),
      ])
      setItems(((inRes.data as any)?.data?.items ?? []) as InboxRow[])
      setOutbox(((outRes.data as any)?.data?.items ?? []) as OutboxRow[])
    } catch {
      setError('دریافت صندوق ورودی ناموفق بود.')
    } finally {
      setLoading(false)
    }
  }, [user?.id])

  useEffect(() => {
    void refresh()
  }, [refresh])

  const onAct = async (id: string, action: 'accepted' | 'rejected' | 'deferred') => {
    setActing(id)
    setError(null)
    try {
      await api.post(`/inbox/${id}/act`, { action })
      await refresh()
    } catch {
      setError('ثبت عملیات ناموفق بود.')
    } finally {
      setActing(null)
    }
  }

  const markRead = async (id: string) => {
    try {
      await api.post(`/inbox/${id}/read`)
    } catch {
      /* non-critical */
    }
  }

  const onCreate = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!recipientId.trim() || !title.trim()) return
    setSending(true)
    setError(null)
    try {
      await api.post('/inbox/', {
        recipient_id: recipientId.trim(),
        item_type: itemType,
        title: title.trim(),
        message: message.trim() || undefined,
        priority,
      })
      setRecipientId('')
      setTitle('')
      setMessage('')
      setPriority('normal')
      await refresh()
      setTab('outbox')
    } catch {
      setError('ارسال آیتم ناموفق بود. شناسه گیرنده را بررسی کنید.')
    } finally {
      setSending(false)
    }
  }

  const pending = items.filter((i) => i.action_state === 'pending')

  return (
    <div className="space-y-5 p-4 sm:p-6">
      <div className="animate-fade-up flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-bold text-slate-900 sm:text-2xl">صندوق ورودی</h1>
          <p className="mt-0.5 text-xs text-slate-500 sm:text-sm">پیگیری‌ها، درخواست‌ها و تأییدها</p>
        </div>
        <div className="flex gap-1.5 rounded-2xl bg-white p-1 shadow-sm border border-slate-200">
          {(
            [
              ['inbox', `ورودی (${pending.length})`],
              ['outbox', 'ارسال‌شده'],
              ['compose', 'آیتم جدید'],
            ] as [Tab, string][]
          ).map(([k, label]) => (
            <button
              key={k}
              onClick={() => setTab(k)}
              className={`rounded-xl px-4 py-2 text-xs font-medium transition-colors ${
                tab === k ? 'bg-brand-600 text-white shadow' : 'text-slate-600 hover:bg-slate-50'
              }`}
            >
              {label}
            </button>
          ))}
        </div>
      </div>

      {error && (
        <p className="animate-fade-in rounded-2xl bg-red-50 px-4 py-3 text-xs text-red-600">{error}</p>
      )}

      {tab === 'compose' ? (
        <section className="card animate-fade-up max-w-2xl">
          <h2 className="mb-4 text-base font-bold text-slate-800">ارسال آیتم جدید</h2>
          <form onSubmit={onCreate} className="space-y-4">
            <div>
              <label className="label" htmlFor="inbox-recipient">شناسه گیرنده (UUID)</label>
              <input
                id="inbox-recipient"
                className="input"
                dir="ltr"
                placeholder="مثلاً afd1b15e-f73a-4cad-96d3-bd96cf47f5dc"
                value={recipientId}
                onChange={(e) => setRecipientId(e.target.value)}
              />
            </div>
            <div>
              <label className="label" htmlFor="inbox-type">نوع آیتم</label>
              <select
                id="inbox-type"
                className="input"
                value={itemType}
                onChange={(e) => setItemType(e.target.value)}
              >
                {Object.entries(ITEM_TYPES).map(([v, l]) => (
                  <option key={v} value={v}>{l}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="label" htmlFor="inbox-title">عنوان</label>
              <input
                id="inbox-title"
                className="input"
                placeholder="عنوان آیتم"
                value={title}
                onChange={(e) => setTitle(e.target.value)}
              />
            </div>
            <div>
              <label className="label" htmlFor="inbox-msg">پیام</label>
              <textarea
                id="inbox-msg"
                className="input min-h-[5rem]"
                placeholder="توضیحات (اختیاری)"
                value={message}
                onChange={(e) => setMessage(e.target.value)}
              />
            </div>
            <div>
              <label className="label" htmlFor="inbox-prio">اولویت</label>
              <select
                id="inbox-prio"
                className="input"
                value={priority}
                onChange={(e) => setPriority(e.target.value)}
              >
                <option value="normal">عادی</option>
                <option value="high">بالا</option>
                <option value="low">پایین</option>
              </select>
            </div>
            <button type="submit" disabled={sending || !recipientId.trim() || !title.trim()} className="btn-primary">
              <Icon d={P.send} className="h-4 w-4" />
              {sending ? '...' : 'ارسال'}
            </button>
          </form>
        </section>
      ) : (
        <section className="card animate-fade-up">
          <h2 className="mb-3 text-base font-bold text-slate-800">
            {tab === 'inbox' ? 'آیتم‌های دریافتی' : 'آیتم‌های ارسال‌شده'}
          </h2>
          {loading ? (
            <p className="text-xs text-slate-400">در حال بارگذاری…</p>
          ) : tab === 'inbox' && items.length === 0 ? (
            <p className="rounded-xl bg-slate-50 px-4 py-8 text-center text-xs text-slate-400">
              آیتمی در صندوق نیست.
            </p>
          ) : tab === 'outbox' && outbox.length === 0 ? (
            <p className="rounded-xl bg-slate-50 px-4 py-8 text-center text-xs text-slate-400">
              آیتمی ارسال نکرده‌اید.
            </p>
          ) : (
            <ul className="max-h-[30rem] space-y-3 overflow-y-auto pl-1">
              {(tab === 'inbox' ? items : outbox as unknown as InboxRow[]).map((it) => (
                <li
                  key={it.id}
                  onClick={() => {
                    if (tab === 'inbox' && it.receipt_state === 'sent') void markRead(it.id)
                  }}
                  className="rounded-2xl border border-slate-100 bg-white p-4 shadow-sm card-hover"
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-medium text-slate-800">{it.title}</span>
                        <span className="badge bg-slate-100 text-slate-500">
                          {ITEM_TYPES[it.item_type] ?? it.item_type}
                        </span>
                        {tab === 'inbox' && (
                          <span className={`badge ${ACTION_TINT[(it as InboxRow).action_state] ?? ''}`}>
                            {(it as InboxRow).action_state}
                          </span>
                        )}
                      </div>
                      {it.message && (
                        <p className="mt-1 text-xs leading-5 text-slate-600">{it.message}</p>
                      )}
                    </div>
                    <span className="badge shrink-0 bg-slate-50 text-slate-400">{fmt(it.created_at)}</span>
                  </div>
                  {tab === 'inbox' && (it as InboxRow).action_state === 'pending' && (
                    <div className="mt-3 flex flex-wrap gap-2">
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
                        onClick={() => void onAct(it.id, 'deferred')}
                        className="btn-ghost disabled:opacity-50 bg-sky-50 text-sky-700 hover:bg-sky-100"
                      >
                        <Icon d={P.clock} className="h-3.5 w-3.5" />
                        به تعویق
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
                  )}
                </li>
              ))}
            </ul>
          )}
        </section>
      )}
    </div>
  )
}
```

==========================================================================================
## FILE: bastehE_frontend/web/src/features/ReportsPage.tsx
## SIZE: 9459 bytes
==========================================================================================

```tsx
import { useCallback, useEffect, useState } from 'react'
import { apiRef as api } from '../api/client'

function Icon({ d, className = 'h-5 w-5' }: { d: string; className?: string }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8}
      strokeLinecap="round" strokeLinejoin="round" className={className} aria-hidden>
      <path d={d} />
    </svg>
  )
}

const P = {
  chart: 'M18 20V10M12 20V4M6 20v-6',
  grid: 'M3 3h7v7H3zM14 3h7v7h-7zM3 14h7v7H3zM14 14h7v7h-7z',
  plus: 'M12 5v14M5 12h14',
  refresh: 'M23 4v6h-6M1 20v-6h6M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15',
  check: 'M20 6 9 17l-5-5',
}

interface LayoutRow {
  id: string
  name: string
  view_mode: string
  is_default: boolean
}

interface WidgetRow {
  widget_key: string
  platform: string
  is_visible: boolean
  position_x: number
  position_y: number
  width: number
  height: number
}

const VIEW_MODES = ['daily', 'weekly', 'monthly'] as const

export default function ReportsPage() {
  const [layouts, setLayouts] = useState<LayoutRow[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const [layoutName, setLayoutName] = useState('')
  const [viewMode, setViewMode] = useState<string>('daily')
  const [savingLayout, setSavingLayout] = useState(false)

  const [widgets, setWidgets] = useState<WidgetRow[]>([])
  const [widgetsLoaded, setWidgetsLoaded] = useState(false)
  const [savingWidgets, setSavingWidgets] = useState(false)

  const loadLayouts = useCallback(async () => {
    setError(null)
    try {
      const res = await api.get('/reporting/layouts')
      setLayouts(((res.data as any)?.data?.layouts ?? []) as LayoutRow[])
    } catch {
      setError('دریافت چیدمان‌های داشبورد ناموفق بود.')
    } finally {
      setLoading(false)
    }
  }, [])

  const loadWidgets = useCallback(async () => {
    try {
      const res = await api.get('/reporting/widgets/settings')
      setWidgets(((res.data as any)?.data?.widgets?.widgets ?? []) as WidgetRow[])
    } catch {
      /* non-critical */
    } finally {
      setWidgetsLoaded(true)
    }
  }, [])

  useEffect(() => {
    void loadLayouts()
    void loadWidgets()
  }, [loadLayouts, loadWidgets])

  const onSaveLayout = async (e: React.FormEvent) => {
    e.preventDefault()
    setSavingLayout(true)
    setError(null)
    try {
      await api.post('/reporting/layouts', {
        name: layoutName.trim() || 'چیدمان جدید',
        view_mode: viewMode,
        is_default: false,
        schema_version: 1,
        blocks: [],
      })
      setLayoutName('')
      await loadLayouts()
    } catch {
      setError('ذخیره چیدمان ناموفق بود.')
    } finally {
      setSavingLayout(false)
    }
  }

  const toggleWidget = (key: string) => {
    setWidgets((prev) =>
      prev.map((w) => (w.widget_key === key ? { ...w, is_visible: !w.is_visible } : w)),
    )
  }

  const onSaveWidgets = async () => {
    setSavingWidgets(true)
    setError(null)
    try {
      await api.post('/reporting/widgets/settings', {
        widgets: widgets.map((w) => ({ ...w })),
      })
    } catch {
      setError('ذخیره تنظیمات ویجت‌ها ناموفق بود.')
    } finally {
      setSavingWidgets(false)
    }
  }

  const onResetWidgets = async () => {
    setError(null)
    try {
      await api.post('/reporting/widgets/settings/reset')
      setWidgets([])
    } catch {
      setError('بازیابی پیش‌فرض ویجت‌ها ناموفق بود.')
    }
  }

  return (
    <div className="space-y-5 p-4 sm:p-6">
      <div className="animate-fade-up">
        <h1 className="text-xl font-bold text-slate-900 sm:text-2xl">گزارش‌ها</h1>
        <p className="mt-0.5 text-xs text-slate-500 sm:text-sm">چیدمان داشبورد و تنظیمات ویجت‌ها</p>
      </div>

      {error && (
        <p className="animate-fade-in rounded-2xl bg-red-50 px-4 py-3 text-xs text-red-600">{error}</p>
      )}

      <div className="grid items-start gap-5 lg:grid-cols-2">
        {/* Layouts */}
        <section className="card animate-fade-up stagger-1">
          <div className="mb-3 flex items-center justify-between">
            <h2 className="flex items-center gap-2 text-base font-bold text-slate-800">
              <Icon d={P.grid} className="h-5 w-5 text-brand-500" />
              چیدمان‌های داشبورد
            </h2>
            <span className="badge bg-brand-50 text-brand-700">{layouts.length} چیدمان</span>
          </div>
          <form onSubmit={onSaveLayout} className="mb-4 space-y-3 rounded-2xl bg-slate-50 p-3">
            <div className="flex gap-2">
              <input
                className="input border-0 bg-white text-xs shadow-sm"
                placeholder="نام چیدمان"
                value={layoutName}
                onChange={(e) => setLayoutName(e.target.value)}
              />
              <select
                className="input w-36 border-0 bg-white text-xs shadow-sm"
                value={viewMode}
                onChange={(e) => setViewMode(e.target.value)}
              >
                {VIEW_MODES.map((v) => (
                  <option key={v} value={v}>{v}</option>
                ))}
              </select>
            </div>
            <button type="submit" disabled={savingLayout} className="btn-primary w-full text-xs">
              <Icon d={P.plus} className="h-4 w-4" />
              {savingLayout ? '...' : 'ذخیره چیدمان'}
            </button>
          </form>
          {loading ? (
            <p className="text-xs text-slate-400">در حال بارگذاری…</p>
          ) : layouts.length === 0 ? (
            <p className="rounded-xl bg-slate-50 px-4 py-6 text-center text-xs text-slate-400">
              چیدمانی ذخیره نشده است.
            </p>
          ) : (
            <ul className="space-y-2">
              {layouts.map((l) => (
                <li key={l.id} className="flex items-center justify-between gap-2 rounded-xl border border-slate-100 px-3.5 py-3">
                  <div className="min-w-0">
                    <p className="truncate text-sm font-medium text-slate-800">{l.name}</p>
                    <p className="text-[11px] text-slate-400">{l.view_mode}</p>
                  </div>
                  {l.is_default ? (
                    <span className="badge shrink-0 bg-emerald-50 text-emerald-700">پیش‌فرض</span>
                  ) : (
                    <span className="badge shrink-0 bg-slate-100 text-slate-500">عادی</span>
                  )}
                </li>
              ))}
            </ul>
          )}
        </section>

        {/* Widgets */}
        <section className="card animate-fade-up stagger-2">
          <div className="mb-3 flex items-center justify-between">
            <h2 className="flex items-center gap-2 text-base font-bold text-slate-800">
              <Icon d={P.chart} className="h-5 w-5 text-brand-500" />
              تنظیمات ویجت‌ها
            </h2>
            <button onClick={() => void onResetWidgets()} className="btn-ghost p-2 text-slate-400 hover:text-slate-700">
              <Icon d={P.refresh} className="h-4 w-4" />
              پیش‌فرض
            </button>
          </div>
          {!widgetsLoaded ? (
            <p className="text-xs text-slate-400">در حال بارگذاری…</p>
          ) : widgets.length === 0 ? (
            <p className="rounded-xl bg-slate-50 px-4 py-6 text-center text-xs text-slate-400">
              ویجتی تنظیم نشده است. وضعیت را تغییر دهید و ذخیره کنید.
            </p>
          ) : (
            <ul className="max-h-72 space-y-2 overflow-y-auto pl-1">
              {widgets.map((w) => (
                <li key={w.widget_key} className="flex items-center justify-between gap-2 rounded-xl border border-slate-100 px-3.5 py-2.5">
                  <div className="min-w-0">
                    <p className="truncate text-sm font-medium text-slate-800">{w.widget_key}</p>
                    <p className="text-[11px] text-slate-400">
                      {w.platform} · {w.width}×{w.height}
                    </p>
                  </div>
                  <button
                    onClick={() => toggleWidget(w.widget_key)}
                    className={`relative h-6 w-11 shrink-0 rounded-full transition-colors ${
                      w.is_visible ? 'bg-brand-500' : 'bg-slate-200'
                    }`}
                    aria-label={w.widget_key}
                  >
                    <span
                      className={`absolute top-0.5 h-5 w-5 rounded-full bg-white shadow transition-all ${
                        w.is_visible ? 'right-0.5' : 'right-5'
                      }`}
                    />
                  </button>
                </li>
              ))}
            </ul>
          )}
          {widgets.length > 0 && (
            <button onClick={() => void onSaveWidgets()} disabled={savingWidgets} className="btn-primary mt-4 w-full text-xs">
              <Icon d={P.check} className="h-4 w-4" />
              {savingWidgets ? '...' : 'ذخیره تنظیمات'}
            </button>
          )}
        </section>
      </div>
    </div>
  )
}
```

==========================================================================================
