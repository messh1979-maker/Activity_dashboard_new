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