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