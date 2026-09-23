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