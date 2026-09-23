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