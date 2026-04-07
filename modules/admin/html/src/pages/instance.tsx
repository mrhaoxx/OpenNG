import { useState, useEffect } from 'preact/hooks'
import { renderWidget } from '../widgets/renderer'
import type { Widget } from '../widgets/types'

interface InstanceMeta {
  name: string
  kind: string
  admin?: {
    title?: string
    category?: string
    root?: Widget
  }
}

interface InstanceProps {
  name: string
}

export function Instance({ name }: InstanceProps) {
  const [meta, setMeta] = useState<InstanceMeta | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    setLoading(true)
    setError(null)
    setMeta(null)
    fetch(`/api/v1/instance/${encodeURIComponent(name)}`)
      .then(r => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`)
        return r.json()
      })
      .then(data => {
        setMeta(data)
        setLoading(false)
      })
      .catch(e => {
        setError(e.message)
        setLoading(false)
      })
  }, [name])

  if (loading) {
    return (
      <div class="flex items-center justify-center h-32 text-neutral-400 text-sm">
        Loading...
      </div>
    )
  }

  if (error) {
    return (
      <div class="p-6">
        <div class="text-red-500 text-sm">Error: {error}</div>
      </div>
    )
  }

  if (!meta) return null

  const admin = meta.admin
  const title = admin?.title || meta.name

  return (
    <div class="flex flex-col h-full">
      <div class="px-6 py-4 border-b border-neutral-200 dark:border-neutral-800 shrink-0">
        <h1 class="text-xl font-semibold text-neutral-900 dark:text-neutral-100">{title}</h1>
        <div class="flex gap-3 mt-1">
          <span class="text-xs bg-neutral-100 dark:bg-neutral-800 text-neutral-500 px-2 py-0.5 rounded font-mono">{meta.kind}</span>
          {admin?.category && (
            <span class="text-xs bg-sky-50 dark:bg-sky-900/30 text-sky-600 dark:text-sky-400 px-2 py-0.5 rounded">{admin.category}</span>
          )}
        </div>
      </div>
      <div class="flex-1 overflow-auto p-6">
        {admin?.root ? (
          renderWidget(admin.root, name)
        ) : (
          <div class="text-neutral-400 text-sm">This instance has no admin interface.</div>
        )}
      </div>
    </div>
  )
}
