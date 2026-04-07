import { useState } from 'preact/hooks'
import { csrfFetch, resolveSource } from '../api'

interface ActionWidgetProps {
  label?: string
  endpoint?: string
  method?: string
  confirm?: string
  successMsg?: string
  instanceName: string
}

export function ActionWidget({ label, endpoint, method = 'POST', confirm: confirmMsg, successMsg, instanceName }: ActionWidgetProps) {
  const [status, setStatus] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  async function handleClick() {
    if (confirmMsg && !window.confirm(confirmMsg)) return
    if (!endpoint) return

    setLoading(true)
    setStatus(null)
    try {
      const url = resolveSource(endpoint, instanceName)
      const resp = await csrfFetch(url, { method })
      if (resp.ok) {
        setStatus(successMsg || 'Done')
      } else {
        const text = await resp.text()
        setStatus(`Error: ${text || resp.statusText}`)
      }
    } catch (e) {
      setStatus((e as Error).message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div class="flex items-center gap-3">
      <button
        onClick={handleClick}
        disabled={loading}
        class="px-3 py-1.5 rounded-md bg-sky-600 text-white hover:bg-sky-700 disabled:opacity-50 text-sm"
      >
        {loading ? 'Working...' : (label || 'Action')}
      </button>
      {status && <span class="text-xs text-neutral-500">{status}</span>}
    </div>
  )
}
