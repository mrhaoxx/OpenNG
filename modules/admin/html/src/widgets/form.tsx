import { useState } from 'preact/hooks'
import { csrfFetch, resolveSource } from '../api'

interface FormField {
  name: string
  label?: string
  type?: 'text' | 'number' | 'checkbox' | 'textarea' | 'select'
  options?: string[]
  placeholder?: string
  required?: boolean
}

interface FormWidgetProps {
  fields?: FormField[]
  endpoint?: string
  method?: string
  submitLabel?: string
  instanceName: string
}

export function FormWidget({ fields = [], endpoint, method = 'POST', submitLabel = 'Submit', instanceName }: FormWidgetProps) {
  const [values, setValues] = useState<Record<string, string>>({})
  const [status, setStatus] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  function setValue(name: string, value: string) {
    setValues(prev => ({ ...prev, [name]: value }))
  }

  async function handleSubmit(e: Event) {
    e.preventDefault()
    if (!endpoint) return

    setLoading(true)
    setStatus(null)
    try {
      const url = resolveSource(endpoint, instanceName)
      const resp = await csrfFetch(url, {
        method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(values)
      })
      if (resp.ok) {
        setStatus('Success')
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
    <form onSubmit={handleSubmit} class="flex flex-col gap-3">
      {fields.map(f => (
        <div key={f.name} class="flex flex-col gap-1">
          {f.label && (
            <label class="text-sm font-medium text-neutral-700 dark:text-neutral-300">{f.label}</label>
          )}
          {f.type === 'textarea' ? (
            <textarea
              name={f.name}
              placeholder={f.placeholder}
              required={f.required}
              value={values[f.name] || ''}
              onInput={(e) => setValue(f.name, (e.target as HTMLTextAreaElement).value)}
              class="px-2 py-1.5 border border-neutral-300 dark:border-neutral-600 rounded text-sm bg-white dark:bg-neutral-800 text-neutral-900 dark:text-neutral-100 font-mono resize-y min-h-[80px]"
            />
          ) : f.type === 'select' ? (
            <select
              name={f.name}
              required={f.required}
              value={values[f.name] || ''}
              onChange={(e) => setValue(f.name, (e.target as HTMLSelectElement).value)}
              class="px-2 py-1.5 border border-neutral-300 dark:border-neutral-600 rounded text-sm bg-white dark:bg-neutral-800 text-neutral-900 dark:text-neutral-100"
            >
              <option value="">Select...</option>
              {f.options?.map(opt => <option key={opt} value={opt}>{opt}</option>)}
            </select>
          ) : (
            <input
              type={f.type || 'text'}
              name={f.name}
              placeholder={f.placeholder}
              required={f.required}
              value={values[f.name] || ''}
              onInput={(e) => setValue(f.name, (e.target as HTMLInputElement).value)}
              class="px-2 py-1.5 border border-neutral-300 dark:border-neutral-600 rounded text-sm bg-white dark:bg-neutral-800 text-neutral-900 dark:text-neutral-100"
            />
          )}
        </div>
      ))}
      <div class="flex items-center gap-3">
        <button
          type="submit"
          disabled={loading}
          class="px-3 py-1.5 rounded bg-sky-600 text-white hover:bg-sky-700 disabled:opacity-50 text-sm"
        >
          {loading ? 'Submitting...' : submitLabel}
        </button>
        {status && <span class="text-xs text-neutral-500">{status}</span>}
      </div>
    </form>
  )
}
