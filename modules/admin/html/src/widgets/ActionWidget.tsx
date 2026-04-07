import { useState } from 'react'
import { Button } from '@/components/ui/button'
import { resolveSource, csrfFetch } from '@/lib/api'

export default function ActionWidget(props: Record<string, unknown> & { instanceName: string }) {
  const { label, endpoint, method, confirm: confirmMsg, variant, instanceName } = props
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<string | null>(null)
  const url = resolveSource(String(endpoint ?? ''), instanceName)

  const onClick = async () => {
    if (confirmMsg && !window.confirm(String(confirmMsg))) return
    setLoading(true)
    setResult(null)
    try {
      const resp = await csrfFetch(url, { method: String(method || 'POST') })
      setResult(resp.ok ? 'OK' : `Error ${resp.status}`)
    } catch {
      setResult('Failed')
    }
    setLoading(false)
  }

  return (
    <div className="mb-3 flex items-center gap-3">
      <Button
        onClick={onClick}
        disabled={loading}
        variant={variant === 'danger' ? 'destructive' : 'default'}
        size="sm"
      >
        {loading ? '…' : String(label ?? 'Action')}
      </Button>
      {result && <span className="text-xs text-muted-foreground">{result}</span>}
    </div>
  )
}
