import { useEffect, useState } from 'react'
import { Badge } from '@/components/ui/badge'
import type { InstanceDetail } from '@/lib/api'
import { fetchJSON } from '@/lib/api'
import WidgetRenderer from '@/widgets/WidgetRenderer'

export default function Instance({ name }: { name: string }) {
  const [detail, setDetail] = useState<InstanceDetail | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    setDetail(null)
    setError(null)
    fetchJSON<InstanceDetail>(`/api/v1/instance/${name}`)
      .then(setDetail)
      .catch(e => setError(e.message))
  }, [name])

  if (error) return <div className="p-6 text-destructive">Error: {error}</div>
  if (!detail) return <div className="flex items-center justify-center h-full text-muted-foreground">Loading...</div>

  return (
    <div className="p-6">
      <div className="mb-6">
        <div className="flex items-center gap-3">
          <h1 className="text-lg font-semibold">{detail.admin?.title || detail.name}</h1>
          <Badge variant="secondary" className="font-mono text-xs">{detail.kind}</Badge>
        </div>
        <p className="text-sm text-muted-foreground mt-1 font-mono">{detail.name}</p>
      </div>
      {detail.admin?.root ? (
        <WidgetRenderer widget={detail.admin.root} instanceName={name} />
      ) : (
        <div className="text-muted-foreground border border-dashed border-border rounded-xl p-12 text-center text-sm">
          This instance does not provide an admin interface.
        </div>
      )}
    </div>
  )
}
