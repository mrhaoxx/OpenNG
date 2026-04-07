import { useEffect, useState } from 'react'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Separator } from '@/components/ui/separator'
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

  const hasDeps = (detail.dependsOn?.length ?? 0) > 0 || (detail.dependedBy?.length ?? 0) > 0

  return (
    <div className="p-6 max-w-5xl">
      {/* Header */}
      <div className="mb-6">
        <div className="flex items-center gap-3">
          <h1 className="text-xl font-semibold font-mono">{detail.name}</h1>
          <Badge variant="secondary" className="font-mono text-xs">{detail.kind}</Badge>
        </div>
      </div>

      {/* Relationships */}
      {hasDeps && (
        <Card className="mb-6">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium">Dependencies</CardTitle>
          </CardHeader>
          <CardContent className="flex gap-8 text-sm">
            {(detail.dependsOn?.length ?? 0) > 0 && (
              <div>
                <p className="text-xs text-muted-foreground mb-2">Depends on</p>
                <div className="flex flex-wrap gap-1.5">
                  {detail.dependsOn!.map(d => (
                    <a key={d} href={`#/instance/${d}`}
                      className="inline-block px-2 py-0.5 rounded bg-secondary text-secondary-foreground font-mono text-xs hover:bg-primary hover:text-primary-foreground transition-colors">
                      {d}
                    </a>
                  ))}
                </div>
              </div>
            )}
            {(detail.dependedBy?.length ?? 0) > 0 && (
              <div>
                <p className="text-xs text-muted-foreground mb-2">Depended by</p>
                <div className="flex flex-wrap gap-1.5">
                  {detail.dependedBy!.map(d => (
                    <a key={d} href={`#/instance/${d}`}
                      className="inline-block px-2 py-0.5 rounded bg-secondary text-secondary-foreground font-mono text-xs hover:bg-primary hover:text-primary-foreground transition-colors">
                      {d}
                    </a>
                  ))}
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      )}

      <Separator className="mb-6" />

      {/* Custom widgets from AdminProvider */}
      {detail.admin?.root ? (
        <WidgetRenderer widget={detail.admin.root} instanceName={name} />
      ) : (
        <div className="text-sm text-muted-foreground">
          No monitoring widgets for this instance.
        </div>
      )}
    </div>
  )
}
