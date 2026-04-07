import { useEffect, useState } from 'react'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { resolveSource } from '@/lib/api'

interface ColumnDef {
  field: string
  label: string
  type?: string
}

function parsePoll(s: unknown): number {
  if (typeof s !== 'string') return 0
  const m = s.match(/^(\d+)(ms|s|m)?$/)
  if (!m) return 0
  const n = parseInt(m[1])
  if (m[2] === 'ms') return n
  if (m[2] === 'm') return n * 60000
  return n * 1000
}

function fmt(val: unknown, type?: string): string {
  if (val == null) return '–'
  if (type === 'datetime' && typeof val === 'string') return new Date(val).toLocaleString()
  if (type === 'bytes' && typeof val === 'number') {
    if (val < 1024) return `${val} B`
    if (val < 1048576) return `${(val / 1024).toFixed(1)} KB`
    return `${(val / 1048576).toFixed(1)} MB`
  }
  return String(val)
}

export default function TableWidget(props: Record<string, unknown> & { instanceName: string }) {
  const { source, columns, poll, instanceName } = props
  const [data, setData] = useState<Record<string, Record<string, unknown>> | null>(null)
  const url = resolveSource(String(source ?? ''), instanceName)
  const cols = (columns as ColumnDef[]) ?? []
  const interval = parsePoll(poll)

  useEffect(() => {
    let cancelled = false
    const load = () => fetch(url).then(r => r.json()).then(d => { if (!cancelled) setData(d) }).catch(() => {})
    load()
    if (interval > 0) {
      const id = setInterval(load, interval)
      return () => { cancelled = true; clearInterval(id) }
    }
    return () => { cancelled = true }
  }, [url, interval])

  const rows = data
    ? Object.entries(data).map(([id, v]) => ({ _id: id, ...(v as Record<string, unknown>) } as Record<string, unknown>))
    : []

  return (
    <div className="rounded-lg border border-border overflow-hidden mb-4">
      <Table>
        <TableHeader>
          <TableRow className="hover:bg-transparent">
            <TableHead className="text-xs w-24">ID</TableHead>
            {cols.map(c => <TableHead key={c.field} className="text-xs">{c.label || c.field}</TableHead>)}
          </TableRow>
        </TableHeader>
        <TableBody>
          {rows.length === 0 && (
            <TableRow>
              <TableCell colSpan={cols.length + 1} className="text-center text-muted-foreground py-8">
                {data === null ? 'Loading…' : 'No data'}
              </TableCell>
            </TableRow>
          )}
          {rows.map(row => (
            <TableRow key={String(row._id)}>
              <TableCell className="font-mono text-xs">{String(row._id)}</TableCell>
              {cols.map(c => (
                <TableCell key={c.field} className="text-xs">{fmt(row[c.field] as unknown, c.type)}</TableCell>
              ))}
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  )
}
