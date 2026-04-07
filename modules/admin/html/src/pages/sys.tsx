import { useState, useEffect } from 'preact/hooks'

interface SysInfo {
  uptime?: string
  connected?: boolean
}

export function Sys() {
  const [uptime, setUptime] = useState<string>('—')
  const [uptimeConnected, setUptimeConnected] = useState(true)
  const [sysData, setSysData] = useState<Record<string, any> | null>(null)

  useEffect(() => {
    async function fetchUptime() {
      try {
        const resp = await fetch('/api/v1/uptime', { redirect: 'error' })
        if (!resp.ok) throw new Error('bad')
        setUptime(await resp.text())
        setUptimeConnected(true)
      } catch {
        setUptime('Disconnected')
        setUptimeConnected(false)
      }
    }

    async function fetchSys() {
      try {
        const resp = await fetch('/sys')
        if (!resp.ok) return
        const data = await resp.json()
        setSysData(data)
      } catch { /* /sys may not exist */ }
    }

    fetchUptime()
    fetchSys()
    const timer = setInterval(fetchUptime, 2000)
    return () => clearInterval(timer)
  }, [])

  return (
    <div class="flex flex-col h-full">
      <div class="px-6 py-4 border-b border-neutral-200 dark:border-neutral-800 shrink-0">
        <h1 class="text-xl font-semibold text-neutral-900 dark:text-neutral-100">System</h1>
      </div>
      <div class="flex-1 overflow-auto p-6">
        <div class="grid grid-cols-1 gap-4 max-w-2xl">
          <div class="border border-neutral-200 dark:border-neutral-700 rounded-lg p-4">
            <div class="text-xs text-neutral-500 uppercase tracking-wider mb-1">Uptime</div>
            <div class={`text-2xl font-semibold ${uptimeConnected ? 'text-neutral-900 dark:text-neutral-100' : 'text-red-500'}`}>
              {uptime}
            </div>
          </div>

          {sysData && (
            <div class="border border-neutral-200 dark:border-neutral-700 rounded-lg p-4">
              <div class="text-sm font-semibold mb-3 text-neutral-900 dark:text-neutral-100">System Info</div>
              <dl class="grid grid-cols-[auto,1fr] gap-x-4 gap-y-2 text-sm">
                {Object.entries(sysData).map(([k, v]) => (
                  <>
                    <dt class="font-medium text-neutral-500 dark:text-neutral-400">{k}</dt>
                    <dd class="text-neutral-900 dark:text-neutral-100 font-mono text-xs break-all">
                      {typeof v === 'object' ? JSON.stringify(v) : String(v ?? '')}
                    </dd>
                  </>
                ))}
              </dl>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
