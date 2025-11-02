import './index.css'

type Connection = {
  bytesrx: number
  bytestx: number
  path: string
  protocols: string
  src: string
  starttime: string
}

type SortKey = 'id' | 'src' | 'path' | 'protocols' | 'bytesrx' | 'bytestx' | 'starttime'

const previousData: Record<string, { bytesRx: number; bytesTx: number; timestamp: number }> = {}
const tbody = document.getElementById('connection-tbody') as HTMLTableSectionElement
let currentSort: { key: SortKey, dir: 'asc' | 'desc' } = { key: 'starttime', dir: 'desc' }

function formatSpeed(speed: number): string {
  if (!isFinite(speed)) return '0 B/s'
  if (speed < 1024) return `${speed.toFixed(2)} B/s`
  if (speed < 1024 * 1024) return `${(speed / 1024).toFixed(2)} KB/s`
  return `${(speed / (1024 * 1024)).toFixed(2)} MB/s`
}

function padZero(v: number): string { return v.toString().padStart(2, '0') }
function formatTime(ms: number): string {
  const sec = Math.floor(ms / 1000)
  const h = Math.floor(sec / 3600)
  const m = Math.floor((sec % 3600) / 60)
  const s = sec % 60
  return `${padZero(h)}:${padZero(m)}:${padZero(s)}`
}

function showResult(message: string) {
  const resultText = document.getElementById('resultText')!
  resultText.textContent = message
  const dialog = document.getElementById('resultDialog') as HTMLDivElement
  dialog.classList.remove('hidden')
  dialog.classList.add('flex')
  document.getElementById('closeButton')!.addEventListener('click', () => {
    dialog.classList.add('hidden')
    dialog.classList.remove('flex')
  }, { once: true })
}

async function killConnection(cid: string) {
  const formData = new FormData()
  formData.append('cid', cid)
  try {
    const resp = await fetch('/api/v1/tcp/connection/kill', { method: 'POST', body: formData })
    if (resp.ok) {
      showResult('Connection killed successfully')
      void fetchData()
    } else {
      showResult('Failed to kill connection')
    }
  } catch (e) {
    console.error(e)
  }
}

async function updateUptime() {
  try {
    const resp = await fetch('/api/v1/uptime', { redirect: 'error' })
    if (!resp.ok) throw new Error('bad')
    const text = await resp.text()
    const el = document.getElementById('uptime')
    if (el) { el.textContent = text; el.classList.remove('disconnected') }
  } catch {
    const el = document.getElementById('uptime')
    if (el) { el.textContent = 'Disconnected'; el.classList.add('disconnected') }
  }
}

function compare(a: any, b: any, key: SortKey): number {
  if (key === 'bytesrx' || key === 'bytestx') {
    return Number(a[key] ?? 0) - Number(b[key] ?? 0)
  }
  if (key === 'starttime') {
    return new Date(a[key]).getTime() - new Date(b[key]).getTime()
  }
  return String(a[key] ?? '').localeCompare(String(b[key] ?? ''))
}

function renderRows(rows: Array<Record<string, any>>) {
  tbody.innerHTML = ''
  const now = Date.now()
  for (const row of rows) {
    const tr = document.createElement('tr')
    tr.className = 'hover:bg-neutral-50 dark:hover:bg-neutral-800/40'

    const start = new Date(row.starttime)
    const prev = previousData[row.id] ?? { bytesRx: row.bytesrx, bytesTx: row.bytestx, timestamp: now }
    const dt = Math.max(0.001, (now - prev.timestamp) / 1000)
    const speedRx = (row.bytesrx - prev.bytesRx) / dt
    const speedTx = (row.bytestx - prev.bytesTx) / dt

    tr.innerHTML = `
      <td class="px-3 py-2 font-mono">${row.id}</td>
      <td class="px-3 py-2 font-mono text-xs">${row.src}</td>
      <td class="px-3 py-2">${row.path}</td>
      <td class="px-3 py-2">${row.protocols}</td>
      <td class="px-3 py-2">${row.bytesrx}</td>
      <td class="px-3 py-2">${row.bytestx}</td>
      <td class="px-3 py-2 font-mono text-xs">${row.starttime}</td>
      <td class="px-3 py-2 font-mono">${formatTime(now - start.getTime())}</td>
      <td class="px-3 py-2 font-mono text-xs">${formatSpeed(speedRx)}</td>
      <td class="px-3 py-2 font-mono text-xs">${formatSpeed(speedTx)}</td>
      <td class="px-3 py-2">
        <button data-cid="${row.id}" class="px-2 py-1 rounded-md bg-red-600 text-white hover:bg-red-700 text-xs">Kill</button>
      </td>
    `
    tbody.appendChild(tr)

    previousData[row.id] = { bytesRx: row.bytesrx, bytesTx: row.bytestx, timestamp: now }
  }
}

async function fetchData() {
  try {
    const resp = await fetch('/api/v1/tcp/connections')
    const json = await resp.json() as Record<string, Connection>
    const rows = Object.keys(json).map(id => ({ id, ...(json[id] || {}) }))
    rows.sort((a, b) => {
      const cmp = compare(a, b, currentSort.key)
      return currentSort.dir === 'asc' ? cmp : -cmp
    })
    renderRows(rows)
  } catch (e) {
    console.error('Error:', e)
  }
}

function setupSorting() {
  const heads = document.querySelectorAll('thead th[data-key]')
  heads.forEach(th => {
    th.addEventListener('click', () => {
      const key = (th as HTMLElement).dataset.key as SortKey
      if (!key) return
      if (currentSort.key === key) {
        currentSort = { key, dir: currentSort.dir === 'asc' ? 'desc' : 'asc' }
      } else {
        currentSort = { key, dir: 'asc' }
      }
      void fetchData()
    })
  })
}

function setupActions() {
  tbody.addEventListener('click', (ev) => {
    const target = ev.target as HTMLElement
    const btn = target.closest('button[data-cid]') as HTMLButtonElement | null
    if (btn && btn.dataset.cid) {
      void killConnection(btn.dataset.cid)
    }
  })
}

setupSorting()
setupActions()
setInterval(fetchData, 1000)
void fetchData()
void updateUptime()
setInterval(updateUptime, 1000)
