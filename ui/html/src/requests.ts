import './index.css'

type RequestInfo = Record<string, any>
type SortKey = 'id' | 'method' | 'host' | 'uri' | 'src' | 'protocol' | 'code' | 'enc' | 'respwritten' | 'starttime'

function padZero(v: number): string { return v.toString().padStart(2, '0') }
function formatTime(ms: number): string {
  const seconds = Math.floor((ms / 1000) % 60)
  const minutes = Math.floor((ms / (1000 * 60)) % 60)
  const hours = Math.floor((ms / (1000 * 60 * 60)) % 24)
  return `${padZero(hours)}:${padZero(minutes)}:${padZero(seconds)}`
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

async function killRequest(requestId: string) {
  try {
    const resp = await fetch('/api/v1/http/request/kill', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `rid=${encodeURIComponent(requestId)}`
    })
    if (resp.ok) {
      showResult('Request killed successfully')
      void fetchRequests()
    } else {
      showResult('Failed to kill request')
    }
  } catch (e) {
    console.log(e)
  }
}

const tbody = document.getElementById('request-tbody') as HTMLTableSectionElement
let currentSort: { key: SortKey, dir: 'asc' | 'desc' } = { key: 'starttime', dir: 'desc' }

function compareValues(a: any, b: any, key: SortKey): number {
  if (key === 'code' || key === 'respwritten') {
    const na = Number(a[key] ?? 0)
    const nb = Number(b[key] ?? 0)
    return na - nb
  }
  if (key === 'starttime') {
    const ta = new Date(a[key]).getTime()
    const tb = new Date(b[key]).getTime()
    return ta - tb
  }
  const sa = String(a[key] ?? '')
  const sb = String(b[key] ?? '')
  return sa.localeCompare(sb)
}

function renderRows(rows: Array<Record<string, any>>) {
  tbody.innerHTML = ''
  for (const row of rows) {
    const tr = document.createElement('tr')
    tr.className = 'hover:bg-neutral-50 dark:hover:bg-neutral-800/40'

    const startTime = new Date(row.starttime)
    const elapsed = formatTime(Date.now() - startTime.getTime())

    tr.innerHTML = `
      <td class="px-3 py-2 font-mono">${row.id}</td>
      <td class="px-3 py-2">${row.method ?? ''}</td>
      <td class="px-3 py-2">${row.host ?? ''}</td>
      <td class="px-3 py-2">${row.uri ?? ''}</td>
      <td class="px-3 py-2 font-mono text-xs">${row.src ?? ''}</td>
      <td class="px-3 py-2">${row.protocol ?? ''}</td>
      <td class="px-3 py-2">${row.code ?? ''}</td>
      <td class="px-3 py-2">${row.enc ?? ''}</td>
      <td class="px-3 py-2">${row.respwritten ?? ''}</td>
      <td class="px-3 py-2 font-mono text-xs">${row.starttime ?? ''}</td>
      <td class="px-3 py-2 font-mono">${elapsed}</td>
      <td class="px-3 py-2">
        <button data-rid="${row.id}" class="px-2 py-1 rounded-md bg-red-600 text-white hover:bg-red-700 text-xs">Kill</button>
      </td>
    `
    tbody.appendChild(tr)
  }
}

async function fetchRequests() {
  try {
    const resp = await fetch('/api/v1/http/requests')
    const data = await resp.json() as Record<string, RequestInfo>

    const rows = Object.keys(data).map(id => ({ id, ...(data[id] || {}) }))
    rows.sort((a, b) => {
      const cmp = compareValues(a, b, currentSort.key)
      return currentSort.dir === 'asc' ? cmp : -cmp
    })

    renderRows(rows)
  } catch (e) {
    console.log(e)
  }
}

function setupSorting() {
  const thead = document.querySelectorAll('thead th[data-key]')
  thead.forEach(th => {
    th.addEventListener('click', () => {
      const key = (th as HTMLElement).dataset.key as SortKey
      if (!key) return
      if (currentSort.key === key) {
        currentSort = { key, dir: currentSort.dir === 'asc' ? 'desc' : 'asc' }
      } else {
        currentSort = { key, dir: 'asc' }
      }
      void fetchRequests()
    })
  })
}

function setupActions() {
  tbody.addEventListener('click', (ev) => {
    const target = ev.target as HTMLElement
    const btn = target.closest('button[data-rid]') as HTMLButtonElement | null
    if (btn && btn.dataset.rid) {
      void killRequest(btn.dataset.rid)
    }
  })
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

setupSorting()
setupActions()
void fetchRequests()
setInterval(fetchRequests, 1000)
void updateUptime()
setInterval(updateUptime, 1000)


