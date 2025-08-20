import './index.css'

type Connection = {
  bytesrx: number
  bytestx: number
  path: string
  protocols: string
  src: string
  starttime: string
}

const previousData: Record<string, { bytesRx: number; bytesTx: number; timestamp: number }> = {}

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

async function fetchData() {
  try {
    const resp = await fetch('/api/v1/tcp/connections')
    const json = await resp.json() as Record<string, Connection>
    displayData(json)
  } catch (e) {
    console.error('Error:', e)
  }
}

function displayData(connections: Record<string, Connection>) {
  const ul = document.getElementById('connection-list') as HTMLUListElement
  ul.innerHTML = ''
  const now = Date.now()
  Object.keys(connections).forEach(key => {
    const c = connections[key]
    const li = document.createElement('li')
    li.className = 'py-3'

    const title = document.createElement('div')
    title.className = 'text-sm font-medium text-neutral-900 dark:text-neutral-100'
    title.textContent = `Connection ID: ${key}`
    li.appendChild(title)

    const start = new Date(c.starttime)
    const prev = previousData[key] ?? { bytesRx: c.bytesrx, bytesTx: c.bytestx, timestamp: now }
    const dt = Math.max(0.001, (now - prev.timestamp) / 1000)
    const speedRx = (c.bytesrx - prev.bytesRx) / dt
    const speedTx = (c.bytestx - prev.bytesTx) / dt

    const meta = document.createElement('div')
    meta.className = 'mt-2 grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-x-6 gap-y-1 text-xs text-neutral-700 dark:text-neutral-300 font-mono'
    meta.innerHTML = `
      <div>BytesRx: ${c.bytesrx}</div>
      <div>BytesTx: ${c.bytestx}</div>
      <div>Path: ${c.path}</div>
      <div>Protocols: ${c.protocols}</div>
      <div>Source: ${c.src}</div>
      <div>Start: ${start.toLocaleString()}</div>
      <div>SpeedRx: ${formatSpeed(speedRx)}</div>
      <div>SpeedTx: ${formatSpeed(speedTx)}</div>
      <div>Elapsed: ${formatTime(now - start.getTime())}</div>
    `
    li.appendChild(meta)

    previousData[key] = { bytesRx: c.bytesrx, bytesTx: c.bytestx, timestamp: now }

    const actions = document.createElement('div')
    actions.className = 'mt-2'
    const killBtn = document.createElement('button')
    killBtn.className = 'px-3 py-1.5 rounded-md bg-red-600 text-white hover:bg-red-700'
    killBtn.textContent = 'Kill'
    killBtn.addEventListener('click', () => killConnection(key))
    actions.appendChild(killBtn)
    li.appendChild(actions)

    ul.appendChild(li)
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

setInterval(fetchData, 1000)
fetchData()
updateUptime()
setInterval(updateUptime, 1000)


