import './index.css'
import { csrfFetch } from './csrf'

function formatCallResult(value: unknown): string {
  if (value === null) return 'null'
  if (value === undefined) return 'undefined'
  if (typeof value === 'string') return value
  if (typeof value === 'number' || typeof value === 'boolean') {
    return JSON.stringify(value)
  }
  try {
    return JSON.stringify(value, null, 2)
  } catch {
    return String(value)
  }
}

function setupCallForm() {
  const kindInput = document.getElementById('call-kind') as HTMLInputElement | null
  const specInput = document.getElementById('call-spec') as HTMLTextAreaElement | null
  const submitBtn = document.getElementById('call-submit') as HTMLButtonElement | null
  const clearBtn = document.getElementById('call-clear') as HTMLButtonElement | null
  const statusEl = document.getElementById('call-status')
  const resultEl = document.getElementById('call-result')

  if (!kindInput || !specInput || !submitBtn || !statusEl || !resultEl) {
    return
  }

  const defaultResult = 'Result will appear here.'
  const setStatus = (text: string) => {
    statusEl.textContent = text
  }

  clearBtn?.addEventListener('click', () => {
    kindInput.value = ''
    specInput.value = ''
    resultEl.textContent = defaultResult
    setStatus('Cleared.')
  })

  submitBtn.addEventListener('click', async () => {
    const kind = kindInput.value.trim()
    if (!kind) {
      setStatus('Kind is required.')
      resultEl.textContent = 'No request executed.'
      kindInput.focus()
      return
    }

    let spec: unknown = null
    const specRaw = specInput.value.trim()
    if (specRaw) {
      try {
        spec = JSON.parse(specRaw)
      } catch (error) {
        setStatus(`Spec JSON invalid: ${(error as Error).message}`)
        resultEl.textContent = specRaw
        return
      }
    }

    setStatus('Calling...')
    submitBtn.disabled = true

    try {
      const response = await csrfFetch('/api/v1/call', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ kind, spec })
      })

      let payload: any
      try {
        payload = await response.clone().json()
      } catch {
        payload = undefined
      }
      const raw = await response.text()

      if (!response.ok) {
        const errorMsg = payload?.error ?? response.statusText ?? 'Request failed'
        setStatus(`Request failed: ${errorMsg}`)
        resultEl.textContent = payload ? JSON.stringify(payload, null, 2) : raw || 'No response body'
        return
      }

      if (!payload) {
        setStatus('Call succeeded (empty response).')
        resultEl.textContent = raw || 'No response body'
        return
      }

      if (payload.success) {
        setStatus('Call succeeded.')
        resultEl.textContent = payload.result !== undefined ? formatCallResult(payload.result) : 'Result: undefined'
      } else {
        const message = payload.error ?? 'Call failed.'
        setStatus(`Call failed: ${message}`)
        resultEl.textContent = JSON.stringify(payload, null, 2)
      }
    } catch (error) {
      setStatus((error as Error).message ?? 'Unexpected error')
      resultEl.textContent = 'Request failed.'
    } finally {
      submitBtn.disabled = false
    }
  })
}

async function updateUptime() {
  fetch('/api/v1/uptime', { redirect: 'error' })
    .then(response => {
      if (!response.ok) throw new Error('Network response was not ok')
      return response.text()
    })
    .then(text => {
      const uptimeDiv = document.getElementById('uptime')
      if (uptimeDiv) {
        uptimeDiv.textContent = text
        uptimeDiv.classList.remove('disconnected')
      }
    })
    .catch(() => {
      const uptimeDiv = document.getElementById('uptime')
      if (uptimeDiv) {
        uptimeDiv.textContent = 'Disconnected'
        uptimeDiv.classList.add('disconnected')
      }
    })
}

setupCallForm()
updateUptime()
setInterval(updateUptime, 1000)

