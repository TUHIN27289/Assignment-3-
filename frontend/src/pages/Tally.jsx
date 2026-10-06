import { useState } from 'react'
import { api } from '../api'

export default function Tally({ onSessionLost }) {
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  async function run() {
    setBusy(true)
    setError('')
    try {
      setResult(await api('/api/tally/run', { method: 'POST' }))
    } catch (e) {
      if (e.status === 401) onSessionLost()
      else setError(e.message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="card">
      <h1>Tally</h1>
      <p className="muted">
        Every stored ballot is checked against the integrity chain before anything is decrypted.
        Ballots that fail are left out and flagged.
      </p>
      <button onClick={run} disabled={busy}>{busy ? 'Running…' : 'Verify and count'}</button>
      {error && <p className="error" role="alert">{error}</p>}
      {result && (
        <>
          <p><strong>{result.counted}</strong> ballots verified and counted.</p>
          {result.rejected.length > 0 && (
            <div className="alert">
              <strong>{result.rejected.length} integrity problem(s):</strong>
              <ul>
                {result.rejected.map((r, i) => (
                  <li key={i}>{r.seq ? `Ballot #${r.seq}: ` : ''}{r.reason}</li>
                ))}
              </ul>
            </div>
          )}
          {Object.entries(result.first_preferences).map(([division, counts]) => (
            <table key={division} className="results">
              <caption>{division}: first preferences</caption>
              <tbody>
                {Object.entries(counts).sort((a, b) => b[1] - a[1]).map(([name, votes]) => (
                  <tr key={name}><td>{name}</td><td>{votes}</td></tr>
                ))}
              </tbody>
            </table>
          ))}
        </>
      )}
    </div>
  )
}
