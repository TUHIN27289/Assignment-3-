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
          <div className={result.reconciliation.ok ? '' : 'alert'}>
            <strong>{result.reconciliation.ok ? 'Reconciliation passed.' : 'Reconciliation FAILED. Do not certify these results.'}</strong>
            <p className="muted">
              Voters issued {result.reconciliation.voters_issued} · tokens issued {result.reconciliation.tokens_issued}
              {' '}({result.reconciliation.tokens_unused} unused) · ballots stored {result.reconciliation.ballots_stored}
            </p>
            {result.reconciliation.problems.length > 0 && (
              <ul>{result.reconciliation.problems.map((p) => <li key={p}>{p}</li>)}</ul>
            )}
          </div>
          <p><strong>{result.counted}</strong> ballots verified and counted.</p>
          {result.excluded.length > 0 && <p className="muted">Excluded by court order: {result.excluded.join(', ')}</p>}
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
