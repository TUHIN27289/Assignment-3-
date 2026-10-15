import { useState } from 'react'
import { api } from '../api'

// SR-19: voters issued vs ballot tokens vs ballots stored must all agree.
export function ReconciliationSummary({ result }) {
  return (
    <div className={result.ok ? '' : 'alert'}>
      <strong>{result.ok ? 'Reconciliation passed.' : 'Reconciliation FAILED. Do not certify these results.'}</strong>
      <p className="muted">
        Voters issued {result.voters_issued} · tokens issued {result.tokens_issued}
        {' '}({result.tokens_unused} unused) · ballots stored {result.ballots_stored}
      </p>
      {result.problems.length > 0 && (
        <ul>{result.problems.map((p) => <li key={p}>{p}</li>)}</ul>
      )}
    </div>
  )
}

// Run the check on its own, without counting (tally officers and auditors, any time during the election).
export default function ReconciliationCheck({ onSessionLost }) {
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  async function check() {
    setBusy(true)
    setError('')
    try {
      setResult(await api('/api/tally/reconcile', { method: 'POST' }))
    } catch (e) {
      if (e.status === 401) onSessionLost()
      else setError(e.message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="card" style={{ marginTop: 16 }}>
      <h2>Reconciliation</h2>
      <p className="muted">
        Checks that voters marked as issued, ballot tokens and stored ballots match, in total and per division.
      </p>
      <button className="secondary" onClick={check} disabled={busy}>{busy ? 'Checking…' : 'Check reconciliation'}</button>
      {error && <p className="error" role="alert">{error}</p>}
      {result && <ReconciliationSummary result={result} />}
    </div>
  )
}
