import { useEffect, useState } from 'react'
import { api } from '../api'

// SR-04: read-only view of the audit log, plus a chain integrity check.
export default function Audit({ onSessionLost }) {
  const [events, setEvents] = useState([])
  const [check, setCheck] = useState(null)
  const [error, setError] = useState('')

  const fail = (e) => (e.status === 401 ? onSessionLost() : setError(e.message))

  useEffect(() => {
    api('/api/audit/events')
      .then((d) => setEvents(d.events))
      .catch((e) => (e.status === 401 ? onSessionLost() : setError(e.message)))
  }, [onSessionLost])

  return (
    <div className="card">
      <h1>Audit log</h1>
      <p className="muted">Entries are hash-chained and the database only allows appending.</p>
      <button onClick={() => api('/api/audit/verify').then(setCheck).catch(fail)}>Verify integrity</button>
      {error && <p className="error" role="alert">{error}</p>}
      {check && (check.ok
        ? <p><strong>Chain intact.</strong> {check.checked} entries checked.</p>
        : (
          <div className="alert">
            <strong>Integrity problems found:</strong>
            <ul>{check.problems.map((p, i) => <li key={i}>{p.seq ? `Entry #${p.seq}: ` : ''}{p.reason}</li>)}</ul>
          </div>
        ))}
      <table className="results">
        <caption>Latest entries</caption>
        <tbody>
          {events.map((e) => (
            <tr key={e.seq}>
              <td className="muted">#{e.seq}</td>
              <td>{e.occurred_at}</td>
              <td><strong>{e.event}</strong></td>
              <td>{e.actor || '-'}</td>
              <td className="muted">{Object.keys(e.details).length ? JSON.stringify(e.details) : ''}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
