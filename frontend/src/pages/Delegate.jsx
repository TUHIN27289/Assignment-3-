import { useCallback, useEffect, useState } from 'react'
import { api } from '../api'

// SR-17: delegates propose candidate changes; a different delegate must approve.
export default function Delegate({ onSessionLost }) {
  const [data, setData] = useState(null)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [form, setForm] = useState(null) // { kind, candidate, reason, party, name }

  const fail = useCallback((e) => (e.status === 401 ? onSessionLost() : setError(e.message)), [onSessionLost])
  const load = useCallback(() => api('/api/candidates').then(setData).catch(fail), [fail])
  useEffect(() => { load() }, [load])

  async function submit(e) {
    e.preventDefault()
    setError('')
    const body = { kind: form.kind, candidate_id: form.candidate.id, reason: form.reason }
    if (form.kind === 'update') {
      body.fields = {}
      if (form.name !== form.candidate.name) body.fields.name = form.name
      if (form.party !== (form.candidate.party || '')) body.fields.party = form.party
    }
    try {
      await api('/api/candidates/changes', { method: 'POST', body })
      setForm(null)
      setNotice('Request sent. Another delegate must approve it before it takes effect.')
      load()
    } catch (err) { fail(err) }
  }

  async function decide(id, action) {
    setError('')
    try {
      await api(`/api/candidates/changes/${id}/${action}`, { method: 'POST' })
      setNotice(action === 'approve' ? 'Change approved and applied.' : 'Change rejected.')
      load()
    } catch (err) { fail(err) }
  }

  if (!data) return error ? <p className="error">{error}</p> : <p>Loading…</p>
  const byId = Object.fromEntries(data.candidates.map((c) => [c.id, c]))

  return (
    <div className="card">
      <h1>Candidates, {data.state}</h1>
      <p className="muted">Every change needs approval from a second delegate (dual control).</p>
      {notice && <p>{notice}</p>}
      {error && <p className="error" role="alert">{error}</p>}

      <h2>Waiting for approval</h2>
      {data.pending.length === 0 && <p className="muted">Nothing pending.</p>}
      {data.pending.map((p) => (
        <div className="alert" key={p.id}>
          <strong>{p.kind}</strong> {byId[p.candidate_id]?.name || p.payload.name}
          {Object.keys(p.payload).length > 0 && <span className="muted"> {JSON.stringify(p.payload)}</span>}
          <br /><span className="muted">Reason: {p.reason} · expires {p.expires_at.replace('T', ' ')} UTC</span>
          <div className="row">
            {p.mine
              ? <span className="muted">You requested this, another delegate must decide.</span>
              : (
                <>
                  <button className="secondary" onClick={() => decide(p.id, 'reject')}>Reject</button>
                  <button onClick={() => decide(p.id, 'approve')}>Approve</button>
                </>
              )}
          </div>
        </div>
      ))}

      <table className="results">
        <caption>House candidates</caption>
        <tbody>
          {data.candidates.map((c) => (
            <tr key={c.id}>
              <td>{c.division} #{c.ballot_order}</td>
              <td>
                <strong style={c.excluded ? { textDecoration: 'line-through' } : null}>{c.name}</strong>
                <br /><span className="muted">{c.party}{c.excluded ? ` · excluded: ${c.exclusion_reason}` : ''}</span>
              </td>
              <td style={{ whiteSpace: 'nowrap' }}>
                {!c.excluded && (
                  <>
                    <button className="link" onClick={() => setForm({ kind: 'update', candidate: c, reason: '', name: c.name, party: c.party || '' })}>Edit</button>
                    {' · '}
                    <button className="link" onClick={() => setForm({ kind: 'exclude', candidate: c, reason: '' })}>Exclude</button>
                  </>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      {form && (
        <form onSubmit={submit} className="card" style={{ marginTop: 16, display: 'flex', flexDirection: 'column', gap: 12 }}>
          <h2>{form.kind === 'exclude' ? `Exclude ${form.candidate.name}` : `Edit ${form.candidate.name}`}</h2>
          {form.kind === 'update' && (
            <>
              <label>Name<input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} /></label>
              <label>Party<input value={form.party} onChange={(e) => setForm({ ...form, party: e.target.value })} /></label>
            </>
          )}
          <label>
            {form.kind === 'exclude' ? 'Court order / reason' : 'Reason for change'}
            <input value={form.reason} onChange={(e) => setForm({ ...form, reason: e.target.value })} minLength={10} required />
          </label>
          <div className="row">
            <button type="button" className="secondary" onClick={() => setForm(null)}>Cancel</button>
            <button type="submit">Request change</button>
          </div>
        </form>
      )}
    </div>
  )
}
