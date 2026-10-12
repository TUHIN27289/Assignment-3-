import { useCallback, useEffect, useState } from 'react'
import { api } from '../api'

// SR-17: delegates propose candidate changes; a different delegate must approve.
const LABELS = { name: 'name', party: 'party', division: 'division', ballot_order: 'ballot position' }

// Plain-English summary of a pending request, so the approver can see exactly what they're signing off
function describe(p, candidate) {
  if (p.kind === 'create') {
    const f = p.payload
    return `Add ${f.name}${f.party ? ` (${f.party})` : ''} to ${f.division} at ballot position ${f.ballot_order}`
  }
  const who = candidate?.name || `candidate #${p.candidate_id}`
  if (p.kind === 'exclude') return `Exclude ${who} from the count`
  const changes = Object.entries(p.payload).map(([k, v]) => `${LABELS[k] || k} to "${v}"`)
  return `Change ${who}: ${changes.join(', ')}`
}

export default function Delegate({ onSessionLost }) {
  const [data, setData] = useState(null)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [form, setForm] = useState(null) // { kind, candidate?, reason, name, party, division, ballot_order }

  const fail = useCallback((e) => (e.status === 401 ? onSessionLost() : setError(e.message)), [onSessionLost])
  const load = useCallback(() => api('/api/candidates').then(setData).catch(fail), [fail])
  useEffect(() => { load() }, [load])

  function open(kind, candidate = null) {
    setError('')
    setNotice('')
    setForm({
      kind, candidate, reason: '',
      name: candidate?.name || '', party: candidate?.party || '',
      division: candidate?.division || '', ballot_order: candidate?.ballot_order || '',
    })
  }

  function changedFields() {
    const c = form.candidate
    const fields = {}
    if (form.name.trim() && form.name.trim() !== (c?.name || '')) fields.name = form.name.trim()
    if (form.party.trim() && form.party.trim() !== (c?.party || '')) fields.party = form.party.trim()
    if (form.kind === 'create' && form.division.trim()) fields.division = form.division.trim()
    const order = Number(form.ballot_order)
    if (form.ballot_order !== '' && order !== c?.ballot_order) fields.ballot_order = order
    return fields
  }

  async function submit(e) {
    e.preventDefault()
    setError('')
    const body = { kind: form.kind, reason: form.reason }
    if (form.candidate) body.candidate_id = form.candidate.id
    if (form.kind !== 'exclude') {
      body.fields = changedFields()
      if (Object.keys(body.fields).length === 0) return setError('Nothing has changed.')
    }
    try {
      await api('/api/candidates/changes', { method: 'POST', body })
      setForm(null)
      setNotice('Request sent. Another delegate must approve it before it takes effect.')
      load()
    } catch (err) { fail(err) }
  }

  async function act(id, action) {
    setError('')
    try {
      await api(`/api/candidates/changes/${id}/${action}`, { method: 'POST' })
      setNotice({ approve: 'Change approved and applied.', reject: 'Change rejected.', withdraw: 'Request withdrawn.' }[action])
      load()
    } catch (err) { fail(err) }
  }

  if (!data) return error ? <p className="error">{error}</p> : <p>Loading…</p>
  const byId = Object.fromEntries(data.candidates.map((c) => [c.id, c]))
  const pendingFor = new Set(data.pending.map((p) => p.candidate_id).filter(Boolean))

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
          <strong>{describe(p, byId[p.candidate_id])}</strong>
          <br /><span className="muted">Reason: {p.reason} · expires {p.expires_at.replace('T', ' ')} UTC</span>
          <div className="row">
            {p.mine
              ? (
                <>
                  <span className="muted">You requested this, another delegate must decide.</span>
                  <button className="secondary" onClick={() => act(p.id, 'withdraw')}>Withdraw</button>
                </>
              )
              : (
                <>
                  <button className="secondary" onClick={() => act(p.id, 'reject')}>Reject</button>
                  <button onClick={() => act(p.id, 'approve')}>Approve</button>
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
                {!c.excluded && pendingFor.has(c.id) && <span className="muted">change pending</span>}
                {!c.excluded && !pendingFor.has(c.id) && (
                  <>
                    <button className="link" onClick={() => open('update', c)}>Edit</button>
                    {' · '}
                    <button className="link" onClick={() => open('exclude', c)}>Exclude</button>
                  </>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {!form && (
        <div className="row"><button className="secondary" onClick={() => open('create')}>Add candidate</button></div>
      )}

      {form && (
        <form onSubmit={submit} className="card" style={{ marginTop: 16, display: 'flex', flexDirection: 'column', gap: 12 }}>
          <h2>
            {form.kind === 'create' && 'Add a candidate'}
            {form.kind === 'update' && `Edit ${form.candidate.name}`}
            {form.kind === 'exclude' && `Exclude ${form.candidate.name}`}
          </h2>
          {form.kind !== 'exclude' && (
            <>
              <label>Name<input value={form.name} maxLength={255} required={form.kind === 'create'}
                onChange={(e) => setForm({ ...form, name: e.target.value })} /></label>
              <label>Party<input value={form.party} maxLength={255}
                onChange={(e) => setForm({ ...form, party: e.target.value })} /></label>
              {form.kind === 'create' && (
                <label>Division<input value={form.division} maxLength={255} required
                  onChange={(e) => setForm({ ...form, division: e.target.value })} /></label>
              )}
              <label>Ballot position<input type="number" min={1} max={100} value={form.ballot_order}
                required={form.kind === 'create'}
                onChange={(e) => setForm({ ...form, ballot_order: e.target.value })} /></label>
            </>
          )}
          <label>
            {form.kind === 'exclude' ? 'Court order / reason' : 'Reason for change'}
            <input value={form.reason} minLength={10} maxLength={500} required
              onChange={(e) => setForm({ ...form, reason: e.target.value })} />
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
