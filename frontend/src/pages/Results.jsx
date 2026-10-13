import { useEffect, useState } from 'react'
import { api } from '../api'
import { downloadPackage } from '../download'
import SignatureInfo from './SignatureInfo'

// SR-18: public page, no login. Shows the latest signed results and checks the signature.
export default function Results() {
  const [pkg, setPkg] = useState(null)
  const [valid, setValid] = useState(null)
  const [error, setError] = useState('')

  useEffect(() => {
    api('/api/results/latest')
      .then(async (p) => {
        setPkg(p)
        const r = await api('/api/results/verify', {
          method: 'POST', body: { package: p.package, kid: p.kid, signature: p.signature },
        })
        setValid(r.valid)
      })
      .catch((e) => setError(e.status === 404 ? 'No results have been published yet.' : e.message))
  }, [])

  if (error) return <div className="card"><h1>Results</h1><p>{error}</p></div>
  if (!pkg) return <p>Loading…</p>

  return (
    <div className="card">
      <h1>Published results</h1>
      <div className={valid ? '' : 'alert'}>
        <strong>{valid === null ? 'Checking signature…' : valid ? 'Signature valid: issued by the AEC and unchanged.' : 'Signature NOT valid. Do not trust these numbers.'}</strong>
      </div>
      <SignatureInfo pkg={pkg} />
      {pkg.package.excluded_candidates.length > 0 && (
        <p className="muted">Excluded by court order: {pkg.package.excluded_candidates.join(', ')}</p>
      )}
      {Object.entries(pkg.package.divisions).map(([division, counts]) => (
        <table key={division} className="results">
          <caption>{division}: first preferences</caption>
          <tbody>
            {Object.entries(counts).sort((a, b) => b[1] - a[1]).map(([name, votes]) => (
              <tr key={name}><td>{name}</td><td>{votes}</td></tr>
            ))}
          </tbody>
        </table>
      ))}
      <div className="row"><button className="secondary" onClick={() => downloadPackage(pkg)}>Download signed package</button></div>
    </div>
  )
}
