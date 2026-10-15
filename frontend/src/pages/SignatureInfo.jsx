export default function SignatureInfo({ pkg }) {
  return (
    <p className="muted">
      Package #{pkg.package.sequence} · generated {pkg.package.generated_at.replace('T', ' ')} ·
      signed with {pkg.algorithm} key {pkg.kid}<br />SHA-256 {pkg.sha256}
    </p>
  )
}
