// Saves a signed results package as a JSON file (SR-18).
export function downloadPackage(pkg) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(pkg, null, 2)], { type: 'application/json' }))
  const a = document.createElement('a')
  a.href = url
  a.download = `results-${pkg.package.election_id}-${pkg.package.sequence}.json`
  a.click()
  URL.revokeObjectURL(url)
}
