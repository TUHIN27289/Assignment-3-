# Releasing (SR-08)

1. All CI checks on `main` are green (tests, Bandit, pip-audit, npm audit, CodeQL).
2. Create a **signed** tag from `main`:
   ```
   git tag -s v1.0.0 -m "v1.0.0"
   git tag -v v1.0.0          # check the signature locally
   git push origin v1.0.0
   ```
   (Set up once: `git config user.signingkey <GPG or SSH key>` and add the key to GitHub,
   so the tag shows as "Verified".)
3. The Release workflow builds the artifacts, SBOMs and `SHA256SUMS`, and signs a build
   provenance attestation. Anyone can verify an artifact with:
   ```
   gh attestation verify frontend-dist.tar.gz --repo <owner>/<repo>
   sha256sum -c SHA256SUMS
   ```
4. Deployment only accepts artifacts that pass both checks.

Recommended repository settings (done in GitHub, not in code): protect `main`
(require PR review + passing CI), enable Dependabot alerts, secret scanning
and push protection, and require signed commits if the team can manage it.
