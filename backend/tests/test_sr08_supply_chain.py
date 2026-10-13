"""SR-08: supply-chain controls are in place and stay in place."""
import json
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"


def lines(path):
    return [l.strip() for l in path.read_text().splitlines() if l.strip() and not l.strip().startswith("#")]


def test_python_dependencies_pinned_exactly():
    for name in ("requirements.txt", "requirements-dev.txt"):
        for line in lines(ROOT / "backend" / name):
            assert re.match(r"^[A-Za-z0-9_.\-\[\]]+==[0-9][\w.]*$", line), f"{name}: '{line}' is not pinned with =="


def test_frontend_lockfile_present():
    lock = json.loads((ROOT / "frontend" / "package-lock.json").read_text())
    assert lock["lockfileVersion"] >= 2 and lock["packages"]


def test_every_action_pinned_to_commit_sha():
    uses = [l for wf in WORKFLOWS.glob("*.yml") for l in lines(wf) if l.lstrip("- ").startswith("uses:")]
    assert uses
    for u in uses:
        assert re.search(r"@[0-9a-f]{40}\b", u), f"not pinned to a commit: {u}"


def test_workflows_use_least_privilege():
    for wf in WORKFLOWS.glob("*.yml"):
        text = wf.read_text()
        assert "\npermissions:" in text, f"{wf.name} has no top-level permissions block"
        assert "write-all" not in text and "pull_request_target" not in text, wf.name
        assert "persist-credentials: false" in text, wf.name


def test_ci_runs_all_checks():
    ci = (WORKFLOWS / "ci.yml").read_text()
    for check in ("pytest", "bandit", "pip-audit", "npm audit", "npm ci", "cyclonedx"):
        assert check in ci, f"CI is missing {check}"


def test_dependabot_covers_all_ecosystems():
    text = (ROOT / ".github" / "dependabot.yml").read_text()
    for eco in ("pip", "npm", "github-actions"):
        assert f"package-ecosystem: {eco}" in text


def test_release_is_attested_and_checksummed():
    text = (WORKFLOWS / "release.yml").read_text()
    assert "attest-build-provenance" in text and "SHA256SUMS" in text and "id-token: write" in text
