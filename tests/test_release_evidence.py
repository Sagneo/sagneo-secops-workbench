import hashlib
import re
from pathlib import Path

EVIDENCE_ROOT = Path("docs/evidence/reports")
INDEX = Path("docs/evidence/EVIDENCE_INDEX.md")
EXPECTED = {
    "01_SOURCE_HEALTH.md",
    "02_ALERT_TRIAGE.md",
    "03_CASE_TIMELINE.md",
    "04_COLLECTION_AND_INTEGRITY.md",
    "05_PROCESS_IMPROVEMENT.md",
    "06_REPRODUCIBILITY_CONTROLS.md",
}


def test_exact_six_evidence_artifacts():
    assert {path.name for path in EVIDENCE_ROOT.iterdir() if path.is_file()} == EXPECTED


def test_evidence_is_synthetic_and_sanitized():
    prohibited = (
        "C:" + "\\Users\\",
        "C:" + "/Users/",
        "BEGIN " + "OPENSSH PRIVATE KEY",
        "password for ",
        ".vmx",
    )
    for path in sorted(EVIDENCE_ROOT.iterdir()):
        text = path.read_text(encoding="utf-8")
        assert "Classification:" in text
        assert "synthetic" in text.lower() or "sanitized" in text.lower()
        assert not any(value in text for value in prohibited)


def test_evidence_index_matches_current_artifact_bytes():
    index = INDEX.read_text(encoding="utf-8")
    for path in sorted(EVIDENCE_ROOT.iterdir()):
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        row = next(line for line in index.splitlines() if f"`{path.name}`" in line)
        assert digest in row
        assert f"{path.stat().st_size:,}" in row


def test_three_runbooks_have_required_operational_sections():
    paths = sorted(Path("docs/runbooks").glob("*.md"))
    assert len(paths) == 3
    required = {
        "Trigger",
        "Prerequisites",
        "Expected checks and evidence",
        "Decisions and escalation",
        "Rollback and recovery",
        "Limitations",
        "Validation notes",
    }
    for path in paths:
        headings = set(re.findall(r"^## (.+)$", path.read_text(encoding="utf-8"), re.M))
        assert required <= headings


def test_readme_is_release_quality_and_fact_bound():
    text = Path("README.md").read_text(encoding="utf-8")
    required_headings = {
        "Review in five minutes",
        "Architecture",
        "Event-to-evidence workflow",
        "Synthetic interface gallery",
        "Verified results",
        "Capabilities and deliberate exclusions",
        "Five-minute reviewer tour",
        "Deterministic local demo",
        "Security and isolation",
        "Technology stack",
        "Limitations and status",
    }
    headings = set(re.findall(r"^## (.+)$", text, re.M))
    assert required_headings <= headings
    assert text.count("```mermaid") == 1
    assert "docs/assets/event-to-evidence-workflow.svg" in text
    screenshots = {
        "ui-alert-queue.jpg",
        "ui-alert-triage.jpg",
        "ui-reviewer-collection.jpg",
    }
    for filename in screenshots:
        assert f"docs/assets/{filename}" in text
        assert (Path("docs/assets") / filename).stat().st_size > 20_000
    for fact in ("1,201", "1,555", "61,910", "666"):
        assert fact in text
    assert "production-ready" not in text.lower()
    assert "does not represent a production soc" in text.lower()
    assert "does not represent" in text.lower()
