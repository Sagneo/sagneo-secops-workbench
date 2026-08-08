import re
import tomllib
from pathlib import Path

ROOT = Path(".")


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_release_version_and_neutral_product_description():
    with (ROOT / "pyproject.toml").open("rb") as handle:
        metadata = tomllib.load(handle)
    assert metadata["project"]["version"] == "1.0.0"
    description = metadata["project"]["description"].lower()
    assert "secops" in description
    assert "port" + "folio" not in description
    assert "vac" + "ancy" not in description


def test_incident_lifecycle_and_report_contract():
    runbook = read("docs/runbooks/02_INCIDENT_CASE_AND_EVIDENCE.md")
    assert "OPEN -> INVESTIGATING -> RESOLVED -> CLOSED" in runbook
    assert "OPEN -> INVESTIGATING -> CONTAINED -> CLOSED" not in runbook

    report = read("docs/INCIDENT_REPORT.md")
    required = {
        "Summary",
        "Scope and impact",
        "Timeline",
        "Evidence",
        "Decisions and resolution",
        "Lessons and improvements",
        "Limitations",
    }
    assert required <= set(re.findall(r"^## (.+)$", report, re.M))
    assert "synthetic" in report.lower()


def test_correction_procedure_is_fail_closed():
    procedure = read("docs/RELEASE_INTEGRITY_RESPONSE.md")
    for heading in ("Triggers", "Required sequence", "Stop conditions", "Preservation boundary"):
        assert f"## {heading}" in procedure
    for control in (
        "Stop dissemination",
        "Preserve facts",
        "Assess impact",
        "Obtain maintainer approval",
        "Correct narrowly",
        "Reverify independently",
    ):
        assert control in procedure


def test_all_html_templates_use_only_the_local_stylesheet():
    expected = '<link rel="stylesheet" href="/static/workbench.css">'
    templates = sorted((ROOT / "app/templates").glob("*.html"))
    assert len(templates) == 9
    for template in templates:
        text = template.read_text(encoding="utf-8")
        assert text.count(expected) == 1
        assert "http://" not in text
        assert "https://" not in text


def test_lab_cookie_transport_mode_is_explicit():
    env_example = (ROOT / ".env.example").read_text(encoding="utf-8")
    compose = (ROOT / "compose.yaml").read_text(encoding="utf-8")
    security = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
    assert "APP_SECURE_COOKIE=false" in env_example
    assert 'APP_SECURE_COOKIE: "false"' in compose
    assert "`APP_SECURE_COOKIE=true`" in security


def test_local_documentation_links_resolve():
    markdown_link = re.compile(r"!?\[[^\]]*]\(([^)]+)\)")
    html_link = re.compile(r'(?:href|src)="([^"]+)"')
    for document in sorted(ROOT.rglob("*.md")):
        text = document.read_text(encoding="utf-8")
        targets = markdown_link.findall(text) + html_link.findall(text)
        for target in targets:
            path_text = target.split("#", 1)[0]
            if not path_text or "://" in path_text or path_text.startswith("mailto:"):
                continue
            resolved = (document.parent / path_text).resolve()
            assert resolved.exists(), f"broken local link in {document}: {target}"
