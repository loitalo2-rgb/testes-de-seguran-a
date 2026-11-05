import pytest
from auditor_headers import SecurityHeaderAuditor

def test_auditor_initialization():
    auditor = SecurityHeaderAuditor("example.com")
    assert auditor.target_url == "https://example.com"
    assert auditor.score == 100
    assert len(auditor.findings) == 0

def test_auditor_scoring_and_findings():
    auditor = SecurityHeaderAuditor("https://example.com")
    success = auditor.run_audit()
    assert success is True
    assert len(auditor.findings) == len(SecurityHeaderAuditor.CRITERIA)
    assert 0 <= auditor.score <= 100
