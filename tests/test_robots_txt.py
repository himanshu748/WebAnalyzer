"""Passive robots.txt parsing and request safety, without network access."""
from io import BytesIO

import pytest

from modules import registry
from modules.plugins import robots_txt as rt
from utils.result_analysis import list_findings

URL = "https://example.org/robots.txt"


class Raw(BytesIO):
    def read(self, amount, decode_content=False):
        assert amount == rt.MAX_BYTES + 1
        assert decode_content is True
        return super().read(amount)


class Response:
    def __init__(self, body=b"", status=200):
        self.status_code = status
        self.raw = Raw(body)
        self.closed = False

    def close(self):
        self.closed = True


def test_lists_distinct_disallow_paths_across_user_agents():
    response = Response(b"\xef\xbb\xbfUser-agent: *\n"
                        b"# Disallow: /ignored\n"
                        b"Disallow: /images/ # comment\n"
                        b"disallow : /admin\n"
                        b"Allow: /admin/public\n"
                        b"User-agent: OtherBot\n"
                        b"Disallow: /images/\n"
                        b"Disallow:\n"
                        b"Disallow /malformed\n"
                        b"Sitemap: https://example.org/map.xml\n")
    requested = []

    def get(url):
        requested.append(url)
        return response

    out = rt.robots_txt("example.org", get=get)
    assert out["found"] is True and out["status"] == 200
    assert out["disallow"] == ["/images/", "/admin"]
    assert out["truncated"] is False
    assert requested == [URL]  # Never fetch a Disallow path or a sitemap.
    assert response.closed


@pytest.mark.parametrize("path", [
    "/admin", "/ADMIN/", "/admin-panel", "/backup.zip", "/backups/",
    "/private/.git/config", "/.git$", "/*/admin/*",
])
def test_sensitive_paths_are_informational_only(path):
    response = Response(f"Disallow: {path}\n".encode())
    out = rt.robots_txt("example.org", get=lambda url: response)
    findings = list_findings({"Robots.txt": out})
    assert len(findings) == 1
    assert findings[0]["severity"] == "info"
    assert findings[0]["location"] == URL
    assert path in findings[0]["description"]
    assert "has not been requested" in findings[0]["description"]


def test_ordinary_paths_and_similar_words_do_not_report_findings():
    response = Response(b"Disallow: /images/\nDisallow: /administration-guide\n"
                        b"Disallow: /.github/\nDisallow: /backupify/\n")
    out = rt.robots_txt("example.org", get=lambda url: response)
    assert len(out["disallow"]) == 4
    assert out["findings"] == []


@pytest.mark.parametrize("body", [b"", b"# No restrictions\n", b"User-agent: *\nDisallow:\n"])
def test_empty_rules_are_valid_and_have_no_findings(body):
    out = rt.robots_txt("example.org", get=lambda url: Response(body))
    assert out["found"] is True
    assert out["disallow"] == out["findings"] == []


@pytest.mark.parametrize("status", [301, 302, 307, 308, 404, 500])
def test_non_success_responses_are_closed_without_reading_or_following(status):
    response = Response(b"Disallow: /admin\n", status=status)
    response.headers = {"Location": "https://169.254.169.254/latest/meta-data/"}
    requested = []

    def get(url):
        requested.append(url)
        return response

    out = rt.robots_txt("example.org", get=get)
    assert out["found"] is False and out["status"] == status
    assert out["disallow"] == out["findings"] == []
    assert requested == [URL]
    assert response.raw.tell() == 0
    assert response.closed


def test_a_network_failure_does_not_report_a_finding():
    def get(url):
        raise OSError("unreachable")

    out = rt.robots_txt("example.org", get=get)
    assert out["found"] is False and out["status"] is None
    assert out["findings"] == []
    assert out["error"] == "Could not fetch robots.txt"


def test_a_read_failure_still_closes_the_response():
    response = Response()

    def fail_read(*args, **kwargs):
        raise OSError("connection interrupted")

    response.raw.read = fail_read
    out = rt.robots_txt("example.org", get=lambda url: response)
    assert out["found"] is False and out["findings"] == []
    assert out["error"] == "Could not fetch robots.txt"
    assert response.closed


def test_limits_reads_and_discards_a_truncated_last_rule():
    prefix = b"Disallow: /images/\n# "
    suffix = b"\nDisallow: /admin"
    body = prefix + b"x" * (rt.MAX_BYTES - len(prefix) - len(suffix))
    response = Response(body + suffix + b"istration-guide\nDisallow: /.git\n")
    out = rt.robots_txt("example.org", get=lambda url: response)
    assert response.raw.tell() == rt.MAX_BYTES + 1
    assert out["truncated"] is True
    assert out["disallow"] == ["/images/"]
    assert out["findings"] == []
    assert response.closed


def test_an_oversized_single_line_is_not_parsed():
    response = Response(b"Disallow: /admin/" + b"x" * rt.MAX_BYTES)
    out = rt.robots_txt("example.org", get=lambda url: response)
    assert out["truncated"] is True
    assert out["disallow"] == out["findings"] == []


def test_default_fetcher_uses_safe_request_options(monkeypatch):
    import requests

    calls = []
    response = Response(b"Disallow: /backup\n")

    def get(url, **kwargs):
        calls.append((url, kwargs))
        return response

    monkeypatch.setattr(requests, "get", get)
    assert rt.robots_txt("example.org")["found"] is True
    assert calls == [(URL, {
        "timeout": 8, "allow_redirects": False, "stream": True,
        "headers": {"User-Agent": "WebAnalyzer robots.txt check"},
    })]
    assert response.closed


def test_plugin_is_registered_as_passive_and_light():
    spec = registry.get("Robots.txt")
    assert spec.run is rt.robots_txt
    assert spec.active is False
    assert spec.group == "recon" and spec.weight == "light"
