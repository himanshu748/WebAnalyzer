"""Read public robots.txt rules without visiting any of the listed paths."""
import re

from modules.registry import module

MAX_BYTES = 64 * 1024
SENSITIVE_PATH = re.compile(
    r"/(?:admin|backups?|\.git)(?:[/.*?$_-]|$)", re.IGNORECASE
)


def parse_disallow(text):
    """List distinct, nonempty Disallow values across all user agents."""
    paths = []
    seen = set()
    for raw in text.splitlines():
        line = raw.partition("#")[0].strip()
        key, separator, value = line.partition(":")
        path = value.strip()
        if separator and key.strip().lower() == "disallow" and path:
            if path not in seen:
                paths.append(path)
                seen.add(path)
    return paths


@module(
    "Robots.txt", description="Disallow paths and sensitive entries in robots.txt",
    group="recon", weight="light", active=False, order=166,
)
def robots_txt(domain, get=None):
    if get is None:
        import requests

        def get(url):
            return requests.get(
                url, timeout=8, allow_redirects=False, stream=True,
                headers={"User-Agent": "WebAnalyzer robots.txt check"},
            )

    url = f"https://{domain}/robots.txt"
    result = {
        "found": False, "url": url, "status": None, "disallow": [],
        "truncated": False, "findings": [],
    }
    response = None
    try:
        response = get(url)
        result["status"] = response.status_code
        if response.status_code != 200:
            return result
        body = response.raw.read(MAX_BYTES + 1, decode_content=True)
        result["truncated"] = len(body) > MAX_BYTES
        body = body[:MAX_BYTES]
        if result["truncated"]:
            # A partial last line could turn a harmless path into a match.
            body = body[:max(body.rfind(b"\n"), body.rfind(b"\r")) + 1]
        paths = parse_disallow(body.decode("utf-8-sig", "replace"))
        result.update(found=True, disallow=paths)
        result["findings"] = [{
            "title": "Potentially sensitive path listed in robots.txt",
            "severity": "info",
            "description": (
                f"Disallow lists {path}. The path has not been requested; "
                "this does not establish that it exists or is accessible."
            ),
            "location": url,
            "recommendation": (
                "Protect sensitive resources with access controls; "
                "robots.txt is public and does not restrict access."
            ),
        } for path in paths if SENSITIVE_PATH.search(path)]
    except Exception:  # noqa: BLE001 - isolate network and response-read failures
        result["error"] = "Could not fetch robots.txt"
    finally:
        if response is not None:
            response.close()
    return result
