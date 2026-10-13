# -*- coding: utf-8 -*-
"""
Clients pour les API externes de threat intelligence.
Toutes les clés sont optionnelles : si absente, le module renvoie
"skipped" au lieu d'échouer, pour que le lab fonctionne même hors-ligne
ou sans compte sur ces services.
"""
import base64
import hashlib
import os
import requests

TIMEOUT = 12


def _skip(reason="no_api_key"):
    return {"status": "skipped", "reason": reason}


def hash_file(filepath: str) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def virustotal_file(filepath: str, api_key: str = None) -> dict:
    api_key = api_key or os.environ.get("VT_API_KEY")
    if not api_key:
        return _skip()
    try:
        sha256 = hash_file(filepath)
        r = requests.get(
            f"https://www.virustotal.com/api/v3/files/{sha256}",
            headers={"x-apikey": api_key},
            timeout=TIMEOUT,
        )
        permalink = f"https://www.virustotal.com/gui/file/{sha256}"
        if r.status_code == 404:
            return {"status": "ok", "found": False, "sha256": sha256, "permalink": permalink}
        r.raise_for_status()
        stats = r.json()["data"]["attributes"]["last_analysis_stats"]
        return {"status": "ok", "found": True, "sha256": sha256, "stats": stats, "permalink": permalink}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def virustotal_url(url: str, api_key: str = None) -> dict:
    api_key = api_key or os.environ.get("VT_API_KEY")
    if not api_key:
        return _skip()
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        permalink = f"https://www.virustotal.com/gui/url/{url_id}"
        r = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers={"x-apikey": api_key},
            timeout=TIMEOUT,
        )
        if r.status_code == 404:
            # Submit for analysis instead
            sub = requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers={"x-apikey": api_key},
                data={"url": url},
                timeout=TIMEOUT,
            )
            sub.raise_for_status()
            return {"status": "ok", "found": False, "submitted": True, "permalink": permalink}
        r.raise_for_status()
        stats = r.json()["data"]["attributes"]["last_analysis_stats"]
        return {"status": "ok", "found": True, "stats": stats, "permalink": permalink}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def urlhaus_url(url: str, api_key: str = None) -> dict:
    # Since June 2025, abuse.ch requires an "Auth-Key" header on every
    # API request (URLhaus, ThreatFox, MalwareBazaar all share the same
    # key). Free to obtain at https://auth.abuse.ch/.
    api_key = api_key or os.environ.get("URLHAUS_AUTH_KEY")
    if not api_key:
        return _skip()
    try:
        r = requests.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={"url": url},
            headers={"Auth-Key": api_key},
            timeout=TIMEOUT,
        )
        r.raise_for_status()
        data = r.json()
        if data.get("query_status") == "ok":
            return {
                "status": "ok",
                "found": True,
                "threat": data.get("threat"),
                "tags": data.get("tags"),
                "url_status": data.get("url_status"),
            }
        return {"status": "ok", "found": False}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def safe_browsing_url(url: str, api_key: str = None) -> dict:
    api_key = api_key or os.environ.get("GSB_API_KEY")
    if not api_key:
        return _skip()
    try:
        body = {
            "client": {"clientId": "legit-lab", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": [
                    "MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }
        r = requests.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}",
            json=body,
            timeout=TIMEOUT,
        )
        r.raise_for_status()
        matches = r.json().get("matches", [])
        return {"status": "ok", "found": bool(matches), "matches": matches}
    except Exception as e:
        return {"status": "error", "message": str(e)}
