# -*- coding: utf-8 -*-
"""
Heuristiques statiques sur une URL : typosquatting, caractères trompeurs,
structure suspecte. Ne nécessite aucune API externe.
"""
import re
import tldextract
from brand_list import POPULAR_DOMAINS, closest_brand

# Force tldextract to use its bundled offline snapshot only — never try to
# fetch the public suffix list over the network. Essential for classroom
# labs running without internet access or behind restrictive firewalls.
_extract = tldextract.TLDExtract(suffix_list_urls=())

SUSPICIOUS_TLDS = {"tk", "ml", "ga", "cf", "gq", "xyz", "top", "work", "click"}

IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


def analyze_url(url: str) -> dict:
    indicators = []
    url_clean = url.strip()
    ext = _extract(url_clean)
    domain = ext.domain.lower()
    suffix = ext.suffix.lower()
    subdomain = ext.subdomain.lower()
    host = ".".join(p for p in [subdomain, domain, suffix] if p)

    if not url_clean.lower().startswith("https://"):
        indicators.append({"key": "NO_HTTPS", "description": "L'URL n'utilise pas HTTPS"})

    if IP_RE.match(domain) or IP_RE.match(host):
        indicators.append({"key": "RAW_IP", "description": "Adresse IP brute utilisée au lieu d'un nom de domaine"})

    if "@" in url_clean:
        indicators.append({"key": "AT_SYMBOL", "description": "Présence du caractère '@' (technique de redirection trompeuse)"})

    if subdomain.count(".") + 1 >= 3:
        indicators.append({"key": "MANY_SUBDOMAINS", "description": f"Nombre élevé de sous-domaines ({subdomain})"})

    if suffix in SUSPICIOUS_TLDS:
        indicators.append({"key": "SUSPICIOUS_TLD", "description": f"Extension de domaine souvent utilisée en phishing (.{suffix})"})

    if len(url_clean) > 90:
        indicators.append({"key": "LONG_URL", "description": "URL anormalement longue"})

    if re.search(r"[^\x00-\x7F]", host):
        indicators.append({"key": "HOMOGRAPH", "description": "Caractères non-ASCII dans le nom de domaine (risque d'homographe/IDN)"})

    if "-" in domain and len(domain) > 12:
        indicators.append({"key": "HYPHEN_LONG", "description": "Domaine long contenant des tirets (souvent utilisé pour imiter une marque)"})

    best_match, best_dist = closest_brand(domain)
    if best_match and best_dist <= 2:
        indicators.append({
            "key": "TYPOSQUATTING",
            "description": f"Similarité suspecte avec le domaine connu « {best_match} » (distance d'édition = {best_dist})",
        })

    risk_score = min(100, len(indicators) * 16)
    if risk_score >= 55:
        verdict = "malicious"
    elif risk_score >= 20:
        verdict = "suspicious"
    else:
        verdict = "legit"

    return {
        "type": "url",
        "url": url_clean,
        "host": host,
        "indicators": indicators,
        "risk_score": risk_score,
        "verdict": verdict,
        "error": None,
    }
