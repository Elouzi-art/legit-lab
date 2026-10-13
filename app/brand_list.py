# -*- coding: utf-8 -*-
"""
Liste de marques connues + distance d'édition, partagées entre :
- url_analysis.py (heuristique statique : signale le typosquatting)
- ml_model.py (feature ML : la distance au plus proche nom connu)

Centraliser ça ici évite que les deux couches divergent, et surtout
permet au modèle ML de "voir" le typosquatting, qu'il ne détectait pas
auparavant (il n'avait que des features génériques comme la longueur ou
le nombre de tirets, sans aucune notion de marque connue).
"""

POPULAR_DOMAINS = [
    "google", "facebook", "apple", "microsoft", "amazon", "paypal",
    "instagram", "whatsapp", "netflix", "linkedin", "github", "orange",
    "gmail", "outlook", "bankofamerica", "wellsfargo", "chase", "poste",
]


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    la, lb = len(a), len(b)
    if la == 0:
        return lb
    if lb == 0:
        return la
    prev = list(range(lb + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * lb
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
        prev = cur
    return prev[lb]


def closest_brand(domain: str):
    """Retourne (marque_la_plus_proche, distance) parmi POPULAR_DOMAINS,
    ou (None, 99) si le domaine correspond exactement à une marque connue
    (donc pas suspect) ou si rien n'est assez proche."""
    domain = domain.lower()
    if domain in POPULAR_DOMAINS:
        return None, 99
    best_match, best_dist = None, 99
    for popular in POPULAR_DOMAINS:
        d = levenshtein(domain, popular)
        if d < best_dist:
            best_match, best_dist = popular, d
    return best_match, best_dist
