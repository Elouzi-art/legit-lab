# -*- coding: utf-8 -*-
"""
Génère un jeu de données SYNTHÉTIQUE d'URLs légitimes / phishing pour
l'entraînement pédagogique du modèle ML, sans dépendre d'un téléchargement
externe (le build Docker reste 100% reproductible hors-ligne).

ATTENTION PÉDAGOGIQUE : ce jeu de données est généré par règles, donc le
modèle entraîné dessus est un modèle de DÉMONSTRATION pour illustrer le
principe (features lexicales -> classification), pas un détecteur
de qualité production. C'est un point de discussion volontaire pour le TP :
comparer ses prédictions à VirusTotal pour voir où il se trompe.
"""
import csv
import os
import random

from brand_list import POPULAR_DOMAINS

random.seed(42)


def typo_variant(brand: str) -> str:
    """Produit une variante à 1 caractère d'écart (substitution, insertion
    ou suppression) d'un nom de marque — pour générer des typosquats
    'propres', sans aucun autre signal suspect mélangé (pas de tiret,
    pas de TLD bizarre)."""
    chars = list(brand)
    idx = random.randrange(len(chars))
    op = random.choice(["sub", "ins", "del"]) if len(chars) > 4 else random.choice(["sub", "ins"])
    if op == "sub":
        digit_lookalikes = {"o": "0", "i": "1", "e": "3", "a": "4", "s": "5"}
        orig = chars[idx]
        chars[idx] = digit_lookalikes.get(orig, random.choice("0134578"))
    elif op == "ins":
        chars.insert(idx, random.choice("0123456789"))
    else:  # del
        del chars[idx]
    variant = "".join(chars)
    return variant if variant != brand else brand + "1"

LEGIT_BRANDS = [
    "google", "wikipedia", "github", "openai", "lemonde", "amazon",
    "microsoft", "apple", "spotify", "netflix", "linkedin", "orange",
    "universite-paris", "ensa-marrakech", "ocp", "cnss", "poste",
]
LEGIT_TLDS = ["com", "org", "net", "edu", "fr", "ma", "io"]
LEGIT_PATHS = ["", "/login", "/accueil", "/about", "/docs", "/fr/produits", "/help", "/contact"]

PHISHING_PREFIXES = ["secure", "login", "verify", "account", "update", "confirm", "support", "signin"]
PHISHING_BRAND_TYPOS = [
    "gooogle", "paypa1", "facebo0k", "micros0ft", "appleid-support",
    "amaz0n-secure", "netfllx", "whatsapp-verify", "instagram-help",
    "bankofamerica-alert", "chase-secure-login",
]
PHISHING_TLDS = ["tk", "ml", "ga", "cf", "xyz", "top", "click", "work", "gq"]


def random_ip():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))


def make_legit_url():
    brand = random.choice(LEGIT_BRANDS)
    tld = random.choice(LEGIT_TLDS)
    path = random.choice(LEGIT_PATHS)
    use_www = random.random() < 0.5
    host = f"{'www.' if use_www else ''}{brand}.{tld}"
    return f"https://{host}{path}"


def make_phishing_url():
    kind = random.random()
    if kind < 0.25:
        # raw IP
        return f"http://{random_ip()}/login/verify"
    elif kind < 0.5:
        # typosquat + suspicious tld + prefix
        prefix = random.choice(PHISHING_PREFIXES)
        brand = random.choice(PHISHING_BRAND_TYPOS)
        tld = random.choice(PHISHING_TLDS)
        sub = random.choice(["", "secure-", "account-"])
        return f"http://{prefix}-{sub}{brand}.{tld}/update-account"
    elif kind < 0.75:
        # long url with many subdomains and @ trick
        brand = random.choice(PHISHING_BRAND_TYPOS)
        depth = random.randint(2, 4)
        subs = ".".join(random.choice(PHISHING_PREFIXES) for _ in range(depth))
        tld = random.choice(PHISHING_TLDS)
        return f"http://{subs}.{brand}.{tld}/secure/account/verify/session={random.randint(10000,99999)}"
    else:
        # "clean" typosquat: HTTPS, popular-looking TLD, no hyphen, no
        # suspicious TLD — only the brand name itself is off by 1-2
        # characters. Teaches the ML model that edit-distance to a known
        # brand is, on its own, a meaningful signal (not just a side
        # effect of other red flags like hyphens or bad TLDs).
        brand = typo_variant(random.choice(POPULAR_DOMAINS))
        tld = random.choice(["com", "net", "org"])
        use_www = random.random() < 0.5
        host = f"{'www.' if use_www else ''}{brand}.{tld}"
        path = random.choice(["", "/login", "/account", "/signin"])
        return f"https://{host}{path}"


def generate(n_each=600, out_path="data/url_dataset.csv"):
    rows = []
    for _ in range(n_each):
        rows.append((make_legit_url(), 0))
    for _ in range(n_each):
        rows.append((make_phishing_url(), 1))
    random.shuffle(rows)

    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["url", "label"])  # label: 0 = legit, 1 = phishing
        writer.writerows(rows)
    print(f"{len(rows)} URLs écrites dans {out_path}")


if __name__ == "__main__":
    generate()
