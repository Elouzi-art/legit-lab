# -*- coding: utf-8 -*-
"""
Analyse statique d'un PDF, inspirée de pdfid.py (Didier Stevens).
Cherche les indicateurs classiques de PDF malveillant :
JavaScript embarqué, actions automatiques, lancement de programme,
fichiers embarqués, et URLs suspectes dans les annotations.
"""
import re
import pikepdf


SUSPICIOUS_KEYS = {
    "/JS": "JavaScript embarqué détecté (clé /JS)",
    "/JavaScript": "JavaScript embarqué détecté (clé /JavaScript)",
    "/OpenAction": "Action automatique à l'ouverture du document (/OpenAction)",
    "/AA": "Action automatique déclenchée par un événement (/AA)",
    "/Launch": "Tentative de lancement d'un programme externe (/Launch)",
    "/EmbeddedFile": "Fichier embarqué détecté",
    "/RichMedia": "Contenu multimédia riche embarqué (Flash/3D) - vecteur historique d'exploit",
    "/AcroForm": "Formulaire AcroForm présent (peut servir à l'exfiltration de données)",
    "/SubmitForm": "Soumission de formulaire automatique détectée",
    "/URI": "URI(s) embarquée(s) dans le document",
}

URL_RE = re.compile(rb"(https?://[^\s\)\]>\"']+)")


def analyze_pdf(filepath: str) -> dict:
    indicators = []
    urls_found = set()
    object_count = 0
    is_encrypted = False
    error = None

    try:
        # Raw byte scan — catches obfuscated/malformed PDFs even if pikepdf
        # can't fully parse the structure (common in malicious samples).
        with open(filepath, "rb") as f:
            raw = f.read()

        for key, desc in SUSPICIOUS_KEYS.items():
            if key.encode() in raw:
                indicators.append({"key": key, "description": desc})

        for match in URL_RE.findall(raw):
            try:
                urls_found.add(match.decode(errors="ignore"))
            except Exception:
                pass

        # Structured parse for extra context (page count, encryption)
        try:
            with pikepdf.open(filepath) as pdf:
                object_count = len(pdf.objects)
                is_encrypted = pdf.is_encrypted
        except pikepdf.PasswordError:
            is_encrypted = True
        except Exception as e:
            error = f"Analyse structurelle partielle (fichier non standard) : {e}"

    except Exception as e:
        error = f"Erreur de lecture du fichier : {e}"

    risk_score = min(100, len(indicators) * 18 + (10 if urls_found else 0))

    if risk_score >= 55:
        verdict = "malicious"
    elif risk_score >= 20:
        verdict = "suspicious"
    elif error:
        verdict = "unknown"
    else:
        verdict = "legit"

    return {
        "type": "pdf",
        "indicators": indicators,
        "urls_found": sorted(urls_found),
        "object_count": object_count,
        "is_encrypted": is_encrypted,
        "risk_score": risk_score,
        "verdict": verdict,
        "error": error,
    }
