# -*- coding: utf-8 -*-
"""
Génère une synthèse en langage naturel du rapport d'analyse, dans la
langue choisie par l'étudiant, via une API LLM gratuite/économique
(Gemini ou DeepSeek). Si aucune clé n'est fournie, on retombe sur un
résumé généré par template (pas de LLM) — le lab reste 100% fonctionnel.
"""
import os
import time
import requests

TIMEOUT = 45  # LLM calls can be slower than threat-intel API calls
MAX_RETRIES = 2  # total attempts on transient errors (503/429/timeout)
RETRY_DELAY = 2  # seconds between retries

LANG_NAMES = {"fr": "français", "en": "English", "ar": "Arabic (العربية)"}


def _build_prompt(analysis: dict, lang: str) -> str:
    lang_name = LANG_NAMES.get(lang, "français")
    return (
        f"Tu es un analyste en cybersécurité qui explique un rapport de triage "
        f"à un utilisateur non spécialiste, en {lang_name}. "
        f"Explique le verdict et les indicateurs ci-dessous, sans jargon inutile, "
        f"et termine par une recommandation concrète. "
        f"CONTRAINTE STRICTE DE FORMAT : réponds en UN SEUL PARAGRAPHE continu, "
        f"3 à 5 phrases maximum, sans titre, sans liste à puces, sans retour à la ligne. "
        f"Pas de texte avant ou après le paragraphe.\n\n"
        f"Données d'analyse (JSON) :\n{analysis}\n"
    )


_TRANSIENT_STATUS = {429, 500, 502, 503, 504}


def _call_gemini(prompt: str, api_key: str) -> str:
    # Gemini has a free tier (Google AI Studio). We use the "-latest" alias
    # rather than pinning a specific model version: Google regularly
    # retires older Gemini models (e.g. gemini-1.5-flash was removed from
    # the API in 2026), which would otherwise break this lab silently.
    # The alias always points to the current best Flash model.
    url = (
        "https://generativelanguage.googleapis.com/v1beta/models/"
        f"gemini-flash-latest:generateContent?key={api_key}"
    )
    body = {"contents": [{"parts": [{"text": prompt}]}]}

    last_exc = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            r = requests.post(url, json=body, timeout=TIMEOUT)
            if r.status_code in _TRANSIENT_STATUS and attempt < MAX_RETRIES:
                time.sleep(RETRY_DELAY)
                continue
            r.raise_for_status()
            data = r.json()
            return data["candidates"][0]["content"]["parts"][0]["text"].strip()
        except requests.exceptions.RequestException as e:
            last_exc = e
            if attempt < MAX_RETRIES:
                time.sleep(RETRY_DELAY)
                continue
            raise
    raise last_exc  # pragma: no cover — defensive, loop always returns or raises


def _call_deepseek(prompt: str, api_key: str) -> str:
    url = "https://api.deepseek.com/chat/completions"
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    body = {
        "model": "deepseek-chat",
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.4,
    }

    last_exc = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            r = requests.post(url, headers=headers, json=body, timeout=TIMEOUT)
            if r.status_code in _TRANSIENT_STATUS and attempt < MAX_RETRIES:
                time.sleep(RETRY_DELAY)
                continue
            r.raise_for_status()
            return r.json()["choices"][0]["message"]["content"].strip()
        except requests.exceptions.RequestException as e:
            last_exc = e
            if attempt < MAX_RETRIES:
                time.sleep(RETRY_DELAY)
                continue
            raise
    raise last_exc  # pragma: no cover


def _template_fallback(analysis: dict, lang: str, key_was_attempted: bool) -> str:
    verdict = analysis.get("final_verdict", "unknown")
    n_ind = len(analysis.get("static", {}).get("indicators", []))

    no_key_note = {
        "fr": "(Résumé généré sans IA — aucune clé API LLM fournie.)",
        "en": "(Template summary — no LLM API key provided.)",
        "ar": "(ملخص بدون ذكاء اصطناعي — لم يتم توفير مفتاح API.)",
    }
    key_failed_note = {
        "fr": "(Résumé généré sans IA — le service IA était temporairement indisponible, voir le détail technique ci-dessous.)",
        "en": "(Template summary — the AI service was temporarily unavailable, see technical detail below.)",
        "ar": "(ملخص بدون ذكاء اصطناعي — كانت خدمة الذكاء الاصطناعي غير متوفرة مؤقتًا، انظر التفاصيل التقنية أدناه.)",
    }
    note = (key_failed_note if key_was_attempted else no_key_note).get(lang, no_key_note["fr"])

    templates = {
        "fr": (
            f"Verdict global : {verdict}. {n_ind} indicateur(s) suspect(s) détecté(s) "
            f"par l'analyse statique. Consultez les sections ci-dessous pour le détail "
            f"de chaque indicateur et des résultats des API externes avant de tirer une conclusion. "
            f"{note}"
        ),
        "en": (
            f"Overall verdict: {verdict}. {n_ind} suspicious indicator(s) found by static "
            f"analysis. Review the sections below for details on each indicator and the "
            f"external API results before drawing a conclusion. {note}"
        ),
        "ar": (
            f"الحكم العام: {verdict}. تم العثور على {n_ind} مؤشر(ات) مشبوه(ة) عبر التحليل الإحصائي. "
            f"راجع الأقسام أدناه لمعرفة تفاصيل كل مؤشر ونتائج الواجهات الخارجية قبل استخلاص النتيجة. {note}"
        ),
    }
    return templates.get(lang, templates["fr"])


def generate_summary(analysis: dict, lang: str = "fr", gemini_key: str = None, deepseek_key: str = None) -> dict:
    gemini_key = gemini_key or os.environ.get("GEMINI_API_KEY")
    deepseek_key = deepseek_key or os.environ.get("DEEPSEEK_API_KEY")
    prompt = _build_prompt(analysis, lang)

    fallback_note = ""
    key_was_attempted = bool(gemini_key or deepseek_key)
    if gemini_key:
        try:
            return {"status": "ok", "source": "gemini", "text": _call_gemini(prompt, gemini_key)}
        except Exception as e:
            fallback_note = f" (Gemini a échoué : {e})"
    elif deepseek_key:
        try:
            return {"status": "ok", "source": "deepseek", "text": _call_deepseek(prompt, deepseek_key)}
        except Exception as e:
            fallback_note = f" (DeepSeek a échoué : {e})"

    return {
        "status": "fallback",
        "source": "template",
        "text": _template_fallback(analysis, lang, key_was_attempted) + fallback_note,
    }
