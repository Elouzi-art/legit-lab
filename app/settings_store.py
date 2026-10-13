# -*- coding: utf-8 -*-
"""
Stockage des clés API saisies depuis l'interface web.

Principe :
- Chaque navigateur reçoit un cookie de session signé contenant un simple
  jeton (pas la clé elle-même).
- Les vraies clés sont gardées en mémoire côté serveur, associées à ce
  jeton. Rien n'est jamais écrit sur disque.
- Si aucune clé n'a été saisie dans l'interface, on retombe sur les
  variables d'environnement (celles passées à `docker run -e ...`).
- Tout est perdu au redémarrage du conteneur — c'est voulu pour un lab :
  pas de clé qui traîne d'une session d'étudiant à l'autre.
"""
import os
import secrets
from flask import session

KEY_NAMES = ["VT_API_KEY", "GSB_API_KEY", "URLHAUS_AUTH_KEY", "GEMINI_API_KEY", "DEEPSEEK_API_KEY"]

# token -> {key_name: value}
_STORE: dict[str, dict[str, str]] = {}


def _get_or_create_token() -> str:
    token = session.get("sid")
    if not token:
        token = secrets.token_hex(16)
        session["sid"] = token
    return token


def save_keys(form_values: dict) -> None:
    """Sauvegarde les clés non vides envoyées par le formulaire.
    Un champ laissé vide ne supprime pas une clé déjà enregistrée,
    sauf si son champ 'clear_<NOM>' est coché."""
    token = _get_or_create_token()
    current = _STORE.setdefault(token, {})
    for name in KEY_NAMES:
        if form_values.get(f"clear_{name}"):
            current.pop(name, None)
            continue
        val = (form_values.get(name) or "").strip()
        if val:
            current[name] = val


def get_key(name: str) -> str:
    """Priorité : clé saisie dans l'interface pour cette session,
    sinon variable d'environnement, sinon chaîne vide."""
    token = session.get("sid")
    if token:
        val = _STORE.get(token, {}).get(name)
        if val:
            return val
    return os.environ.get(name, "")


def status_for_session() -> dict:
    """Retourne, pour chaque clé, d'où elle vient : 'session', 'env' ou None."""
    token = session.get("sid")
    stored = _STORE.get(token, {}) if token else {}
    result = {}
    for name in KEY_NAMES:
        if stored.get(name):
            result[name] = "session"
        elif os.environ.get(name):
            result[name] = "env"
        else:
            result[name] = None
    return result


def masked(value: str) -> str:
    if not value or len(value) < 8:
        return "••••••••"
    return value[:4] + "…" + value[-4:]
