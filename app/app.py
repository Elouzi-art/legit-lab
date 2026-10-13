# -*- coding: utf-8 -*-
"""
Lab de Triage de Légitimité — application Flask.
Analyse un PDF ou une URL via heuristiques statiques, API externes
(VirusTotal, URLhaus, Safe Browsing) et un modèle ML, puis génère
un rapport multilingue (FR/EN/AR), avec synthèse optionnelle par LLM.
"""
import os
import secrets
import uuid
from flask import Flask, render_template, request, redirect, url_for
from werkzeug.utils import secure_filename

import pdf_analysis
import url_analysis
import api_clients
import ml_model
import llm_report
import settings_store
import module_summaries
from i18n import t, TRANSLATIONS

BASE_DIR = os.path.dirname(__file__)
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 20 * 1024 * 1024  # 20 MB max upload
# Secret key for signing the session cookie that holds the (anonymous)
# session token used by settings_store. Regenerated at each container
# start on purpose: sessions — and any keys typed in the UI — don't
# survive a restart, which is the right default for a shared lab machine.
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)


def combine_verdict(*scores_and_verdicts):
    """Combine plusieurs verdicts partiels en un verdict final prudent
    (on retient le pire cas, sauf si tout le reste est 'unknown')."""
    order = {"malicious": 3, "suspicious": 2, "legit": 1, "unknown": 0}
    worst = "unknown"
    for v in scores_and_verdicts:
        if v and order.get(v, 0) > order.get(worst, 0):
            worst = v
    return worst if worst != "unknown" else "unknown"


@app.route("/")
def index():
    lang = request.args.get("lang", "fr")
    return render_template("index.html", t=t(lang), lang=lang, langs=list(TRANSLATIONS.keys()))


@app.route("/settings", methods=["GET", "POST"])
def settings_route():
    lang = request.args.get("lang") or request.form.get("lang", "fr")
    saved = False
    if request.method == "POST":
        settings_store.save_keys(request.form)
        saved = True

    status = settings_store.status_for_session()
    return render_template(
        "settings.html",
        t=t(lang),
        lang=lang,
        langs=list(TRANSLATIONS.keys()),
        status=status,
        key_names=settings_store.KEY_NAMES,
        saved=saved,
    )


@app.route("/analyze/pdf", methods=["POST"])
def analyze_pdf_route():
    lang = request.form.get("lang", "fr")
    file = request.files.get("pdf_file")
    if not file or file.filename == "":
        return redirect(url_for("index", lang=lang))

    # secure_filename strips path separators and other dangerous characters
    # from the user-supplied filename — without it, a crafted filename like
    # "../../etc/something" could write outside UPLOAD_DIR.
    safe_name = secure_filename(file.filename) or "upload.pdf"
    fname = f"{uuid.uuid4().hex}_{safe_name}"
    fpath = os.path.join(UPLOAD_DIR, fname)
    file.save(fpath)

    static_result = pdf_analysis.analyze_pdf(fpath)
    vt_result = api_clients.virustotal_file(fpath, api_key=settings_store.get_key("VT_API_KEY"))

    urls_in_pdf = static_result.get("urls_found", [])
    urlhaus_key = settings_store.get_key("URLHAUS_AUTH_KEY")
    urlhaus_results = [api_clients.urlhaus_url(u, api_key=urlhaus_key) for u in urls_in_pdf[:5]]

    final_verdict = combine_verdict(
        static_result["verdict"],
        _vt_file_verdict(vt_result),
    )

    analysis = {
        "filename": file.filename,
        "static": static_result,
        "virustotal": vt_result,
        "urlhaus_on_embedded_urls": list(zip(urls_in_pdf[:5], urlhaus_results)),
        "ml": {"status": "not_applicable_for_pdf"},
        "final_verdict": final_verdict,
    }

    summary = llm_report.generate_summary(
        analysis, lang,
        gemini_key=settings_store.get_key("GEMINI_API_KEY"),
        deepseek_key=settings_store.get_key("DEEPSEEK_API_KEY"),
    )

    module_conclusions = {
        "static": module_summaries.static_summary(static_result, lang),
        "virustotal": module_summaries.virustotal_summary(vt_result, lang),
    }

    try:
        os.remove(fpath)
    except OSError:
        pass

    return render_template(
        "report.html", t=t(lang), lang=lang, analysis=analysis, summary=summary,
        kind="pdf", module_conclusions=module_conclusions,
    )


@app.route("/analyze/url", methods=["POST"])
def analyze_url_route():
    lang = request.form.get("lang", "fr")
    target_url = request.form.get("url", "").strip()
    if not target_url:
        return redirect(url_for("index", lang=lang))
    if not target_url.lower().startswith(("http://", "https://")):
        target_url = "http://" + target_url

    static_result = url_analysis.analyze_url(target_url)
    vt_result = api_clients.virustotal_url(target_url, api_key=settings_store.get_key("VT_API_KEY"))
    urlhaus_result = api_clients.urlhaus_url(target_url, api_key=settings_store.get_key("URLHAUS_AUTH_KEY"))
    gsb_result = api_clients.safe_browsing_url(target_url, api_key=settings_store.get_key("GSB_API_KEY"))
    ml_result = ml_model.predict_url(target_url)

    final_verdict = combine_verdict(
        static_result["verdict"],
        _vt_url_verdict(vt_result),
        "malicious" if urlhaus_result.get("found") else None,
        "malicious" if gsb_result.get("found") else None,
        ml_result.get("verdict"),
    )

    analysis = {
        "url": target_url,
        "static": static_result,
        "virustotal": vt_result,
        "urlhaus": urlhaus_result,
        "safe_browsing": gsb_result,
        "ml": ml_result,
        "final_verdict": final_verdict,
    }

    summary = llm_report.generate_summary(
        analysis, lang,
        gemini_key=settings_store.get_key("GEMINI_API_KEY"),
        deepseek_key=settings_store.get_key("DEEPSEEK_API_KEY"),
    )

    module_conclusions = {
        "static": module_summaries.static_summary(static_result, lang),
        "virustotal": module_summaries.virustotal_summary(vt_result, lang),
        "urlhaus": module_summaries.urlhaus_summary(urlhaus_result, lang),
        "safe_browsing": module_summaries.safe_browsing_summary(gsb_result, lang),
        "ml": module_summaries.ml_summary(ml_result, lang),
    }

    return render_template(
        "report.html", t=t(lang), lang=lang, analysis=analysis, summary=summary,
        kind="url", module_conclusions=module_conclusions,
    )


def _vt_file_verdict(vt_result):
    if vt_result.get("status") != "ok" or not vt_result.get("found"):
        return None
    stats = vt_result.get("stats", {})
    if stats.get("malicious", 0) > 0:
        return "malicious"
    if stats.get("suspicious", 0) > 0:
        return "suspicious"
    return "legit"


def _vt_url_verdict(vt_result):
    if vt_result.get("status") != "ok" or not vt_result.get("found"):
        return None
    stats = vt_result.get("stats", {})
    if stats.get("malicious", 0) > 0:
        return "malicious"
    if stats.get("suspicious", 0) > 0:
        return "suspicious"
    return "legit"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
