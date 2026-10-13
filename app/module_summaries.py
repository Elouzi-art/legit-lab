# -*- coding: utf-8 -*-
"""
Génère une conclusion courte (3 phrases maximum) pour CHAQUE module
d'analyse séparément (statique, VirusTotal, Safe Browsing, URLhaus, ML),
en plus de la synthèse globale par IA.

Volontairement basé sur des templates (pas d'appel LLM) : instantané,
gratuit, et disponible même sans aucune clé API configurée — contrairement
à la synthèse IA globale qui, elle, dépend de Gemini/DeepSeek.
"""


def _join(*sentences):
    return " ".join(s for s in sentences if s)


def static_summary(result: dict, lang: str) -> str:
    n = len(result.get("indicators", []))
    score = result.get("risk_score", 0)
    if lang == "ar":
        if n == 0:
            return "لم يكشف التحليل الإحصائي عن أي مؤشر مشبوه. درجة الخطورة الأولية منخفضة. هذا لا يستبعد التهديد تمامًا، فهو يعتمد فقط على أنماط معروفة."
        return f"تم رصد {n} مؤشر(ات) مشبوه(ة) في التحليل الإحصائي، بدرجة خطورة {score}/100. راجع التفاصيل أدناه لفهم كل مؤشر. هذا التحليل وحده لا يكفي لاتخاذ القرار النهائي."
    if lang == "en":
        if n == 0:
            return "Static analysis found no suspicious indicator. The baseline risk score is low. This doesn't rule out a threat entirely, as it only checks known patterns."
        return f"{n} suspicious indicator(s) found, risk score {score}/100. See the detail below for what each one means. This layer alone isn't enough to conclude — check the other sections too."
    # fr (default)
    if n == 0:
        return "L'analyse statique n'a trouvé aucun indicateur suspect. Le score de risque de base est faible. Cela n'exclut pas totalement une menace, car cette couche ne vérifie que des motifs connus."
    return f"{n} indicateur(s) suspect(s) détecté(s), score de risque {score}/100. Consulte le détail ci-dessous pour comprendre chacun. Cette couche seule ne suffit pas à conclure — regarde aussi les autres sections."


def virustotal_summary(result: dict, lang: str) -> str:
    status = result.get("status")
    if status == "skipped":
        return {"fr": "Clé API non fournie, ce module a été ignoré.",
                "en": "No API key provided, this module was skipped.",
                "ar": "لم يتم توفير مفتاح API، تم تجاوز هذه الوحدة."}[lang if lang in ("fr", "en", "ar") else "fr"]
    if status == "error":
        return {"fr": "La requête vers VirusTotal a échoué techniquement — résultat indisponible, pas d'information exploitable ici.",
                "en": "The VirusTotal request failed technically — no result available, nothing usable here.",
                "ar": "فشل طلب VirusTotal تقنيًا — النتيجة غير متوفرة، لا توجد معلومات يمكن استخدامها هنا."}[lang if lang in ("fr", "en", "ar") else "fr"]
    if not result.get("found"):
        return {"fr": "Cet élément n'est pas encore référencé chez VirusTotal, aucun historique de détection disponible.",
                "en": "This item isn't referenced on VirusTotal yet, no detection history available.",
                "ar": "هذا العنصر غير مسجل بعد في VirusTotal، لا يوجد سجل اكتشاف متاح."}[lang if lang in ("fr", "en", "ar") else "fr"]
    stats = result.get("stats", {})
    mal, susp, harmless = stats.get("malicious", 0), stats.get("suspicious", 0), stats.get("harmless", 0)
    if lang == "ar":
        if mal > 0:
            return f"صنّف {mal} محرك(ات) مضاد فيروسات هذا العنصر كخبيث، مقابل {harmless} اعتبروه سليمًا. هذا إجماع يستحق أخذه على محمل الجد. راجع التفاصيل الكاملة على موقع VirusTotal إذا أردت التعمق."
        if susp > 0:
            return f"لم يُصنَّف العنصر كخبيث صراحة، لكن {susp} محرك(ات) أشارت إليه كمشبوه. الأغلبية ({harmless}) اعتبرته سليمًا. الحذر مستحسن لكن لا يوجد إجماع واضح على الخطورة."
        return f"جميع المحركات التي فحصت هذا العنصر ({harmless}) اعتبرته سليمًا. لا يوجد أي تنبيه حاليًا على VirusTotal."
    if lang == "en":
        if mal > 0:
            return f"{mal} antivirus engine(s) flagged this as malicious, versus {harmless} that found it harmless. That's a consensus worth taking seriously. Check the full breakdown on VirusTotal's site for more detail."
        if susp > 0:
            return f"Not flagged as outright malicious, but {susp} engine(s) marked it suspicious. The majority ({harmless}) found it harmless. Some caution is warranted, but there's no clear consensus on danger."
        return f"All engines that scanned this item ({harmless}) found it harmless. No current alert on VirusTotal."
    if mal > 0:
        return f"{mal} moteur(s) antivirus ont classé ceci comme malveillant, contre {harmless} qui le jugent inoffensif. C'est un consensus à prendre au sérieux. Consulte le détail complet sur le site de VirusTotal si besoin."
    if susp > 0:
        return f"Pas classé franchement malveillant, mais {susp} moteur(s) l'ont marqué suspect. La majorité ({harmless}) le juge inoffensif. Une certaine prudence est de mise, sans consensus clair sur le danger."
    return f"Tous les moteurs ayant analysé cet élément ({harmless}) le jugent inoffensif. Aucune alerte actuelle sur VirusTotal."


def urlhaus_summary(result: dict, lang: str) -> str:
    status = result.get("status")
    if status == "skipped":
        return {"fr": "Clé API non fournie, ce module a été ignoré.",
                "en": "No API key provided, this module was skipped.",
                "ar": "لم يتم توفير مفتاح API، تم تجاوز هذه الوحدة."}[lang if lang in ("fr", "en", "ar") else "fr"]
    if status == "error":
        return {"fr": "La requête vers URLhaus a échoué techniquement — résultat indisponible.",
                "en": "The URLhaus request failed technically — no result available.",
                "ar": "فشل طلب URLhaus تقنيًا — النتيجة غير متوفرة."}[lang if lang in ("fr", "en", "ar") else "fr"]
    if result.get("found"):
        threat = result.get("threat", "?")
        if lang == "ar":
            return f"هذا الرابط موجود في قاعدة بيانات URLhaus العامة للبرمجيات الخبيثة، بتصنيف « {threat} ». هذا مؤشر قوي جدًا على الخطورة، لأن القاعدة تعتمد على بلاغات مؤكدة من الباحثين. يُنصح بشدة بعدم زيارة هذا الرابط."
        if lang == "en":
            return f"This link is present in URLhaus's public malware database, tagged as « {threat} ». That's a strong signal, since the database relies on confirmed reports from researchers. Visiting this link is strongly discouraged."
        return f"Ce lien figure dans la base de données publique de malware URLhaus, sous l'étiquette « {threat} ». C'est un signal fort, car cette base repose sur des signalements confirmés par des chercheurs. Il est fortement déconseillé de visiter ce lien."
    return {"fr": "Ce lien n'est pas (encore) référencé dans la base URLhaus. Ça ne prouve pas qu'il est sûr — ça veut juste dire que personne ne l'a signalé ici. Si VirusTotal ou le modèle ML donnent l'alerte, fais confiance à ces résultats en priorité.",
            "en": "This link isn't (yet) referenced in the URLhaus database. That doesn't prove it's safe — it just means nobody has reported it here. If VirusTotal or the ML model raise an alert, trust those results first.",
            "ar": "هذا الرابط غير مُدرج (بعد) في قاعدة بيانات URLhaus. هذا لا يثبت أنه آمن — فقط يعني أن أحدًا لم يُبلغ عنه هنا. إذا كان VirusTotal أو نموذج التعلم الآلي يحذر، فثق بتلك النتائج أولاً."}[lang if lang in ("fr", "en", "ar") else "fr"]


def safe_browsing_summary(result: dict, lang: str) -> str:
    status = result.get("status")
    if status == "skipped":
        return {"fr": "Clé API non fournie, ce module a été ignoré.",
                "en": "No API key provided, this module was skipped.",
                "ar": "لم يتم توفير مفتاح API، تم تجاوز هذه الوحدة."}[lang if lang in ("fr", "en", "ar") else "fr"]
    if status == "error":
        return {"fr": "La requête vers Google Safe Browsing a échoué techniquement — résultat indisponible.",
                "en": "The Google Safe Browsing request failed technically — no result available.",
                "ar": "فشل طلب Google Safe Browsing تقنيًا — النتيجة غير متوفرة."}[lang if lang in ("fr", "en", "ar") else "fr"]
    if result.get("found"):
        return {"fr": "Google Safe Browsing a trouvé une correspondance sur sa liste de menaces connues (malware, hameçonnage ou logiciel indésirable). C'est l'un des filtres les plus utilisés au monde (intégré à Chrome), donc une alerte ici est significative. Évite ce lien.",
                "en": "Google Safe Browsing found a match on its list of known threats (malware, phishing or unwanted software). This is one of the most widely used filters in the world (built into Chrome), so a hit here is meaningful. Avoid this link.",
                "ar": "وجدت خدمة Google Safe Browsing تطابقًا في قائمة التهديدات المعروفة لديها (برمجيات خبيثة، تصيد احتيالي أو برامج غير مرغوب فيها). هذه من أكثر المرشحات استخدامًا في العالم (مدمجة في متصفح Chrome)، لذا فإن التنبيه هنا ذو دلالة. تجنب هذا الرابط."}[lang if lang in ("fr", "en", "ar") else "fr"]
    return {"fr": "Aucune correspondance sur les listes de menaces de Google Safe Browsing. C'est un bon signe, mais ces listes réagissent souvent après coup — un site de phishing tout juste créé peut ne pas encore y figurer. Si d'autres couches signalent un danger, ne te fie pas uniquement à ce résultat.",
            "en": "No match on Google Safe Browsing's threat lists. That's a good sign, but these lists often react after the fact — a brand-new phishing site may not be listed yet. If other layers raise an alert, don't rely on this result alone.",
            "ar": "لا يوجد تطابق في قوائم تهديدات Google Safe Browsing. علامة جيدة، لكن هذه القوائم غالبًا ما تتفاعل بعد وقوع الحدث — موقع تصيد جديد قد لا يكون مُدرجًا بعد. إذا حذّرت طبقات أخرى، لا تعتمد على هذه النتيجة وحدها."}[lang if lang in ("fr", "en", "ar") else "fr"]


def ml_summary(result: dict, lang: str) -> str:
    if result.get("status") == "untrained":
        return {"fr": "Le modèle ML n'est pas entraîné sur cette instance — relance train_model.py.",
                "en": "The ML model isn't trained on this instance — run train_model.py.",
                "ar": "نموذج التعلم الآلي غير مدرب على هذه النسخة — شغّل train_model.py."}[lang if lang in ("fr", "en", "ar") else "fr"]
    if result.get("status") == "not_applicable_for_pdf":
        return {"fr": "Le modèle ML analyse uniquement les URLs, pas les fichiers PDF — non applicable ici.",
                "en": "The ML model only analyzes URLs, not PDF files — not applicable here.",
                "ar": "يحلل نموذج التعلم الآلي الروابط فقط، وليس ملفات PDF — غير قابل للتطبيق هنا."}[lang if lang in ("fr", "en", "ar") else "fr"]
    proba = result.get("phishing_probability", 0) * 100
    if lang == "ar":
        if proba >= 70:
            return f"يقدّر النموذج احتمال التصيد بـ {proba:.0f}٪، استنادًا إلى أنماط الرابط (الطول، الأحرف، التشابه مع علامة تجارية معروفة...). هذه احتمالية عالية تستحق الحذر. تذكّر أن النموذج مدرّب على بيانات اصطناعية، فتحقق أيضًا من الطبقات الأخرى."
        if proba >= 40:
            return f"احتمال التصيد المقدر {proba:.0f}٪ — منطقة وسطى غير حاسمة. لا يكفي هذا وحده لاستخلاص نتيجة. قارن مع نتائج VirusTotal والتحليل الإحصائي."
        return f"احتمال التصيد المقدر منخفض ({proba:.0f}٪) بناءً على أنماط الرابط اللغوية. هذا لا يعني شرعية مؤكدة، فقط عدم وجود نمط تصيد نموذجي في بنية الرابط."
    if lang == "en":
        if proba >= 70:
            return f"The model estimates a {proba:.0f}% phishing probability, based on URL patterns (length, characters, similarity to a known brand...). That's a high probability worth taking seriously. Remember the model is trained on synthetic data, so cross-check the other layers too."
        if proba >= 40:
            return f"Estimated phishing probability: {proba:.0f}% — a grey zone, not decisive on its own. Compare with VirusTotal and the static analysis results."
        return f"Estimated phishing probability is low ({proba:.0f}%) based on the URL's lexical patterns. This doesn't guarantee legitimacy, just the absence of a typical phishing shape in the URL's structure."
    if proba >= 70:
        return f"Le modèle estime la probabilité de phishing à {proba:.0f}%, en se basant sur les motifs de l'URL (longueur, caractères, ressemblance avec une marque connue...). C'est une probabilité élevée à prendre au sérieux. Le modèle étant entraîné sur des données synthétiques, croise ce résultat avec les autres couches."
    if proba >= 40:
        return f"Probabilité de phishing estimée à {proba:.0f}% — une zone grise, pas décisive à elle seule. Compare avec les résultats VirusTotal et l'analyse statique."
    return f"La probabilité de phishing estimée est faible ({proba:.0f}%) d'après les motifs lexicaux de l'URL. Cela ne garantit pas la légitimité, juste l'absence d'un profil de phishing typique dans la structure de l'URL."
