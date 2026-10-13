# Legit-Lab — Lab de Triage de Légitimité (PDF / URL)

Image Docker pédagogique pour les TP de cybersécurité : un étudiant dépose
un **PDF** ou une **URL**, l'outil l'analyse via plusieurs couches
indépendantes et produit un **rapport multilingue** (français / anglais /
arabe) avec un verdict argumenté.

> ⚠️ Outil pédagogique, à usage de laboratoire / salle de classe.
> Ne téléversez jamais de fichiers ou d'URLs appartenant à des tiers sans
> leur consentement.

## Couches d'analyse

| Couche | Fonctionnement | Nécessite une clé API ? |
|---|---|---|
| **Heuristiques statiques** | PDF : `/JS`, `/OpenAction`, `/Launch`, fichiers embarqués, URLs internes (inspiré de `pdfid.py`). URL : typosquatting, IP brute, TLD suspect, homographes, etc. | Non |
| **VirusTotal** | Réputation du hash de fichier / de l'URL auprès de dizaines d'antivirus | Oui (gratuit) |
| **URLhaus (abuse.ch)** | Base de données publique de malware URLs | Oui (gratuit, obligatoire depuis juin 2025) |
| **Google Safe Browsing** | Vérification de la réputation de l'URL par Google | Oui (gratuit) |
| **Modèle ML** | Régression logistique entraînée sur des features lexicales de l'URL (longueur, tirets, IP, TLD, etc.) | Non — entraîné au build de l'image |
| **Synthèse IA** | Résumé en langage naturel du rapport, dans la langue choisie, via Gemini ou DeepSeek. Sans clé : résumé par template (toujours fonctionnel). | Optionnel |

Toutes les clés API sont **optionnelles**. Sans aucune clé, le lab reste
pleinement fonctionnel (analyse statique + ML + rapport template).

Les clés peuvent être saisies de deux façons :
1. **Depuis l'interface web** (page "⚙ Paramètres API") — gardées en
   mémoire serveur, liées à la session du navigateur, jamais écrites sur
   disque, effacées au redémarrage du conteneur. C'est la méthode
   recommandée pour un usage en TP.
2. **Via `docker run -e CLE=valeur`** — utile pour une config par défaut
   partagée. Une clé saisie dans l'interface est toujours prioritaire.

## Nouveautés récentes

- **Chaque module a maintenant sa propre mini-conclusion** (3 phrases max, générée par template — toujours disponible, même sans clé API), en plus de la synthèse IA globale.
- **Le modèle ML détecte désormais le typosquatting** : une nouvelle feature mesure la distance d'édition au nom de marque connu le plus proche (ex. `amaz0n.com` → très proche de `amazon`). Avant cet ajout, le ML ne voyait que des features génériques (longueur, tirets, HTTPS...) et ratait systématiquement les typosquats "propres" sans autre signal.
- **Gemini/DeepSeek : retentative automatique** sur erreurs transitoires (503, 429, timeout), timeout augmenté (20s → 45s), et la synthèse IA est forcée en **un seul paragraphe** de 3 à 5 phrases.
- Le message de repli distingue maintenant **"aucune clé fournie"** de **"clé fournie mais service indisponible"** — avant, le même message trompeur s'affichait dans les deux cas.
- **Lien direct vers le rapport complet VirusTotal** affiché sous sa mini-conclusion (quand une clé VT est configurée).
- La synthèse IA affiche maintenant explicitement sa source ("Selon Gemini :", "Selon DeepSeek :", ou "Résumé automatique (sans IA) :").
- Le disclaimer n'est plus limité à un usage "labo / TP" — formulé pour un usage quotidien aussi bien que pédagogique.

## ⚠️ À propos du modèle ML

Le modèle est entraîné sur un **jeu de données synthétique généré par
règles** (`generate_dataset.py`), pas sur un vrai corpus de phishing
réel — c'est volontaire pour que le build Docker reste 100% reproductible
hors-ligne. C'est un bon point de discussion en TP : comparez ses
prédictions à celles de VirusTotal et discutez des cas où il se trompe
(faux positifs / faux négatifs, biais du dataset synthétique).

Pour aller plus loin, vous pouvez remplacer `data/url_dataset.csv` par un
vrai dataset (ex. PhishTank, OpenPhish) et relancer `python ml_model.py`.

## Construction de l'image

```bash
docker build -t legit-lab .
```

Le dataset et le modèle ML sont générés et entraînés **pendant le build**
(pas de délai au premier lancement).

## Lancement

### Sans aucune clé API (mode 100% hors-ligne / ML + heuristiques)

```bash
docker run -p 5000:5000 legit-lab
```

Ouvrez http://localhost:5000

### Avec les clés API (toutes optionnelles)

```bash
docker run -p 5000:5000 \
  -e VT_API_KEY=xxxxx \
  -e GSB_API_KEY=xxxxx \
  -e GEMINI_API_KEY=xxxxx \
  legit-lab
```

Ou copiez `.env.example` en `.env`, remplissez vos clés, puis :

```bash
docker run -p 5000:5000 --env-file .env legit-lab
```

### Obtenir les clés

4 des 5 services sont 100% gratuits (juste un compte à créer, aucune
carte bancaire requise) : VirusTotal, Safe Browsing, URLhaus, Gemini.
DeepSeek est payant (prépaiement) — optionnel, à utiliser seulement si tu
veux une alternative à Gemini.

- **VirusTotal** : https://www.virustotal.com/gui/my-apikey
- **Google Safe Browsing** : https://developers.google.com/safe-browsing/v4/get-started
- **URLhaus (abuse.ch)** : https://auth.abuse.ch/ (connecte-toi, puis section "Optional" → "Create Auth-Key")
- **Gemini (Google AI Studio)** : https://aistudio.google.com/app/apikey
- **DeepSeek** : https://platform.deepseek.com/api_keys

## Utilisation en TP

1. L'étudiant choisit la langue du rapport (FR / EN / AR) en haut de la page.
2. Il dépose un PDF fourni par l'enseignant, ou colle un lien suspect.
3. Il obtient un rapport avec :
   - un verdict global (légitime / suspect / malveillant),
   - le détail de chaque indicateur statique déclenché,
   - les résultats des API externes (si clés fournies),
   - la probabilité de phishing du modèle ML (pour les URLs),
   - une synthèse en langage naturel.

Idée d'exercice : demander aux étudiants de forger un PDF ou une URL qui
trompe une couche mais pas les autres, pour comprendre les limites de
chaque méthode de détection.

## Structure du projet

```
legit-lab/
├── Dockerfile
├── entrypoint.sh
├── requirements.txt
├── .env.example
└── app/
    ├── app.py                # Serveur Flask (routes + orchestration)
    ├── pdf_analysis.py        # Heuristiques statiques PDF
    ├── url_analysis.py        # Heuristiques statiques URL
    ├── api_clients.py         # VirusTotal / URLhaus / Safe Browsing
    ├── ml_model.py            # Extraction de features + prédiction ML
    ├── generate_dataset.py    # Génération du dataset synthétique
    ├── llm_report.py          # Synthèse IA (Gemini / DeepSeek / fallback)
    ├── i18n.py                # Traductions FR / EN / AR
    ├── templates/             # index.html, report.html
    └── static/style.css
```

## Sécurité — à lire avant de publier l'image ou de l'exposer sur un réseau

- **Prévu pour un usage local** (`localhost`) ou sur un réseau de confiance — le serveur Flask intégré n'est pas un serveur de production et il n'y a aucune authentification. Ne l'expose pas directement sur internet sans mettre un reverse proxy (HTTPS + authentification) devant.
- **Ne jamais figer de clé API dans le Dockerfile** (`ENV VT_API_KEY=...` codé en dur) avant de publier l'image — passe toujours les clés via `-e` au lancement, ou via la page "⚙ Paramètres" de l'interface.
- Les fichiers uploadés sont supprimés immédiatement après analyse ; rien ne persiste entre deux analyses.
- Aucun secret n'est intégré dans l'image telle que fournie — vérifié avant chaque publication de ce projet.

## Limites connues (bonnes pour la discussion en TP)

- Le modèle ML est un modèle de démonstration (dataset synthétique).
- `tldextract` utilise volontairement son instantané hors-ligne (pas de
  tentative de téléchargement réseau), pour fonctionner en salle isolée.
- Les quotas gratuits des API (VirusTotal notamment) sont limités —
  prévoir une clé par groupe d'étudiants plutôt qu'une clé partagée.
