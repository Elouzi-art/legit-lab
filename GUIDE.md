# Guide complet — Installation et utilisation du Lab de Triage de Légitimité

Ce guide s'adresse à quelqu'un qui n'a **jamais utilisé Docker**. Suis les
étapes dans l'ordre, tu n'as besoin d'aucune connaissance préalable.

---

## 1. Qu'est-ce que c'est, concrètement ?

Un site web (que tu lances sur ton propre ordinateur) où tu peux :
- déposer un fichier **PDF** (par exemple un PDF fourni par un enseignant, ou trouvé en ligne),
- ou coller une **URL** (un lien suspect),

et obtenir un **rapport** qui te dit si c'est probablement légitime,
suspect, ou malveillant — avec les raisons, dans la langue que tu choisis
(français, anglais ou arabe).

Tout se passe **dans un conteneur isolé** : rien n'est installé en dur sur
ton ordinateur, et tu peux tout supprimer d'un coup à la fin.

---

## 2. Installer Docker (une seule fois)

Docker est le logiciel qui fait tourner le lab. Si tu l'as déjà, passe à
l'étape 3.

1. Va sur https://www.docker.com/products/docker-desktop/
2. Télécharge **Docker Desktop** pour ton système (Windows, Mac, ou Linux).
3. Installe-le comme n'importe quel logiciel (double-clic, suivant,
   suivant...). Sur Windows, il peut te demander d'activer "WSL2" —
   accepte, c'est normal.
4. Redémarre ton ordinateur si l'installateur te le demande.
5. Lance **Docker Desktop**. Attends que l'icône (en bas à droite sur
   Windows, en haut sur Mac) devienne stable — ça veut dire que Docker
   tourne.

**Vérifier que ça marche** : ouvre un terminal (Invite de commandes /
PowerShell sur Windows, Terminal sur Mac/Linux) et tape :

```bash
docker --version
```

Si tu vois une version s'afficher (ex: `Docker version 27.x.x`), c'est bon.

---

## 3. Récupérer le projet

1. Télécharge le fichier `legit-lab.zip` qu'on t'a fourni.
2. Décompresse-le où tu veux sur ton ordinateur (clic droit → Extraire tout,
   ou double-clic sur Mac).
3. Tu obtiens un dossier `legit-lab/` avec plusieurs fichiers dedans
   (`Dockerfile`, `app/`, `README.md`, etc.). Ne renomme rien.

---

## 4. Construire l'image Docker (une seule fois)

C'est l'étape où Docker lit les instructions du projet et prépare tout
(installe les bibliothèques Python, entraîne le petit modèle de détection,
etc.). Ça prend 1 à 3 minutes selon ta connexion.

1. Ouvre un terminal.
2. Déplace-toi dans le dossier du projet :

```bash
cd chemin/vers/legit-lab
```

   (remplace `chemin/vers/` par l'endroit où tu as décompressé le dossier —
   par exemple `cd Downloads/legit-lab` ou `cd Desktop/legit-lab`)

3. Lance la construction :

```bash
docker build -t legit-lab .
```

   ⚠️ Ne pas oublier le point `.` à la fin, il veut dire "construis à
   partir du dossier actuel".

4. Tu vas voir défiler plein de lignes (installation des dépendances,
   entraînement du modèle...). À la fin, tu dois voir quelque chose comme :

```
Successfully tagged legit-lab:latest
```

Si tu vois ça, l'image est prête. Tu n'as **plus besoin de refaire cette
étape**, sauf si tu modifies le code du projet.

---

## 5. Lancer le lab

Toujours dans le même terminal (ou un nouveau, peu importe), tape :

```bash
docker run -p 5000:5000 legit-lab
```

Tu dois voir s'afficher :

```
[legit-lab] Démarrage du serveur sur http://0.0.0.0:5000 ...
```

👉 **Laisse ce terminal ouvert** — c'est lui qui fait tourner le serveur.
Si tu le fermes, le lab s'arrête.

---

## 6. Ouvrir l'interface

Ouvre ton navigateur (Chrome, Firefox, etc.) et va à cette adresse :

```
http://localhost:5000
```

Tu dois voir la page d'accueil du lab, avec en haut trois boutons de
langue : **Français / English / العربية**.

---

## 7. Utiliser le lab

### Analyser un PDF

1. Clique sur l'onglet **"Analyser un PDF"**.
2. Clique sur **"Choisir un fichier PDF"** et sélectionne ton fichier.
3. Clique sur **"Analyser"**.
4. Tu arrives sur la page de rapport avec :
   - un **badge coloré** en haut (vert = légitime, orange = suspect,
     rouge = malveillant),
   - une **synthèse** qui explique le verdict en une ou deux phrases,
   - le détail des **indicateurs techniques** trouvés (par exemple :
     "JavaScript embarqué détecté"),
   - les résultats des services externes (VirusTotal, etc. — vides si tu
     n'as pas configuré de clé API, voir section 9).

### Analyser une URL

1. Clique sur l'onglet **"Analyser une URL"**.
2. Colle ou tape un lien, par exemple `http://exemple-suspect.tk`.
3. Clique sur **"Analyser"**.
4. Même type de rapport, avec en plus une section **"Prédiction du modèle
   ML"** qui donne un pourcentage de probabilité de phishing.

### Configurer les clés API (optionnel)

Clique sur **"⚙ Paramètres API"** en haut de la page d'accueil — voir la
section 9 plus bas pour le détail complet.

### Changer de langue

Clique sur **Français / English / العربية** en haut de la page d'accueil
*avant* de lancer une analyse — le rapport sera généré dans la langue
choisie (y compris l'affichage de droite à gauche pour l'arabe).

---

## 8. Comprendre un rapport — exemple concret

Si tu analyses `http://secure-paypa1-login.tk/verify`, tu verras
probablement :

- **Verdict : SUSPECT ou MALVEILLANT**
- Indicateurs : pas de HTTPS, TLD `.tk` (souvent utilisé en phishing),
  ressemblance avec "paypal" (typosquatting)
- Modèle ML : probabilité de phishing élevée (> 90%)

C'est un lien **fictif** conçu pour déclencher ces alertes — ne va pas le
visiter, il n'existe pas réellement, c'est juste un exemple pédagogique.

---

## 9. (Optionnel) Activer les vérifications en ligne

Par défaut, le lab fonctionne **sans aucune clé API** (analyse statique +
modèle ML seulement). Pour avoir en plus les résultats de VirusTotal,
Google Safe Browsing, URLhaus, et un résumé rédigé par une vraie IA, il
faut des clés API.

**4 des 5 services sont 100% gratuits : il suffit de créer un compte**,
aucune carte bancaire n'est demandée. Le 5ᵉ (DeepSeek) est une
alternative payante à très bas coût — tu peux l'ignorer complètement et
utiliser Gemini à la place, qui est gratuit et suffit largement.

### Étape 1 — Obtenir les clés (prends seulement celles que tu veux)

| Service | Lien | Coût réel |
|---|---|---|
| VirusTotal | https://www.virustotal.com/gui/my-apikey — crée un compte, la clé est sur ton profil | **Gratuit**, juste un compte (quota limité/jour) |
| Google Safe Browsing | Crée un projet sur https://console.cloud.google.com/, active "Safe Browsing API", puis "API et services → Identifiants → Créer une clé API" | **Gratuit**, juste un compte Google (Google peut demander d'activer un compte de facturation GCP par principe, mais aucun frais n'est prélevé pour cet usage) |
| URLhaus (abuse.ch) | https://auth.abuse.ch/ — connecte-toi (GitHub, Google...), section "Optional" → "Create Auth-Key" | **Gratuit**, juste un compte |
| Gemini (recommandé) | https://aistudio.google.com/app/apikey — connexion avec un compte Google, clique "Create API key" | **Gratuit**, juste un compte Google (niveau gratuit généreux) |
| DeepSeek (optionnel, non recommandé si tu veux rester 100% gratuit) | https://platform.deepseek.com/api_keys | **Payant** (prépaiement, quelques centimes par utilisation) — inutile si tu as déjà configuré Gemini |

👉 En pratique, pour un lab 100% gratuit : configure VirusTotal, Google
Safe Browsing, URLhaus et Gemini. Laisse DeepSeek de côté, il ne sert que
de solution de secours si Gemini est indisponible.

### Étape 2 — Saisir les clés directement dans l'interface (le plus simple)

Pas besoin de toucher au terminal ni de relancer Docker :

1. Sur la page d'accueil, clique sur **"⚙ Paramètres API"**.
2. Colle chaque clé dans le champ correspondant (laisse vide ce que tu ne
   veux pas activer).
3. Clique sur **"Enregistrer"**.
4. Un badge 🟢 "Configurée (interface)" confirme que c'est pris en compte.
5. Retourne à l'accueil et relance une analyse — les modules correspondants
   sont maintenant actifs.

⚠️ Ces clés sont gardées en mémoire côté serveur, **liées à ton
navigateur** (cookie de session), jamais écrites sur le disque, et
effacées au redémarrage du conteneur. Si tu changes de navigateur ou
d'ordinateur, il faut les ressaisir.

### Étape 2 bis — Alternative : les passer au démarrage du conteneur

Si tu préfères (par exemple pour que toute la classe ait les mêmes clés
par défaut sans repasser par l'interface à chaque fois) :

```bash
docker run -p 5000:5000 \
  -e VT_API_KEY=colle_ta_cle_ici \
  -e GEMINI_API_KEY=colle_ta_cle_ici \
  legit-lab
```

Ces clés apparaîtront avec le badge 🟡 "Configurée (docker run -e)" dans
la page Paramètres. Une clé saisie dans l'interface est toujours
prioritaire sur celle passée au démarrage.

Dans tous les cas, tu peux n'activer qu'un seul service si tu veux — les
autres modules indiqueront simplement "clé API non fournie — module
ignoré" dans le rapport.

---

## 10. Arrêter et relancer le lab

- **Arrêter** : retourne dans le terminal où ça tourne, appuie sur
  `Ctrl + C`.
- **Relancer plus tard** : pas besoin de refaire `docker build`, juste
  `docker run -p 5000:5000 legit-lab` à nouveau (ou avec tes clés si tu
  en utilises).
- **Tout supprimer** (libérer l'espace disque) :

```bash
docker rmi legit-lab
```

---

## 11. Dépannage

**"docker: command not found"**
→ Docker Desktop n'est pas installé ou pas lancé. Relance l'application
Docker Desktop et réessaie.

**"port is already allocated" / "address already in use"**
→ Un autre programme utilise déjà le port 5000. Lance plutôt sur un autre
port, par exemple :
```bash
docker run -p 8080:5000 legit-lab
```
puis ouvre `http://localhost:8080` à la place.

**La page ne s'affiche pas dans le navigateur**
→ Vérifie dans le terminal que tu vois bien la ligne "Démarrage du
serveur...". Si le terminal affiche une erreur, copie-la et demande de
l'aide à ton enseignant ou relis les étapes 4 et 5.

**Le build (`docker build`) échoue avec une erreur réseau**
→ Il te faut une connexion internet au moment du `build` (pour installer
les dépendances Python). Une fois l'image construite, le `run` quotidien
peut fonctionner sans connexion (sauf si tu utilises les clés API).

**J'ai modifié le code et mes changements n'apparaissent pas**
→ Il faut reconstruire l'image après chaque modification :
```bash
docker build -t legit-lab .
docker run -p 5000:5000 legit-lab
```

---

## 12. Rappel important

Ce lab est un outil **pédagogique**. Le modèle de détection est entraîné
sur des données synthétiques (pas un vrai corpus de phishing), donc il
peut se tromper — c'est volontaire et fait partie de l'exercice : comparer
ses résultats à ceux de VirusTotal et comprendre pourquoi chaque méthode a
ses limites. N'utilise jamais ce lab, ni aucun fichier/lien analysé dessus,
contre une personne sans son consentement.
