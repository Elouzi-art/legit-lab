#!/bin/sh
set -e

cd /app

if [ ! -f "data/phishing_model.joblib" ]; then
  echo "[legit-lab] Entraînement du modèle ML (première exécution)..."
  python ml_model.py
fi

echo "[legit-lab] Démarrage du serveur sur http://0.0.0.0:5000 ..."
exec python app.py
