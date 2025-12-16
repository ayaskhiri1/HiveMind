🐝 HiveMind - AI-Powered Network Anomaly Detection
Système intelligent de détection d'anomalies réseau avec IA

Analyse automatique de logs avec Ollama et API REST Flask.
Détection proactive des menaces réseau par analyse intelligente des log

## ✨ Fonctionnalités

### 🚀 API REST Complète
- **Endpoint principal** : `/api/v1/analyze` - Analyse de logs uniques
- **Batch processing** : `/api/v1/analyze/batch` - Analyse multiple
- **Traitement de fichiers** : `/api/v1/analyze/file` - Analyse de fichiers logs
- **Monitoring** : Endpoints `/health` et `/status`
- **CORS activé** : Compatible avec les applications web

### 🤖 Intelligence Artificielle
- **Intégration Ollama** : Support de modèles LLM (Llama 3, Mistral, Gemma, etc.)
- **Détection intelligente** : Analyse contextuelle des logs réseau
- **Confiance mesurée** : Scores de confiance pour chaque analyse
- **Multi-modèles** : Changement dynamique de modèle

### 📊 Dashboard Temps Réel
- **Interface Rich** : Dashboard CLI professionnel
- **Statistiques live** : Visualisation des anomalies détectées
- **Catégorisation** : Répartition par type d'anomalie
- **Alertes visuelles** : Codes couleur pour la sévérité

### 🔄 Monitoring Automatique
- **Surveillance de dossiers** : Détection automatique des nouveaux logs
- **Traitement automatique** : Analyse et archivage en temps réel
- **Gestion d'erreurs** : Retry automatique et fallback
- **Multi-encodage** : Support UTF-8, UTF-16, CP1252, etc.

### 🛡️ Système CIEMS
- **Recommandations automatisées** : Actions préventives et correctives
- **Niveaux de sévérité** : Critical, High, Medium, Low
- **Réponses auto** : Scripts de réponse automatisés
- **Catégories d'anomalies** : Network scan, DDoS, malware, etc.


## 🚀 Installation Rapide

### Prérequis
- Python 3.9+
- [Ollama](https://ollama.ai/) installé et configuré
- Modèle LLM téléchargé (ex: `ollama pull llama3:latest`)

### Installation
# 1. Cloner le projet
git clone https://github.com/ayaskhiri1/HiveMind/tree/eya/ai.git
cd hivemind-ai

# 2. Créer un environnement virtuel
python -m venv venv
source venv/bin/Activate.ps1   # Linux/Mac
# ou
.\venv\Scripts\Activate.ps1      # Windows

# 3. Installer les dépendances
pip install -r requirements.txt

# 4. Configurer l'environnement
cp .env .env
# Éditer .env selon vos besoins

# 5. Démarrer Ollama (dans un autre terminal)
ollama serve
ollama pull llama3:latest


📖 Utilisation
Mode API (Recommandé)
# Démarrer le serveur API
python api.py

# Dans un autre terminal, tester l'API
curl -X POST http://localhost:5001/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{"log": "Failed SSH login from 192.168.1.100"}'

# Accéder à la documentation
curl http://localhost:5001/


Mode Monitoring
# Surveillance automatique des logs
python monitor_logs.py

# Avec options spécifiques
python monitor_logs.py --mode api --interval 5 --delete
Mode Dashboard
# Dashboard temps réel (après avoir lancé le monitoring)
python monitoring_dashboard.py


Mode CLI Direct
# Analyse directe de logs
python detect_anomaly.py --log "Port scan detected"

# Analyse de fichier
python detect_anomaly.py --file logs/attack.log

# Mode interactif
python detect_anomaly.py


📁 Structure du Projet

hivemind-ai/

├── api.py                    # Serveur API Flask 

principal

├── detect_anomaly.py         # Module IA de détection d'anomalies

├── monitor_logs.py           # Service de surveillance automatique

├── monitoring_dashboard.py      # Dashboard temps réel

├── requirements.txt          # Dépendances Python

├── .env.example              # Configuration d'environnement

├── README.md                 # Ce fichier

├── .gitignore                # Fichiers à ignorer par Git

│
├── logs/                     # Dossier des logs à analyser

├── archive/                  # Logs archivés après traitement

├── results/                  # Rapports d'analyse

│
├── api.log                   # Logs du serveur API

└── monitor.log              # Logs du service de surveillance



🔧 Configuration
Variables d'environnement (.env)
# API Configuration
PORT=5001
HOST=0.0.0.0
FLASK_ENV=development

# IA Configuration
DEFAULT_MODEL=llama3:latest
OLLAMA_HOST=http://localhost:11434

# Logging
LOG_LEVEL=INFO

# Directories
LOGS_DIR=logs
ARCHIVE_DIR=archive
RESULTS_DIR=results


Arguments de ligne de commande

# Pour monitor_logs.py
--mode [direct|api|simulation]  # Mode d'analyse
--model llama3:latest           # Modèle Ollama
--interval 2                    # Intervalle de vérification (secondes)
--log-dir logs                  # Dossier source
--archive-dir archive           # Dossier d'archivage
--delete                        # Supprimer après traitement
--verbose                       # Mode détaillé


📡 API Endpoints

GET /
Documentation complète de l'API avec exemples.

POST /api/v1/analyze
Analyse un log unique.

{
  "log": "Port scan detected from 192.168.1.100",
  "model": "llama3:latest"
}
POST /api/v1/analyze/batch
Analyse plusieurs logs en une requête.

{
  "logs": ["log1", "log2", "log3"],
  "model": "mistral"
}
POST /api/v1/analyze/file
Upload et analyse d'un fichier log.

bash
curl -X POST http://localhost:5001/api/v1/analyze/file \
  -F "file=@/path/to/logfile.log" \
  -F "model=llama3:latest"
GET /api/v1/models
Liste les modèles Ollama disponibles.

GET /api/v1/health
Vérification de l'état du service.

GET /api/v1/status
Statut complet du système.


🔍 Exemples d'Analyse
Logs détectés comme anomalies
✅ "User admin logged in successfully" → Normal
⚠️  "Failed login attempt for user root" → Warning
🚨 "Port scan detected from 192.168.1.100" → Anomaly
🔴 "DDoS attack in progress from multiple IPs" → Critical


Réponse CIEMS Exemple
{
  "anomaly": true,
  "confidence": 0.92,
  "category": "network_scan",
  "ciems": {
    "prevention": "Bloquer l'IP source temporairement (15 min)",
    "recommendation": "Activer le rate limiting sur le firewall",
    "auto_response": "firewall_block_temp",
    "severity": "high"
  }
}


🐛 Dépannage
Ollama non accessible
# Vérifier qu'Ollama tourne
ollama serve

# Vérifier les modèles disponibles
curl http://localhost:11434/api/tags
Erreur de port
# Changer le port si 5001 est occupé
export PORT=5002
python api.py

Problèmes de dépendances
# Mettre à jour pip
pip install --upgrade pip

# Réinstaller les dépendances
pip install -r requirements.txt --force-reinstall


📊 Dashboard
Le dashboard Rich fournit une interface temps réel :
✅ Statistiques globales
📈 Graphiques des anomalies
🚨 Alertes en temps réel
🏷️ Catégorisation automatique
⏱️ Historique des événements


🤝 Contribution
Fork le projet
Créer une branche (git checkout -b feature/AmazingFeature)
Commiter les changements (git commit -m 'Add AmazingFeature')
Pusher la branche (git push origin feature/AmazingFeature)
Ouvrir une Pull Request


🙏 Remerciements
Ollama pour les modèles LLM locaux
Flask pour le framework web
Rich pour l'interface CLI
La communauté open source