"""
Module de détection d'anomalies IA
Utilise Ollama pour analyser des logs réseau et détecter des comportements suspects
"""

"""
# Analyser un log unique
python detect_anomaly.py --log "Failed login attempt from 10.0.0.5"

# Analyser un fichier
python detect_anomaly.py --file logs/test.log

# Mode interactif
python detect_anomaly.py
"""

import json
import re
import os
import logging
from typing import Dict, List, Optional, Union
from ollama import chat
from datetime import datetime

# Configuration du logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ============================================================================
# CONSTANTES DE CONFIGURATION
# ============================================================================

DEFAULT_MODEL = "llama3:latest"  # Modèle par défaut
LOGS_DIR = "logs"                # Dossier des logs à analyser
ARCHIVE_DIR = "archive"          # Dossier d'archivage
SUPPORTED_ENCODINGS = ['utf-8', 'cp1252', 'latin-1', 'iso-8859-1']

# ============================================================================
# FONCTIONS CIEMS
# ============================================================================

def generate_ciems_response(analysis: Dict, log_text: str) -> Dict:
    """
    Génère des recommandations CIEMS professionnelles et spécifiques
    VERSION AMÉLIORÉE : Réponses détaillées pour chaque catégorie
    """
    if not analysis.get("anomaly"):
        return {
            "prevention": None,
            "recommendation": "Continuer la surveillance normale",
            "auto_response": None,
            "severity": "none",
            "technical_details": "Aucune anomalie détectée",
            "priority": 0
        }
    
    category = analysis.get("category", "unknown").lower()
    confidence = analysis.get("confidence", 0)
    
    # Mapping catégorie → actions
    ciems_rules = {
        # ATTAQUES RÉSEAU
        "network_scan": {
            "prevention": "🛡️ Blocage IP source immédiat (15 minutes) + Rate limiting",
            "recommendation": "1. Activer IDS/IPS (Snort/Suricata)\n2. Configurer fail2ban avec seuil 5 connexions/min\n3. Vérifier les ports exposés (nmap audit)\n4. Activer logging détaillé firewall",
            "auto_response": "firewall_block_temp",
            "severity": "high",
            "technical_details": f"Scan de ports détecté. Confidence: {confidence:.0%}. Action: DROP paquets source pendant 15min.",
            "priority": 8,
            "estimated_impact": "Moyen - Tentative de reconnaissance réseau",
            "remediation_time": "15 minutes (automatique)",
            "soc_alert": True
        },
        
        "port_scan": {
            "prevention": "🛡️ Blocage IP source immédiat (15 minutes) + Rate limiting",
            "recommendation": "1. Activer IDS/IPS (Snort/Suricata)\n2. Configurer fail2ban avec seuil 5 connexions/min\n3. Vérifier les ports exposés (nmap audit)\n4. Activer logging détaillé firewall",
            "auto_response": "firewall_block_temp",
            "severity": "high",
            "technical_details": f"Scan de ports détecté. Confidence: {confidence:.0%}. Action: DROP paquets source pendant 15min.",
            "priority": 8,
            "estimated_impact": "Moyen - Tentative de reconnaissance réseau",
            "remediation_time": "15 minutes (automatique)",
            "soc_alert": True
        },
        
        # ATTAQUES DDOS
        "ddos_attack": {
            "prevention": "🚨 ACTIVATION MODE DDOS PROTECTION IMMÉDIATE\n- Cloudflare/Akamai: Under Attack Mode ON\n- Rate limiting agressif: 10 req/s par IP\n- Challenge CAPTCHA pour toutes requêtes suspectes\n- Géo-blocking pays non autorisés",
            "recommendation": "1. Activer WAF (Web Application Firewall) en mode strict\n2. Augmenter capacité serveur (autoscaling +200%)\n3. Activer CDN caching maximal (TTL 1h)\n4. Contacter ISP pour mitigation upstream\n5. Préparer communication clients (status page)\n6. Logger toutes IPs sources pour analyse forensique",
            "auto_response": "cloudflare_ddos_mode",
            "severity": "critical",
            "technical_details": f"Attaque DDoS détectée. Confidence: {confidence:.0%}. Protocole: HTTP Flood probable. Volume estimé: Critique. Action: Activation protection multi-couches.",
            "priority": 10,
            "estimated_impact": "CRITIQUE - Service potentiellement indisponible",
            "remediation_time": "30-60 minutes (avec mitigation)",
            "soc_alert": True,
            "incident_response": "Déclencher procédure IR-001: DDoS Response Plan"
        },
        
        "ddos": {  # Alias
            "prevention": "🚨 ACTIVATION MODE DDOS PROTECTION IMMÉDIATE\n- Cloudflare/Akamai: Under Attack Mode ON\n- Rate limiting agressif: 10 req/s par IP\n- Challenge CAPTCHA pour toutes requêtes suspectes\n- Géo-blocking pays non autorisés",
            "recommendation": "1. Activer WAF (Web Application Firewall) en mode strict\n2. Augmenter capacité serveur (autoscaling +200%)\n3. Activer CDN caching maximal (TTL 1h)\n4. Contacter ISP pour mitigation upstream\n5. Préparer communication clients (status page)\n6. Logger toutes IPs sources pour analyse forensique",
            "auto_response": "cloudflare_ddos_mode",
            "severity": "critical",
            "technical_details": f"Attaque DDoS détectée. Confidence: {confidence:.0%}. Action: Activation protection multi-couches.",
            "priority": 10,
            "estimated_impact": "CRITIQUE - Service potentiellement indisponible",
            "remediation_time": "30-60 minutes (avec mitigation)",
            "soc_alert": True,
            "incident_response": "Déclencher procédure IR-001: DDoS Response Plan"
        },
        
        # AUTHENTIFICATION
        "authentication_failure": {
            "prevention": "🔒 Blocage compte après 3 tentatives + IP blacklist 1h",
            "recommendation": "1. Forcer MFA (Multi-Factor Authentication) pour tous comptes\n2. Déployer fail2ban avec jail SSH/HTTP\n3. Audit des mots de passe (force minimum 12 caractères)\n4. Notification email/SMS tentatives échouées\n5. Vérifier logs accès pour pattern bruteforce",
            "auto_response": "account_lockout",
            "severity": "high" if confidence > 0.8 else "medium",
            "technical_details": f"Échecs d'authentification répétés. Confidence: {confidence:.0%}. Bruteforce probable.",
            "priority": 7,
            "estimated_impact": "Élevé - Tentative d'accès non autorisé",
            "remediation_time": "Immédiat (auto-lock)",
            "soc_alert": True
        },
        
        "bruteforce": {
            "prevention": "🔒 Blocage compte + IP après 3 tentatives (1 heure)",
            "recommendation": "1. Activer MFA obligatoire\n2. Configurer fail2ban (jail SSH/HTTP)\n3. Policy mots de passe renforcée (min 12 chars + complexité)\n4. Alertes temps réel (email/Slack)\n5. Analyse forensique des logs",
            "auto_response": "account_lockout",
            "severity": "high",
            "technical_details": f"Attaque bruteforce détectée. Confidence: {confidence:.0%}. Protocole: SSH/HTTP probable.",
            "priority": 8,
            "estimated_impact": "Élevé - Compromission compte possible",
            "remediation_time": "Immédiat",
            "soc_alert": True
        },
        
        # MALWARE
        "malware_detected": {
            "prevention": "☣️ QUARANTAINE IMMÉDIATE HOST INFECTÉ\n- Isolation réseau (VLAN quarantaine)\n- Blocage toutes connexions (in/out)\n- Snapshot état actuel (forensique)\n- Désactivation comptes utilisateur local",
            "recommendation": "1. Scanner complet multi-antivirus (ClamAV + Windows Defender)\n2. Analyse forensique mémoire RAM (Volatility)\n3. Vérifier persistence (registry, startup, cron)\n4. Réinitialiser TOUS les credentials système\n5. Restaurer depuis backup propre (< 7 jours)\n6. Notifier CERT/ANSSI si APT suspecté",
            "auto_response": "host_quarantine",
            "severity": "critical",
            "technical_details": f"Malware détecté. Confidence: {confidence:.0%}. Type: À identifier (analyse en cours). Host: Quarantaine réseau.",
            "priority": 10,
            "estimated_impact": "CRITIQUE - Compromission système",
            "remediation_time": "4-8 heures (investigation + cleanup)",
            "soc_alert": True,
            "incident_response": "Déclencher procédure IR-003: Malware Incident Response"
        },
        
        # EXFILTRATION DE DONNÉES
        "data_exfiltration": {
            "prevention": "🚫 BLOCAGE TOTAL CONNEXIONS SORTANTES SUSPECTES\n- Firewall: DROP toutes connexions non whitelistées\n- DLP (Data Loss Prevention): Mode strict\n- Capture trafic réseau (Wireshark/tcpdump)\n- Isolation complète host source",
            "recommendation": "1. Audit complet des données exfiltrées (volume, destination)\n2. Rotation immédiate de TOUTES les clés/tokens/credentials\n3. Investigation forensique approfondie (timeline complète)\n4. Vérification intégrité backups\n5. Notification RGPD si données personnelles (72h max)\n6. Déclaration CNIL/autorités si nécessaire\n7. Communication clients si données exposées",
            "auto_response": "network_isolation",
            "severity": "critical",
            "technical_details": f"Exfiltration de données détectée. Confidence: {confidence:.0%}. Volume: À quantifier. Destination: Analyse en cours.",
            "priority": 10,
            "estimated_impact": "CRITIQUE - Fuite données sensibles",
            "remediation_time": "24-48 heures (investigation complète)",
            "soc_alert": True,
            "incident_response": "Déclencher procédure IR-004: Data Breach Response + Notification légale",
            "legal_obligation": "Notification RGPD sous 72h si données personnelles"
        },
        
        # INJECTION SQL
        "sql_injection": {
            "prevention": "🛡️ Blocage IP + Analyse requête malveillante\n- WAF: Bloquer pattern SQL (UNION, SELECT, DROP)\n- Rate limiting: 1 req/s pour IP suspecte\n- Session utilisateur invalidée",
            "recommendation": "1. Audit code application (prepared statements)\n2. Review toutes requêtes SQL (utiliser ORM)\n3. Vérifier si données compromises (logs BDD)\n4. Activer SQL query logging (performance impact)\n5. Tester avec SQLMap (pentest interne)\n6. Formation développeurs (OWASP Top 10)",
            "auto_response": "waf_block",
            "severity": "critical",
            "technical_details": f"Tentative injection SQL. Confidence: {confidence:.0%}. Payload détecté. DB: À vérifier.",
            "priority": 9,
            "estimated_impact": "Critique - Accès BDD possible",
            "remediation_time": "2-4 heures (patch + audit)",
            "soc_alert": True
        },
        
        # XSS (Cross-Site Scripting)
        "xss_attack": {
            "prevention": "🛡️ Sanitize input + CSP (Content Security Policy)\n- Bloquer payload JavaScript malveillant\n- Invalider sessions utilisateur concernées",
            "recommendation": "1. Review code: escape tous inputs utilisateur\n2. Activer CSP headers strict (script-src 'self')\n3. Utiliser bibliothèques sanitization (DOMPurify)\n4. Audit cookies (HttpOnly, Secure, SameSite)\n5. Test automatisé XSS (Burp Suite/OWASP ZAP)",
            "auto_response": "waf_block",
            "severity": "high",
            "technical_details": f"Tentative XSS détectée. Confidence: {confidence:.0%}. Type: À identifier (Reflected/Stored/DOM).",
            "priority": 7,
            "estimated_impact": "Élevé - Vol de session utilisateur",
            "remediation_time": "1-2 heures",
            "soc_alert": True
        },
        
        # ACCÈS NON AUTORISÉ
        "unauthorized_access": {
            "prevention": "🚫 Révocation accès immédiate + Audit trail\n- Terminer toutes sessions actives\n- Révoquer tokens/API keys\n- Blocage IP source",
            "recommendation": "1. Investigation: comment accès obtenu?\n2. Audit permissions (principe moindre privilège)\n3. Review logs accès (timeline complète)\n4. Vérifier compromission credentials\n5. Renforcer contrôles accès (Zero Trust)",
            "auto_response": "revoke_access",
            "severity": "high",
            "technical_details": f"Accès non autorisé détecté. Confidence: {confidence:.0%}. User/IP à identifier.",
            "priority": 8,
            "estimated_impact": "Élevé - Accès ressource protégée",
            "remediation_time": "1-3 heures",
            "soc_alert": True
        }
    }
    
    # Récupération de la réponse CIEMS ou réponse par défaut
    response = ciems_rules.get(category, {
        "prevention": f"⚠️ Surveillance accrue + Logging détaillé de l'événement",
        "recommendation": f"1. Analyser manuellement le log pour catégorisation précise\n2. Corréler avec autres événements de sécurité\n3. Rechercher IoC (Indicators of Compromise) similaires\n4. Documenter dans SIEM pour futures détections\n5. Créer règle personnalisée si pattern récurrent",
        "auto_response": "alert_admin",
        "severity": "medium" if confidence > 0.7 else "low",
        "technical_details": f"Anomalie détectée (catégorie: {category}). Confidence: {confidence:.0%}. Classification: Nécessite analyse manuelle.",
        "priority": 5,
        "estimated_impact": "Moyen - Nécessite investigation",
        "remediation_time": "Variable (analyse requise)",
        "soc_alert": False
    })
    
    # Ajout des métadonnées
    response.update({
        "category": category,
        "confidence": confidence,
        "timestamp": datetime.now().isoformat(),
        "log_sample": log_text[:100],
        "detection_method": "AI-based (Ollama LLM)",
        "false_positive_probability": round((1 - confidence) * 100, 1)
    })
    
    return response

# ============================================================================
# FONCTION PRINCIPALE DE DÉTECTION
# ============================================================================

def detect_anomaly(log_text: str, model: str = DEFAULT_MODEL) -> Dict:
    """
    Analyse un log réseau avec un modèle IA pour détecter des anomalies
    
    Args:
        log_text (str): Le message de log à analyser
        model (str): Nom du modèle Ollama à utiliser (par défaut: "llama3:latest")
    
    Returns:
        Dict: Résultat d'analyse au format JSON contenant:
            - anomaly (bool): True si anomalie détectée
            - confidence (float): Niveau de confiance (0.0 à 1.0)
            - reason (str): Explication en français
            - category (str): Type d'anomalie
            - model_used (str): Modèle utilisé pour l'analyse
            - ciems (Dict): Recommandations CIEMS (nouveau)
    
    Example:
        >>> result = detect_anomaly("Port scan detected from 192.168.1.100")
        >>> print(result)
        {
            "anomaly": true,
            "confidence": 0.92,
            "reason": "Scan de ports détecté, comportement suspect",
            "category": "network_scan",
            "model_used": "llama3:latest",
            "ciems": {
                "prevention": "Bloquer l'IP source temporairement (15 min)",
                "recommendation": "Activer le rate limiting sur le firewall",
                "auto_response": "firewall_block_temp",
                "severity": "high"
            }
        }
    """
    
    # Construction du prompt pour le modèle IA
    prompt = f"""
    Tu es un expert en sécurité réseau. Analyse ce log et détermine s'il s'agit d'une anomalie.
    
    CONTEXTE:
    - Un log normal: connexions réussies, requêtes HTTP 200, activités autorisées
    - Une anomalie: scans de ports, attaques DDoS, tentatives de bruteforce, accès non autorisés
    
    LOG À ANALYSER: "{log_text}"
    
    FORMAT DE RÉPONSE OBLIGATOIRE (JSON uniquement):
    {{
        "anomaly": true ou false,
        "confidence": un nombre entre 0.0 et 1.0,
        "reason": "explication courte en français",
        "category": "type d'anomalie (si applicable)"
    }}
    
    Réponds uniquement avec le JSON, sans commentaires supplémentaires.
    """
    
    try:
        logger.debug(f"Analyse du log avec le modèle '{model}': {log_text[:50]}...")
        
        # Appel au modèle IA via Ollama
        response = chat(
            model=model,
            messages=[{'role': 'user', 'content': prompt}],
            options={'temperature': 0.1}  # Faible température pour des réponses cohérentes
        )
        
        # Extraction de la réponse
        response_text = response['message']['content']
        
        # Recherche du JSON dans la réponse
        json_match = re.search(r'\{.*\}', response_text, re.DOTALL)
        
        if json_match:
            # Parsing du JSON
            result = json.loads(json_match.group(0))
            
            # Validation et normalisation du résultat
            validated_result = {
                "anomaly": bool(result.get("anomaly", False)),
                "confidence": float(result.get("confidence", 0.5)),
                "reason": str(result.get("reason", "Analyse effectuée")),
                "category": str(result.get("category", "unknown")),
                "model_used": model,
                "timestamp": datetime.now().isoformat(),
                "original_log": log_text[:200]  # Limité pour éviter des logs trop longs
            }
            
            # S'assurer que la confiance est dans [0, 1]
            validated_result["confidence"] = max(0.0, min(1.0, validated_result["confidence"]))
            
            # 🆕 AJOUT CIEMS - Générer les recommandations
            validated_result["ciems"] = generate_ciems_response(validated_result, log_text)
            
            # Logging adapté à la sévérité
            if validated_result["anomaly"]:
                severity = validated_result["ciems"]["severity"]
                if severity == "critical":
                    logger.critical(f"ANOMALIE CRITIQUE détectée: {validated_result['reason']} (confiance: {validated_result['confidence']:.2f})")
                elif severity == "high":
                    logger.error(f"Anomalie grave détectée: {validated_result['reason']} (confiance: {validated_result['confidence']:.2f})")
                else:
                    logger.warning(f"Anomalie détectée: {validated_result['reason']} (confiance: {validated_result['confidence']:.2f})")
            else:
                logger.info(f"Aucune anomalie détectée (confiance: {validated_result['confidence']:.2f})")
            
            return validated_result
            
        else:
            # Aucun JSON trouvé dans la réponse
            logger.warning(f"Aucun JSON valide dans la réponse du modèle: {response_text[:100]}...")
            result = {
                "anomaly": False,
                "confidence": 0.0,
                "reason": "Format de réponse invalide du modèle IA",
                "category": "parsing_error",
                "model_used": model,
                "timestamp": datetime.now().isoformat()
            }
            result["ciems"] = generate_ciems_response(result, log_text)
            return result
            
    except json.JSONDecodeError as e:
        logger.error(f"Erreur de décodage JSON: {e}")
        result = {
            "anomaly": False,
            "confidence": 0.0,
            "reason": f"Erreur de format JSON: {str(e)}",
            "category": "json_error",
            "model_used": model,
            "timestamp": datetime.now().isoformat()
        }
        result["ciems"] = generate_ciems_response(result, log_text)
        return result
        
    except Exception as e:
        logger.error(f"Erreur lors de l'appel à Ollama: {e}")
        result = {
            "anomaly": False,
            "confidence": 0.0,
            "reason": f"Erreur de connexion au modèle IA: {str(e)}",
            "category": "connection_error",
            "model_used": model,
            "timestamp": datetime.now().isoformat()
        }
        result["ciems"] = generate_ciems_response(result, log_text)
        return result

# ============================================================================
# FONCTIONS UTILITAIRES POUR LA GESTION DES FICHIERS
# ============================================================================

def ensure_directory(directory_path: str) -> None:
    """Crée un dossier s'il n'existe pas"""
    if not os.path.exists(directory_path):
        os.makedirs(directory_path)
        logger.info(f"Dossier créé: {directory_path}")

def detect_file_encoding(filepath: str) -> str:
    """
    Détecte l'encodage d'un fichier texte
    
    Args:
        filepath (str): Chemin du fichier
    
    Returns:
        str: Encodage détecté (ex: 'utf-8', 'cp1252')
    """
    try:
        import chardet
        with open(filepath, 'rb') as f:
            raw_data = f.read(10000)  # Lire les 10 premiers Ko
            detection = chardet.detect(raw_data)
            return detection.get('encoding', 'utf-8')
    except ImportError:
        logger.warning("Module chardet non installé, utilisation de l'encodage par défaut")
        return 'utf-8'
    except Exception as e:
        logger.error(f"Erreur lors de la détection d'encodage: {e}")
        return 'utf-8'

def read_log_file(filepath: str) -> List[str]:
    """
    Lit un fichier log en gérant automatiquement l'encodage
    
    Args:
        filepath (str): Chemin du fichier log
    
    Returns:
        List[str]: Liste des lignes du fichier
    """
    try:
        # Essayer différents encodages courants
        for encoding in SUPPORTED_ENCODINGS:
            try:
                with open(filepath, 'r', encoding=encoding) as f:
                    lines = [line.strip() for line in f if line.strip()]
                logger.debug(f"Fichier lu avec l'encodage: {encoding}")
                return lines
            except UnicodeDecodeError:
                continue
        
        # Si aucun encodage standard ne fonctionne
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            lines = [line.strip() for line in f if line.strip()]
        logger.warning(f"Fichier lu avec ignore errors: {filepath}")
        return lines
        
    except Exception as e:
        logger.error(f"Erreur lors de la lecture du fichier {filepath}: {e}")
        return []

# ============================================================================
# FONCTION D'ANALYSE DE FICHIERS COMPLETS
# ============================================================================

def analyze_log_file(filepath: str, model: str = DEFAULT_MODEL) -> Dict:
    """
    Analyse toutes les lignes d'un fichier log
    
    Args:
        filepath (str): Chemin du fichier à analyser
        model (str): Modèle Ollama à utiliser
    
    Returns:
        Dict: Résultats de l'analyse avec statistiques
    """
    logger.info(f"Début de l'analyse du fichier: {filepath}")
    
    # Lire le fichier
    lines = read_log_file(filepath)
    if not lines:
        return {
            "success": False,
            "error": "Fichier vide ou impossible à lire",
            "file": os.path.basename(filepath)
        }
    
    # Analyser chaque ligne
    results = []
    anomalies = []
    ciems_responses = []  # Nouveau: collecter les réponses CIEMS
    
    for i, line in enumerate(lines, 1):
        result = detect_anomaly(line, model)
        result["line_number"] = i
        result["original_log"] = line
        results.append(result)
        
        if result["anomaly"]:
            anomalies.append(result)
            # Collecter les réponses CIEMS pour les anomalies
            ciems_responses.append({
                "line_number": i,
                "category": result["category"],
                "severity": result["ciems"]["severity"],
                "recommendation": result["ciems"]["recommendation"]
            })
        
        # Log progressif
        if i % 10 == 0:
            logger.debug(f"Progression: {i}/{len(lines)} lignes analysées")
    
    # Compilation des statistiques
    stats = {
        "total_lines": len(lines),
        "analyzed_lines": len(results),
        "anomalies_detected": len(anomalies),
        "anomaly_rate": len(anomalies) / len(results) if results else 0,
        "most_common_category": max(
            [r["category"] for r in results if r["anomaly"]],
            key=[r["category"] for r in results if r["anomaly"]].count,
            default="none"
        )
    }
    
    # 🆕 Statistiques CIEMS
    if ciems_responses:
        severity_counts = {}
        for resp in ciems_responses:
            severity_counts[resp["severity"]] = severity_counts.get(resp["severity"], 0) + 1
        
        stats["ciems"] = {
            "total_responses": len(ciems_responses),
            "severity_breakdown": severity_counts,
            "recommendations_summary": list(set([r["recommendation"] for r in ciems_responses]))
        }
    
    logger.info(f"Analyse terminée: {stats['anomalies_detected']} anomalies détectées sur {stats['total_lines']} lignes")
    
    return {
        "success": True,
        "file": os.path.basename(filepath),
        "statistics": stats,
        "anomalies": anomalies[:10],  # Limiter à 10 anomalies pour éviter un retour trop long
        "ciems_summary": stats.get("ciems", {}),
        "sample_results": results[:5],  # Retourne les 5 premiers résultats comme échantillon
        "model_used": model,
        "timestamp": datetime.now().isoformat()
    }

# ============================================================================
# FONCTION PRINCIPALE POUR L'ANALYSE EN LIGNE DE COMMANDE
# ============================================================================

def main():
    """Fonction principale pour l'exécution en ligne de commande"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Analyseur de logs réseau avec IA')
    parser.add_argument('--log', type=str, help='Log unique à analyser')
    parser.add_argument('--file', type=str, help='Fichier log à analyser')
    parser.add_argument('--model', type=str, default=DEFAULT_MODEL, 
                       help=f"Modèle Ollama à utiliser (défaut: {DEFAULT_MODEL})")
    parser.add_argument('--list-models', action='store_true', 
                       help='Lister les modèles Ollama disponibles')
    parser.add_argument('--ciems-only', action='store_true',
                       help='Afficher uniquement les recommandations CIEMS')
    
    args = parser.parse_args()
    
    # Lister les modèles disponibles
    if args.list_models:
        try:
            from ollama import list as list_models
            models = list_models()
            print("📦 Modèles Ollama disponibles:")
            for model in models.get('models', []):
                print(f"  • {model['name']}")
        except Exception as e:
            print(f"❌ Erreur lors de la liste des modèles: {e}")
        return
    
    # Analyser un log unique
    if args.log:
        print(f"🔍 Analyse du log avec le modèle '{args.model}':")
        print(f"   Log: {args.log}")
        result = detect_anomaly(args.log, args.model)
        
        if args.ciems_only:
            print("\n🎯 RECOMMANDATIONS CIEMS:")
            ciems = result.get("ciems", {})
            if ciems.get("severity") == "none":
                print("✅ Aucune action requise")
            else:
                print(f"\n⚠️  SÉVÉRITÉ: {ciems.get('severity', 'unknown').upper()}")
                print(f"📊 Confiance: {ciems.get('confidence', 0):.0%}")
                print(f"🎯 Priorité: {ciems.get('priority', 0)}/10")
                print(f"\n🛡️  PRÉVENTION IMMÉDIATE:")
                print(f"   {ciems.get('prevention', 'N/A')}")
                print(f"\n💡 RECOMMANDATIONS:")
                print(f"   {ciems.get('recommendation', 'N/A')}")
                print(f"\n🤖 Réponse Automatique: {ciems.get('auto_response', 'N/A')}")
                print(f"⏱️  Temps de remédiation: {ciems.get('remediation_time', 'N/A')}")
                print(f"📈 Impact estimé: {ciems.get('estimated_impact', 'N/A')}")
        else:
            print(f"\n📊 Résultat complet:")
            print(json.dumps(result, indent=2, ensure_ascii=False))
    
    # Analyser un fichier
    elif args.file:
        if os.path.exists(args.file):
            result = analyze_log_file(args.file, args.model)
            print(json.dumps(result, indent=2, ensure_ascii=False))
        else:
            print(f"❌ Fichier non trouvé: {args.file}")
    
    else:
        print("🤖 Mode interactif - Tapez 'quit' pour quitter")
        while True:
            try:
                log_input = input("\n📝 Entrez un log: ").strip()
                if log_input.lower() in ['quit', 'exit', 'q']:
                    break
                if log_input:
                    result = detect_anomaly(log_input)
                    
                    if result.get("anomaly"):
                        ciems = result.get("ciems", {})
                        print(f"\n🚨 ANOMALIE DÉTECTÉE: {result['reason']}")
                        print(f"   Sévérité: {ciems.get('severity', 'unknown').upper()}")
                        print(f"   Prévention: {ciems.get('prevention', 'N/A')}")
                        print(f"   Recommandation: {ciems.get('recommendation', 'N/A')[:100]}...")
                    else:
                        print(f"✅ {result['reason']}")
                        
            except KeyboardInterrupt:
                print("\n\n👋 Au revoir!")
                break
            except Exception as e:
                print(f"❌ Erreur: {e}")

if __name__ == "__main__":
    main()