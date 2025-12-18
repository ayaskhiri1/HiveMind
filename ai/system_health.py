"""
Module de monitoring de santé système
Détecte les anomalies de performance (CPU, RAM, température, disque)
Peut indiquer une intrusion, malware, ou minage de crypto
"""

import psutil
import time
import json
from datetime import datetime
from typing import Dict, List
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ============================================================================
# SEUILS D'ALERTE (PERSONNALISABLES)
# ============================================================================

THRESHOLDS = {
    "cpu_percent": {
        "warning": 75,    # 75% CPU = warning
        "critical": 90    # 90% CPU = critique
    },
    "memory_percent": {
        "warning": 80,
        "critical": 95
    },
    "disk_percent": {
        "warning": 85,
        "critical": 95
    },
    "temperature": {
        "warning": 70,    # 70°C
        "critical": 85    # 85°C
    },
    "network_connections": {
        "warning": 500,   # Plus de 500 connexions
        "critical": 1000
    }
}

# ============================================================================
# FONCTIONS DE COLLECTE DE MÉTRIQUES
# ============================================================================

def get_cpu_usage() -> Dict:
    """Collecte l'utilisation CPU"""
    cpu_percent = psutil.cpu_percent(interval=1)
    cpu_count = psutil.cpu_count()
    cpu_freq = psutil.cpu_freq()
    
    return {
        "percent": cpu_percent,
        "count": cpu_count,
        "frequency_mhz": cpu_freq.current if cpu_freq else None,
        "per_cpu": psutil.cpu_percent(interval=1, percpu=True)
    }

def get_memory_usage() -> Dict:
    """Collecte l'utilisation mémoire"""
    mem = psutil.virtual_memory()
    swap = psutil.swap_memory()
    
    return {
        "total_gb": round(mem.total / (1024**3), 2),
        "used_gb": round(mem.used / (1024**3), 2),
        "available_gb": round(mem.available / (1024**3), 2),
        "percent": mem.percent,
        "swap_percent": swap.percent
    }

def get_disk_usage() -> Dict:
    """Collecte l'utilisation disque"""
    disk = psutil.disk_usage('/')
    io = psutil.disk_io_counters()
    
    return {
        "total_gb": round(disk.total / (1024**3), 2),
        "used_gb": round(disk.used / (1024**3), 2),
        "free_gb": round(disk.free / (1024**3), 2),
        "percent": disk.percent,
        "read_mb": round(io.read_bytes / (1024**2), 2) if io else None,
        "write_mb": round(io.write_bytes / (1024**2), 2) if io else None
    }

def get_temperature() -> Dict:
    """Collecte la température (si disponible)"""
    try:
        temps = psutil.sensors_temperatures()
        if temps:
            # Moyenne de toutes les températures
            all_temps = []
            for name, entries in temps.items():
                for entry in entries:
                    all_temps.append(entry.current)
            
            avg_temp = sum(all_temps) / len(all_temps) if all_temps else None
            max_temp = max(all_temps) if all_temps else None
            
            return {
                "average_celsius": round(avg_temp, 1) if avg_temp else None,
                "max_celsius": round(max_temp, 1) if max_temp else None,
                "sensors": temps
            }
        else:
            return {"status": "not_available"}
    except Exception as e:
        logger.debug(f"Température non disponible: {e}")
        return {"status": "not_supported"}

def get_network_stats() -> Dict:
    """Collecte les statistiques réseau"""
    net_io = psutil.net_io_counters()
    connections = psutil.net_connections(kind='inet')
    
    # Comptage par état
    connection_states = {}
    for conn in connections:
        state = conn.status
        connection_states[state] = connection_states.get(state, 0) + 1
    
    return {
        "bytes_sent_mb": round(net_io.bytes_sent / (1024**2), 2),
        "bytes_recv_mb": round(net_io.bytes_recv / (1024**2), 2),
        "packets_sent": net_io.packets_sent,
        "packets_recv": net_io.packets_recv,
        "total_connections": len(connections),
        "connection_states": connection_states
    }

def get_top_processes(limit: int = 5) -> List[Dict]:
    """Liste les processus les plus gourmands"""
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
        try:
            processes.append({
                "pid": proc.info['pid'],
                "name": proc.info['name'],
                "cpu_percent": proc.info['cpu_percent'],
                "memory_percent": round(proc.info['memory_percent'], 2)
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    
    # Trier par CPU
    processes.sort(key=lambda x: x['cpu_percent'], reverse=True)
    return processes[:limit]

# ============================================================================
# ANALYSE D'ANOMALIES
# ============================================================================

def analyze_health_anomalies(metrics: Dict) -> Dict:
    """
    Analyse les métriques et détecte les anomalies
    Retourne un rapport avec recommandations
    """
    anomalies = []
    severity = "normal"
    ciems_recommendations = []
    
    # 1. ANALYSE CPU
    cpu_percent = metrics["cpu"]["percent"]
    if cpu_percent >= THRESHOLDS["cpu_percent"]["critical"]:
        severity = "critical"
        anomalies.append({
            "metric": "cpu",
            "value": cpu_percent,
            "threshold": THRESHOLDS["cpu_percent"]["critical"],
            "message": f"CPU critique: {cpu_percent}%"
        })
        ciems_recommendations.append({
            "issue": "CPU surchargé",
            "prevention": "1. Identifier processus gourmand (top/htop)\n2. Kill si malveillant\n3. Vérifier mining crypto (xmrig, ethminer)",
            "possible_causes": ["Malware minage crypto", "DDoS bot", "Processus légitime mal optimisé"],
            "commands": [
                "top -o %CPU",
                "ps aux --sort=-%cpu | head -10",
                "kill -9 <PID>"
            ]
        })
    elif cpu_percent >= THRESHOLDS["cpu_percent"]["warning"]:
        severity = "warning" if severity == "normal" else severity
        anomalies.append({
            "metric": "cpu",
            "value": cpu_percent,
            "threshold": THRESHOLDS["cpu_percent"]["warning"],
            "message": f"CPU élevé: {cpu_percent}%"
        })
    
    # 2. ANALYSE MÉMOIRE
    mem_percent = metrics["memory"]["percent"]
    if mem_percent >= THRESHOLDS["memory_percent"]["critical"]:
        severity = "critical"
        anomalies.append({
            "metric": "memory",
            "value": mem_percent,
            "threshold": THRESHOLDS["memory_percent"]["critical"],
            "message": f"Mémoire critique: {mem_percent}%"
        })
        ciems_recommendations.append({
            "issue": "Mémoire saturée",
            "prevention": "1. Vérifier memory leak\n2. Redémarrer services gourmands\n3. Inspecter processus suspects",
            "possible_causes": ["Memory leak", "Malware", "Base de données non optimisée"],
            "commands": [
                "free -h",
                "ps aux --sort=-%mem | head -10"
            ]
        })
    
    # 3. ANALYSE DISQUE
    disk_percent = metrics["disk"]["percent"]
    if disk_percent >= THRESHOLDS["disk_percent"]["critical"]:
        severity = "critical"
        anomalies.append({
            "metric": "disk",
            "value": disk_percent,
            "threshold": THRESHOLDS["disk_percent"]["critical"],
            "message": f"Disque critique: {disk_percent}%"
        })
        ciems_recommendations.append({
            "issue": "Disque plein",
            "prevention": "1. Nettoyer logs anciens\n2. Vérifier fichiers suspects volumineux\n3. Analyser avec ncdu",
            "possible_causes": ["Logs non rotés", "Exfiltration de données", "Remplissage malveillant"],
            "commands": [
                "du -sh /* | sort -h",
                "find / -size +1G -exec ls -lh {} \\;",
                "journalctl --vacuum-time=7d"
            ]
        })
    
    # 4. ANALYSE TEMPÉRATURE
    if metrics["temperature"]["status"] not in ["not_available", "not_supported"]:
        temp = metrics["temperature"].get("max_celsius")
        if temp and temp >= THRESHOLDS["temperature"]["critical"]:
            severity = "critical"
            anomalies.append({
                "metric": "temperature",
                "value": temp,
                "threshold": THRESHOLDS["temperature"]["critical"],
                "message": f"Température critique: {temp}°C"
            })
            ciems_recommendations.append({
                "issue": "Surchauffe système",
                "prevention": "1. Vérifier ventilation\n2. Arrêter processus intensifs\n3. Inspecter mining crypto",
                "possible_causes": ["Mining crypto", "Ventilation défaillante", "Malware intensif"],
                "commands": ["sensors", "nvidia-smi (si GPU)"]
            })
    
    # 5. ANALYSE RÉSEAU
    total_conns = metrics["network"]["total_connections"]
    if total_conns >= THRESHOLDS["network_connections"]["critical"]:
        severity = "critical"
        anomalies.append({
            "metric": "network_connections",
            "value": total_conns,
            "threshold": THRESHOLDS["network_connections"]["critical"],
            "message": f"Connexions réseau critiques: {total_conns}"
        })
        ciems_recommendations.append({
            "issue": "Trop de connexions réseau",
            "prevention": "1. Inspecter connexions suspectes\n2. Vérifier botnet/C2\n3. Bloquer IPs malveillantes",
            "possible_causes": ["Botnet DDoS", "Port scan actif", "Malware C2"],
            "commands": [
                "netstat -antp | grep ESTABLISHED | wc -l",
                "ss -s",
                "tcpdump -i any -c 100"
            ]
        })
    
    # 6. ANALYSE PROCESSUS SUSPECTS
    top_procs = metrics["top_processes"]
    for proc in top_procs:
        # Noms suspects communs
        suspicious_names = ['xmrig', 'ethminer', 'minerd', 'cgminer', 'cryptonight']
        if any(sus in proc['name'].lower() for sus in suspicious_names):
            severity = "critical"
            anomalies.append({
                "metric": "suspicious_process",
                "value": proc['name'],
                "message": f"Processus suspect détecté: {proc['name']} (PID: {proc['pid']})"
            })
            ciems_recommendations.append({
                "issue": f"Processus malveillant: {proc['name']}",
                "prevention": f"1. Kill immédiat: kill -9 {proc['pid']}\n2. Analyser avec VirusTotal\n3. Vérifier persistence (cron/startup)",
                "possible_causes": ["Mining crypto", "Malware confirmé"],
                "commands": [
                    f"kill -9 {proc['pid']}",
                    f"lsof -p {proc['pid']}",
                    "crontab -l"
                ]
            })
    
    return {
        "status": severity,
        "anomalies_detected": len(anomalies),
        "anomalies": anomalies,
        "ciems_recommendations": ciems_recommendations,
        "timestamp": datetime.now().isoformat()
    }

# ============================================================================
# FONCTION PRINCIPALE DE MONITORING
# ============================================================================

def collect_system_health() -> Dict:
    """Collecte toutes les métriques système"""
    metrics = {
        "timestamp": datetime.now().isoformat(),
        "cpu": get_cpu_usage(),
        "memory": get_memory_usage(),
        "disk": get_disk_usage(),
        "temperature": get_temperature(),
        "network": get_network_stats(),
        "top_processes": get_top_processes(5)
    }
    
    # Analyse des anomalies
    analysis = analyze_health_anomalies(metrics)
    metrics["analysis"] = analysis
    
    return metrics

def monitor_loop(interval: int = 10, output_file: str = "logs/health_monitoring.log"):
    """
    Boucle de monitoring continue
    Args:
        interval: Intervalle en secondes
        output_file: Fichier de sortie
    """
    logger.info(f"🏥 Démarrage monitoring santé système (intervalle: {interval}s)")
    
    try:
        while True:
            health = collect_system_health()
            
            # Affichage console
            status = health["analysis"]["status"]
            emoji = "🔴" if status == "critical" else "🟡" if status == "warning" else "🟢"
            
            print(f"\n{emoji} [{datetime.now().strftime('%H:%M:%S')}] Statut: {status.upper()}")
            print(f"   CPU: {health['cpu']['percent']:.1f}% | RAM: {health['memory']['percent']:.1f}% | Disque: {health['disk']['percent']:.1f}%")
            
            if health["analysis"]["anomalies_detected"] > 0:
                print(f"   ⚠️ {health['analysis']['anomalies_detected']} anomalies détectées !")
                for anomaly in health["analysis"]["anomalies"]:
                    print(f"      - {anomaly['message']}")
            
            # Écriture fichier log
            with open(output_file, 'a', encoding='utf-8') as f:
                f.write(json.dumps(health, ensure_ascii=False) + "\n")
            
            # Si critique, déclencher alerte
            if status == "critical":
                logger.critical(f"🚨 ALERTE CRITIQUE SYSTÈME !")
                # Ici: intégration avec votre API pour analyse IA
                # send_to_ai_analysis(health)
            
            time.sleep(interval)
            
    except KeyboardInterrupt:
        print("\n\n👋 Arrêt du monitoring")

# ============================================================================
# INTÉGRATION AVEC L'API IA
# ============================================================================

def send_to_ai_analysis(health_data: Dict, api_url: str = "http://localhost:5001/api/v1/analyze"):
    """Envoie les anomalies à l'API IA pour analyse contextuelle"""
    import requests
    
    if health_data["analysis"]["anomalies_detected"] == 0:
        return
    
    # Construire un log textuel pour l'IA
    log_message = f"System Health Alert: {health_data['analysis']['status'].upper()}\n"
    log_message += f"CPU: {health_data['cpu']['percent']}%, "
    log_message += f"RAM: {health_data['memory']['percent']}%, "
    log_message += f"Disk: {health_data['disk']['percent']}%\n"
    log_message += f"Anomalies: {', '.join([a['message'] for a in health_data['analysis']['anomalies']])}"
    
    try:
        response = requests.post(
            api_url,
            json={"log": log_message, "model": "llama3:latest"},
            timeout=10
        )
        
        if response.status_code == 200:
            ai_result = response.json()
            logger.info(f"✅ Analyse IA: {ai_result['data']['analysis']['reason']}")
            return ai_result
        else:
            logger.error(f"❌ Erreur API: {response.status_code}")
    except Exception as e:
        logger.error(f"❌ Erreur envoi API: {e}")

# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Monitoring santé système')
    parser.add_argument('--interval', type=int, default=10, help='Intervalle en secondes')
    parser.add_argument('--once', action='store_true', help='Vérification unique')
    parser.add_argument('--output', default='logs/health_monitoring.log', help='Fichier de sortie')
    
    args = parser.parse_args()
    
    if args.once:
        health = collect_system_health()
        print(json.dumps(health, indent=2, ensure_ascii=False))
    else:
        monitor_loop(args.interval, args.output)