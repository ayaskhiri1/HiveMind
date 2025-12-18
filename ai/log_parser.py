"""
Parser universel de logs - Support Texte + JSON
Compatible avec ELK, Kafka, fichiers logs standards
"""

import json
import logging
from typing import Dict, Union, Any
from datetime import datetime

logger = logging.getLogger(__name__)

# ============================================================================
# PARSER UNIVERSEL
# ============================================================================

def parse_log_entry(log_input: Union[str, Dict, Any]) -> Dict:
    """
    Parse un log quel que soit son format (texte, JSON, dict)
    
    Args:
        log_input: Log à parser (string, dict, ou JSON string)
    
    Returns:
        Dict normalisé avec les champs :
        - message: Le message principal à analyser
        - metadata: Informations contextuelles (timestamp, IP, etc.)
        - format: Type de format détecté
    
    Examples:
        >>> parse_log_entry("Failed SSH login from 10.0.0.5")
        {
            "message": "Failed SSH login from 10.0.0.5",
            "metadata": {},
            "format": "text"
        }
        
        >>> parse_log_entry('{"level":"ERROR","message":"DDoS detected"}')
        {
            "message": "DDoS detected",
            "metadata": {"level": "ERROR"},
            "format": "json"
        }
    """
    
    # CAS 1 : Déjà un dictionnaire Python
    if isinstance(log_input, dict):
        return _parse_dict_log(log_input)
    
    # CAS 2 : String (peut être texte brut ou JSON string)
    if isinstance(log_input, str):
        log_input = log_input.strip()
        
        # Essayer de parser comme JSON
        if log_input.startswith('{') or log_input.startswith('['):
            try:
                parsed_json = json.loads(log_input)
                return _parse_dict_log(parsed_json)
            except json.JSONDecodeError:
                logger.debug("Pas du JSON valide, traitement comme texte")
        
        # Traiter comme texte brut
        return {
            "message": log_input,
            "metadata": _extract_metadata_from_text(log_input),
            "format": "text",
            "original": log_input
        }
    
    # CAS 3 : Autre type (convertir en string)
    return {
        "message": str(log_input),
        "metadata": {},
        "format": "unknown",
        "original": log_input
    }

# ============================================================================
# PARSERS SPÉCIFIQUES
# ============================================================================

def _parse_dict_log(log_dict: Dict) -> Dict:
    """Parse un log au format dictionnaire/JSON"""
    
    # Extraire le message principal (plusieurs champs possibles)
    message_fields = ['message', 'msg', 'event', 'description', 'log', 'text']
    message = None
    
    for field in message_fields:
        if field in log_dict:
            message = str(log_dict[field])
            break
    
    # Si pas de message trouvé, concaténer tous les champs importants
    if not message:
        important_fields = ['event_type', 'error', 'alert', 'warning']
        for field in important_fields:
            if field in log_dict:
                message = f"{field}: {log_dict[field]}"
                break
    
    # Dernier recours : utiliser le JSON complet comme message
    if not message:
        message = json.dumps(log_dict, ensure_ascii=False)
    
    # Extraire les métadonnées
    metadata = {k: v for k, v in log_dict.items() if k not in message_fields}
    
    # Enrichir le message avec le contexte si disponible
    enriched_message = _enrich_message_with_context(message, metadata)
    
    return {
        "message": enriched_message,
        "metadata": metadata,
        "format": "json",
        "original": log_dict
    }

def _enrich_message_with_context(message: str, metadata: Dict) -> str:
    """
    Enrichit le message avec des informations contextuelles importantes
    pour améliorer l'analyse IA
    """
    context_parts = [message]
    
    # Ajouter l'IP source si disponible
    if 'source_ip' in metadata:
        context_parts.append(f"from IP {metadata['source_ip']}")
    elif 'src_ip' in metadata:
        context_parts.append(f"from IP {metadata['src_ip']}")
    
    # Ajouter le user si disponible
    if 'user' in metadata or 'username' in metadata:
        user = metadata.get('user', metadata.get('username'))
        context_parts.append(f"by user {user}")
    
    # Ajouter le port si disponible
    if 'port' in metadata or 'target_port' in metadata:
        port = metadata.get('port', metadata.get('target_port'))
        context_parts.append(f"on port {port}")
    
    # Ajouter le niveau de sévérité
    if 'level' in metadata or 'severity' in metadata:
        level = metadata.get('level', metadata.get('severity'))
        if level.upper() in ['CRITICAL', 'ERROR', 'FATAL']:
            context_parts.append(f"[{level.upper()}]")
    
    return " ".join(context_parts)

def _extract_metadata_from_text(text: str) -> Dict:
    """
    Extrait des métadonnées basiques depuis un log texte
    (IP, timestamp, etc.)
    """
    import re
    
    metadata = {}
    
    # Pattern IP
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ips = re.findall(ip_pattern, text)
    if ips:
        metadata['detected_ips'] = ips
        metadata['source_ip'] = ips[0]  # Premier IP = source probable
    
    # Pattern port
    port_pattern = r'\bport\s+(\d+)\b'
    ports = re.findall(port_pattern, text, re.IGNORECASE)
    if ports:
        metadata['detected_ports'] = ports
        metadata['port'] = int(ports[0])
    
    # Pattern user
    user_pattern = r'\buser\s+(\w+)\b'
    users = re.findall(user_pattern, text, re.IGNORECASE)
    if users:
        metadata['user'] = users[0]
    
    # Détection niveau de sévérité par mots-clés
    if any(word in text.lower() for word in ['critical', 'fatal', 'emergency']):
        metadata['inferred_level'] = 'CRITICAL'
    elif any(word in text.lower() for word in ['error', 'fail', 'denied']):
        metadata['inferred_level'] = 'ERROR'
    elif any(word in text.lower() for word in ['warning', 'warn']):
        metadata['inferred_level'] = 'WARNING'
    
    return metadata

# ============================================================================
# FORMATS SPÉCIFIQUES (ELK, SYSLOG, etc.)
# ============================================================================

def parse_elk_format(log_dict: Dict) -> Dict:
    """
    Parse spécifique pour les logs ELK/Logstash
    
    Format typique ELK:
    {
        "@timestamp": "2025-12-18T20:30:45.123Z",
        "@version": "1",
        "host": "server01",
        "message": "Failed login attempt",
        "tags": ["security", "authentication"]
    }
    """
    message = log_dict.get('message', '')
    
    metadata = {
        'timestamp': log_dict.get('@timestamp'),
        'host': log_dict.get('host'),
        'tags': log_dict.get('tags', []),
        'version': log_dict.get('@version'),
        'elk_format': True
    }
    
    # Enrichir avec d'autres champs ELK
    for key in ['source', 'type', 'fields', 'beat']:
        if key in log_dict:
            metadata[key] = log_dict[key]
    
    return {
        "message": message,
        "metadata": metadata,
        "format": "elk",
        "original": log_dict
    }

def parse_syslog_format(log_text: str) -> Dict:
    """
    Parse format Syslog standard (RFC 5424)
    
    Format: <priority>timestamp hostname application: message
    Exemple: <34>Dec 18 20:30:45 server01 sshd[1234]: Failed login
    """
    import re
    
    # Pattern syslog simplifié
    pattern = r'<(\d+)>(\w+ \d+ \d+:\d+:\d+) (\S+) (\S+?)(\[\d+\])?: (.+)'
    match = re.match(pattern, log_text)
    
    if match:
        priority, timestamp, hostname, app, pid, message = match.groups()
        
        return {
            "message": message,
            "metadata": {
                "priority": int(priority),
                "timestamp": timestamp,
                "hostname": hostname,
                "application": app,
                "pid": pid.strip('[]') if pid else None,
                "syslog_format": True
            },
            "format": "syslog",
            "original": log_text
        }
    else:
        # Fallback: traiter comme texte normal
        return parse_log_entry(log_text)

# ============================================================================
# DÉTECTION AUTOMATIQUE DE FORMAT
# ============================================================================

def auto_detect_format(log_input: Union[str, Dict]) -> str:
    """Détecte automatiquement le format du log"""
    
    if isinstance(log_input, dict):
        # Format ELK ?
        if '@timestamp' in log_input or '@version' in log_input:
            return 'elk'
        # Format JSON standard
        return 'json'
    
    if isinstance(log_input, str):
        log_input = log_input.strip()
        
        # Format JSON ?
        if log_input.startswith('{'):
            return 'json'
        
        # Format Syslog ?
        if log_input.startswith('<') and '>' in log_input[:10]:
            return 'syslog'
        
        # Format CSV ?
        if ',' in log_input and not ' ' in log_input.split(',')[0]:
            return 'csv'
    
    return 'text'

# ============================================================================
# FONCTION PRINCIPALE UNIFIÉE
# ============================================================================

def parse_any_log(log_input: Union[str, Dict, Any], format_hint: str = None) -> Dict:
    """
    Parse universel avec détection automatique ou hint manuel
    
    Args:
        log_input: Le log à parser
        format_hint: Format suggéré ('text', 'json', 'elk', 'syslog')
    
    Returns:
        Dict normalisé prêt pour analyse IA
    """
    
    # Détection automatique si pas de hint
    if not format_hint:
        format_hint = auto_detect_format(log_input)
    
    # Routing vers le parser approprié
    if format_hint == 'elk':
        if isinstance(log_input, str):
            log_input = json.loads(log_input)
        return parse_elk_format(log_input)
    
    elif format_hint == 'syslog':
        if isinstance(log_input, dict):
            log_input = json.dumps(log_input)
        return parse_syslog_format(log_input)
    
    else:
        # Fallback: parser universel
        return parse_log_entry(log_input)

# ============================================================================
# TESTS UNITAIRES
# ============================================================================

def test_parser():
    """Tests rapides du parser"""
    
    print("🧪 Tests du parser universel\n")
    
    # Test 1: Texte brut
    result1 = parse_any_log("Failed SSH login from 10.0.0.5 on port 22")
    print("✅ Test 1 (texte):", result1['message'])
    print("   Metadata:", result1['metadata'])
    
    # Test 2: JSON string
    result2 = parse_any_log('{"level":"ERROR","message":"DDoS attack","source_ip":"203.0.113.45"}')
    print("\n✅ Test 2 (JSON):", result2['message'])
    print("   Metadata:", result2['metadata'])
    
    # Test 3: Dict Python
    result3 = parse_any_log({
        "timestamp": "2025-12-18T20:30:45Z",
        "message": "Port scan detected",
        "source_ip": "192.168.1.100",
        "port": 80
    })
    print("\n✅ Test 3 (Dict):", result3['message'])
    print("   Metadata:", result3['metadata'])
    
    # Test 4: Format ELK
    result4 = parse_any_log({
        "@timestamp": "2025-12-18T20:30:45.123Z",
        "host": "server01",
        "message": "Authentication failure",
        "tags": ["security"]
    }, format_hint='elk')
    print("\n✅ Test 4 (ELK):", result4['message'])
    print("   Metadata:", result4['metadata'])
    
    # Test 5: Syslog
    result5 = parse_any_log("<34>Dec 18 20:30:45 server01 sshd[1234]: Failed login")
    print("\n✅ Test 5 (Syslog):", result5['message'])
    print("   Metadata:", result5['metadata'])

if __name__ == "__main__":
    test_parser()