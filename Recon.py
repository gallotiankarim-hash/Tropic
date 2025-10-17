import sys
import os
import requests
import time
import socket
from datetime import datetime
from requests.exceptions import RequestException
from urllib.parse import urlparse

# ===============================================================================
#                             PHASE 1 : CONFIGURATION GLOBALE
# ===============================================================================

# --- RÈGLES DE TIME-OUT ET AGENT ---
TIMEOUT_DNS_RESOLVE = 2.0
TIMEOUT_HTTP_PROBE = 5.0
USER_AGENT_PRO = "TROPIC-MultiVector-Recon/1.1 (EthicalHacking; High-Volume-Action)"

# --- RÈGLES DE VALIDATION D'ACTIVITÉ ---
ACTIVE_STATUS_CODES = [200, 201, 204, 301, 302, 307, 308, 401, 403]
ALERT_STATUS_CODES = [500, 501, 502, 503, 504, 400]

# --- LISTES DE WORDS CRITIQUES ---
CRITICAL_PREFIXES = [
    'www', 'api', 'dev', 'admin', 'test', 'stage', 'prod', 'uat', 'accept', 'beta', 
    'cms', 'docs', 'sso', 'vpn', 'proxy', 'mail', 'ftp', 'ssh', 'db', 'app'
]
INFRA_PREFIXES = [
    'jenkins', 'gitlab', 'jira', 'confluence', 'intranet', 'monitoring', 'logs', 
    'config', 'vault', 'cpanel', 'webmail', 'router', 'gateway', 'backend'
]
CLOUD_PREFIXES = [
    's3', 'cdn', 'assets', 'static', 'storage', 'data', 'blob', 'files', 'cloud', 'buckets'
]

# ===============================================================================
#                             PHASE 2 : FONCTIONS DU MOTEUR
# ===============================================================================

def load_prefixes():
    """Charge toutes les listes de préfixes pour générer la liste massive de cibles."""
    all_prefixes = sorted(list(set(CRITICAL_PREFIXES + INFRA_PREFIXES + CLOUD_PREFIXES)))
    return all_prefixes

def dns_resolution_check(domain, output_lines):
    """Tente la résolution DNS directe (Action critique pour écarter les cibles mortes)."""
    output_lines.append(f"[ACTION 1.A] DNS Check: Attempting resolution for {domain}...")
    try:
        ip_address = socket.gethostbyname(domain)
        output_lines.append(f"[ACTION 1.B] DNS Result: {domain} resolved to IP {ip_address}.")
        return ip_address
    except socket.gaierror:
        output_lines.append(f"[ACTION 1.C] DNS Result: {domain} failed to resolve. Skipping HTTP probe.")
        return None
    except Exception as e:
        output_lines.append(f"[ACTION 1.D] DNS ERROR: {domain} - {str(e)}.")
        return None

def http_probe_check(url, output_lines, http_timeout, user_agent):
    """
    Effectue la vérification HTTP/HTTPS complète.
    Utilise allow_redirects=True pour gérer les chaînes de redirection.
    Retourne (statut, url_finale, corps_reponse_tronqué)
    """
    response_body_snippet = ""
    
    try:
        headers = {'User-Agent': user_agent}
        # Utiliser allow_redirects=True pour obtenir directement l'état final
        response = requests.get(url, headers=headers, timeout=http_timeout, allow_redirects=True) 
        
        status = response.status_code
        final_url = response.url # URL de destination finale
        
        log_detail = f"Final Status {status}. URL Finale: {final_url}"

        # Ajoute des détails si des redirections ont eu lieu
        if response.history:
            log_detail = f"Redirected {len(response.history)} time(s). Final Status {status}. URL Finale: {final_url}"
        
        # Capture du corps de la réponse pour les statuts critiques
        if status in ALERT_STATUS_CODES:
            response_body_snippet = response.text[:300].replace('\n', ' ').strip() + "..." if response.text else "EMPTY RESPONSE"
        
        output_lines.append(f"[ACTION 2.A] HTTP Probe: {url} -> {log_detail}")
        
        return status, final_url, response_body_snippet
    
    except RequestException as e:
        output_lines.append(f"[ACTION 2.B] HTTP Probe FAILED: {url} - Connection Error/Timeout.")
        return 0, url, "" 
    except Exception as e:
        output_lines.append(f"[ACTION 2.C] HTTP Probe CRITICAL ERROR: {url} - {str(e)}.")
        return 0, url, ""

# ===============================================================================
#                             PHASE 3 : FLUX D'EXÉCUTION PRINCIPAL
# ===============================================================================

def run_recon(target, config): 
    """
    Fonction principale exécutant les actions de reconnaissance en cascade.
    """
    
    output_lines = []
    active_subdomains = []
    
    # Configuration dynamique
    http_timeout = config.get('timeout', 7)
    use_fallback = config.get('use_http_fallback', True)
    user_agent = config.get('user_agent', USER_AGENT_PRO)

    output_lines.append(f"[{datetime.now().strftime('%H:%M:%S')}] --- MODULE 1 Démarrage ---")
    output_lines.append(f"[INFO] Démarrage de la Reconnaissance Multi-Vecteur pour {target}")

    # Préparation de la liste massive de cibles
    prefixes = load_prefixes()
    targets_to_check = [target]
    targets_to_check.extend([f"{p}.{target}" for p in prefixes])
    
    total_checks_count = len(targets_to_check) * 2

    output_lines.append(f"[INFO] {len(prefixes)} préfixes chargés. {total_checks_count} actions minimales de vérification prévues.")
    
    # Boucle d'exécution principale
    for i, domain_target in enumerate(targets_to_check):
        output_lines.append(f"\n[ACTION 3.{i:03d}] Processing Target: {domain_target} ({i+1}/{len(targets_to_check)})")
        
        ip_address = dns_resolution_check(domain_target, output_lines)
        
        if ip_address:
            
            status_https = 0
            status_http = 0
            body_snippet = ""

            url_https = f"https://{domain_target}"
            status_https, final_url_https, body_https = http_probe_check(url_https, output_lines, http_timeout, user_agent)
            
            is_active = False

            if status_https in ACTIVE_STATUS_CODES:
                is_active = True
                log_line = f"[ACTIVE HTTPS {status_https}] {url_https} -> {final_url_https}"
                if status_https in ALERT_STATUS_CODES:
                    body_snippet = body_https
                
            elif use_fallback: 
                url_http = f"http://{domain_target}"
                status_http, final_url_http, body_http = http_probe_check(url_http, output_lines, http_timeout, user_agent)
                
                if status_http in ACTIVE_STATUS_CODES:
                    is_active = True
                    log_line = f"[ACTIVE HTTP {status_http}] {url_http} -> {final_url_http} (HTTPS ÉCHEC)"
                    if status_http in ALERT_STATUS_CODES:
                        body_snippet = body_http
                else:
                    log_line = f"[INACTIVE] {domain_target} (DNS OK, HTTP/S FAILED)"
            
            else:
                log_line = f"[INACTIVE] {domain_target} (HTTPS ÉCHEC, HTTP Fallback désactivé)"
            
            output_lines.append(f"[ACTION 4.A] Final Status: {log_line}")
            
            if is_active and domain_target not in active_subdomains:
                active_subdomains.append(domain_target)
            
            if status_https in ALERT_STATUS_CODES or status_http in ALERT_STATUS_CODES:
                 output_lines.append(f"[ACTION 5.A] !!! ALERTE MAJEURE !!! Statut {status_https} ou {status_http} détecté.")
                 
                 if body_snippet:
                     output_lines.append("[DATA] Response Body Snippet (Error Page):")
                     output_lines.append(f"       -> {body_snippet}")

        else:
            output_lines.append(f"[ACTION 4.B] Target Skipped: {domain_target} (DNS Failed)")


    output_file_path = os.path.join("output", f"{target}_active_subdomains.txt")
    
    try:
        os.makedirs("output", exist_ok=True)
        with open(output_file_path, 'w') as f:
            for sub in active_subdomains:
                f.write(sub + '\n')
                
        output_lines.append(f"\n[{datetime.now().strftime('%H:%M:%S')}] --- RECON TERMINÉE ---")
        output_lines.append(f"[Rapport Final] Total de {len(active_subdomains)} actifs enregistrés dans {output_file_path}.")
    except Exception as e:
        output_lines.append(f"[CRITICAL] Erreur d'écriture de fichier: {e}")
        
    print('\n'.join(output_lines))
