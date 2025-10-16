# Api_scan.py (MODULE 2 : INJECTION ET FUZZING ACTIF)
import sys
import os
import requests
import json
import random 
from datetime import datetime
from requests.exceptions import RequestException
from urllib.parse import urljoin

# ===============================================================================
#                             PHASE 1 : CONFIGURATION GLOBALE
# ===============================================================================

TIMEOUT = 7
USER_AGENT_PRO = "TROPIC-ProAPI-Analyzer/2.1 (EthicalHacking; High-Fidelity-Scoring)"

# --- CONFIGURATION DU SCORE DE SÉCURITÉ ---
SECURITY_SCORE_WEIGHTS = {
    'Strict-Transport-Security': 20, 
    'Content-Security-Policy': 20,    
    'X-Content-Type-Options': 10,     
    'X-Frame-Options': 10,            
    'Referrer-Policy': 5,              
    'X-Powered-By': 5,                
    'Server': 5,                      
    'ENDPOINT_EXPOSED': 15,           
    'ENDPOINT_REDIRECT': 5,           
    'INJECTION_VULNERABLE': 30,       
    'PARAM_REFLECTION': 10,           
}

# --- LISTES MASSIVES DE CIBLES API ET PAYLOADS D'INJECTION ---
API_ENDPOINTS_CRITICAL = [
    '/api/v1/users', '/api/v2/config', '/api/v3/auth', '/v1/secret', '/v2/admin', 
    '/v1/debug', '/test/data', '/staging/db', '/temp/files', '/logs/access', 
    '/admin/settings', '/panel/login', '/web.config', '/.htaccess', '/crossdomain.xml'
]
API_ENDPOINTS_COMMON = [
    '/api/status', '/health', '/metrics', '/info', '/version', '/public/users', 
    '/client/v1', '/portal/data', '/docs', '/robots.txt', '/sitemap.xml', 
    '/assets/js/main.js' 
]
INJECTION_PAYLOADS = [
    ("SQLi_TEST", "' OR 1=1 --", ["SQL syntax", "error in your SQL", "ORA-"]),
    ("RCE_TEST", "; id;", ["uid=", "bin/sh"]),
    ("XSS_TEST", "<script>alert(1)</script>", ["alert(1)", "XSS-protection"])
]
CRITICAL_FUZZ_PARAMS = [
    'id', 'user_id', 'account', 'profile', 'cmd', 'exec', 'file', 
    'redirect', 'url', 'source', 'debug', 'key', 'token', 'version'
]

# ===============================================================================
#                             PHASE 2 : FONCTIONS DU MOTEUR
# ===============================================================================

def check_security_headers(headers, target_url, output_lines):
    """Analyse les Headers de Sécurité, calcule le score et documente les failles."""
    score = 100
    findings = []
    
    output_lines.append(f"[ACTION] Analyse approfondie des {len(headers)} Headers reçus...")
    output_lines.append("[DATA] Headers Bruts Reçus:")
    for key, value in headers.items():
        output_lines.append(f"       -> {key}: {value}")
    
    for header, penalty in SECURITY_SCORE_WEIGHTS.items():
        if header not in headers and penalty > 5:
            finding = {"severity": "CRITICAL" if penalty >= 20 else "HIGH", "type": "HEADER_MISSING", "header": header, "description": f"Header {header} manquant. Risque de {header} non implémenté. (-{penalty} pts)",}
            findings.append(finding)
            output_lines.append(f"[🔥 {finding['severity']}] Manquant: {header} (-{penalty} points)")
            score -= penalty
        
    if 'X-Powered-By' in headers:
        info = headers['X-Powered-By']
        score -= SECURITY_SCORE_WEIGHTS['X-Powered-By']
        findings.append({"severity": "MEDIUM", "type": "INFO_LEAK", "header": "X-Powered-By", "description": f"Divulgation de la technologie : {info}."})
        output_lines.append(f"[⚠️ MEDIUM] Divulgation X-Powered-By: {info} (-{SECURITY_SCORE_WEIGHTS['X-Powered-By']} pts)")
    
    if 'Server' in headers and 'cloud' not in headers['Server'].lower():
        info = headers['Server']
        score -= SECURITY_SCORE_WEIGHTS['Server']
        findings.append({"severity": "MEDIUM", "type": "INFO_LEAK", "header": "Server", "description": f"Divulgation du serveur : {info}."})
        output_lines.append(f"[⚠️ MEDIUM] Divulgation Server: {info} (-{SECURITY_SCORE_WEIGHTS['Server']} pts)")

    return max(0, score), findings

def check_for_injection(url, output_lines, api_timeout, user_agent):
    """Tente d'injecter des payloads pour détecter des vulnérabilités SQLi/RCE/XSS."""
    vulnerability_detected = 0
    headers = {'User-Agent': user_agent, 'Content-Type': 'application/x-www-form-urlencoded'}
    
    for test_name, payload, error_signatures in INJECTION_PAYLOADS:
        try:
            response = requests.post(url, headers=headers, data={'id': payload}, timeout=api_timeout)
            response_text = response.text.lower()
            
            if response.status_code == 200 or response.status_code == 500:
                for signature in error_signatures:
                    if signature.lower() in response_text:
                        output_lines.append(f"[🔥 CRITICAL VULN] Injection détectée ({test_name}) sur {url} avec le code {response.status_code}.")
                        output_lines.append(f"   -> Payload: {payload[:20]}...")
                        vulnerability_detected += 1
                        return vulnerability_detected 
                        
        except RequestException:
            pass
    return vulnerability_detected

def check_parameter_fuzzing(url, output_lines, api_timeout, user_agent):
    """Tente de découvrir des paramètres vulnérables ou exposés (GET)."""
    vulnerabilities_found = 0
    headers = {'User-Agent': user_agent}

    if url.endswith(('.txt', '.xml', '.js')):
        return 0

    test_param = random.choice(CRITICAL_FUZZ_PARAMS)
    reflection_string = "TROPIC_ECHO"
    test_url = f"{url}?{test_param}={reflection_string}"
    
    try:
        response = requests.get(test_url, headers=headers, timeout=api_timeout, allow_redirects=True)
        if response.status_code == 200 and reflection_string in response.text:
            output_lines.append(f"[⚠️ REFLECTION HIGH] Paramètre {test_param} trouvé et réfléchi (Reflected XSS/SSRF possible).")
            vulnerabilities_found += 1
            
    except RequestException:
        pass
            
    return vulnerabilities_found

def discover_api_endpoints(target_url, output_lines, api_timeout, user_agent):
    """Recherche des endpoints d'API critiques et communs avec suivi de redirection."""
    discovery_results = []
    vulnerabilities_found = 0
    reflection_found = 0
    headers = {'User-Agent': user_agent}
    all_endpoints = API_ENDPOINTS_CRITICAL + API_ENDPOINTS_COMMON
    
    output_lines.append(f"\n[SECTION] Fuzzing de {len(all_endpoints)} Endpoints...")

    for endpoint in all_endpoints:
        api_url = urljoin(target_url, endpoint)
        
        try:
            response = requests.get(api_url, headers=headers, timeout=api_timeout, allow_redirects=True)
            status = response.status_code
            
            discovery_entry = {"endpoint": endpoint, "status": status, "description": "Not Found"}
            
            # 1. Vérification d'injection/fuzzing sur les endpoints qui répondent
            if status in [200, 403, 500]: 
                vulnerabilities_found += check_for_injection(api_url, output_lines, api_timeout, user_agent)
                reflection_found += check_parameter_fuzzing(api_url, output_lines, api_timeout, user_agent)
            
            # 2. Capture des données de réponse
            response_data = ""
            if status in [200, 403]:
                try:
                    response_data = json.dumps(response.json(), indent=2)
                except requests.exceptions.JSONDecodeError:
                    response_data = response.text[:200].strip() + "..." if response.text else "EMPTY RESPONSE"
                
                output_lines.append(f"[DATA] {endpoint} ({status}) Response Snippet:")
                output_lines.append("------SNIPPET START------")
                for line in response_data.split('\n'):
                    output_lines.append(f"       {line}")
                output_lines.append("------SNIPPET END------")

            if status == 200:
                output_lines.append(f"[🔥 200 OK] Endpoint CRITIQUE trouvé: {endpoint} (Final URL: {response.url})")
                discovery_entry['description'] = "Found (200 OK)"
            elif 400 <= status < 500 and status != 404:
                output_lines.append(f"[🔒 {status}] Endpoint Protégé ou Erreur Client: {endpoint}")
                discovery_entry['description'] = f"Protected/Client Error ({status})"
            elif status >= 500:
                output_lines.append(f"[🛑 {status}] Erreur Serveur Inattendue: {endpoint}")
                discovery_entry['description'] = f"Server Error ({status})"
            elif response.history:
                output_lines.append(f"[➡️ {status}] Redirection Finale: {endpoint} -> {response.url}")
                discovery_entry['description'] = f"Redirect Final Status ({status})"
            
            discovery_results.append(discovery_entry)

        except RequestException:
            output_lines.append(f"[❌ ERROR] Échec du test sur l'endpoint: {endpoint}")
            discovery_results.append({"endpoint": endpoint, "status": 0, "description": "Connection Error"})

    return discovery_results, vulnerabilities_found, reflection_found

# ===============================================================================
#                             PHASE 3 : FLUX D'EXÉCUTION PRINCIPAL
# ===============================================================================

def run_api_scan(target, config):
    """Fonction principale exécutant l'analyse d'API et Headers UP, en utilisant la configuration fournie."""
    
    output_lines = []
    all_reports = []

    api_timeout = config.get('timeout', TIMEOUT)
    user_agent = config.get('user_agent', USER_AGENT_PRO)
    
    output_lines.append(f"[{datetime.now().strftime('%H:%M:%S')}] --- MODULE 2 Démarrage ---")
    
    input_file = os.path.join("output", f"{target}_active_subdomains.txt")
    
    if os.path.exists(input_file):
        with open(input_file, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]
    else:
        targets = [target]

    total_injection_found = 0
    total_reflection_found = 0
    
    for i, domain_target in enumerate(targets):
        https_url = f"https://{domain_target}"
        output_lines.append(f"\n[{datetime.now().strftime('%H:%M:%S')}] >>> Analyse Cible {i+1}: {https_url} <<<")

        try:
            initial_response = requests.get(
                https_url, 
                headers={'User-Agent': user_agent}, 
                timeout=api_timeout
            )
            
            headers_score, headers_findings = check_security_headers(
                initial_response.headers, https_url, output_lines
            )

            api_results, injection_found, reflection_found = discover_api_endpoints(
                https_url, output_lines, api_timeout, user_agent
            )
            total_injection_found += injection_found
            total_reflection_found += reflection_found
            
            # Calcul du score final (Ajustement par Puissance)
            api_exposure_count = sum(1 for res in api_results if res['status'] == 200)
            
            final_score = headers_score - \
                          (api_exposure_count * SECURITY_SCORE_WEIGHTS['ENDPOINT_EXPOSED']) - \
                          (injection_found * SECURITY_SCORE_WEIGHTS['INJECTION_VULNERABLE']) - \
                          (reflection_found * SECURITY_SCORE_WEIGHTS['PARAM_REFLECTION'])
            
            
            output_lines.append(f"\n[RÉSUMÉ] Score Initial Headers: {headers_score}/100")
            output_lines.append(f"[RÉSUMÉ] Score Final (Ajusté Puissance): {max(0, final_score)}/100")

            all_reports.append({
                "target_url": https_url,
                "final_score": max(0, final_score),
                "header_findings": headers_findings,
                "api_discovery": api_results,
                "injection_detected": injection_found > 0,
                "reflection_detected": reflection_found > 0
            })
            
        except RequestException as e:
            output_lines.append(f"[❌ CRITICAL] Échec total de la connexion HTTPS à {https_url}: {e}")
            all_reports.append({"target_scurl": https_url, "error": str(e), "final_score": 0})
        
    final_report = {
        "metadata": {
            "target_domain": target,
            "scanner": "TROPIC API/HEADER Analyzer (v2.3)",
            "injections_detected": total_injection_found,
            "reflections_detected": total_reflection_found
        },
        "scan_results": all_reports
    }
    
    report_file_path = os.path.join("output", f"{target}_api_report.json")
    try:
        os.makedirs("output", exist_ok=True)
        with open(report_file_path, 'w') as f:
            json.dump(final_report, f, indent=4)
                
        output_lines.append(f"\n[{datetime.now().strftime('%H:%M:%S')}] --- API SCAN TERMINÉ ---")
    except Exception as e:
        output_lines.append(f"[CRITICAL] Erreur d'écriture du rapport : {e}")
        
    print('\n'.join(output_lines))
