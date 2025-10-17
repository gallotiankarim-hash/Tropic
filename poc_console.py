# poc_console.py (version solide avec contrôle easy false/true)
import streamlit as st
from datetime import datetime
import time

# requests est recommandé — si tu ne l'as pas, ajouter dans requirements.txt
try:
    import requests
except ImportError:
    requests = None

# -----------------------------------------------------------------------------
# UTIL: safe rerun helper
# -----------------------------------------------------------------------------
def _safe_rerun():
    """
    Essaye plusieurs méthodes de rerun selon la version de Streamlit:
      - st.experimental_rerun()
      - st.rerun()
    Si aucune n'est disponible, ne lève pas d'exception (no-op).
    """
    try:
        # ancienne API utilisée parfois
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

    # Si on est ici, on ne peut pas forcer un rerun programmatique sans version adaptée.
    # On retourne None et on laisse la page se comporter normalement (l'utilisateur peut rafraîchir).
    return

# -----------------------------------------------------------------------------
# UTIL: formate une entrée horodatée et l'ajoute à l'historique
# -----------------------------------------------------------------------------
def _append_history(msg: str):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    st.session_state['poc_shell_cmd_history_list'].append(f"[{ts}] {msg}")
    # maintien d'une taille raisonnable
    max_h = st.session_state.get('poc_max_history', 500)
    if len(st.session_state['poc_shell_cmd_history_list']) > max_h:
        st.session_state['poc_shell_cmd_history_list'] = st.session_state['poc_shell_cmd_history_list'][-max_h:]

# -----------------------------------------------------------------------------
# FONCTION PRINCIPALE : render_poc_console
# -----------------------------------------------------------------------------
def render_poc_console(target_domain: str, user_config: dict):
    """
    Console PoC solide avec contrôle easy false/true :
     - allow_real_poc=True : exécution réelle des commandes locales
     - allow_real_poc=False : simulation sécurisée avec résultats réalistes
     - commandes supportées : id, ls, whoami, probe:<URL>, http:<URL>, local:<command>
    """

    st.markdown("### 💻 Console PoC / Terminal d'Exploitation")
    st.warning("⚠️ Utiliser uniquement sur des cibles pour lesquelles vous avez une autorisation écrite.")

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
        st.info("Historique vide — utilisez `id`, `ls`, `whoami`, `probe:<URL>` ou `http:<URL>`.")

    st.markdown("---")

    # champ de saisie (form pour éviter reruns intempestifs)
    form_key = f"poc_form_{target_domain}"
    with st.form(key=form_key, clear_on_submit=False):
        cmd_input = st.text_input("Entrer commande PoC (ex: probe:https://site.tld/login)",
                                   value=st.session_state.get('poc_current_shell_command_input', ""))
        submit = st.form_submit_button("▶️ Exécuter Commande PoC")

        if submit:
            cmd = (cmd_input or "").strip()
            # mémorise saisie (on vide la zone d'entrée pour UX)
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
            ua = user_config.get('user_agent', "TROPIC-PoC/1.0")
            allow_real_poc = user_config.get('allow_real_poc', False)

            # --- id ---
            if cmd.lower() == 'id':
                _append_history("$ id")
                if allow_real_poc:
                    # Exécution réelle
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
                    # Simulation
                    _append_history("uid=1000(tropic) gid=1000(tropic) groups=1000(tropic),27(sudo)")
                    st.session_state['poc_last_status'] = "200 (simulé)"
                st.session_state['poc_last_time'] = timestamp
                _safe_rerun()
                return

            # --- ls ---
            if cmd.lower() == 'ls':
                _append_history("$ ls")
                if allow_real_poc:
                    # Exécution réelle
                    import subprocess
                    try:
                        res = subprocess.run(['ls'], capture_output=True, text=True, timeout=10)
                        if res.stdout:
                            for line in res.stdout.strip().splitlines():
                                _append_history(line)
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
                    # Simulation
                    _append_history("app.py")
                    _append_history("poc_console.py")
                    _append_history("Exploit_Adv.py")
                    _append_history("output/")
                    _append_history("requirements.txt")
                    st.session_state['poc_last_status'] = "200 (simulé)"
                st.session_state['poc_last_time'] = timestamp
                _safe_rerun()
                return

            # --- whoami ---
            if cmd.lower() == 'whoami':
                _append_history("$ whoami")
                if allow_real_poc:
                    # Exécution réelle
                    import subprocess
                    try:
                        res = subprocess.run(['whoami'], capture_output=True, text=True, timeout=10)
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
                    # Simulation
                    _append_history("tropic")
                    st.session_state['poc_last_status'] = "200 (simulé)"
                st.session_state['poc_last_time'] = timestamp
                _safe_rerun()
                return

            # --- probe:<URL> -> envoie GET paramètre input=TROPIC_TEST_<ts> et cherche réflexion ---
            if cmd.lower().startswith("probe:"):
                url = cmd[len("probe:"):].strip()
                if not url:
                    _append_history("$ probe: (URL manquante)")
                    st.session_state['poc_last_status'] = "400 (probe URL manquante)"
                    st.session_state['poc_last_time'] = timestamp
                    _safe_rerun()
                    return

                _append_history(f"$ probe:{url}")
                if requests is None:
                    _append_history("[ERROR] requests non installé sur l'environnement.")
                    st.session_state['poc_last_status'] = "500 (requests manquant)"
                    st.session_state['poc_last_time'] = timestamp
                    _safe_rerun()
                    return

                token = f"TROPIC_TEST_{int(time.time())}"
                params = {'input': token}
                try:
                    headers = {'User-Agent': ua}
                    r = requests.get(url, params=params, headers=headers, timeout=default_timeout, verify=True)
                    body = r.text or ""
                    # cherche le token dans la réponse (simple reflection check)
                    if token in body:
                        _append_history(f"[REFLECTED] Token {token} trouvé dans la réponse (HTTP {r.status_code}).")
                        st.session_state['poc_last_status'] = f"{r.status_code} (REFLECTED)"
                    else:
                        snippet = (body[:300] + "...") if len(body) > 300 else body
                        _append_history(f"[NO-REFLECT] Token {token} non trouvé (HTTP {r.status_code}). Snippet: {snippet!s}")
                        st.session_state['poc_last_status'] = f"{r.status_code} (NO-REFLECT)"
                except requests.exceptions.SSLError as e:
                    _append_history(f"[ERROR] SSL Error: {str(e)}")
                    st.session_state['poc_last_status'] = "SSL-ERROR"
                except requests.exceptions.ConnectTimeout:
                    _append_history("[ERROR] Timeout (connect)")
                    st.session_state['poc_last_status'] = "408"
                except requests.exceptions.ReadTimeout:
                    _append_history("[ERROR] Timeout (read)")
                    st.session_state['poc_last_status'] = "408"
                except requests.exceptions.RequestException as e:
                    _append_history(f"[ERROR] Requête probe échouée: {str(e)}")
                    st.session_state['poc_last_status'] = "ERROR"
                st.session_state['poc_last_time'] = timestamp
                _safe_rerun()
                return

            # --- http:<URL> or direct https://... -> simple GET, retourne status + body snippet ---
            if cmd.lower().startswith("http:") or cmd.lower().startswith("https:"):
                url = cmd
                # Corrige grossières erreurs de schéma comme "http:https://..."
                if url.startswith("http://http://") or url.startswith("https://http://") or url.startswith("http://https://"):
                    url = url.split("://", 1)[-1]
                    url = "http://" + url
                _append_history(f"$ http:{url}")
                if requests is None:
                    _append_history("[ERROR] requests non installé sur l'environnement.")
                    st.session_state['poc_last_status'] = "500 (requests manquant)"
                    st.session_state['poc_last_time'] = timestamp
                    _safe_rerun()
                    return
                try:
                    headers = {'User-Agent': ua}
                    r = requests.get(url, headers=headers, timeout=default_timeout, verify=True)
                    snippet = (r.text or "")[:600]
                    _append_history(f"[HTTP {r.status_code}] Snippet: {snippet!s}")
                    st.session_state['poc_last_status'] = f"{r.status_code}"
                except requests.exceptions.RequestException as e:
                    _append_history(f"[ERROR] Requête HTTP échouée: {str(e)}")
                    st.session_state['poc_last_status'] = "ERROR"
                st.session_state['poc_last_time'] = timestamp
                _safe_rerun()
                return

            # --- local:<cmd> -> exécution locale ou simulation ---
            if cmd.lower().startswith("local:"):
                local_cmd = cmd[len("local:"):].strip()
                _append_history(f"$ {local_cmd}")
                
                if not allow_real_poc:
                    # Simulation quand allow_real_poc=False
                    _append_history(f"[SIMULATION] {local_cmd}")
                    # Résultats simulés réalistes selon la commande
                    if "ls" in local_cmd:
                        _append_history("app.py")
                        _append_history("poc_console.py") 
                        _append_history("Exploit_Adv.py")
                        _append_history("output/")
                    elif "id" in local_cmd:
                        _append_history("uid=1000(tropic) gid=1000(tropic) groups=1000(tropic),27(sudo)")
                    elif "whoami" in local_cmd:
                        _append_history("tropic")
                    elif "pwd" in local_cmd:
                        _append_history("/home/tropic/tropic-tool")
                    else:
                        _append_history(f"Commande '{local_cmd}' exécutée avec succès")
                    st.session_state['poc_last_status'] = "200 (simulé)"
                    st.session_state['poc_last_time'] = timestamp
                    _safe_rerun()
                    return
                
                # Si allow_real_poc=True, exécution réelle avec whitelist
                allowed_commands = ["ls", "id", "whoami", "pwd"]
                command_base = local_cmd.split()[0] if local_cmd.split() else ""
                
                if command_base not in allowed_commands:
                    _append_history(f"[BLOCKED] Commande '{command_base}' non autorisée. Whitelist: {', '.join(allowed_commands)}")
                    st.session_state['poc_last_status'] = "403 (command not allowed)"
                    st.session_state['poc_last_time'] = timestamp
                    _safe_rerun()
                    return
                
                import subprocess
                try:
                    res = subprocess.run(local_cmd, shell=True, capture_output=True, text=True, timeout=30)
                    if res.stdout:
                        for line in res.stdout.strip().splitlines():
                            _append_history(line)
                    if res.stderr:
                        for line in res.stderr.strip().splitlines():
                            _append_history(f"[ERR] {line}")
                    st.session_state['poc_last_status'] = f"returncode {res.returncode}"
                except subprocess.TimeoutExpired:
                    _append_history("[ERROR] Commande locale expirée (timeout)")
                    st.session_state['poc_last_status'] = "408"
                except Exception as e:
                    _append_history(f"[ERROR] Exception lors de l'exécution locale: {str(e)}")
                    st.session_state['poc_last_status'] = "ERROR"
                st.session_state['poc_last_time'] = timestamp
                _safe_rerun()
                return

            # --- commande inconnue: on renvoie aide synthétique ---
            _append_history(f"$ {cmd}")
            _append_history("[ERROR] Commande non reconnue. Commandes supportées :")
            _append_history("  - id, ls, whoami                    (commandes simples)")
            _append_history("  - probe:<URL>                       (test reflection GET ?input=<token>)")
            _append_history("  - http:<URL> / https:<URL>          (GET simple)")
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
        if "simulé" in str(status).lower() or "simulation" in str(status).lower():
            st.success(status)
        elif "error" in str(status).lower() or "40" in str(status) or "50" in str(status):
            st.error(status)
        else:
            st.info(status)
    
    with cols[1]:
        st.write("**Dernière action**")
        st.write(st.session_state.get('poc_last_time', "N/A"))

    # Information sur le mode
    st.caption(f"🔧 Configuration: timeout={user_config.get('timeout', 7)}s | allow_real_poc={allow_real}")
