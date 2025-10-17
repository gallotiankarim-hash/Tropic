# poc_console.py
import streamlit as st
import subprocess
from datetime import datetime

# ===============================================================================
#                       FONCTION DE LA CONSOLE PoC
# ===============================================================================

def render_poc_console(target_domain: str, user_config: dict):
    """
    Console d'exécution PoC pour le module 3 (Exploit/Advanced Vulnerability Scan)
    - Utilise st.session_state avec préfixe 'poc_'
    - Permet exécution de commandes, logs persistants et historique
    """
    
    st.markdown("### 💻 Console PoC / Terminal d'Exploitation")
    
    # --- Préparation des clefs session_state ---
    if 'poc_shell_cmd_history_list' not in st.session_state:
        st.session_state['poc_shell_cmd_history_list'] = []
    if 'poc_current_shell_command_input' not in st.session_state:
        st.session_state['poc_current_shell_command_input'] = ""
    if 'poc_last_status' not in st.session_state:
        st.session_state['poc_last_status'] = None
    if 'poc_last_time' not in st.session_state:
        st.session_state['poc_last_time'] = None
    if 'poc_max_history' not in st.session_state:
        st.session_state['poc_max_history'] = 500  # Limite raisonnable pour la perf

    # --- Affichage historique ---
    if st.session_state['poc_shell_cmd_history_list']:
        st.markdown("#### Historique des commandes")
        st.code("\n".join(st.session_state['poc_shell_cmd_history_list'][-st.session_state['poc_max_history']:]), language='bash')

    # --- Input pour la commande ---
    st.session_state['poc_current_shell_command_input'] = st.text_input(
        "Entrer commande PoC (Ex: ls -la /tmp)", 
        value=st.session_state.get('poc_current_shell_command_input', ""), 
        key="poc_input_cmd"
    )

    # --- Bouton Exécuter ---
    if st.button("▶️ Exécuter Commande PoC"):
        cmd = st.session_state['poc_current_shell_command_input'].strip()
        if not cmd:
            st.warning("Veuillez entrer une commande avant d'appuyer sur Exécuter.")
            return
        
        # --- Vérification consentement utilisateur ---
        if not user_config.get('allow_real_poc', False):
            st.error("Exécution réelle de PoC désactivée par configuration. Autorisez-la dans la sidebar.")
            return
        
        # --- Ajout à l'historique ---
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        st.session_state['poc_shell_cmd_history_list'].append(f"[{timestamp}] $ {cmd}")
        if len(st.session_state['poc_shell_cmd_history_list']) > st.session_state['poc_max_history']:
            st.session_state['poc_shell_cmd_history_list'] = st.session_state['poc_shell_cmd_history_list'][-st.session_state['poc_max_history']:]
        
        # --- Exécution sécurisée de la commande ---
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=120)
            output = result.stdout.strip()
            error = result.stderr.strip()
            if output:
                st.session_state['poc_shell_cmd_history_list'].append(output)
            if error:
                st.session_state['poc_shell_cmd_history_list'].append(f"[ERROR] {error}")
            st.session_state['poc_last_status'] = "Succès" if result.returncode == 0 else f"Échec (Code {result.returncode})"
        except subprocess.TimeoutExpired:
            st.session_state['poc_shell_cmd_history_list'].append("[ERROR] Commande expirée (Timeout)")
            st.session_state['poc_last_status'] = "Timeout"
        except Exception as e:
            st.session_state['poc_shell_cmd_history_list'].append(f"[ERROR] Exception : {str(e)}")
            st.session_state['poc_last_status'] = f"Erreur critique: {str(e)}"

        st.session_state['poc_last_time'] = timestamp
        st.session_state['poc_current_shell_command_input'] = ""

        # --- Rafraîchissement du code area ---
        st.experimental_rerun()

    # --- Affichage du dernier statut ---
    if st.session_state['poc_last_status']:
        st.markdown(f"**Dernier statut :** {st.session_state['poc_last_status']} (à {st.session_state['poc_last_time']})")
