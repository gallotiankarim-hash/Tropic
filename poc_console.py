# poc_console.py
import streamlit as st
import streamlit.components.v1 as components
from datetime import datetime
from typing import Tuple

# --- Importer simulate_poc_execution depuis Exploit_Adv si disponible ---
try:
    from Exploit_Adv import simulate_poc_execution
except Exception:
    # Placeholder si Exploit_Adv absent : simulate_poc_execution(target, command, force_real) -> (output, status_code)
    def simulate_poc_execution(target: str, command: str, force_real: bool = False) -> Tuple[str, int]:
        cmd = (command or "").strip().lower()
        if cmd == "id":
            return "uid=1000(tropic) gid=1000(tropic) groups=1000(tropic),27(sudo)", 200
        if cmd == "ls":
            return "app.py\npoc_console.py\nRecon.py\noutput/\nExploit_Adv.py", 200
        # If command looks like a URL, emulate a remote GET
        if cmd.startswith("http://") or cmd.startswith("https://"):
            return f"[SIMULATED HTTP GET] {command}\n<response simulated>", 200
        return f"[SIMULATED] Commande '{command}' non reconnue par le placeholder.", 404


# -----------------------------------------------------------------------
# Petit JS pour recadrer le focus sur le champ text entrée (améliore UX)
# -----------------------------------------------------------------------
_focus_js = """
<script>
(function(){
  const inputs = parent.document.querySelectorAll('input[data-testid^="stTextInput"]');
  if(inputs && inputs.length){
    const last = inputs[inputs.length-1];
    last.focus();
    // place caret at end
    const val = last.value;
    last.value = '';
    last.value = val;
  }
})();
</script>
"""


def _set_focus():
    """Injecte le JS qui tente de remettre le focus sur le dernier text_input Streamlit."""
    try:
        components.html(_focus_js, height=0)
    except Exception:
        # Ne pas casser l'UI si l'injection échoue
        pass


# ===============================================================================
#                       FONCTION DE LA CONSOLE PoC (EXTERNE)
# ===============================================================================
def render_poc_console(target_domain: str, user_config: dict):
    """
    Console PoC intégrée :
    - Utilise simulate_poc_execution(target, command, force_real)
    - Stocke l'historique dans st.session_state sous clefs 'poc_*'
    - Evite st.rerun() et conserve le contexte via st.form + mise à jour directe
    """

    st.markdown("### 💻 Console PoC / Terminal d'Exploitation")
    st.warning("⚠️ N'utilisez que sur des cibles pour lesquelles vous avez une autorisation écrite.")

    # --- INITIALISATION DES CLÉS D'ÉTAT ---
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

    # --- Affichage de l'historique (ne pas forcer rerun) ---
    hist_display = st.empty()
    hist_list = st.session_state['poc_shell_cmd_history_list'][-st.session_state['poc_max_history']:]
    if hist_list:
        hist_display.code("\n".join(hist_list), language='bash')
    else:
        hist_display.code("Aucun historique. Tapez 'id' ou 'ls' pour tester.", language='bash')

    st.markdown("---")

    # --- Utiliser un formulaire pour soumettre la commande (évite reruns intempestifs) ---
    form_key = f"poc_form_{target_domain}"
    with st.form(key=form_key, clear_on_submit=False):
        cmd_input = st.text_input(
            f"tropic@{target_domain}:~#",
            value=st.session_state.get('poc_current_shell_command_input', ""),
            key=f"poc_input_{target_domain}",
            label_visibility="collapsed"
        )

        submit = st.form_submit_button("▶️ Exécuter PoC")

        if submit:
            command = (cmd_input or "").strip()
            # Sauvegarde immédiate de l'input dans session (utile si l'UI est rechargée)
            st.session_state['poc_current_shell_command_input'] = ""

            if not command:
                st.warning("Aucune commande fournie.")
            else:
                # Vérification du flag d'autorisation
                allow_real = bool(user_config.get('allow_real_poc', False))
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                # Ajout d'une entrée de requête dans l'historique
                st.session_state['poc_shell_cmd_history_list'].append(f"[{timestamp}] $ {command}")

                # Exécuter via simulate_poc_execution (Exploit_Adv) — la fonction renvoie (output, status_code)
                try:
                    # On tente d'appeler avec signature moderne (force_real)
                    try:
                        output_text, status_code = simulate_poc_execution(target_domain, command, force_real=allow_real)
                    except TypeError:
                        # Fallback si la fonction n'accepte que (target, command)
                        output_text, status_code = simulate_poc_execution(target_domain, command)
                except Exception as exc:
                    output_text = f"[ERROR] simulate_poc_execution a levé une exception: {exc}"
                    status_code = 500

                # Normaliser la sortie en chaîne
                if not isinstance(output_text, str):
                    try:
                        output_text = str(output_text)
                    except Exception:
                        output_text = "[ERROR] Impossible de convertir la sortie en texte."

                # Découper la sortie en lignes et l'ajouter à l'historique
                for line in output_text.splitlines():
                    st.session_state['poc_shell_cmd_history_list'].append(line)

                # Ajouter un séparateur visuel
                st.session_state['poc_shell_cmd_history_list'].append("-" * 60)

                # Truncation si l'historique dépasse la limite
                if len(st.session_state['poc_shell_cmd_history_list']) > st.session_state['poc_max_history']:
                    st.session_state['poc_shell_cmd_history_list'] = st.session_state['poc_shell_cmd_history_list'][-st.session_state['poc_max_history']:]

                # Mettre à jour le statut et l'heure
                st.session_state['poc_last_status'] = status_code
                st.session_state['poc_last_time'] = timestamp

                # Mise à jour immédiate de la zone d'historique (sans rerun complet)
                hist_display.code("\n".join(st.session_state['poc_shell_cmd_history_list'][-st.session_state['poc_max_history']:]), language='bash')

                # Remettre le focus sur l input pour confort
                _set_focus()

                # Affichage court du statut
                if status_code == 200:
                    st.success(f"Commande exécutée (HTTP {status_code}).")
                elif status_code == 404:
                    st.error("Cible/commande introuvable (404).")
                elif status_code == 408:
                    st.error("Timeout lors de l'appel.")
                elif status_code == 500:
                    st.error("Erreur interne lors de l'exécution du PoC.")
                else:
                    st.warning(f"Statut: {status_code}")

    # --- Panneau d'informations / métadonnées ---
    meta_col1, meta_col2 = st.columns([1, 3])
    with meta_col1:
        st.markdown("**Dernier statut**")
        st.write(st.session_state.get('poc_last_status', "N/A"))
    with meta_col2:
        st.markdown("**Dernier appel**")
        st.write(st.session_state.get('poc_last_time', "N/A"))

    st.markdown("")  # petit espace final
