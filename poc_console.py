# poc_console.py - VERSION FATASS FLAGRANT DINGUE
import streamlit as st
import streamlit.components.v1 as components
from datetime import datetime
import threading
import time

# ------------------------------------------------------------
# IMPORT SIMULATEUR/EXECUTEUR PoC
# ------------------------------------------------------------
try:
    from Exploit_Adv import simulate_poc_execution
except ImportError:
    # Placeholder pour tests rapides
    def simulate_poc_execution(target, command, force_real):
        if command.lower() == 'id':
            return "uid=1000(tropic) gid=1000(tropic) groups=1000(tropic),27(sudo)", 200
        elif command.lower() == 'ls':
            return "app.py\npoc_console.py\nRecon.py\noutput/", 200
        else:
            return f"Commande '{command}' simulée. Utilise 'id' ou 'ls'.", 404

# ------------------------------------------------------------
# CONSTANTES
# ------------------------------------------------------------
MAX_HISTORY_LINES = 100  # Limite pour la performance
TERMINAL_EMOJI = "💥"
STATUS_COLOR = {200: "green", 404: "orange", 500: "red"}

# ------------------------------------------------------------
# FOCUS AUTO SUR INPUT
# ------------------------------------------------------------
def set_focus_on_input():
    js_code = """
        <script>
            const inputElement = parent.document.querySelector('[data-testid="stTextInput"] input');
            if(inputElement){ window.requestAnimationFrame(()=>{inputElement.focus();}); }
        </script>
    """
    components.html(js_code, height=0, width=0)

# ------------------------------------------------------------
# AFFICHAGE HISTORIQUE
# ------------------------------------------------------------
def update_console_display(console_display_area):
    history = st.session_state.shell_cmd_history_list
    if len(history) > MAX_HISTORY_LINES:
        history = history[-MAX_HISTORY_LINES:]

    full_text = "\n".join(history) if history else "Tapez 'id' ou 'ls' pour tester l'accès (PoC)."
    
    with console_display_area.container():
        st.markdown(TERMINAL_EMOJI + "="*50 + TERMINAL_EMOJI)
        st.code(full_text, language='bash')
    set_focus_on_input()

# ------------------------------------------------------------
# EXECUTION ASYNCHRONE POUR NE JAMAIS BLOQUER L'UI
# ------------------------------------------------------------
def execute_command_async(target, command, user_config, console_display_area):
    def runner():
        try:
            force_real = bool(user_config.get('allow_real_poc', True))
            output, status_code = simulate_poc_execution(target, command, force_real)
        except Exception as e:
            output, status_code = f"ERREUR CRITIQUE D'EXECUTION: {str(e)}", 500

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        st.session_state.shell_cmd_history_list.append(f"[{timestamp}] tropic@{target}:~# {command}")
        st.session_state.shell_cmd_history_list.append(f"STATUT HTTP : {status_code}")
        st.session_state.shell_cmd_history_list.extend(output.splitlines())
        st.session_state.shell_cmd_history_list.append("\n" + TERMINAL_EMOJI*10 + "\n")
        st.session_state.current_shell_command_input = ""
        update_console_display(console_display_area)
    
    threading.Thread(target=runner, daemon=True).start()

# ------------------------------------------------------------
# RENDER CONSOLE PRINCIPALE
# ------------------------------------------------------------
def render_poc_console(target, user_config):
    st.header(f"💻 Console PoC Actif - {target}")
    st.warning("⚠️ Utilisez uniquement sur des cibles autorisées.")

    # INITIALISATION SESSION
    if 'shell_cmd_history_list' not in st.session_state:
        st.session_state.shell_cmd_history_list = []
    if 'current_shell_command_input' not in st.session_state:
        st.session_state.current_shell_command_input = ""

    console_display_area = st.empty()

    # INPUT DE COMMANDE
    st.text_input(
        f"tropic@{target}:~# ",
        key="current_shell_command_input",
        label_visibility="collapsed",
        on_change=lambda: execute_command_async(
            target,
            st.session_state.current_shell_command_input.strip(),
            user_config,
            console_display_area
        )
    )

    # BOUTON EXECUTION
    col1, _ = st.columns([1, 4])
    with col1:
        st.button(
            "Exécuter PoC",
            type="secondary",
            use_container_width=True,
            on_click=lambda: execute_command_async(
                target,
                st.session_state.current_shell_command_input.strip(),
                user_config,
                console_display_area
            )
        )

    # AFFICHAGE INITIAL
    update_console_display(console_display_area)
