# poc_console.py (Nouvelle version optimisée pour la performance)
import streamlit as st
import streamlit.components.v1 as components
from datetime import datetime

# NOTE : Importation de la fonction d'exécution.
try:
    from Exploit_Adv import simulate_poc_execution
except ImportError:
    # --- Fonction de Placeholder en cas d'échec d'importation ---
    def simulate_poc_execution(target, command, force_real):
        """Placeholder pour le simulateur/exécuteur de PoC."""
        if command.lower() == 'id':
            output = "uid=1000(tropic) gid=1000(tropic) groups=1000(tropic),27(sudo)"
            return output, 200
        elif command.lower() == 'ls':
            output = "app.py\npoc_console.py\nRecon.py\noutput/"
            return output, 200
        else:
            output = f"Commande '{command}' simulée. Utilise 'id' ou 'ls' pour un résultat 200.", 404


# -----------------------------------------------------------------------
# UTILITAIRE DE FOCUS (Injection JS pour éviter la sensation d'éjection)
# -----------------------------------------------------------------------
def set_focus_on_input():
    """Injecte JS pour mettre le focus sur l'élément input de la console PoC."""
    js_code = """
        <script>
            // Cible l'élément <input> par son attribut data-testid Streamlit
            const inputElement = parent.document.querySelector(
                '[data-testid="stTextInput"] input'
            );
            if (inputElement) {
                // S'assure que le DOM est prêt
                window.requestAnimationFrame(() => {
                    inputElement.focus();
                });
            }
        </script>
        """
    components.html(js_code, height=0, width=0)

# -----------------------------------------------------------------------
# FONCTION PRINCIPALE DE LA CONSOLE
# -----------------------------------------------------------------------
def render_poc_console(target, user_config):
    """
    Affiche l'interface de la console PoC et gère l'exécution des commandes.
    Utilise une liste pour une gestion plus logique de l'historique.
    """
    
    st.header(f"💻 Console PoC Actif - {target}")
    st.warning("⚠️ Utilisez uniquement sur des cibles autorisées.")

    # --- INITIALISATION DE L'ÉTAT (NÉCESSAIRE pour la Liste et la Saisie) ---
    if 'shell_cmd_history_list' not in st.session_state:
        st.session_state['shell_cmd_history_list'] = []
    if 'current_shell_command_input' not in st.session_state:
        st.session_state['current_shell_command_input'] = ""
    
    # Placeholder pour l'affichage de la console (mis à jour plus tard)
    console_display_area = st.empty()

    # --- FONCTION DE MISE À JOUR DE L'AFFICHAGE ---
    def update_console_display():
        """Met à jour le contenu de l'historique affiché."""
        # Join la liste des lignes d'historique en une seule chaîne
        full_history_text = "\n".join(st.session_state.shell_cmd_history_list)
        
        # Le texte d'intro si l'historique est vide
        if not full_history_text:
            full_history_text = "Tapez 'id' ou 'ls' pour tester l'accès (PoC) et appuyez sur ENTRÉE ou cliquez sur 'Exécuter PoC'."

        # Met à jour le contenu du conteneur st.empty()
        with console_display_area.container():
             st.markdown("---") # Ligne de séparation
             st.code(full_history_text, language='bash')
             
        # 🔥 Tente de récupérer le focus après la mise à jour 🔥
        set_focus_on_input()

    # --- HANDLER D'EXÉCUTION (Callback) ---
    def execute_shell_command():
        """Exécute la commande PoC, met à jour la liste d'historique et déclenche le refresh."""
        command = st.session_state.current_shell_command_input.strip()
        
        if not command:
            st.session_state.current_shell_command_input = "" 
            # Re-afficher pour vider le champ (même si vide)
            update_console_display() 
            return 

        new_output = ""
        status_code = 500
        
        try:
            force_real = bool(user_config.get('allow_real_poc', True))
            new_output, status_code = simulate_poc_execution(target, command, force_real=force_real)
        except Exception as e:
            new_output = f"ERREUR CRITIQUE D'EXÉCUTION: {str(e)}"
            status_code = 500
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Ajoute les lignes à la liste d'historique
        st.session_state.shell_cmd_history_list.append(f"[{timestamp}] tropic@{target}:~# {command}")
        st.session_state.shell_cmd_history_list.append(f"STATUT HTTP : {status_code}")
        st.session_state.shell_cmd_history_list.extend(new_output.splitlines())
        st.session_state.shell_cmd_history_list.append("\n" + "="*50 + "\n") # Séparateur visuel plus clair
        
        # Vider le champ de saisie
        st.session_state.current_shell_command_input = "" 
        
        # Mise à jour immédiate de l'affichage (déclenche le rerun)
        update_console_display()
        
    # --- INTERFACE DE COMMANDE ---
    
    # 1. Dessiner le champ de saisie
    st.text_input(
        f"tropic@{target}:~# ", 
        key="current_shell_command_input", 
        label_visibility="collapsed",
        on_change=execute_shell_command 
    )
    
    # 2. Dessiner le bouton
    col1, col2 = st.columns([1, 4])
    with col1:
        st.button(
            "Exécuter PoC", 
            type="secondary", 
            use_container_width=True, 
            on_click=execute_shell_command
        )

    # 3. Affichage initial de la console (ou mise à jour après un rerun complet)
    update_console_display()

