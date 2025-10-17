# app.py (VERSION FINALE AVEC CONSOLE PERSISTANTE ET STATUS) - FORCE REAL POC ENABLED
import streamlit as st
import pandas as pd
import json
import os
import sys
from io import StringIO
from datetime import datetime
import subprocess
import time

# Importation des moteurs d'analyse.
try:
    from Recon import run_recon
    from Api_scan import run_api_scan, SECURITY_SCORE_WEIGHTS
    # Le module 3 est Exploit_Adv.py
    from Exploit_Adv import run_vulnerability_scan, simulate_poc_execution 
except ImportError as e:
    # Définit des placeholders si l'importation échoue.
    def placeholder_func(*args, **kwargs):
        if kwargs.get('command'):
            return f"ERREUR CRITIQUE: Le module de sécurité est manquant. Détails: {e}", 500
        raise ImportError(f"FATAL ERROR: Security module missing or misnamed. Details: {e}")
    run_recon = run_api_scan = run_vulnerability_scan = simulate_poc_execution = placeholder_func
    SECURITY_SCORE_WEIGHTS = {'ENDPOINT_EXPOSED': 15, 'INJECTION_VULNERABLE': 30, 'PARAM_REFLECTION': 10}


# ===============================================================================
#                             FONCTIONS D'EXECUTION / LOGS
# ===============================================================================

def execute_and_capture(func, target, config=None, module_name="Module"):
    """Exécute une fonction d'analyse et capture son output stdout/logs."""
    
    if module_name == "Module 3": 
        # Le Module 3 (Vulnerability Scan) utilise un générateur pour les logs en temps réel, 
        # il n'est donc pas exécuté ici. Le code principal gère son exécution.
        return "", 0 
        
    start_time = datetime.now()
    old_stdout = sys.stdout
    redirected_output = sys.stdout = StringIO()
    try:
        if config:
            func(target, config)
        else:
            func(target)
    finally:
        sys.stdout = old_stdout
    elapsed_time = (datetime.now() - start_time).total_seconds()
    return redirected_output.getvalue(), elapsed_time


def execute_post_scan_command(target_domain, command, output_lines):
    """Exécute une commande système fournie par l'utilisateur."""
    final_command = command.replace("{TARGET}", target_domain)
    output_lines.append(f"\n[POST-SCAN] >>> EXÉCUTION DE COMMANDE SYSTÈME <<<")
    output_lines.append(f"[POST-SCAN] Commande lancée: {final_command}")
    try:
        result = subprocess.run(final_command, shell=True, capture_output=True, text=True, check=True)
        output_lines.append(f"[POST-SCAN] Statut: SUCCÈS (Code {result.returncode})")
        output_lines.append(f"[POST-SCAN] Sortie standard (stdout):")
        output_lines.append("------STDOUT START------")
        output_lines.extend(result.stdout.splitlines())
        output_lines.append("------STDOUT END------")
    except subprocess.CalledProcessError as e:
        output_lines.append(f"[POST-SCAN] Statut: ERREUR D'EXÉCUTION (Code {e.returncode})")
        output_lines.append(f"[POST-SCAN] Erreur standard (stderr):")
        output_lines.append("------STDERR START------")
        output_lines.extend(e.stderr.splitlines())
        output_lines.append("------STDERR END------")
    except FileNotFoundError:
        output_lines.append("[POST-SCAN] Statut: ERREUR")
        output_lines.append("[POST-SCAN] CRITICAL: Commande introuvable.")
    except Exception as e:
        output_lines.append(f"[POST-SCAN] Statut: ERREUR CRITIQUE: {str(e)}")

# ===============================================================================
#                           CONFIGURATION DES MODULES
# ===============================================================================

def load_user_config():
    """Charge les options de configuration depuis la sidebar."""
    st.sidebar.header("⚙️ Configuration des Modules")
    
    # --- Définition des Objectifs/Scope ---
    st.sidebar.subheader("🎯 Objectifs du Pentest")
    pentest_goal = st.sidebar.text_area(
        "Scope / But Principal du Test",
        value="Vérifier la configuration de sécurité de l'infrastructure web (Headers et exposition API).",
        height=100,
        key="pentest_goal_input",
        help="Définissez clairement ce que le test doit découvrir ou valider."
    )
    st.sidebar.markdown("---")
    
    st.sidebar.subheader("Général")
    timeout = st.sidebar.slider("Délai d'attente (Timeout) en secondes", min_value=3, max_value=20, value=7, step=1, help="Durée maximale d'attente pour une réponse HTTP/S pour Recon et API Scan.")
    st.sidebar.markdown("---")
    st.sidebar.subheader("Module 1 (Recon)")
    use_http_fallback = st.sidebar.checkbox("Utiliser Fallback HTTP (si HTTPS échoue)", value=True, help="Si cochée, le scan testera HTTP si HTTPS ne répond pas.")
    st.sidebar.subheader("Module 2 (API Scan)")
    custom_ua = st.sidebar.text_input("User Agent Personnalisé", value="TROPIC-ProAPI-Analyzer/2.1 (EthicalHacking)", help="Identifiant utilisé pour les requêtes HTTP/S dans le Module 2.")
    st.sidebar.markdown("---")
    st.sidebar.subheader("🌐 Post-Scan Executor")
    post_scan_command = st.sidebar.text_input("Commande Terminal à Exécuter", value="echo Scan TROPIC terminé pour {TARGET}", help="Sera exécuté après tous les modules.")
    
    # --- Module 3 explicit force flag (FORCE TRUE by default)
    st.sidebar.markdown("---")
    st.sidebar.subheader("Module 3 (Exploit / PoC)")
    allow_real_poc = st.sidebar.checkbox(
        "Autoriser l'exécution réelle (RCE) depuis la Console PoC (FORCÉ)",
        value=True,  # DEFAULT = True -> FORCE behavior
        help="Cochez uniquement si vous avez un consentement explicite et comprenez les risques. Par défaut activé (FORCE)."
    )
    
    return {
        "timeout": timeout,
        "use_http_fallback": use_http_fallback,
        "user_agent": custom_ua,
        "post_scan_command": post_scan_command,
        "pentest_goal": pentest_goal,
        "allow_real_poc": allow_real_poc
    }

# ===============================================================================
#                             FONCTIONS D'AFFICHAGE DU RAPPORT
# ===============================================================================

def display_recon_report(target):
    st.subheader("📊 Module 1 : Résultat de la Reconnaissance")
    active_file = os.path.join("output", f"{target}_active_subdomains.txt")
    if os.path.exists(active_file):
        with open(active_file, 'r') as f:
            subdomains = [line.strip() for line in f if line.strip()]
        st.success(f"**{len(subdomains)}** sous-domaines actifs trouvés et enregistrés.")
        df = pd.DataFrame(subdomains, columns=['Sous-Domaine Actif'])
        st.dataframe(df, use_container_width=True)
    else:
        st.warning("Aucun fichier de cibles actives trouvé. Le scan a pu échouer.")

def display_api_scan_report(target):
    st.subheader("🛡️ Module 2 : Analyse Sécurité API/Headers")
    report_file = os.path.join("output", f"{target}_api_report.json")
    if not os.path.exists(report_file):
        st.error("Rapport API non trouvé.")
        return

    with open(report_file, 'r') as f:
        report = json.load(f)
    
    if not report['scan_results']:
        st.warning("Aucun rapport d'analyse API n'a pu être généré (probablement dû à une erreur de connexion sur toutes les cibles testées).")
        return
    
    main_report = report['scan_results'][0] 
    final_score = main_report.get('final_score', 0)
    
    col1, col2 = st.columns([1, 2])
    with col1:
        if final_score >= 80:
            st.success(f"Score de Sécurité : **{final_score}/100** 🛡️", icon="✅")
            st.markdown("*Niveau : **EXCELLENT**. Configuration robuste.*")
        elif final_score >= 50:
            st.warning(f"Score de Sécurité : **{final_score}/100** ⚠️", icon="🟡")
            st.markdown("*Niveau : **MOYEN**. Des failles critiques nécessitent une action immédiate.*")
        else:
            st.error(f"Score de Sécurité : **{final_score}/100** ❌", icon="🚨")
            st.markdown("*Niveau : **CRITIQUE**. Fuites d'informations importantes et/ou absence de mesures de sécurité de base.*")
        st.markdown(f"**Cible :** `{main_report['target_url']}`")
    with col2:
        penalty_value = SECURITY_SCORE_WEIGHTS.get('ENDPOINT_EXPOSED', 15)
        st.markdown(f"**Pénalité par Endpoint Exposé (200 OK) :** -{penalty_value} points.")
    findings = main_report['header_findings']
    if findings:
        st.markdown("#### Failles d'En-tête Détectées")
        df_findings = pd.DataFrame(findings)
        st.dataframe(df_findings[['severity', 'header', 'description']], use_container_width=True, hide_index=True)
    else:
        st.info("Aucun manquement critique ou divulgation d'en-tête de sécurité détecté.")
    api_results = main_report['api_discovery']
    exposed_endpoints = [res for res in api_results if res['status'] == 200]
    st.markdown("#### Fuzzing d'Endpoints API")
    if exposed_endpoints:
        st.warning(f"**{len(exposed_endpoints)} Endpoints Critiques exposés (200 OK)**")
        df_exposed = pd.DataFrame(exposed_endpoints)
        st.dataframe(df_exposed[['endpoint', 'description']], use_container_width=True, hide_index=True)
    else:
        st.info("Aucun endpoint critique n'a répondu 200 OK lors du fuzzing.")

def display_vuln_scan_report(target):
    st.subheader("🚨 Module 3 : Rapport de Vulnérabilités Avancé")
    report_file = os.path.join("output", f"{target}_vulnerability_report.json")
    if not os.path.exists(report_file):
        st.error("Rapport de vulnérabilités non trouvé.")
        return
    with open(report_file, 'r') as f:
        report = json.load(f)
    vulns = report['vulnerabilities']
    total_vulns = len(vulns)
    st.metric(label="Vulnérabilités Totales Trouvées", value=total_vulns)
    if total_vulns > 0:
        st.error(f"**{total_vulns}** découvertes de vulnérabilités enregistrées.")
        df_vulns = pd.DataFrame(vulns)
        display_cols = ['severity', 'target', 'title', 'remediation']
        st.dataframe(df_vulns.sort_values(by='severity', ascending=False)[display_cols], use_container_width=True, hide_index=True)
        with st.expander("Voir les recommandations de remédiation détaillées"):
            for title, remediation in df_vulns[['title', 'remediation']].drop_duplicates().values:
                st.markdown(f"**{title}**\n> *Remédiation :* {remediation}\n")
    else:
        st.info("Aucune vulnérabilité n'a été trouvée.")

# Fonction pour l'interface du Shell Simulé (Console de Diagnostic Actif)
def display_active_diagnostic_console(target, user_config):
    """
    Console PoC robuste — persistance garantie, sans éjection.
    """
    st.header(f"💻 Console PoC Actif - {target}")
    st.warning("⚠️ Utilisez uniquement sur des cibles autorisées.")

    # Initialisation persistante
    history_key = f"shell_cmd_history_{target}"
    if history_key not in st.session_state:
        st.session_state[history_key] = ""

    # Affichage de l'historique
    history_container = st.empty()
    history_text = st.session_state[history_key]
    history_container.code(history_text if history_text else "Historique vide. Tapez une commande.", language='bash')

    # Formulaire pour input de commande
    form_key = f"poc_form_{target}"
    with st.form(key=form_key, clear_on_submit=False):
        cmd = st.text_input("tropic@{}:~#".format(target), key=f"poc_input_{target}", label_visibility="collapsed")
        submit = st.form_submit_button("Exécuter PoC")

        if submit:
            command = (cmd or "").strip()
            if not command:
                st.warning("Aucune commande saisie.")
            else:
                force_real = bool(user_config.get('allow_real_poc', True))
                try:
                    output, status_code = simulate_poc_execution(target, command, force_real=force_real)
                except Exception as e:
                    output, status_code = f"ERREUR : {str(e)}", 500

                # Ajout à l'historique
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                entry = f"[{timestamp}] tropic@{target}:~# {command}\nSTATUT : {status_code}\n{output}\n\n"
                st.session_state[history_key] += entry

                # Mise à jour de l'affichage
                history_container.code(st.session_state[history_key], language='bash')

                # Clear input pour la prochaine commande
                st.session_state[f"poc_input_{target}"] = ""

                # Notification rapide
                if status_code == 200:
                    st.success(f"Commande exécutée avec succès (HTTP {status_code}).")
                else:
                    st.warning(f"Commande terminée avec statut {status_code}.")
        
    
    # --- HANDLER D'EXÉCUTION (POUR LE CALLBACK DU BOUTON) ---
    def execute_shell_command():
        """Exécute la commande PoC et met à jour l'historique directement via la session state."""
        
        # Récupère la commande saisie via sa clé (avant que le champ ne soit vidé)
        command = st.session_state.current_shell_command_input.strip()
        
        if not command:
            return # Ne rien faire si la commande est vide

        new_output = ""
        status_code = 500
        
        # --- BLOC D'EXÉCUTION DU PoC (avec gestion des erreurs) ---
        try:
            # Exécution du PoC (via le Module 3)
            # Utilisation du PoC SIMULÉ/RÉEL (selon le verrou éthique dans Exploit_Adv.py)
            # Ici on lit explicitement le flag depuis user_config passé par main()
            force_real = bool(user_config.get('allow_real_poc', True))
            # Passe le flag force_real à la fonction (ATTENTION: Exploit_Adv.simulate_poc_execution doit accepter ce paramètre)
            new_output, status_code = simulate_poc_execution(target, command, force_real=force_real)
        except ImportError:
            new_output = "ERREUR CRITIQUE: Le module Exploit_Adv.py ou la fonction simulate_poc_execution est manquant(e)."
            status_code = 500
        except TypeError:
            # Cas où simulate_poc_execution n'accepte pas encore le paramètre force_real :
            # On retente l'appel historique (compatibilité descendante)
            try:
                new_output, status_code = simulate_poc_execution(target, command)
            except Exception as e:
                new_output = f"ERREUR D'EXÉCUTION DU PoC (fallback failed): {str(e)}"
                status_code = 500
        except Exception as e:
            new_output = f"ERREUR D'EXÉCUTION DU PoC: {str(e)}"
            status_code = 500
        
        # Construit le nouveau contenu pour l'affichage (ajoute la commande et la sortie)
        st.session_state.shell_cmd_history += f"tropic@{target}:~# {command}\n"
        st.session_state.shell_cmd_history += f"STATUT HTTP : {status_code}\n"
        st.session_state.shell_cmd_history += new_output + "\n\n"
        
        # Pour vider visuellement le champ de saisie après l'exécution
        st.session_state.current_shell_command_input = "" 
        # Streamlit re-runnera automatiquement, affichant le nouvel historique.


    # --- INTERFACE DE COMMANDE ---

    # Champ de saisie pour la commande
    command_input = st.text_input(
        f"tropic@{target}:~# ", 
        key="current_shell_command_input", 
        label_visibility="collapsed",
        # Le on_change permet d'exécuter la commande si l'utilisateur appuie sur ENTER
        on_change=execute_shell_command 
    )
    
    col1, col2 = st.columns([1, 4])
    
    with col1:
        # Le bouton déclenche l'exécution en utilisant le handler
        execute_button = st.button(
            "Exécuter PoC", 
            type="secondary", 
            use_container_width=True, 
            on_click=execute_shell_command # Le clic exécute directement la fonction de mise à jour de l'état
        )

    # Affichage de la Console
    st.markdown("---")
    st.code(st.session_state.shell_cmd_history if st.session_state.shell_cmd_history else "Tapez 'id' ou 'ls' pour tester l'accès (PoC) et appuyez sur ENTRÉE ou cliquez sur 'Exécuter PoC'.", language='bash')

# ===============================================================================
#                             INTERFACE PRINCIPALE
# ===============================================================================

def main():
    
    # 1. INJECTION DU THÈME CYBER/MATRIX (CSS STATIQUE)
    st.markdown("""
    <style>
        /* STYLE NÉON POUR LE TITRE PRINCIPAL */
        .neon {
          color: #FFFFFF;
          text-shadow:
            0 0 7px #00FFFF,
            0 0 10px #00FFFF,
            0 0 21px #00FFFF,
            0 0 42px #0000FF,
            0 0 82px #0000FF,
            0 0 92px #0000FF,
            0 0 102px #0000FF,
            0 0 151px #0000FF;
          font-family: 'Monospace', monospace; 
          text-transform: uppercase;
          font-size: 3em; 
        }

        /* AMÉLIORATION DE LA BARRE LATÉRALE (SIDEBAR) */
        [data-testid="stSidebar"] {
            background-color: #1A1A2E; 
            color: #00FFFF;
            box-shadow: 0 0 10px #00FFFF33; 
        }
        
        /* Modification des boutons pour un style plus agressif */
        .stButton>button {
            background-color: #00FFFF;
            color: #0E1117; 
            border: 2px solid #00FFFF;
            box-shadow: 0 0 8px #00FFFF;
            transition: all 0.3s ease;
        }
        .stButton>button:hover {
            background-color: #000000;
            color: #00FFFF;
            box-shadow: 0 0 15px #00FFFF;
            border-color: #00FFFF;
        }
        
        /* AVERTISSEMENT RED FLAG */
        .red-flag-box {
            background-color: #330000 !important; 
            border: 3px solid #ff0000 !important; 
            padding: 15px; 
            margin-bottom: 20px; 
            box-shadow: 0 0 15px rgba(255, 0, 0, 0.7); 
        }
        .red-flag-box p {
            color: #ff9999 !important;
        }
        
        /* Style pour les logs en temps réel */
        .stCode {
            background-color: #0c0c0c !important;
            color: #00ff00 !important;
            border: 1px solid #00ff00;
            padding: 15px;
            font-size: 14px;
            overflow-x: auto;
            max-height: 400px; 
        }
        
        /* 🚨🚨 CORRECTION VISUELLE DE LA BARRE DE PROGRESSION ROUGE FIXE 🚨🚨 */
        .stProgress > div > div > div > div {
            background-color: #ff0000; 
        }
        .stProgress > div > div > div {
            background-color: #330000; 
            border: 1px solid #ff0000; 
        }
        .stSidebar > div > div {
            color: #FFFFFF !important; 
        }
    </style>
    """, unsafe_allow_html=True)
    
    # Titre Néon
    st.markdown('<h1 class="neon">TROPIC 🌴 by Karim</h1>', unsafe_allow_html=True)
    st.markdown("Outil de sécurité complet en 3 phases, incluant un exécuteur de commandes post-scan.")

    # AVERTISSEMENT RED FLAG MASSIF
    st.markdown("""
        <div class="red-flag-box">
            <p style="color: #ff0000; font-weight: bold; font-size: 1.5em; text-align: center;">
                🛑 RED FLAG WARNING: HACKER ETHIQUE - VOS RISQUES ENGAGÉS 🛑
            </p>
            <p style="font-weight: bold;">
                L'interface de Console d'Exploitation (PoC) est fournie pour la CONFIRMATION DE VULNÉRABILITÉS CRITIQUES détectées.
            </p>
            <p style="font-size: 0.9em;">
                L'utilisation de TROPIC sur toute cible sans autorisation explicite, au-delà du simple test passif, est une violation criminelle. En utilisant ce panel, vous assumez l'entière et unique responsabilité de vos actions, incluant les conséquences légales et éthiques.
            </p>
        </div>
    """, unsafe_allow_html=True)

    # --- CHARGEMENT DE LA CONFIGURATION UTILISATEUR ---
    user_config = load_user_config()

    # --- PERSISTANCE SESSION_STATE (Module 3) ---
    # Initialise les clés nécessaires pour éviter l'éjection de la console PoC après un rerun
    if 'module3_logs' not in st.session_state:
        st.session_state['module3_logs'] = ""
    if 'module3_elapsed' not in st.session_state:
        st.session_state['module3_elapsed'] = 0.0
    if 'module3_run_id' not in st.session_state:
        st.session_state['module3_run_id'] = None
    if 'module3_running' not in st.session_state:
        st.session_state['module3_running'] = False

    # --- AFFICHAGE DU SCOPE ---
    st.markdown(f"**🎯 Objectif du Test :** _{user_config['pentest_goal']}_")
    st.markdown("---")

    # --- INPUT DOMAIN ---
    target_domain = st.text_input("Domaine Cible (Ex: votre-cible.com)", value="votre-cible.com")
    st.markdown("---")

    # --- SÉLECTION DES MODULES ---
    st.sidebar.header("Options d'Exécution")
    run_all = st.sidebar.checkbox("Exécuter les 3 Modules en Séquence", value=True)
    
    if not run_all:
        st.sidebar.markdown("Ou sélectionner un module unique :")
        run_recon_module = st.sidebar.button("▶️ Lancer Module 1 (Reconnaissance)")
        run_api_module = st.sidebar.button("▶️ Lancer Module 2 (API Scan)")
        run_vuln_module = st.sidebar.button("▶️ Lancer Module 3 (Vuln. Scan)")
    else:
        run_sequence = st.button("🚀 Lancer l'Analyse Complète (3 Modules)", type="primary", use_container_width=True)
        run_recon_module = run_api_module = run_vuln_module = False
        if run_sequence:
            run_recon_module = run_api_module = run_vuln_module = True

    # --- LOGIQUE D'EXÉCUTION ---
    if run_recon_module or run_api_module or run_vuln_module:
        
        if not target_domain:
            st.error("Veuillez entrer un domaine cible.")
            return

        os.makedirs("output", exist_ok=True)
        placeholder = st.empty()
        all_logs = []
        
        # 1. MODULE DE RECONNAISSANCE
        if run_recon_module:
            with placeholder.status(f"Module 1: Exécution de la Reconnaissance sur **{target_domain}**...", expanded=True) as status:
                log, time_elapsed = execute_and_capture(run_recon, target_domain, user_config, module_name="Module 1") 
                all_logs.append(f"\n--- LOGS MODULE 1 ({time_elapsed:.2f}s) ---\n" + log)
                status.update(label=f"✅ Module 1 (Recon) terminé en {time_elapsed:.2f}s", state="complete", expanded=False)
            display_recon_report(target_domain)
            st.markdown("---")

        # 2. MODULE API SCAN
        if run_api_module:
            if not os.path.exists(os.path.join("output", f"{target_domain}_active_subdomains.txt")):
                st.warning("⏩ Skipping Module 2 : Le fichier des cibles actives est manquant. Lancez le Module 1 d'abord.")
            else:
                with placeholder.status(f"Module 2: Exécution de l'Analyse API/Headers...", expanded=True) as status:
                    log, time_elapsed = execute_and_capture(run_api_scan, target_domain, user_config, module_name="Module 2")
                    all_logs.append(f"\n--- LOGS MODULE 2 ({time_elapsed:.2f}s) ---\n" + log)
                    status.update(label=f"✅ Module 2 (API Scan) terminé en {time_elapsed:.2f}s", state="complete", expanded=False)
                display_api_scan_report(target_domain)
                st.markdown("---")

        # 3. MODULE VULN SCAN (Exploit_Adv.py) - LOGS EN TEMPS RÉEL (PERSISTENT)
        if run_vuln_module:
            if not os.path.exists(os.path.join("output", f"{target_domain}_active_subdomains.txt")):
                st.warning("⏩ Skipping Module 3 : Le fichier des cibles actives est manquant. Lancez le Module 1 d'abord.")
            else:
                
                # --- BARRE DE STATUT & PROGRESSION DANS LE CONTENEUR PRINCIPAL ---
                st.subheader("💻 Terminal d'Exploitation en Temps Réel (Logs)")
                
                # Relancer manuellement si besoin (reset du state)
                col_r1, col_r2 = st.columns([4, 1])
                with col_r2:
                    if st.button("🔁 Relancer Module 3 (Vuln. Scan)"):
                        st.session_state['module3_logs'] = ""
                        st.session_state['module3_elapsed'] = 0.0
                        st.session_state['module3_run_id'] = None
                        st.session_state['module3_running'] = False
                        # Force la relance immédiate
                        run_vuln_module = True

                # Si on a déjà un log final sauvegardé POUR CETTE CIBLE, on l'affiche (persistant entre reruns)
                if st.session_state.get('module3_run_id') == target_domain and st.session_state.get('module3_logs'):
                    elapsed = st.session_state.get('module3_elapsed', 0.0)
                    st.success(f"Module 3 : Dernier scan pour {target_domain} (terminé en {elapsed:.2f}s).")
                    st.code(st.session_state['module3_logs'], language='bash')
                    # Toujours afficher le rapport final si disponible
                    display_vuln_scan_report(target_domain)
                    st.markdown("---")
                # Si un scan est en cours sur cette session (déjà lancé dans la même run)
                elif st.session_state.get('module3_running', False) and st.session_state.get('module3_run_id') == target_domain:
                    st.info("Un scan Module 3 est en cours (sous cette session). Affichage des logs en direct.")
                    st.code(st.session_state['module3_logs'], language='bash')
                else:
                    # Aucun log sauvegardé pour cette cible -> on lance le generator *uniquement maintenant*
                    with placeholder.status(f"Module 3: Préparation du Scan de Vulnérabilités Avancé sur **{target_domain}**...", expanded=True) as status:
                        
                        # Place la barre de progression DANS le statut
                        progress_bar = status.progress(0, text="Initialisation...")
                        
                        # Crée un placeholder pour les logs DANS le statut pour les logs de progression/processus
                        status_log_area = status.empty() 
                        full_log_text = ""
                        
                        start_time = datetime.now()
                        
                        # Marque l'exécution en cours dans le session_state (empêche relance involontaire)
                        st.session_state['module3_running'] = True
                        st.session_state['module3_run_id'] = target_domain
                        st.session_state['module3_logs'] = ""  # reset live accumulation

                        # L'exécution du générateur de scan
                        scan_generator = run_vulnerability_scan(target_domain, user_config)
                        
                        # Affiche le conteneur de logs réels juste en dessous de la barre de statut principale
                        log_area_main = st.empty() 
                        
                        for log_line in scan_generator:
                            
                            # 1. Mise à jour de la barre de progression (détection du format [STATE])
                            try:
                                if isinstance(log_line, str) and log_line.startswith("[STATE]"):
                                    try:
                                        parts = log_line[7:].strip().split('/')
                                        # support formats like "X/Y" or other messages "message"
                                        if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
                                            completed = int(parts[0])
                                            total = int(parts[1])
                                            percent_complete = completed / total if total > 0 else 0.0
                                            progress_bar.progress(percent_complete, text=f"Scanning... {completed}/{total} cibles.")
                                            status_log_area.write(f"Avancement: {completed} de {total} cibles...")
                                        else:
                                            # not numeric progress; display as status message
                                            status_log_area.write(log_line[7:].strip())
                                    except Exception:
                                        status_log_area.write(f"Log de statut: {log_line}")
                                else:
                                    # 2. Affichage du Log normal (pour le terminal principal)
                                    full_log_text += f"\n{log_line}"
                                    # Stocke aussi progressivement dans session_state pour persistance en cas de rerun
                                    st.session_state['module3_logs'] = (st.session_state.get('module3_logs','') + "\n" + str(log_line)).strip()
                                    log_area_main.code(st.session_state['module3_logs'], language='bash') 
                            except Exception as e:
                                # En cas d'erreur lors du traitement d'une ligne, on l'ajoute au log
                                full_log_text += f"\n[LOG-PROCESS-ERROR] {str(e)}\n{repr(log_line)}"
                                st.session_state['module3_logs'] = (st.session_state.get('module3_logs','') + "\n" + f"[LOG-PROCESS-ERROR] {str(e)}").strip()
                                log_area_main.code(st.session_state['module3_logs'], language='bash')

                        elapsed_time = (datetime.now() - start_time).total_seconds()
                        
                        # Sauvegarde finale dans le session_state
                        st.session_state['module3_elapsed'] = elapsed_time
                        st.session_state['module3_running'] = False
                        
                        # Finalisation du statut
                        status.update(label=f"✅ Module 3 (Vuln. Scan) terminé en {elapsed_time:.2f}s", state="complete", expanded=False)

                        # Mise à jour des logs finaux (all_logs)
                        all_logs.append(f"\n--- LOGS MODULE 3 ({elapsed_time:.2f}s) ---\n" + st.session_state.get('module3_logs', ''))
                        
                        # Affiche le rapport de vulnérabilités si généré par le module
                        display_vuln_scan_report(target_domain)
                        st.markdown("---")
        
        
        # 4. POST-SCAN EXECUTOR
        if user_config['post_scan_command']:
             with placeholder.status(f"🌐 Exécution de la commande Post-Scan...", expanded=True) as status:
                output_lines = []
                execute_post_scan_command(target_domain, user_config['post_scan_command'], output_lines)
                all_logs.append(f"\n--- LOGS POST-SCAN EXECUTOR ---\n" + "\n".join(output_lines))
                status.update(label=f"✅ Commande Post-Scan terminée", state="complete", expanded=False)

        
        # 5. CONSOLE DE DIAGNOSTIC ACTIF
        st.markdown("---")
        # NOTE : Cette fonction utilise maintenant un on_click callback pour l'exécution
        # On passe user_config pour que la console sache si l'on force l'exécution réelle
        display_active_diagnostic_console(target_domain, user_config)
        
        # Section de Documentation Éthique et Méthodologie
        st.markdown("---")
        
        with st.expander("Méthodologie TROPIC : Détails du Score de Sécurité et Éthique"):
            st.markdown("""
                L'évaluation de TROPIC repose sur une méthodologie à deux piliers pour garantir la pertinence éthique :
                
                ### 1. Score des Headers (Max 100 points)
                Le score initial est de 100 points. Chaque en-tête manquant ou mal configuré entraîne une déduction immédiate.
                
                | En-tête / Problème | Sévérité | Pénalité | Explication Éthique |
                | :--- | :--- | :--- | :--- |
                | **Strict-Transport-Security (HSTS)** | CRITICAL | -20 pts | Défaut de forcer HTTPS (risque de session hijacking). |
                | **Content-Security-Policy (CSP)** | CRITICAL | -20 pts | Permet les injections de code (XSS), non conforme aux bonnes pratiques modernes. |
                | **X-Frame-Options / X-Content-Type-Options** | HIGH | -10 pts | Failles contre le clickjacking et l'exécution de contenu non désiré. |
                | **Divulgation Serveur / X-Powered-By** | MEDIUM | -5 pts | Fournit à l'attaquant des informations faciles pour cibler les vulnérabilités. |
                
                ### 2. Ajustement par Exposition d'API
                Le score des Headers est ensuite ajusté par le nombre d'endpoints critiques non protégés (réponse **200 OK**) et par la détection d'injection active.
                
                * **Pénalité par Endpoint (ENDPOINT_EXPOSED) :** -{} points.
                * **Pénalité par Injection (INJECTION_VULNERABLE) :** -{} points.
                * **Pénalité par Réflexion (PARAM_REFLECTION) :** -{} points.
                
                Le score final est le score ajusté (minimum 0).
            """.format(SECURITY_SCORE_WEIGHTS.get('ENDPOINT_EXPOSED', 15), SECURITY_SCORE_WEIGHTS.get('INJECTION_VULNERABLE', 30), SECURITY_SCORE_WEIGHTS.get('PARAM_REFLECTION', 10))) 
            
            st.info("L'objectif de TROPIC est de fournir une évaluation claire et exploitable pour permettre la **remédiation** immédiate des failles de sécurité de base.")


        # Affichage du Log Final
        with st.expander("Voir les Logs d'Exécution Bruts (Multi-Module et Post-Scan)"):
            st.code(''.join(all_logs), language='bash')
        
        st.balloons()

# --- BLOC DE LANCEMENT SIMPLIFIÉ ---
if __name__ == "__main__":
    main()
