# app.py (VERSION FINALE PROPRE, MODULAIRE ET STABLE avec marge corrigée et refonte UI)
import streamlit as st
import pandas as pd
import json
import os
import sys
from io import StringIO
from datetime import datetime
import subprocess
import time

# 🔥 Importation des modules (Moteurs d'Analyse et Console PoC)
try:
    # Assurez-vous que ces modules existent dans votre environnement
    from Recon import run_recon
    from Api_scan import run_api_scan, SECURITY_SCORE_WEIGHTS
    from Exploit_Adv import run_vulnerability_scan, simulate_poc_execution 
except ImportError as e:
    # Définit des placeholders si l'importation échoue.
    def placeholder_func(*args, **kwargs):
        if kwargs.get('command'):
            return f"ERREUR CRITIQUE: Le module de sécurité est manquant. Détails: {e}", 500
        raise ImportError(f"FATAL ERROR: Security module missing or misnamed. Details: {e}") 
    run_recon = run_api_scan = run_vulnerability_scan = simulate_poc_execution = placeholder_func
    # Valeurs par défaut si le module Api_scan est manquant
    SECURITY_SCORE_WEIGHTS = {'ENDPOINT_EXPOSED': 15, 'INJECTION_VULNERABLE': 30, 'PARAM_REFLECTION': 10}
# La console PoC (poc_console) est importée dans la fonction main() pour gérer les dépendances.


# ===============================================================================
#                             FONCTIONS D'EXECUTION / LOGS
# ===============================================================================

def execute_and_capture(func, target, config=None, module_name="Module"):
    """Exécute une fonction d'analyse et capture son output stdout/logs."""
    
    if module_name == "Module 3": 
        # Le Module 3 (Vulnerability Scan) utilise un générateur pour les logs en temps réel.
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
        # Utilisation de shell=True pour la substitution de commande et l'exécution
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
    """Charge les options de configuration depuis la sidebar, regroupées dans des expanders."""
    st.sidebar.header("⚙️ Configuration des Modules")
    
    # --- Définition des Objectifs/Scope (Reste critique et visible) ---
    st.sidebar.subheader("🎯 Objectifs du Pentest")
    pentest_goal = st.sidebar.text_area(
        "Scope / But Principal du Test",
        value="Vérifier la configuration de sécurité de l'infrastructure web (Headers et exposition API).",
        height=100,
        key="pentest_goal_input",
        help="Définissez clairement ce que le test doit découvrir ou valider."
    )
    st.sidebar.divider() # Utilisation du séparateur moderne
    
    # --- Paramètres Généraux (Regroupés) ---
    with st.sidebar.expander("Général (Timeout / Fallback)"):
        timeout = st.slider("Délai d'attente (Timeout) en secondes", min_value=3, max_value=20, value=7, step=1, help="Durée maximale d'attente pour une réponse HTTP/S pour Recon et API Scan.")
        use_http_fallback = st.checkbox("Utiliser Fallback HTTP (si HTTPS échoue)", value=True, help="Si cochée, le scan testera HTTP si HTTPS ne répond pas.")

    # --- Configuration Module 2 (Regroupée) ---
    with st.sidebar.expander("Configuration Module 2 (API Scan)"):
        custom_ua = st.text_input("User Agent Personnalisé", value="TROPIC-ProAPI-Analyzer/2.1 (EthicalHacking)", help="Identifiant utilisé pour les requêtes HTTP/S dans le Module 2.")
    
    # --- Post-Scan Executor (Regroupé) ---
    with st.sidebar.expander("🌐 Post-Scan Executor"):
        post_scan_command = st.text_input("Commande Terminal à Exécuter", value="echo Scan TROPIC terminé pour {TARGET}", help="Sera exécuté après tous les modules.")
    
    # --- Module 3 (Exploit / PoC) (Reste visible ou regroupé si nécessaire, ici conservé pour la clarté critique) ---
    st.sidebar.divider()
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
    # Retiré le st.subheader car il est dans l'onglet
    active_file = os.path.join("output", f"{target}_active_subdomains.txt")
    if os.path.exists(active_file):
        with open(active_file, 'r') as f:
            subdomains = [line.strip() for line in f if line.strip()]
        st.success(f"**{len(subdomains)}** sous-domains actifs trouvés et enregistrés.")
        df = pd.DataFrame(subdomains, columns=['Sous-Domaine Actif'])
        st.dataframe(df, use_container_width=True)
    else:
        st.warning("Aucun fichier de cibles actives trouvé. Le scan a pu échouer. Lancez le Module 1.")

def display_api_scan_report(target):
    # Retiré le st.subheader
    report_file = os.path.join("output", f"{target}_api_report.json")
    if not os.path.exists(report_file):
        st.error("Rapport API non trouvé. Lancez le Module 2.")
        return

    with open(report_file, 'r') as f:
        report = json.load(f)
    
    if not report['scan_results']:
        st.warning("Aucun rapport d'analyse API n'a pu être généré (probablement dû à une erreur de connexion sur toutes les cibles testées).")
        return
    
    main_report = report['scan_results'][0] 
    final_score = main_report.get('final_score', 0)
    
    # --- Affichage Visuel du Score Amélioré (Design) ---
    st.markdown("#### Score de Sécurité Final")
    col_score, col_info = st.columns([1, 2])
    
    with col_score:
        # Utilisation de la structure Markdown/CSS pour un affichage Néon stylisé
        color = "#00FF00" if final_score >= 80 else ("#FFFF00" if final_score >= 50 else "#FF0000")
        level = "EXCELLENT" if final_score >= 80 else ("MOYEN" if final_score >= 50 else "CRITIQUE")
        
        st.markdown(f"""
            <div style="text-align: center; border: 2px solid {color}; padding: 10px; border-radius: 5px; box-shadow: 0 0 5px {color}88;">
                <p style="font-size: 0.9em; margin-bottom: 0; color: #FFFFFF;">Score TROPIC</p>
                <p style="font-size: 3em; font-weight: bold; margin-top: 5px; margin-bottom: 5px; color: {color};">
                    {final_score}<span style="font-size: 0.5em;">/100</span>
                </p>
                <p style="font-size: 0.8em; margin: 0; color: {color};">Niveau : **{level}**</p>
            </div>
        """, unsafe_allow_html=True)
        st.markdown(f"**Cible :** `{main_report['target_url']}`")

    with col_info:
        st.markdown("#### Détails & Pénalités")
        st.markdown(f"**Pénalité par Endpoint Exposé (200 OK) :** -{SECURITY_SCORE_WEIGHTS.get('ENDPOINT_EXPOSED', 15)} points.")
        st.markdown(f"**Pénalité par Injection Vulnérable :** -{SECURITY_SCORE_WEIGHTS.get('INJECTION_VULNERABLE', 30)} points.")
        st.markdown("---")
        if final_score < 50:
            st.error("Des failles critiques ont été identifiées. Voir les résultats des En-têtes ci-dessous.")
        elif final_score < 80:
            st.warning("Des failles moyennes nécessitent une attention immédiate.")
        else:
            st.success("La configuration de base des Headers est robuste.")


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
        st.error(f"**{len(exposed_endpoints)} Endpoints Critiques exposés (200 OK)**")
        df_exposed = pd.DataFrame(exposed_endpoints)
        st.dataframe(df_exposed[['endpoint', 'description']], use_container_width=True, hide_index=True)
    else:
        st.info("Aucun endpoint critique n'a répondu 200 OK lors du fuzzing.")

def display_vuln_scan_report(target):
    # Retiré le st.subheader
    report_file = os.path.join("output", f"{target}_vulnerability_report.json")
    if not os.path.exists(report_file):
        st.error("Rapport de vulnérabilités non trouvé. Lancez le Module 3.")
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
          /* 💡 CORRECTION MARGE HAUTE du TITRE */
          margin-top: 0px !important; 
        }
        /* Style spécifique pour les onglets pour coller au thème */
        .stTabs [data-testid="stTabContent"] {
            padding: 10px 0; /* Réduit le padding interne des onglets */
        }
        .stTabs button {
            color: #00FFFF !important;
            border-bottom: 3px solid #00FFFF;
            background-color: #1A1A2E !important;
            box-shadow: 0 0 5px #00FFFF55;
            margin-right: 5px;
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
        /* Style pour centrer l'image native st.image */
        [data-testid="stImage"] {
            text-align: center;
        }

        /* --- BANNIÈRE --- */
        .banner-container {
            display: flex;
            justify-content: center;
            align-items: center;
            background-color: transparent;
            /* 💡 CORRECTION MARGE HAUTE du CONTENEUR BANNER */
            margin: 0 auto 16px auto !important; 
            padding: 4px;
            border-radius: 8px;
        }
        /* Styles pour l'image générée par st.image */
        .stImage > img {
            max-width: 100%;
            height: auto;
            max-height: 160px;
            border-radius: 6px;
        }
        
        /* Séparateur pour les champs de formulaire */
        .stTextInput, .stSlider, .stCheckbox {
            margin-bottom: 5px;
        }

    </style>
    """, unsafe_allow_html=True)

    # -----------------------------
    # 🎨 BANNIÈRE GIF EN HAUT (avec espacement latéral)
    # -----------------------------
    col_left_spacer, col_content, col_right_spacer = st.columns([1, 6, 1])

    def _find_banner_path():
        """
        Retourne le chemin du premier .gif trouvé dans le dossier 'assets/' 
        (qui doit être au même niveau que app.py).
        """
        # CHEMIN CORRIGÉ: Recherche directement dans le dossier 'assets'
        assets_dir = "assets" 
        
        # Testez les candidats en minuscules (meilleure pratique)
        candidates = ["banner.gif", "tropic_banner.gif"] 

        for c in candidates:
            p = os.path.join(assets_dir, c)
            if os.path.exists(p):
                return p
        
        # Fallback générique : cherche n'importe quel .gif dans le dossier (case-insensitive)
        if os.path.isdir(assets_dir):
            for f in os.listdir(assets_dir):
                if f.lower().endswith(".gif"):
                    p = os.path.join(assets_dir, f)
                    return p
        
        return None

    with col_content:
        gif_path = _find_banner_path()

        if gif_path and os.path.exists(gif_path):
            st.markdown('<div class="banner-container">', unsafe_allow_html=True)
            st.image(
                gif_path, 
                caption=None, 
                use_container_width=True, 
                output_format="GIF" 
            )
            st.markdown('</div>', unsafe_allow_html=True)
        else:
            st.warning("⚠️ Bannière introuvable : place ton fichier GIF (ex: banner.gif) dans le dossier 'assets/' au même niveau que app.py.")

        # Titre Néon (la marge supérieure est réinitialisée par le CSS ci-dessus)
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

        # --- CHARGEMENT DE LA CONFIGURATION UTILISATEUR (Refonte Sidebar) ---
        # La fonction load_user_config() a été modifiée pour utiliser st.expander
        user_config = load_user_config()
        
        all_logs = [] 
        scan_successful = True

        # --------------------------------------------------------------------------
        # --- PERSISTANCE SESSION_STATE (INITIALISATION) ---
        # --------------------------------------------------------------------------
        
        if 'module3_logs' not in st.session_state:
            st.session_state['module3_logs'] = ""
        if 'module3_elapsed' not in st.session_state:
            st.session_state['module3_elapsed'] = 0.0
        if 'module3_run_id' not in st.session_state:
            st.session_state['module3_run_id'] = None
        if 'module3_running' not in st.session_state:
            st.session_state['module3_running'] = False
            
        if 'shell_cmd_history' in st.session_state:
            del st.session_state['shell_cmd_history']
            
        if 'shell_cmd_history_list' not in st.session_state:
            st.session_state['shell_cmd_history_list'] = []
        if 'current_shell_command_input' not in st.session_state:
            st.session_state['current_shell_command_input'] = ""

        # --- AFFICHAGE DU SCOPE ---
        st.markdown(f"**🎯 Objectif du Test :** _{user_config['pentest_goal']}_")
        st.divider() # Utilisation du séparateur moderne
        
        # --- INPUT DOMAIN ---
        target_domain = st.text_input("Domaine Cible (Ex: votre-cible.com)", value="votre-cible.com")
        st.divider() # Utilisation du séparateur moderne

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
                st.stop()

            os.makedirs("output", exist_ok=True)
            placeholder = st.empty()
            
            # Définir les onglets pour les rapports AVANT l'exécution
            tab_recon, tab_api, tab_vuln = st.tabs(["📊 Module 1: Reconnaissance", "🛡️ Module 2: Sécurité API", "🚨 Module 3: Vulnérabilités"])

            # 1. MODULE DE RECONNAISSANCE
            if run_recon_module:
                with placeholder.status(f"Module 1: Exécution de la Reconnaissance sur **{target_domain}**...", expanded=True) as status:
                    log, time_elapsed = execute_and_capture(run_recon, target_domain, user_config, module_name="Module 1") 
                    all_logs.append(f"\n--- LOGS MODULE 1 ({time_elapsed:.2f}s) ---\n" + log)
                    status.update(label=f"✅ Module 1 (Recon) terminé en {time_elapsed:.2f}s", state="complete", expanded=False)
                with tab_recon:
                    display_recon_report(target_domain)
                st.divider()

            # 2. MODULE API SCAN
            if run_api_module:
                # Vérification de dépendance
                if (run_all or run_api_module) and not os.path.exists(os.path.join("output", f"{target_domain}_active_subdomains.txt")):
                    st.warning("⏩ Skipping Module 2 : Le fichier des cibles actives est manquant. Lancez le Module 1 d'abord.")
                    scan_successful = False
                elif scan_successful: # Exécution réelle
                    with placeholder.status(f"Module 2: Exécution de l'Analyse API/Headers...", expanded=True) as status:
                        log, time_elapsed = execute_and_capture(run_api_scan, target_domain, user_config, module_name="Module 2")
                        all_logs.append(f"\n--- LOGS MODULE 2 ({time_elapsed:.2f}s) ---\n" + log)
                        status.update(label=f"✅ Module 2 (API Scan) terminé en {time_elapsed:.2f}s", state="complete", expanded=False)
                    with tab_api:
                        display_api_scan_report(target_domain)
                    st.divider()

            # 3. MODULE VULN SCAN (Exploit_Adv.py) - LOGS EN TEMPS RÉEL (PERSISTENT)
            if run_vuln_module:
                # Vérification de dépendance
                if (run_all or run_vuln_module) and not os.path.exists(os.path.join("output", f"{target_domain}_active_subdomains.txt")):
                     st.warning("⏩ Skipping Module 3 : Le fichier des cibles actives est manquant. Lancez le Module 1 d'abord.")
                     scan_successful = False
                elif scan_successful: # Exécution réelle
                    
                    with tab_vuln:
                        st.subheader("💻 Terminal d'Exploitation en Temps Réel (Logs)")
                        
                        col_r1, col_r2 = st.columns([4, 1])
                        with col_r2:
                            if st.button("🔁 Relancer Module 3 (Vuln. Scan)", key="rerun_mod3"):
                                st.session_state['module3_logs'] = ""
                                st.session_state['module3_elapsed'] = 0.0
                                st.session_state['module3_run_id'] = None
                                st.session_state['module3_running'] = False
                                st.rerun() 
                                
                        # Affichage du dernier résultat si déjà terminé
                        if st.session_state.get('module3_run_id') == target_domain and st.session_state.get('module3_logs') and not st.session_state.get('module3_running'):
                            elapsed = st.session_state.get('module3_elapsed', 0.0)
                            st.success(f"Module 3 : Dernier scan pour {target_domain} (terminé en {elapsed:.2f}s).")
                            st.code(st.session_state['module3_logs'], language='bash')
                            display_vuln_scan_report(target_domain)
                            st.divider()
                        elif st.session_state.get('module3_running', False) and st.session_state.get('module3_run_id') == target_domain:
                            st.info("Un scan Module 3 est en cours (sous cette session). Affichage des logs en direct.")
                            st.code(st.session_state['module3_logs'], language='bash')
                        else: # Lancement du scan
                            with placeholder.status(f"Module 3: Préparation du Scan de Vulnérabilités Avancé sur **{target_domain}**...", expanded=True) as status:
                                
                                progress_bar = status.progress(0, text="Initialisation...")
                                status_log_area = status.empty() 
                                
                                start_time = datetime.now()
                                st.session_state['module3_running'] = True
                                st.session_state['module3_run_id'] = target_domain
                                st.session_state['module3_logs'] = "" 

                                try:
                                    scan_generator = run_vulnerability_scan(target_domain, user_config)
                                    log_area_main = st.empty() 
                                    
                                    for log_line in scan_generator:
                                        
                                        try:
                                            if isinstance(log_line, str) and log_line.startswith("[STATE]"):
                                                parts = log_line[7:].strip().split('/')
                                                if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
                                                    completed = int(parts[0])
                                                    total = int(parts[1])
                                                    percent_complete = completed / total if total > 0 else 0.0
                                                    progress_bar.progress(percent_complete, text=f"Scanning... {completed}/{total} cibles.")
                                                    status_log_area.write(f"Avancement: {completed} de {total} cibles...")
                                                else:
                                                    status_log_area.write(log_line[7:].strip())
                                            else:
                                                st.session_state['module3_logs'] = (st.session_state.get('module3_logs','') + "\n" + str(log_line)).strip()
                                                log_area_main.code(st.session_state['module3_logs'], language='bash') 
                                        except Exception as e:
                                            st.session_state['module3_logs'] = (st.session_state.get('module3_logs','') + "\n" + f"[LOG-PROCESS-ERROR] {str(e)}").strip()
                                            log_area_main.code(st.session_state['module3_logs'], language='bash')

                                except Exception as e:
                                    st.error(f"Erreur critique lors du lancement du Module 3: {e}")
                                    scan_successful = False
                                
                                elapsed_time = (datetime.now() - start_time).total_seconds()
                                
                                st.session_state['module3_elapsed'] = elapsed_time
                                st.session_state['module3_running'] = False
                                
                                status.update(label=f"✅ Module 3 (Vuln. Scan) terminé en {elapsed_time:.2f}s", state="complete", expanded=False)

                                all_logs.append(f"\n--- LOGS MODULE 3 ({elapsed_time:.2f}s) ---\n" + st.session_state.get('module3_logs', ''))
                                
                                display_vuln_scan_report(target_domain)
                                st.divider()
            
            
            # 4. POST-SCAN EXECUTOR
            if user_config['post_scan_command']:
                 with placeholder.status(f"🌐 Exécution de la commande Post-Scan...", expanded=True) as status:
                    output_lines = []
                    execute_post_scan_command(target_domain, user_config['post_scan_command'], output_lines)
                    all_logs.append(f"\n--- LOGS POST-SCAN EXECUTOR ---\n" + "\n".join(output_lines))
                    status.update(label=f"✅ Commande Post-Scan terminée", state="complete", expanded=False)
            
            # Effets de fin après l'exécution de tous les modules
            if scan_successful:
                st.balloons() 
                st.toast("Analyse complète terminée avec succès ! 🚀", icon='✅')
            else:
                st.snow() 
                st.toast("Analyse terminée avec des avertissements/erreurs. ⚠️", icon='🚨')

        
        # =======================================================
        # 5. CONSOLE PoC (external)
        # =======================================================
        
        # Ajout des colonnes pour l'espacement: 1 (gauche), 3 (contenu), 1 (droite)
        col_spacer_left, col_content, col_spacer_right = st.columns([1, 3, 1])

        with col_content:
            st.divider() # Utilisation du séparateur moderne

            # --- Prépare les clefs session_state dédiées à la console PoC pour éviter collisions ---
            if 'poc_shell_cmd_history_list' not in st.session_state:
                st.session_state['poc_shell_cmd_history_list'] = []
            if 'poc_current_shell_command_input' not in st.session_state:
                st.session_state['poc_current_shell_command_input'] = ""
            if 'poc_last_status' not in st.session_state:
                st.session_state['poc_last_status'] = None
            if 'poc_last_time' not in st.session_state:
                st.session_state['poc_last_time'] = None
            if 'poc_max_history' not in st.session_state:
                st.session_state['poc_max_history'] = 500  # limite raisonnable pour la perf

            # --- Import et appel de la console PoC externe ---
            try:
                from poc_console import render_poc_console
            except Exception as e:
                st.error(f"Impossible de charger poc_console.py : {e}")
                st.info(
                    "La console PoC est indisponible. "
                    "Vérifiez que poc_console.py est dans le même dossier et qu'elle expose render_poc_console(target, user_config)."
                )
            else:
                try:
                    # render_poc_console doit utiliser ses propres clefs st.session_state (préfixées 'poc_')
                    render_poc_console(target_domain, user_config)
                except Exception as e:
                    st.error(f"Erreur lors de l'exécution de la console PoC : {e}")
                    try:
                        import traceback
                        tb = traceback.format_exc()
                        st.text("Traceback (debug):")
                        st.text(tb)
                    except Exception:
                        pass

            # --- Fin de la console PoC ---
            st.divider() # Utilisation du séparateur moderne

            
        # Section de Documentation Éthique et Méthodologie
        st.divider() # Utilisation du séparateur moderne
        
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

# --- BLOC DE LANCEMENT SIMPLIFIÉ ---
if __name__ == "__main__":
    main()
