# app.py (VERSION FINALE TROPIC PRO - CONSOLE DE DIAGNOSTIC ACTIF + AUTO-LAUNCH)
import streamlit as st
import pandas as pd
import json
import os
import sys
from io import StringIO
from datetime import datetime
import subprocess

# Importation des moteurs d'analyse.
try:
    from Recon import run_recon
    from Api_scan import run_api_scan, SECURITY_SCORE_WEIGHTS
    # Le module 3 est Exploit_Adv.py
    from Exploit_Adv import run_vulnerability_scan, simulate_poc_execution 
except ImportError as e:
    # Si l'importation échoue ici, nous n'affichons qu'un message d'erreur simple
    # car les fonctions d'erreur de Streamlit ne sont pas encore prêtes.
    print(f"FATAL ERROR: Failed to import security modules. Ensure Recon.py, Api_scan.py, and Exploit_Adv.py exist. Details: {e}")
    sys.exit(1)

# ===============================================================================
#                             FONCTIONS D'EXECUTION / LOGS
# ===============================================================================

def execute_and_capture(func, target, config=None):
    """Exécute une fonction d'analyse et capture son output stdout/logs, en passant la config."""
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
    
    return {
        "timeout": timeout,
        "use_http_fallback": use_http_fallback,
        "user_agent": custom_ua,
        "post_scan_command": post_scan_command,
        "pentest_goal": pentest_goal
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
def display_active_diagnostic_console(target):
    st.header("💻 Console de Diagnostic Actif (PoC)")
    st.warning("⚠️ ATTENTION : La **Console de Diagnostic Actif** envoie des charges utiles spécifiques. N'utilisez cette console que sur des cibles pour lesquelles vous avez un consentement **écrit**.")
    
    if 'poc_output' not in st.session_state:
        st.session_state.poc_output = ""
    if 'shell_cmd_history' not in st.session_state:
        st.session_state.shell_cmd_history = ""
    if 'last_command' not in st.session_state:
        st.session_state.last_command = ""
    
    # Champ de saisie pour la commande
    command = st.text_input(
        f"tropic@{target}:~# ", 
        key="shell_cmd_input", 
        label_visibility="collapsed"
    )
    
    # Logique d'exécution
    col1, col2 = st.columns([1, 4])
    
    with col1:
        execute_button = st.button("Exécuter PoC", type="secondary", use_container_width=True)

    if execute_button or (command and st.session_state.last_command != command):
        
        if command:
            st.session_state.last_command = command 
            
            # Exécution du PoC (via le Module 3)
            new_output, status_code = simulate_poc_execution(target, command)
            
            # Construit le nouveau contenu pour l'affichage (ajoute la commande et la sortie)
            st.session_state.shell_cmd_history += f"tropic@{target}:~# {command}\n"
            st.session_state.shell_cmd_history += f"{new_output}\n\n"
            
            # Vide le champ d'entrée après l'exécution pour une nouvelle commande
            st.session_state.shell_cmd_input = "" 
            
    # Affichage de la Console
    st.markdown("---")
    st.code(st.session_state.shell_cmd_history if st.session_state.shell_cmd_history else "Tapez 'id' ou 'ls' pour tester l'accès (PoC) après avoir lancé un scan.", language='bash')

# ===============================================================================
#                             INTERFACE PRINCIPALE
# ===============================================================================

def main():
    st.set_page_config(
        page_title="TROPIC Scanner",
        layout="wide"
    )

    # 1. INJECTION DU THÈME CYBER/MATRIX (CSS STATIQUE)
    st.markdown(
        """
        <style>
        /* Force la police monospace partout */
        body, p, h1, h2, h3, h4, .st-ax, .st-emotion-cache-1c5v44v {
            font-family: monospace !important;
        }
        
        /* FOND STATIQUE DE STYLE GRID */
        .main {
            background-image: radial-gradient(rgba(0, 196, 0, 0.1) 1px, transparent 0);
            background-size: 40px 40px;
            background-color: #0d1117; 
        }

        /* Titre principal (H1) avec effet néon/glow vert */
        .st-emotion-cache-10trblm {
            text-shadow: 0 0 10px #00c400, 0 0 20px #00c400;
            color: #90ff83;
        }

        /* Style pour les blocs de code et Logs (effet Terminal) */
        .stCode {
            background-color: #0c0c0c !important;
            color: #00ff00 !important;
            border: 1px solid #00ff00;
            box-shadow: 0 0 10px rgba(0, 255, 0, 0.7);
            padding: 15px;
            font-size: 14px;
            overflow-x: auto;
        }

        /* AVERTISSEMENT RED FLAG - Fond et Bordure Rouge Vif */
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

        /* Modifie l'apparence des alertes WARNING pour un look "terminal jaune" */
        .stAlert p {
            font-family: monospace !important;
        }
        .stAlert [data-testid="stAlert"] {
            border-left: 6px solid #ffcc00 !important;
            background-color: #2e2e00 !important;
            color: #ffcc00 !important;
        }
        
        </style>
        """, 
        unsafe_allow_html=True
    )
    
    st.title("TROPIC 🌴")
    
    # Intégration de la mention "By Karim"
    st.markdown("Développé et maintenu par **Karim**. | Outil de sécurité complet en 3 phases, incluant un exécuteur de commandes post-scan.")

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

    # --- AFFICHAGE DU SCOPE ---
    st.markdown(f"**🎯 Objectif du Test :** _{user_config['pentest_goal']}_")
    st.markdown("---")

    # --- INPUT DOMAIN ---
    target_domain = st.text_input("Domaine Cible (Ex: example.com)", value="sypahwellness.com")
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
            with placeholder.status(f"Module 1: Exécution de la Reconnaissance sur **{target_domain}**... (1500+ actions)", expanded=True) as status:
                log, time = execute_and_capture(run_recon, target_domain, user_config) 
                all_logs.append(f"\n--- LOGS MODULE 1 ({time:.2f}s) ---\n" + log)
                status.update(label=f"✅ Module 1 (Recon) terminé en {time:.2f}s", state="complete", expanded=False)
            display_recon_report(target_domain)
            st.markdown("---")

        # 2. MODULE API SCAN
        if run_api_module:
            if not os.path.exists(os.path.join("output", f"{target_domain}_active_subdomains.txt")):
                st.warning("⏩ Skipping Module 2 : Le fichier des cibles actives est manquant. Lancez le Module 1 d'abord.")
            else:
                with placeholder.status(f"Module 2: Exécution de l'Analyse API/Headers...", expanded=True) as status:
                    log, time = execute_and_capture(run_api_scan, target_domain, user_config)
                    all_logs.append(f"\n--- LOGS MODULE 2 ({time:.2f}s) ---\n" + log)
                    status.update(label=f"✅ Module 2 (API Scan) terminé en {time:.2f}s", state="complete", expanded=False)
                display_api_scan_report(target_domain)
                st.markdown("---")

        # 3. MODULE VULN SCAN (Exploit_Adv.py)
        if run_vuln_module:
            if not os.path.exists(os.path.join("output", f"{target_domain}_active_subdomains.txt")):
                st.warning("⏩ Skipping Module 3 : Le fichier des cibles actives est manquant. Lancez le Module 1 d'abord.")
            else:
                with placeholder.status(f"Module 3: Exécution du Scan de Vulnérabilités...", expanded=True) as status:
                    log, time = execute_and_capture(run_vulnerability_scan, target_domain, user_config)
                    all_logs.append(f"\n--- LOGS MODULE 3 ({time:.2f}s) ---\n" + log)
                    status.update(label=f"✅ Module 3 (Vuln Scan) terminé en {time:.2f}s", state="complete", expanded=False)
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
        display_active_diagnostic_console(target_domain)
        
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


if __name__ == "__main__":
    # --- SOLUTION DE L'ERREUR 'Command not found' ---
    
    # 1. Installe les dépendances via pip
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
    except Exception as e:
        # Tente l'installation sans requirements.txt s'il échoue (juste au cas où)
        subprocess.check_call([sys.executable, "-m", "pip", "install", "streamlit", "pandas", "requests"])
    
    # 2. Lance Streamlit en utilisant l'exécutable Python (méthode la plus fiable)
    print("\nAttempting to launch Streamlit application via python -m streamlit...")
    
    try:
        subprocess.run(
            [
                sys.executable, "-m", "streamlit", "run", "app.py",
                "--server.port", "8501", 
                "--server.address", "0.0.0.0"
            ],
            check=True
        )
    except subprocess.CalledProcessError as e:
        print(f"CRITICAL ERROR: Streamlit execution failed. The command 'streamlit run' could not be executed.")
        print("Please check if the Code Space environment has sufficient permissions or dependencies.")
        sys.exit(1)
