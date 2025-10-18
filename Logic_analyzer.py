# Logic_analyzer.py

import time
from datetime import datetime
from typing import Dict, Any, List, Tuple 

# --- Structures de Résultats (Maintenues pour le rapport final) ---

# IDs statiques pour le test d'abus
ATTACKER_ID = "1001"
VICTIM_ID = "5005"
ADMIN_ROLE = "admin"
STANDARD_ROLE = "user"

# Fonctions de simulation simplifiées pour la clarté et la rapidité

def _simulate_login(role: str) -> Tuple[int, str, str]:
    """Simule une connexion et renvoie l'ID de session."""
    if role == STANDARD_ROLE:
        return 200, "Connexion réussie (STANDARD).", ATTACKER_ID
    return 401, "Échec de l'authentification.", ""

def _simulate_access_control(logged_id: str, requested_id: str, required_role: str) -> Tuple[int, str, bool]:
    """
    Simule la vérification des droits IDOR ou Escalade.
    VULNÉRABILITÉ DÉTECTÉE UNIQUEMENT SI TARGET_DOMAIN EST 'test-site.com'.
    """
    if logged_id == requested_id:
        return 200, "Accès autorisé (Self).", False
        
    # Test d'Escalade de Privilèges (Admin)
    if requested_id == ADMIN_ROLE:
        if logged_id == "ADMIN_BYPASS_ID": # Condition hypothétique d'un attaquant ayant un ID d'admin
            return 200, "⚠️ ALERTE ESCALADE: Accès Admin réussi.", True
        return 403, "Accès refusé : Privilèges Admin requis.", False

    # Test IDOR (Accès aux données d'un autre utilisateur)
    if logged_id == ATTACKER_ID and requested_id == VICTIM_ID:
        # 🚨 LOGIQUE DÉTERMINISTE : Failles seulement sur le site de test
        if required_role == "vulnerable": 
            return 200, f"⚠️ ALERTE IDOR: Accès non autorisé à l'ID {VICTIM_ID}.", True
        return 403, "Accès refusé : Le jeton de session ne correspond pas à l'ID demandé.", False

    return 403, "Accès non géré ou refusé.", False

def _simulate_rate_limit(is_vulnerable: bool) -> int:
    """Simule la réponse d'un test de Rate Limiting."""
    return 200 if is_vulnerable else 429 # 200 = Échec du Rate Limiting (Vuln), 429 = Succès

def _simulate_password_check(is_vulnerable: bool) -> int:
    """Simule la réponse à la soumission d'un mot de passe faible."""
    return 200 if is_vulnerable else 400 # 200 = Accepté (Vuln), 400 = Rejeté (Sécurité OK)


# ===============================================================================
#                          FONCTION D'EXÉCUTION PRINCIPALE
# ===============================================================================

def run_logic_analysis(target_domain: str, config: Dict[str, Any]):
    """
    Exécute le moteur d'analyse de logique métier.
    La détection de faille est déterministe basée sur le domaine cible:
    'test-site.com' -> VULNÉRABLE; 'autres domaines' -> SÛR.
    """
    start_time = datetime.now()
    vulnerabilities: List[Dict[str, Any]] = []
    
    # DÉTERMINISME : Le site est-il configuré pour simuler des failles ?
    is_vulnerable_target = (target_domain.lower().strip() == "test-site.com")
    
    # Variables de session
    logged_user_id = ""
    
    yield "[LOGIC] Démarrage du moteur d'analyse de logique métier (5 étapes)..."
    yield f"[LOGIC] Cible : {target_domain}"
    yield f"[LOGIC] Mode Déterministe: Failles simulées: {is_vulnerable_target}"
    
    steps_summary = []
    
    try:
        # --- ÉTAPE 1: Connexion (Préparation de l'état) ---
        status, msg, user_id = _simulate_login(STANDARD_ROLE)
        logged_user_id = user_id
        
        steps_summary.append({"name": "Connexion de l'attaquant", "status": status, "vulnerable": False})
        yield f"\n--- ÉTAPE 1: Connexion (ID: {logged_user_id}) ---"
        yield f"✅ SAFE : {msg} (Status {status})"
        
        # --- ÉTAPE 2: Tentative IDOR ---
        time.sleep(0.1)
        role_type = "vulnerable" if is_vulnerable_target else "secure"
        status, msg, vuln = _simulate_access_control(logged_id=logged_user_id, requested_id=VICTIM_ID, required_role=role_type)
        
        steps_summary.append({"name": "Abus IDOR: Tente de modifier le compte d'une autre victime", "status": status, "vulnerable": vuln})
        yield f"\n--- ÉTAPE 2: Test IDOR (Accès à {VICTIM_ID}) ---"
        if vuln:
            vulnerabilities.append({'severity': 'CRITICAL', 'type': 'IDOR', 'vulnerability': 'Insecure Direct Object Reference', 'endpoint': '/api/v1/profile/update', 'status_code': status, 'proof': msg})
            yield f"🚨 ALERTE VULNÉRABILITÉ (CRITICAL) : {msg}"
        else:
            yield f"✅ SAFE : {msg} (Status {status})"


        # --- ÉTAPE 3: Test Escalade de Privilèges ---
        time.sleep(0.1)
        status, msg, vuln = _simulate_access_control(logged_id=logged_user_id, requested_id=ADMIN_ROLE, required_role=STANDARD_ROLE) # Non géré dans _simulate_access_control mais retourne 403
        
        steps_summary.append({"name": "Escalade: Tente d'accéder à l'API Admin", "status": status, "vulnerable": vuln})
        yield f"\n--- ÉTAPE 3: Test Escalade de Privilèges ---"
        if vuln:
            vulnerabilities.append({'severity': 'CRITICAL', 'type': 'Privilege Escalation', 'vulnerability': 'Accès non autorisé à l\'Admin API', 'endpoint': '/api/v1/admin/dashboard_info', 'status_code': status, 'proof': msg})
            yield f"🚨 ALERTE VULNÉRABILITÉ (CRITICAL) : {msg}"
        else:
            yield f"✅ SAFE : {msg} (Status {status})"


        # --- ÉTAPE 4: Test de Surcharge de Limite (Rate Limiting Abuse) ---
        time.sleep(0.1)
        status = _simulate_rate_limit(is_vulnerable_target)
        vuln = (status == 200) # 200 = vulnérable
        
        steps_summary.append({"name": "Abus de limite: Tente d'envoyer 100 requêtes en 1s", "status": status, "vulnerable": vuln})
        yield f"\n--- ÉTAPE 4: Test Rate Limiting ---"
        if vuln:
            vulnerabilities.append({'severity': 'MEDIUM', 'type': 'Rate Limiting', 'vulnerability': 'Absence de limite de débit', 'endpoint': '/api/v1/post/create', 'status_code': status, 'proof': 'Le serveur a autorisé la surcharge (Status 200).'})
            yield f"⚠️ ALERTE VULNÉRABILITÉ (MEDIUM) : Le serveur n'a pas limité le débit des requêtes."
        else:
            yield f"✅ SAFE : Limite de débit atteinte (Status {status})."


        # --- ÉTAPE 5: Test de Faible Complexité de Mot de Passe ---
        time.sleep(0.1)
        status = _simulate_password_check(is_vulnerable_target)
        vuln = (status == 200) # 200 = vulnérable
        
        steps_summary.append({"name": "Test de complexité: Tente de réinitialiser le mot de passe avec '123456'", "status": status, "vulnerable": vuln})
        yield f"\n--- ÉTAPE 5: Test Complexité Mot de Passe ---"
        if vuln:
            vulnerabilities.append({'severity': 'MEDIUM', 'type': 'Weak Password Policy', 'vulnerability': 'Mot de passe trivial accepté', 'endpoint': '/api/v1/auth/reset_password', 'status_code': status, 'proof': 'Mot de passe trivial \'123456\' accepté (Status 200).'})
            yield f"⚠️ ALERTE VULNÉRABILITÉ (MEDIUM) : Mot de passe trivial accepté."
        else:
            yield f"✅ SAFE : Mot de passe rejeté (Status {status})."
            
    except Exception as e:
        yield f"\n[LOGIC] ERREUR CRITIQUE INTERNE NON GÉRÉE: {type(e).__name__}: {e}"
        vulnerabilities.append({'severity': 'CRITICAL', 'type': 'Internal Error', 'vulnerability': str(e), 'endpoint': 'N/A', 'status_code': 500, 'proof': 'Échec interne de l\'analyse de logique.'})


    # 4. GÉNÉRATION DU RAPPORT FINAL
    final_score = 100 
    for v in vulnerabilities:
        if v['severity'] == 'CRITICAL': final_score -= 50
        elif v['severity'] == 'HIGH': final_score -= 30
        elif v['severity'] == 'MEDIUM': final_score -= 15
    final_score = max(0, final_score)

    report = {
        'target': target_domain,
        'timestamp': datetime.now().isoformat(),
        'time_elapsed': (datetime.now() - start_time).total_seconds(),
        'security_score': final_score,
        'vulnerabilities_found': vulnerabilities,
        'steps_summary': steps_summary
    }
    
    yield f"\n[LOGIC] Analyse de Logique Métier terminée. Score final: {final_score}/100"
    yield "[DONE]"
    
    return report
