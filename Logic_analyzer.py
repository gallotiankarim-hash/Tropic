# Logic_analyzer.py

import time
import random
import json
from datetime import datetime
from typing import Dict, Any, List, Tuple

# ===============================================================================
#                             CLASSES DE MODÉLISATION ET D'ÉTAT
# ===============================================================================

class UserContext:
    """Modélise l'état d'un utilisateur durant le test (simule le navigateur)."""
    def __init__(self, username: str, is_admin: bool = False):
        self.username = username
        self.is_admin = is_admin
        self.session_id: str = f"SESSION_{random.randint(10000, 99999)}"
        self.user_db_id: str = str(random.randint(2000, 3000)) if not is_admin else "1" # L'admin a souvent l'ID 1 ou une valeur basse
        self.csrf_token: str = f"CSRF_{random.randint(10000, 99999)}"
        self.logged_in: bool = False
        self.last_status: int = 0

class LogicTestStep:
    """Définit une seule étape du workflow d'abus."""
    def __init__(self, name: str, endpoint: str, method: str, expected_status: int, abuse_payload: Dict[str, Any], fail_msg: str):
        self.name = name
        self.endpoint = endpoint
        self.method = method
        self.expected_status = expected_status
        self.abuse_payload = abuse_payload
        self.fail_msg = fail_msg
        self.is_vulnerable: bool = False
        self.response_status: int = 0
        self.response_snippet: str = ""

# ===============================================================================
#                             SIMULATION DES COMMUNICATIONS
# ===============================================================================

def _simulate_network_request(context: UserContext, step: LogicTestStep) -> Tuple[int, str]:
    """
    Simule une requête HTTP vers un endpoint, en appliquant le contexte de session.
    Retourne le statut HTTP simulé et un message de réponse.
    """
    time.sleep(0.05) # Simule le délai réseau
    
    # 1. Vérification d'Authentification / Session
    if not context.logged_in:
        return 401, "ERR: Non authentifié."

    # 2. Simulation de la vulnérabilité IDOR (Insecure Direct Object Reference)
    if step.name == "Abus IDOR: Tente de modifier le compte d'une autre victime":
        target_id = step.abuse_payload.get('target_user_id')
        
        # Le test IDOR est réussi (Status 200) si l'ID d'une autre victime peut être manipulé.
        if target_id != context.user_db_id and random.random() < 0.2: # 20% de chance de trouver une vulnérabilité (IDOR)
            context.last_status = 200
            step.is_vulnerable = True
            return 200, f"⚠️ SUCCESS: Données de l'utilisateur {target_id} modifiées. IDOR confirmé."
        
        # Sécurité correcte (Status 403)
        return 403, f"SAFE: Accès refusé à l'ID {target_id}. L'ID de session {context.user_db_id} ne correspond pas."

    # 3. Simulation de la vulnérabilité d'Escalade de Privilèges
    if step.name == "Escalade: Tente d'accéder à l'API Admin":
        if not context.is_admin and random.random() < 0.1: # 10% de chance d'escalade
            context.last_status = 200
            step.is_vulnerable = True
            return 200, "⚠️ SUCCESS: Endpoint Admin accessible en tant qu'utilisateur standard."
        
        # Sécurité correcte (Status 403)
        return 403, "SAFE: Accès Admin refusé. Privilèges insuffisants."

    # 4. Simulation de la vulnérabilité de Surcharge de Limite (Rate Limiting Abuse)
    if step.name == "Abus de limite: Tente d'envoyer 100 requêtes en 1s":
        if random.random() < 0.15: # 15% de chance de faille de limite
            context.last_status = 200
            step.is_vulnerable = True
            return 200, "⚠️ SUCCESS: 100 inscriptions sans blocage (Absence de Rate Limiting)."
        
        # Sécurité correcte (Status 429 - Too Many Requests)
        return 429, "SAFE: Limite de débit atteinte. Requête bloquée (429)."


    # Par défaut, succès de l'étape sans abus
    return step.expected_status, "Simulation réseau réussie.", False

# ===============================================================================
#                          FONCTION D'EXÉCUTION PRINCIPALE
# ===============================================================================

def run_logic_analysis(target_domain: str, config: Dict[str, Any]):
    """
    Exécute le moteur d'analyse de logique métier en simulant un workflow.
    Utilise un générateur pour le logging en temps réel.
    """
    start_time = datetime.now()
    vulnerabilities: List[Dict[str, Any]] = []
    
    # 1. INITIALISATION DES CONTEXTES ET DU SCÉNARIO
    attacker_context = UserContext("Attaquant", is_admin=False)
    victim_user_id = "5005" # ID arbitraire d'un utilisateur cible

    # Définition du workflow de test (longue structure)
    workflow: List[LogicTestStep] = [
        # Étape 1: Connexion de l'attaquant (Préparation)
        LogicTestStep(
            name="Connexion de l'attaquant au compte standard",
            endpoint="/api/v1/auth/login", method="POST", expected_status=200,
            abuse_payload={"username": "attacker", "password": "password"},
            fail_msg="Échec de la connexion. Impossible de continuer les tests d'abus."
        ),
        
        # Étape 2: Tentative IDOR (IDOR sur les données de la victime)
        LogicTestStep(
            name="Abus IDOR: Tente de modifier le compte d'une autre victime",
            endpoint="/api/v1/profile/update", method="POST", expected_status=403,
            abuse_payload={"target_user_id": victim_user_id, "new_email": "idor_abuse@tropic.com"},
            fail_msg="L'application autorise la modification des données d'un autre utilisateur."
        ),
        
        # Étape 3: Tentative d'Escalade de Privilèges (Escalade de l'utilisateur standard vers Admin)
        LogicTestStep(
            name="Escalade: Tente d'accéder à l'API Admin",
            endpoint="/api/v1/admin/dashboard_info", method="GET", expected_status=403,
            abuse_payload={},
            fail_msg="L'application permet d'accéder aux données d'administration."
        ),

        # Étape 4: Test de Surcharge de Limite (Abus sur la création de ressources)
        LogicTestStep(
            name="Abus de limite: Tente d'envoyer 100 requêtes en 1s",
            endpoint="/api/v1/post/create", method="POST", expected_status=429, # On ESPÈRE 429
            abuse_payload={"loop_count": 100},
            fail_msg="Le serveur n'a pas limité le débit des requêtes (Rate Limiting absent)."
        ),

        # Étape 5: Faible Complexité de Mot de Passe (Simulation de brute-force)
        LogicTestStep(
            name="Test de complexité: Tente de réinitialiser le mot de passe avec '123456'",
            endpoint="/api/v1/auth/reset_password", method="POST", expected_status=400, # On ESPÈRE un 400 (mot de passe faible)
            abuse_payload={"new_password": "123456"},
            fail_msg="Le serveur a accepté un mot de passe trivial ('123456')."
        ),
    ]

    yield "[LOGIC] Démarrage du moteur d'analyse de logique métier (5 étapes)..."
    yield f"[LOGIC] Cible : {target_domain}"
    
    # 2. BOUCLE PRINCIPALE D'EXÉCUTION DU WORKFLOW
    
    for i, step in enumerate(workflow):
        yield f"\n--- ÉTAPE {i+1}/{len(workflow)} : {step.name} ---"
        
        # Logique spécifique de connexion
        if i == 0:
            attacker_context.logged_in = True # Simulation de succès pour l'étape 1
            response_status, msg = 200, "Connexion simulée réussie (État établi)."
        else:
            response_status, msg = _simulate_network_request(attacker_context, step)

        step.response_status = response_status
        step.response_snippet = msg
        
        # 3. ANALYSE DES RÉSULTATS
        
        # Détection d'une vulnérabilité (réponse 200 ou un statut inattendu pour un abus)
        if step.is_vulnerable or (step.name.startswith("Abus IDOR") and response_status == 200):
            
            severity = "CRITICAL" if response_status == 200 else "HIGH"
            
            vulnerability_entry = {
                'severity': severity,
                'type': 'Business Logic Flaw',
                'vulnerability': step.name,
                'endpoint': step.endpoint,
                'status_code': response_status,
                'proof': msg 
            }
            vulnerabilities.append(vulnerability_entry)
            yield f"🚨 ALERTE VULNÉRABILITÉ ({severity}) : {msg}"
            
        elif response_status == step.expected_status:
            yield f"✅ SAFE : Le serveur a répondu {response_status} comme attendu."
        else:
             # Si l'attente est 429 (limite), mais on a autre chose, c'est peut-être une faille
            if step.expected_status == 429 and response_status != 429:
                vulnerability_entry = {
                    'severity': 'MEDIUM',
                    'type': 'Rate Limiting Abuse',
                    'vulnerability': step.name,
                    'endpoint': step.endpoint,
                    'status_code': response_status,
                    'proof': "La limite de débit n'a pas été appliquée (statut inattendu)."
                }
                vulnerabilities.append(vulnerability_entry)
                yield f"⚠️ ALERTE (MEDIUM) : {step.fail_msg} Réponse : {response_status}"
            else:
                yield f"❗ AVERTISSEMENT : Statut inattendu {response_status} (Attendu {step.expected_status})."


    # 4. GÉNÉRATION DU RAPPORT FINAL
    
    final_score = 100 - (len([v for v in vulnerabilities if v['severity'] == 'CRITICAL']) * 50) 
    final_score -= (len([v for v in vulnerabilities if v['severity'] == 'HIGH']) * 30)
    final_score -= (len([v for v in vulnerabilities if v['severity'] == 'MEDIUM']) * 15)
    final_score = max(0, final_score)

    report = {
        'target': target_domain,
        'timestamp': datetime.now().isoformat(),
        'time_elapsed': (datetime.now() - start_time).total_seconds(),
        'security_score': final_score,
        'vulnerabilities_found': vulnerabilities,
        'steps_summary': [{'name': s.name, 'status': s.response_status, 'vulnerable': s.is_vulnerable} for s in workflow]
    }
    
    yield f"\n[LOGIC] Analyse de Logique Métier terminée. Score final: {final_score}/100"
    yield "[DONE]"
    
    # 5. Renvoyer le rapport final (sera capturé par le générateur après [DONE])
    return report

