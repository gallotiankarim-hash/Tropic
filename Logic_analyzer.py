# Logic_analyzer.py (Partie à modifier : la fonction run_logic_analysis)

# ... (tous les imports et classes restent les mêmes) ...
# ... (toutes les fonctions de simulation restent les mêmes) ...

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
    # ... (Le code du workflow reste le même) ...
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

        # Étape 4: Test de Surcharge de Limite (Rate Limiting Abuse)
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
    
    # 💡 AJOUT DU BLOC TRY/EXCEPT POUR ASSURER LA GÉNÉRATION DU RAPPORT FINAL
    try:
        
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
        
    except Exception as e:
        # En cas d'erreur de code inattendue, le rapport sera incomplet, mais il sera renvoyé.
        yield f"\n[LOGIC] ERREUR CRITIQUE INTERNE NON GÉRÉE: {type(e).__name__}: {e}"
        vulnerabilities.append({'severity': 'CRITICAL', 'type': 'Internal Error', 'vulnerability': str(e), 'endpoint': 'N/A', 'status_code': 500, 'proof': 'Échec interne de l\'analyse de logique.'})


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
    
    # 5. Renvoyer le rapport final (ceci est capturé par l'exception StopIteration dans app.py)
    return report

