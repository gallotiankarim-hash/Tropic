<div align="center">
  <img src="https://raw.githubusercontent.com/gallotiankarim-hash/Tropic/ce9a0afef78a8cc702c561881b8c09978537c5e0/assets/IMG_3503.jpeg" alt="TROPIC Logo Cyber/Matrix" width="500"/>
  <h1>TROPIC :: Multi-Module Security Analyzer 🌴</h1>
  <p>Développé et maintenu par <b>Karim.</b></p>
  <p>Un outil de sécurité robuste et éthique, conçu pour les Hackers Éthiques et les professionnels de la cybersécurité.</p>
  <br>
  <a href="#fonctionnalités-clés">Fonctionnalités Clés</a> •
  <a href="#avertissement-red-flag">⚠️ Avertissement Red Flag</a> •
  <a href="#architecture-des-modules">Architecture des Modules</a> •
  <a href="#démarrage-rapide">🚀 Démarrage Rapide</a> •
  <a href="#console-de-diagnostic-actif-poc">💻 Console de Diagnostic Actif (PoC)</a> •
  <a href="#rapports-et-score-de-sécurité">📊 Rapports et Score</a> •
  <a href="#contribution">🤝 Contribution</a> •
  <a href="#licence">📄 Licence</a>
</div>

---

## ⚡️ Introduction

**TROPIC** est un système d'analyse de sécurité multi-modules conçu pour identifier et diagnostiquer les vulnérabilités au sein d'infrastructures web. Développé dans une optique de hacking éthique, TROPIC combine des phases de reconnaissance passive et active, d'analyse API/Headers, et une phase avancée de détection d'exploitabilité.

Son interface utilisateur, propulsée par Streamlit, offre une expérience intuitive pour lancer des scans, visualiser des rapports détaillés et interagir avec une **Console de Diagnostic Actif (PoC)** unique en son genre, tout en respectant un cadre éthique strict.

## ✨ Fonctionnalités Clés

* **Analyse Multi-Phases** : De la reconnaissance initiale à la détection d'exploit avancée.
* **Interface Intuitive** : Propulsée par Streamlit avec un thème cyberpunk distinctif.
* **Reconnaissance Active** : Découverte des sous-domaines, vérifications DNS et HTTP/S.
* **Analyse API/Headers** : Évaluation des en-têtes de sécurité, détection d'exposition d'API, tests d'injection (SQLi/XSS) et de réflexion de paramètres.
* **Détection de Vulnérabilités Avancée** : Identification de failles critiques comme la désérialisation.
* **Console de Diagnostic Actif (PoC)** : Un "shell" éthiquement contrôlé pour confirmer la vulnérabilité suite à une détection critique.
* **Rapports Détaillés** : Scores de sécurité, listes des vulnérabilités, recommandations de remédiation.
* **Post-Scan Executor** : Exécution de commandes systèmes personnalisées après les scans.

## ⚠️ Avertissement RED FLAG : Hacking Éthique - Vos Risques Engagés

L'utilisation de **TROPIC** est strictement réservée à des fins de sécurité éthique et de test sur des systèmes dont vous avez l'autorisation **explicite et écrite**.

* **La Console de Diagnostic Actif (PoC)** est fournie pour la **confirmation de vulnérabilités CRITIQUES détectées**. Elle simule l'exécution de commandes système pour valider l'existence d'une faille, **sans pour autant exploiter réellement le système**.
* Toute utilisation de TROPIC sur une cible sans consentement préalable et au-delà du simple test passif constitue une violation criminelle et engage votre **entière et unique responsabilité**.
* **Depiction is not Endorsement** : La capacité de TROPIC à diagnostiquer des vulnérabilités ne constitue en aucun cas une incitation ou une approbation d'activités illégales.

**En utilisant TROPIC, vous assumez pleinement les conséquences légales et éthiques de vos actions.**

## ⚙️ Architecture des Modules

TROPIC est structuré en plusieurs modules Python, chacun ayant une responsabilité distincte :

1.  **`app.py`** : L'interface utilisateur Streamlit principale. Gère le flux d'exécution, la configuration, l'affichage des rapports et la **Console de Diagnostic Actif**.
2.  **`Recon.py`** : Module de **Reconnaissance**. Découvre les sous-domaines, vérifie les résolutions DNS et les réponses HTTP/S avec des règles de timeout et des User-Agents professionnels.
3.  **`Api_scan.py`** : Module d'**Analyse API et Headers**. Évalue la robustesse des en-têtes de sécurité, effectue des fuzzing d'endpoints API, et réalise des tests d'injection actifs (SQLi, XSS, etc.) avec un système de scoring détaillé.
4.  **`Exploit_Adv.py`** : Module d'**Exploitation Avancée**. Détecte des vulnérabilités critiques (ex: désérialisation) et alimente la logique de la **Console de Diagnostic Actif (PoC)** pour la validation éthique des failles.

## 🚀 Démarrage Rapide

Suivez ces étapes pour lancer TROPIC dans votre environnement :

### Pré-requis

* Python 3.8+
* `pip` (gestionnaire de paquets Python)

### Installation

1.  **Cloner le dépôt GitHub :**
    ```bash
    git clone [https://github.com/gallotiankarim-hash/Tropic]
    cd Tropic
    ```
    
2.  **Installer les dépendances Python :**
    ```bash
    pip install -r requirements.txt
    ```
    *(**Note :** Vous devrez créer un fichier `requirements.txt` contenant : `streamlit`, `requests`, `pandas`)*

### Lancement de l'Application

1.  **Exécuter l'application Streamlit :**
    ```bash
    streamlit run app.py --server.port 8501 --server.address 0.0.0.0
    ```
2.  **Accéder à l'interface :**
    Ouvrez votre navigateur et naviguez vers l'URL affichée par Streamlit (généralement `http://localhost:8501` ou l'adresse fournie par votre Code Space).

## 💻 Console de Diagnostic Actif (PoC)

La console est votre interface pour interagir avec les vulnérabilités détectées.

* **Activation :** Elle devient "active" (permettant des réponses de diagnostic positives) **seulement si le Module 3 (Exploit_Adv.py) détecte une vulnérabilité critique de type RCE ou Désérialisation.**
* **Commandes Suggérées pour le Diagnostic :**
    * `id` : Vérifie les privilèges de l'utilisateur.
    * `whoami` : Confirme l'utilisateur courant.
    * `ls -la` : Liste le contenu du répertoire.
    * `cat /etc/passwd` : Accède à des fichiers sensibles (diagnostic d'accès en lecture).
    * Toute autre commande : TROPIC confirmera l'exécution de la commande de diagnostic.

## 📊 Rapports et Score de Sécurité

TROPIC génère des rapports détaillés dans le dossier `output/` :

* **Score de Sécurité (Module 2)** : Un score sur 100 basé sur la présence d'en-têtes de sécurité, l'exposition d'endpoints API et la détection d'injections.
* **Rapports JSON/TXT** : Contenant les sous-domaines actifs, les découvertes API, et les vulnérabilités identifiées avec des recommandations de remédiation.

## 🤝 Contribution

Nous encourageons les contributions à TROPIC, notamment pour l'ajout de nouvelles signatures de vulnérabilités, l'amélioration des modules de scan, ou l'optimisation de l'interface utilisateur.

Pour contribuer :

1.  Faites un "fork" du dépôt.
2.  Créez une nouvelle branche pour vos fonctionnalités (`git checkout -b feature/nouvelle-fonctionnalite`).
3.  Commitez vos changements (`git commit -m 'feat: Ajouter une nouvelle fonctionnalité'`).
4.  Poussez vers votre branche (`git push origin feature/nouvelle-fonctionnalite`).
5.  Ouvrez une Pull Request.

## 📄 Licence

Ce projet est sous licence MIT. Pour plus de détails, consultez le fichier `LICENSE`.

---

<div align="center">
  <p>Développé avec passion par Karim. <br> ⚡️ Gardez le code propre, la sécurité forte. ⚡️</p>
</div>
