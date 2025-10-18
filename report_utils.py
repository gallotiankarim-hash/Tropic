# report_utils.py

import json
from datetime import datetime
import streamlit as st

def get_json_download_link(data, filename_prefix="report"):
    """
    Génère un lien de téléchargement Streamlit pour un dictionnaire Python encodé en JSON.
    """
    json_string = json.dumps(data, indent=4)
    # Encoder la chaîne JSON en bytes
    b64 = json_string.encode('utf-8')
    
    # Créer le nom de fichier
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{filename_prefix}_{timestamp}.json"
    
    return st.download_button(
        label="⬇️ Télécharger le Rapport JSON",
        data=b64,
        file_name=filename,
        mime='application/json',
        key=f"download_{filename_prefix}_{timestamp}" # Clé unique pour forcer le re-rendu
    )
