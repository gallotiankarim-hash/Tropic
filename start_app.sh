#!/bin/bash

# Script de lancement robuste pour Code Spaces

echo "Starting TROPIC app robustly..."

# 1. Tenter de tuer tout processus utilisant le port 8501 (mitige l'erreur CRITICAL ERROR: Port 8501 is already in use)
echo "Checking for existing processes on port 8501..."
PID=$(lsof -t -i:8501)
if [ ! -z "$PID" ]; then
    echo "Found process $PID on port 8501. Killing it..."
    kill -9 $PID
    sleep 2 # Laisse le temps au système de libérer le port
    echo "Port 8501 is now free."
else
    echo "Port 8501 is free."
fi

# 2. Lancer l'application Streamlit de manière fiable
echo "Launching Streamlit TROPIC app..."
# Utilisation de la méthode 'python -m streamlit' pour garantir le bon PATH
exec python -m streamlit run app.py --server.port 8501 --server.address 0.0.0.0
