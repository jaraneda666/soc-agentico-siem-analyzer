@echo off
chcp 65001 > nul
echo Iniciando SOC Agentico con Streamlit y Ollama local...
cd /d "%~dp0"
python -m streamlit run app.py
pause

