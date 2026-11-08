# SOC Agéntico: Analizador Forense de SIEM

Plataforma analítica interactiva para investigación de incidentes de seguridad e ingesta de telemetría SIEM en formato Excel (.xlsx). Ejecuta correlación heurística de eventos de Windows y Sysmon, integrando inferencia técnica local y exportación de informes en PDF.

---

## Arquitectura y Componentes

- **Interfaz:** Dashboard reactivo en Streamlit con métricas y distribución temporal de eventos.
- **Heurística:** Detección de Password Spraying (T1110.003), elevación de privilegios y tareas programadas (T1053.005).
- **Inferencia local:** Integración con motor Ollama en puerto 11434 para generación de dictámenes ejecutivos.
- **Generación documental:** Compilación de informes en PDF A4 mediante Playwright.

---

## Instrucciones de Uso

```powershell
# Lanzamiento de la aplicación web
python -m streamlit run app.py
```

---

## Consideraciones de Seguridad

- Este repositorio almacena código fuente, utilitarios de prueba y documentación técnica de ingeniería.
- Todas las credenciales, llaves privadas y variables de entorno deben suministrarse de forma local mediante archivos no versionados.
- Las herramientas de auditoría contenidas deben utilizarse exclusivamente en entornos autorizados y laboratorios de prueba.

---

**Autor:** Juan Carlos Araneda M.  
**Licencia:** MIT License (consulte [LICENSE](LICENSE))
