import os
import sys
from pathlib import Path
from datetime import datetime
import json
import importlib
import pandas as pd
import streamlit as st

# Agregar directorio tools al path
tools_dir = Path(__file__).parent / "tools"
sys.path.append(str(tools_dir))

import soc_log_agent
importlib.reload(soc_log_agent)
from soc_log_agent import SIEMLogAnalyzer, OllamaClient, generate_sample_siem_dataset

import anti_slop
importlib.reload(anti_slop)
from anti_slop import get_anti_slop_prompt_directive, audit_slop, sanitize_anti_slop

# Configuración de Streamlit
st.set_page_config(
    page_title="SOC Agéntico | Analizador Forense de SIEM con IA Local",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Estilos CSS Profesionales
st.markdown("""
<style>
    .main-header {
        background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
        border-bottom: 2px solid #0284c7;
        padding: 20px 24px;
        border-radius: 8px;
        margin-bottom: 24px;
        color: #f8fafc;
    }
    .main-header h1 {
        margin: 0;
        font-size: 26px;
        font-weight: 800;
        color: #f8fafc;
    }
    .main-header p {
        margin: 4px 0 0 0;
        font-size: 14px;
        color: #94a3b8;
    }
    .metric-card {
        background-color: #1e293b;
        border: 1px solid #334155;
        border-radius: 8px;
        padding: 16px;
        text-align: center;
        color: #f8fafc;
    }
    .metric-num {
        font-size: 32px;
        font-weight: 800;
        margin: 6px 0;
    }
    .metric-label {
        font-size: 13px;
        color: #94a3b8;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }
    .badge-critico {
        background-color: #ef4444;
        color: white;
        padding: 3px 8px;
        border-radius: 4px;
        font-weight: 700;
        font-size: 11px;
    }
    .badge-alto {
        background-color: #f97316;
        color: white;
        padding: 3px 8px;
        border-radius: 4px;
        font-weight: 700;
        font-size: 11px;
    }
    .badge-medio {
        background-color: #eab308;
        color: black;
        padding: 3px 8px;
        border-radius: 4px;
        font-weight: 700;
        font-size: 11px;
    }
    .badge-bajo {
        background-color: #10b981;
        color: white;
        padding: 3px 8px;
        border-radius: 4px;
        font-weight: 700;
        font-size: 11px;
    }
</style>
""", unsafe_allow_html=True)

# Inicializar sesión
if "df_logs" not in st.session_state:
    st.session_state.df_logs = None
if "anomalies" not in st.session_state:
    st.session_state.anomalies = []
if "executive_summary" not in st.session_state:
    st.session_state.executive_summary = ""
if "technical_summary" not in st.session_state:
    st.session_state.technical_summary = ""
if "chat_history" not in st.session_state:
    st.session_state.chat_history = []

ollama = OllamaClient()
ollama_ok, available_models = ollama.check_health()

# SIDEBAR
with st.sidebar:
    st.markdown("### 🏢 Consultoría CTI")
    st.caption("Firma de Ciberseguridad • Estocolmo, Suecia")
    st.markdown("---")
    
    st.markdown("#### 🤖 Estado de IA Local")
    if ollama_ok:
        st.success(f"Ollama Conectado ({len(available_models)} modelos)")
        default_idx = 0
        for pref in ["llama3.2:latest", "llama3.1:8b-instruct-q4_K_M", "qwen2.5-coder:7b"]:
            if pref in available_models:
                default_idx = available_models.index(pref)
                break
        selected_model = st.selectbox("Modelo Ollama:", available_models, index=default_idx)
        if "deepseek-r1" in selected_model:
            st.caption("ℹ️ *DeepSeek-R1 incluye cadena de razonamiento y puede tardar más en responder.*")
    else:
        st.error(f"Ollama Desconectado ({ollama.base_url})")
        selected_model = "llama3.2:latest"
        st.caption("Asegúrese de tener el servicio `ollama serve` activo.")
        if st.button("▶️ Levantar Ollama", use_container_width=True):
            with st.spinner("Iniciando Ollama en segundo plano..."):
                ollama.start_service()
                st.rerun()

    st.markdown("---")
    st.markdown("#### 📂 Ingesta de Logs SIEM")
    
    # 1. Cargar archivo oficial del cliente de Estocolmo
    official_file_path = Path(__file__).parent / "referencias" / "SOC_L2_Logs_Ampliados_Multiples_Incidentes.xlsx"
    if official_file_path.exists():
        if st.button("🎯 Cargar Logs Oficiales (Cliente Estocolmo)", type="primary", use_container_width=True):
            with st.spinner("Analizando archivo oficial de logs SIEM..."):
                analyzer = SIEMLogAnalyzer(official_file_path)
                st.session_state.df_logs = analyzer.df
                st.session_state.anomalies = analyzer.run_heuristic_analysis()
                st.success(f"Archivo oficial cargado: {len(st.session_state.df_logs)} logs procesados.")

    # 2. Botón de carga de muestra sintética
    sample_file_path = Path(__file__).parent / "referencias" / "dataset_siem_muestra.xlsx"
    if st.button("📥 Cargar Dataset de Muestra Sintético", use_container_width=True):
        if not sample_file_path.exists():
            with st.spinner("Generando dataset sintético..."):
                generate_sample_siem_dataset(sample_file_path, total_rows=2500)
        
        with st.spinner("Analizando dataset sintético..."):
            analyzer = SIEMLogAnalyzer(sample_file_path)
            st.session_state.df_logs = analyzer.df
            st.session_state.anomalies = analyzer.run_heuristic_analysis()
            st.success(f"Dataset cargado con éxito: {len(st.session_state.df_logs)} registros.")

    # 3. Uploader interactivo
    uploaded_file = st.file_uploader("O arrastrar/subir archivo (.xlsx, .csv):", type=["xlsx", "xls", "csv"])
    if uploaded_file is not None:
        try:
            with st.spinner("Procesando archivo subido..."):
                analyzer = SIEMLogAnalyzer(uploaded_file)
                st.session_state.df_logs = analyzer.df
                st.session_state.anomalies = analyzer.run_heuristic_analysis()
                st.success(f"Archivo cargado: {len(st.session_state.df_logs)} registros procesados.")
        except Exception as e:
            st.error(f"Error al procesar archivo: {e}")

    st.markdown("---")
    st.markdown("👨‍💻 **Analista SOC Nivel 2:** Security Analyst")
    st.caption("Bootcamp Analista SOC L2 • Comunidad Dojo")


# ENCABEZADO PRINCIPAL
st.markdown("""
<div class="main-header">
    <div style="display: flex; justify-content: space-between; align-items: center;">
        <div>
            <h1>🛡️ SOC Agéntico — Analizador Forense de SIEM</h1>
            <p>Plataforma interactiva de detección de anomalías, correlación MITRE ATT&CK e inferencia con IA local en Ollama</p>
        </div>
        <div style="text-align: right;">
            <span style="background: #0284c7; color: white; padding: 4px 10px; border-radius: 4px; font-size: 12px; font-weight: 700;">TIER 2 SOC ANALYST</span>
        </div>
    </div>
</div>
""", unsafe_allow_html=True)

if st.session_state.df_logs is None:
    st.info("👋 **Bienvenido al Analizador de Incidentes de SOC.** Utiliza la barra lateral para cargar el **Dataset de Muestra** con ataques inyectados o sube el archivo de logs oficial en formato Excel (`.xlsx`).")
    st.stop()

# TABS PRINCIPALES
tab_dash, tab_matrix, tab_ai, tab_pdf = st.tabs([
    "📊 Dashboard Ejecutivo",
    "🔍 Matriz de Anomalías e IoCs",
    "🤖 Agente de CTI (Ollama)",
    "📑 Generador de Informes PDF"
])

# TAB 1: DASHBOARD EJECUTIVO
with tab_dash:
    df = st.session_state.df_logs
    anomalies = st.session_state.anomalies

    # Métricas
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-label">Total de Eventos</div>
            <div class="metric-num" style="color: #38bdf8;">{len(df):,}</div>
            <div style="font-size: 12px; color: #94a3b8;">Logs procesados</div>
        </div>
        """, unsafe_allow_html=True)
    with col2:
        crit_count = sum(1 for a in anomalies if a["severidad"] in ["Crítico", "Alto"])
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-label">Alertas Críticas / Altas</div>
            <div class="metric-num" style="color: #ef4444;">{crit_count}</div>
            <div style="font-size: 12px; color: #f87171;">Requieren contención</div>
        </div>
        """, unsafe_allow_html=True)
    with col3:
        unique_ips = len(set(a["ip_origen"] for a in anomalies if a["ip_origen"] not in ["Local", "Host Local"]))
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-label">IPs Atacantes Únicas</div>
            <div class="metric-num" style="color: #f59e0b;">{unique_ips}</div>
            <div style="font-size: 12px; color: #fbbf24;">Vectores de origen</div>
        </div>
        """, unsafe_allow_html=True)
    with col4:
        all_targets = set()
        for a in anomalies:
            for u in a["usuarios_afectados"]:
                if u:
                    all_targets.add(u)
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-label">Cuentas Comprometidas / Foco</div>
            <div class="metric-num" style="color: #10b981;">{len(all_targets)}</div>
            <div style="font-size: 12px; color: #34d399;">Usuarios bajo ataque</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # Gráficos
    gcol1, gcol2 = st.columns([3, 2])
    with gcol1:
        st.markdown("##### 📈 Distribución Temporal de Eventos de Seguridad")
        if "timestamp" in df.columns and pd.api.types.is_datetime64_any_dtype(df["timestamp"]):
            timeline_df = df.set_index("timestamp").resample("1h").count()["event_id"].reset_index()
            timeline_df.columns = ["Hora", "Volumen de Eventos"]
            st.line_chart(timeline_df, x="Hora", y="Volumen de Eventos", color="#0284c7")
        else:
            st.caption("No se detectó columna temporal continua para renderizar línea de tiempo.")

    with gcol2:
        st.markdown("##### 🎯 Tácticas y Técnicas MITRE ATT&CK")
        mitre_data = {}
        for a in anomalies:
            m = f"{a['mitre_id']} - {a['mitre_name'][:25]}"
            mitre_data[m] = mitre_data.get(m, 0) + 1
        
        if mitre_data:
            mitre_df = pd.DataFrame(list(mitre_data.items()), columns=["Técnica MITRE", "Ocurrencias"]).sort_values(by="Ocurrencias", ascending=False)
            st.bar_chart(mitre_df, x="Técnica MITRE", y="Ocurrencias", color="#ef4444")
        else:
            st.caption("Sin técnicas MITRE ATT&CK identificadas.")

# TAB 2: MATRIZ FORENSE
with tab_matrix:
    st.markdown("### 🔍 Matriz Consolidada de Hallazgos Forenses")
    st.caption("Anomalías detectadas mediante reglas heurísticas de correlación de SOC Tier 2:")
    
    if anomalies:
        table_rows = []
        for i, a in enumerate(anomalies, 1):
            table_rows.append({
                "#": i,
                "Severidad": a["severidad"],
                "Tipo de Ataque": a["tipo"],
                "Técnica MITRE": f"{a['mitre_id']} ({a['mitre_name']})",
                "IP Origen": a["ip_origen"],
                "Cuentas Afectadas": ", ".join(a["usuarios_afectados"]) if a["usuarios_afectados"] else "N/A",
                "Event ID": a["event_id"],
                "Descripción": a["descripcion"]
            })
        
        df_anomalies = pd.DataFrame(table_rows)
        
        # Filtro de severidad
        sev_filter = st.multiselect("Filtrar por Severidad:", ["Crítico", "Alto", "Medio", "Bajo"], default=["Crítico", "Alto", "Medio"])
        if sev_filter:
            df_filtered = df_anomalies[df_anomalies["Severidad"].isin(sev_filter)]
        else:
            df_filtered = df_anomalies

        st.dataframe(df_filtered, use_container_width=True, hide_index=True)
    else:
        st.success("No se encontraron anomalías o amenazas en el conjunto de logs evaluado.")

def _compact_anomalies(items, max_n=10):
    res = []
    for a in items[:max_n]:
        entry = {
            "tipo": a.get("tipo"),
            "severidad": a.get("severidad"),
            "mitre": f"{a.get('mitre_id', '')} ({a.get('mitre_name', '')})",
            "ip_origen": a.get("ip_origen"),
            "usuarios": a.get("usuarios_afectados"),
            "descripcion": a.get("descripcion", "")
        }
        if a.get("comando"):
            entry["comando"] = a["comando"]
        res.append(entry)
    return json.dumps(res, indent=2, ensure_ascii=False)

# TAB 3: AGENTE DE CTI (OLLAMA)
with tab_ai:
    st.markdown("### 🤖 Agente de Inteligencia Artificial & CTI (Ollama Local)")
    st.caption(f"Motor activo: `{selected_model}` • Endpoint: `{ollama.base_url}`")

    if not ollama_ok:
        col_warn, col_act = st.columns([3, 1])
        with col_warn:
            st.warning(f"⚠️ El servicio de Ollama no responde en `{ollama.base_url}`.")
        with col_act:
            if st.button("▶️ Iniciar Ollama Ahora", type="primary", use_container_width=True):
                with st.spinner("Iniciando Ollama en segundo plano..."):
                    ollama.start_service()
                    st.rerun()

    col_btn1, col_btn2 = st.columns(2)
    with col_btn1:
        if st.button("🚀 Generar Resumen Ejecutivo con IA (Para Directores)", use_container_width=True, disabled=not ollama_ok):
            prompt = f"""
            Eres un Analista Senior de Ciberseguridad de una firma consultora en Estocolmo.
            Analiza las siguientes anomalías detectadas en los logs corporativos:
            {_compact_anomalies(anomalies, 8)}

            Genera un RESUMEN EJECUTIVO formal en español (3 párrafos), dirigido a la junta directiva y al CISO:
            1. Contexto general del incidente y cronología de la intrusión.
            2. Impacto potencial en el negocio (riesgo operacional, exposición de datos o interrupción).
            3. Conclusiones y nivel de riesgo general determinado.

            {get_anti_slop_prompt_directive()}
            """
            st.markdown("##### 👔 Redactando Resumen Ejecutivo...")
            with st.spinner("Generando análisis para el comité ejecutivo (filtro Anti-Slop activo)..."):
                res_text = st.write_stream(ollama.chat_stream(prompt, model=selected_model))
                clean_res, _ = sanitize_anti_slop(res_text)
                st.session_state.executive_summary = clean_res

    with col_btn2:
        if st.button("🔬 Generar Informe Técnico con IA (Para Ingenieros SOC)", use_container_width=True, disabled=not ollama_ok):
            prompt = f"""
            Eres un Analista Forense y de Threat Intelligence (SOC Nivel 2).
            Analiza las siguientes anomalías técnicas detectadas en los logs:
            {_compact_anomalies(anomalies, 10)}

            Genera un INFORME TÉCNICO DETALLADO en español para el equipo de seguridad e ingenieros de sistemas:
            1. Vectores de ataque utilizados y técnicas MITRE ATT&CK identificadas.
            2. Cadena de explotación (Fuerza bruta -> Acceso con cuenta legítima -> Reconocimiento/Living off the Land -> Persistencia).
            3. Matriz de Indicadores de Compromiso (IoCs) clave (IPs, cuentas, comandos).
            4. Plan de contención y remediación priorizado (SLAs inmediatos bajo NIST CSF).

            {get_anti_slop_prompt_directive()}
            """
            st.markdown("##### 🛠️ Redactando Informe Técnico...")
            with st.spinner("Compilando informe técnico detallado (filtro Anti-Slop activo)..."):
                res_text = st.write_stream(ollama.chat_stream(prompt, model=selected_model))
                clean_res, _ = sanitize_anti_slop(res_text)
                st.session_state.technical_summary = clean_res

    if st.session_state.executive_summary:
        st.markdown("#### 👔 Resumen Ejecutivo Consolidado")
        st.info(st.session_state.executive_summary)

    if st.session_state.technical_summary:
        st.markdown("#### 🛠️ Informe Técnico Detallado Consolidado")
        st.markdown(st.session_state.technical_summary)

    # Chat Interactivo con el Agente
    st.markdown("---")
    st.markdown("#### 💬 Consulta Interactiva al Agente Forense")
    user_q = st.text_input("Haz una pregunta específica sobre el incidente (ej. ¿Qué cuenta se usó para la persistencia?, ¿Cuáles son las IPs maliciosas?):")
    if st.button("Enviar Consulta", key="btn_chat") and user_q:
        if ollama_ok:
            chat_prompt = f"""
            Contexto de las anomalías detectadas en el SIEM:
            {_compact_anomalies(anomalies, 8)}

            Pregunta del analista: {user_q}
            Responde de forma concisa, precisa y basada estrictamente en los datos anteriores.
            """
            with st.spinner("Consultando al Agente de CTI..."):
                reply = st.write_stream(ollama.chat_stream(chat_prompt, model=selected_model))
                st.session_state.chat_history.append((user_q, reply))
        else:
            st.error("Ollama no está disponible.")

    for q, a in reversed(st.session_state.chat_history[-4:]):
        st.chat_message("user").write(q)
        st.chat_message("assistant").write(a)

# TAB 4: GENERADOR DE PDF
with tab_pdf:
    st.markdown("### 📑 Compilación y Descarga del Informe PDF Oficial")
    st.caption("Generación automática del documento para la entrega final a la consultora y evaluación de Comunidad Dojo:")

    # Métricas de estado de generación y filtro anti-slop
    col_st1, col_st2, col_st3, col_st4 = st.columns(4)
    with col_st1:
        st.markdown(f"**Resumen Ejecutivo:** {'✅ Listo' if st.session_state.executive_summary else '⚡ Pericial Auto'}")
    with col_st2:
        st.markdown(f"**Informe Técnico (3):** {'✅ Listo' if st.session_state.technical_summary else '⚡ Pericial Auto'}")
    with col_st3:
        st.markdown(f"**Anomalías Evaluadas:** `{len(anomalies)} eventos`")
    with col_st4:
        st.markdown("**Filtro Anti-IA:** 🛡️ `Activo (Anti-Slop)`")

    st.markdown("---")

    # Botón de compilación
    if st.button("📄 Compilar Informe Oficial en PDF", type="primary", use_container_width=True):
        output_dir = Path(__file__).parent / "output"
        output_dir.mkdir(parents=True, exist_ok=True)
        timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        pdf_filename = f"informe_soc_agentico_{timestamp_str}.pdf"
        pdf_path = output_dir / pdf_filename

        with st.spinner("Compilando informe en PDF con diseño pericial SOC Nivel 2..."):
            import report_styler
            import importlib
            importlib.reload(report_styler)
            from report_styler import build_pericial_pdf_html

            exec_txt = st.session_state.executive_summary
            tech_txt = st.session_state.technical_summary

            html_doc = build_pericial_pdf_html(
                anomalies=anomalies,
                df_logs=st.session_state.df_logs,
                exec_summary=exec_txt,
                tech_summary=tech_txt
            )

            # Render con Playwright
            from playwright.sync_api import sync_playwright
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                page = browser.new_page()
                page.set_content(html_doc)
                page.pdf(
                    path=str(pdf_path),
                    format="A4",
                    print_background=True,
                    display_header_footer=True,
                    header_template="<div></div>",
                    footer_template="""<div style="font-family: -apple-system, Segoe UI, Arial; font-size: 7.5pt; color: #64748b; width: 100%; padding: 0 14mm; display: flex; justify-content: space-between;"><span>SOC Agéntico • Análisis Forense de Incidentes SIEM (Security Analyst)</span><span>Página <span class="pageNumber"></span> de <span class="totalPages"></span></span></div>""",
                    margin={"top": "14mm", "bottom": "16mm", "left": "14mm", "right": "14mm"}
                )
                browser.close()

            st.success(f"Informe compilado exitosamente: `{pdf_filename}`")
            with open(pdf_path, "rb") as f:
                st.download_button(
                    label="⬇️ Descargar Informe PDF Oficial",
                    data=f.read(),
                    file_name=pdf_filename,
                    mime="application/pdf",
                    use_container_width=True
                )

