# Lanzador robusto de la aplicación Streamlit de SOC Agéntico
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   SOC Agéntico | Analizador Forense de SIEM con IA Local   " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

Set-Location -Path $PSScriptRoot

# 1. Limpieza de procesos huérfanos previos de Streamlit
Write-Host "[1/3] Verificando instancias previas de Streamlit..." -ForegroundColor Yellow
$oldProcs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object { 
    $_.CommandLine -like "*streamlit run app.py*" 
}
if ($oldProcs) {
    foreach ($p in $oldProcs) {
        Write-Host "  -> Finalizando proceso previo PID $($p.ProcessId)..." -ForegroundColor DarkGray
        Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
    }
    Start-Sleep -Milliseconds 800
}

# 2. Verificar y levantar el servicio de Ollama automáticamente
Write-Host "[2/3] Verificando servicio de Ollama..." -ForegroundColor Yellow
$ollamaEndpoints = @("http://127.0.0.1:1143", "http://127.0.0.1:11434")
$ollamaOnline = $false
$activeEndpoint = ""

foreach ($ep in $ollamaEndpoints) {
    try {
        $res = Invoke-RestMethod -Uri "$ep/api/tags" -Method Get -TimeoutSec 2 -ErrorAction Stop
        if ($res -and $res.models) {
            $ollamaOnline = $true
            $activeEndpoint = $ep
            break
        }
    } catch { }
}

if (-not $ollamaOnline) {
    Write-Host "  -> Ollama no responde. Iniciando 'ollama serve' automáticamente..." -ForegroundColor Magenta
    $ollamaExe = "C:\Users\Developer\AppData\Local\Programs\Ollama\ollama.exe"
    if (Test-Path $ollamaExe) {
        Start-Process -FilePath $ollamaExe -ArgumentList "serve" -WindowStyle Hidden
    } else {
        Start-Process -FilePath "ollama" -ArgumentList "serve" -WindowStyle Hidden -ErrorAction SilentlyContinue
    }

    # Esperar hasta 8 segundos a que responda
    for ($i = 0; $i -lt 8; $i++) {
        Start-Sleep -Seconds 1
        foreach ($ep in $ollamaEndpoints) {
            try {
                $res = Invoke-RestMethod -Uri "$ep/api/tags" -Method Get -TimeoutSec 1 -ErrorAction Stop
                if ($res -and $res.models) {
                    $ollamaOnline = $true
                    $activeEndpoint = $ep
                    break
                }
            } catch { }
        }
        if ($ollamaOnline) { break }
    }
}

if ($ollamaOnline) {
    Write-Host "  [OK] Ollama activo y respondiendo en $activeEndpoint" -ForegroundColor Green
} else {
    Write-Host "  [WARN] Ollama no respondió en los endpoints candidatos. Iniciando Streamlit..." -ForegroundColor DarkYellow
}

# 3. Lanzar Streamlit
Write-Host "[3/3] Lanzando interfaz web Streamlit..." -ForegroundColor Cyan
python -m streamlit run app.py
