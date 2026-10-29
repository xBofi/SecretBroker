<#
.SYNOPSIS
    Updates the installed SecretBroker in place with the code in this working copy, keeping the
    vault, the service account and the Windows Hello unlock. Asks for administrator once (UAC).

    Default: copies the secretbroker package over the installed one and restarts the service
             and the app (a few seconds). Enough while only the Python code changes.
    -Full:   builds the installer and runs it silently on top. Use it when dependencies or the
             files in installer\ changed.
#>
param(
    [switch]$Full,
    [switch]$Elevated
)

$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
. (Join-Path $root "installer\common.ps1")
$sitePackages = Join-Path $InstallDir "python\Lib\site-packages"
$log = Join-Path $env:TEMP "secretbroker-update.log"

function Invoke-ElevatedCopy {
    Start-Transcript -Path $log -Force | Out-Null
    try {
        Write-Step "Parando el servicio y la app"
        Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        Stop-SecretBrokerProcesses $InstallDir
        Start-Sleep -Seconds 1

        Write-Step "Copiando el código"
        $target = Join-Path $sitePackages "secretbroker"
        Remove-Item $target -Recurse -Force
        Invoke-Native { robocopy (Join-Path $root "secretbroker") $target /E /NFL /NDL /NJH /NJS /NP /XD "__pycache__" /XF "*.pyc" } | Out-Null
        if ($LASTEXITCODE -ge 8) { throw "robocopy falló ($LASTEXITCODE)" }
        Invoke-Native { & $Python -I -m compileall -q $target } | Out-Null
        $check = Invoke-Native { & $Python -I -c "import secretbroker.app, secretbroker.service, secretbroker.mcp_server; print('ok')" }
        if ("$check" -notmatch "ok") { throw "El código nuevo no arranca (¿dependencias nuevas? usa -Full): $check" }
        $version = (Invoke-Native { & $Python -I -c "import secretbroker; print(secretbroker.__version__)" }).Trim()
        $uninstallKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{6B0F2E8A-4C1D-4E7B-9A35-5D2C8F1E7A90}_is1"
        if (Test-Path $uninstallKey) { Set-ItemProperty $uninstallKey -Name DisplayVersion -Value $version }

        Write-Step "Arrancando el servicio $version"
        Remove-Item (Join-Path $DataRoot "public\broker.json") -ErrorAction SilentlyContinue
        Start-ScheduledTask -TaskName $TaskName
        for ($i = 0; $i -lt 40; $i++) {
            Start-Sleep -Milliseconds 750
            $out = Invoke-Native { & $Python -I -c "from secretbroker import client; print('UP' if client.is_running() else 'DOWN')" }
            if ("$out" -match "UP") { return }
        }
        throw "El servicio no ha arrancado."
    } finally {
        Stop-Transcript | Out-Null
    }
}

if ($Elevated) {
    Invoke-ElevatedCopy
    exit 0
}

if (-not (Test-Path $Python)) { throw "SecretBroker no está instalado: usa el instalador la primera vez." }

if ($Full) {
    & (Join-Path $PSScriptRoot "build_installer.ps1")
    $version = (& (Join-Path $root ".venv\Scripts\python.exe") -c "import tomllib; print(tomllib.load(open(r'$root\pyproject.toml','rb'))['project']['version'])").Trim()
    $setup = Join-Path $root "dist\SecretBroker-Setup-$version.exe"
    Write-Step "Instalando $version encima de la versión actual"
    $process = Start-Process $setup -ArgumentList "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART" -Verb RunAs -Wait -PassThru
    if ($process.ExitCode -ne 0) { throw "El instalador terminó con el código $($process.ExitCode)." }
} else {
    $process = Start-Process powershell.exe -Verb RunAs -Wait -PassThru -WindowStyle Hidden -ArgumentList `
        "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$PSCommandPath`"", "-Elevated"
    if ($process.ExitCode -ne 0) { Get-Content $log -Tail 20 | Write-Host; throw "La actualización falló (registro: $log)." }
}

# The app runs as you, never elevated.
Start-Process $PythonW -ArgumentList "-I", "-m", "secretbroker.app" -WorkingDirectory $InstallDir
Write-Host "`nSecretBroker actualizado." -ForegroundColor Green
