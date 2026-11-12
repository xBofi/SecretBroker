<#
.SYNOPSIS
    Builds dist\SecretBroker-Setup-<version>.exe: a private Python runtime with SecretBroker
    pre-installed (no internet needed on the target PC), packaged with Inno Setup.

    Requirements on the build machine: the project's .venv (Python 3.12) and Inno Setup 6
    (winget install JRSoftware.InnoSetup).
#>
$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
. (Join-Path $root "installer\common.ps1")

$venvPython = Join-Path $root ".venv\Scripts\python.exe"
$pythonHome = (& $venvPython -c "import sys; print(sys.base_prefix)").Trim()
$version = (& $venvPython -c "import tomllib; print(tomllib.load(open(r'$root\pyproject.toml','rb'))['project']['version'])").Trim()
$stage = Join-Path $root "build\stage"
$runtime = Join-Path $stage "python"
$iscc = @("$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe", "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $iscc) { throw "Inno Setup 6 no está instalado (winget install JRSoftware.InnoSetup)." }

Write-Step "Preparando Python $pythonHome"
if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
# Only what SecretBroker needs: no Tcl/Tk, IDLE, tests, docs, headers or the original site-packages.
Invoke-Native { robocopy $pythonHome $runtime /E /NFL /NDL /NJH /NJS /NP `
    /XD "site-packages" "Scripts" "Doc" "include" "libs" "tcl" "__pycache__" `
        (Join-Path $pythonHome "Lib\test") (Join-Path $pythonHome "Lib\idlelib") (Join-Path $pythonHome "Lib\tkinter") `
        (Join-Path $pythonHome "Lib\turtledemo") (Join-Path $pythonHome "Lib\ensurepip") (Join-Path $pythonHome "Tools") `
    /XF "_tkinter.pyd" "tcl86t.dll" "tk86t.dll" } | Out-Null
if ($LASTEXITCODE -ge 8) { throw "robocopy falló ($LASTEXITCODE)" }

Write-Step "Instalando SecretBroker $version y dependencias"
$sitePackages = Join-Path $runtime "Lib\site-packages"
# Every package from the hash-pinned locks (requirements\, tools\update_locks.py): the exact versions and files
# reviewed, nothing resolved from PyPI by name. The build backend (setuptools, requirements\build.txt) goes into
# the build venv and the builds run without isolation, so pip never fetches an unpinned one (for SecretBroker
# itself, and proxy-tools, which has no wheel).
$pipArgs = @("-m", "pip", "install", "--disable-pip-version-check", "--quiet", "--no-warn-script-location", "--no-cache-dir")
Invoke-Native { & $venvPython @pipArgs --require-hashes --no-deps -r (Join-Path $root "requirements\build.txt") } | Write-Host
if ($LASTEXITCODE -ne 0) { throw "pip install (build.txt) falló" }
Invoke-Native { & $venvPython @pipArgs --require-hashes --no-deps --no-build-isolation `
    --target $sitePackages -r (Join-Path $root "requirements\app.txt") } | Write-Host
if ($LASTEXITCODE -ne 0) { throw "pip install (app.txt) falló" }
Invoke-Native { & $venvPython @pipArgs --no-deps --no-build-isolation --no-index --upgrade --target $sitePackages $root } | Write-Host
if ($LASTEXITCODE -ne 0) { throw "pip install falló" }
Remove-Item (Join-Path $sitePackages "bin") -Recurse -Force -ErrorAction SilentlyContinue

Write-Step "Precompilando"
Invoke-Native { & (Join-Path $runtime "python.exe") -I -m compileall -q -j 0 $runtime } | Out-Null

Write-Step "Comprobando el runtime"
$check = Invoke-Native { & (Join-Path $runtime "python.exe") -I -c "import secretbroker.app, secretbroker.service, secretbroker.mcp_server, webview, winrt.windows.security.credentials, paramiko; print('ok')" }
if ("$check" -notmatch "ok") { throw "El runtime no funciona: $check" }

Write-Step "Compilando el instalador"
Invoke-Native { & $iscc "/DAppVersion=$version" "/Q" (Join-Path $root "installer\SecretBroker.iss") } | Write-Host
if ($LASTEXITCODE -ne 0) { throw "Inno Setup falló" }
$exe = Join-Path $root "dist\SecretBroker-Setup-$version.exe"
Write-Host ("`nListo: {0} ({1:N1} MB)" -f $exe, ((Get-Item $exe).Length / 1MB)) -ForegroundColor Green
