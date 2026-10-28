<#
.SYNOPSIS
    System configuration run (elevated) by the SecretBroker setup program.

    -Owner / -OwnerAppData   install: create the service account, protect the data folder,
                             import an existing vault and start the service.
    -Uninstall [-RemoveData] uninstall: disconnect Claude and delete preferences for the owner,
                             stop and remove the service and its account.
#>
param(
    [string]$Owner,
    [string]$OwnerAppData,
    [switch]$Uninstall,
    [switch]$RemoveData
)

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "common.ps1")
$account = "$env:COMPUTERNAME\$ServiceUser"
$log = Join-Path $PSScriptRoot "configure.log"
Start-Transcript -Path $log -Force | Out-Null

function Remove-Service {
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    }
    Stop-SecretBrokerProcesses $InstallDir
    if (Get-LocalUser -Name $ServiceUser -ErrorAction SilentlyContinue) {
        [SecretBrokerLsa]::RemoveAll($account)
        Remove-LocalUser -Name $ServiceUser
    }
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList" -Name $ServiceUser -ErrorAction SilentlyContinue
}

# The uninstaller runs elevated, possibly as another account: find the owner's profile through the
# --owner argument of the service task, and clean up as if running in that profile.
function Remove-OwnerIntegrations {
    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if (-not $task -or $task.Actions[0].Arguments -notmatch '--owner "([^"]+)"') { Write-Host "Propietario desconocido."; return }
    $sid = (New-Object Security.Principal.NTAccount($Matches[1])).Translate([Security.Principal.SecurityIdentifier]).Value
    $profileDir = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid" -ErrorAction SilentlyContinue).ProfileImagePath
    if (-not $profileDir) { Write-Host "No se encontró el perfil de $($Matches[1])."; return }
    $env:USERPROFILE = $profileDir
    $env:APPDATA = Join-Path $profileDir "AppData\Roaming"
    $env:LOCALAPPDATA = Join-Path $profileDir "AppData\Local"
    Invoke-Native { & $Python -I -c "from secretbroker import integrations; integrations.remove_all()" } | Write-Host
}

try {
    if (-not (Test-Admin)) { throw "Hacen falta permisos de administrador." }

    if ($Uninstall) {
        Write-Step "Desconectando Claude y borrando preferencias"
        try { Remove-OwnerIntegrations } catch { Write-Host "AVISO: $($_.Exception.Message)" }
        Write-Step "Quitando el servicio"
        Remove-Service
        Remove-Item (Join-Path $DataRoot "public") -Recurse -Force -ErrorAction SilentlyContinue
        if ($RemoveData) { Remove-Item $DataRoot -Recurse -Force -ErrorAction SilentlyContinue }
        exit 0
    }

    # On an update the account and its task are kept: resetting the account password would make
    # Windows discard the account's DPAPI keys, and with them the "unlock with Windows" key.
    $upgrade = (Get-LocalUser -Name $ServiceUser -ErrorAction SilentlyContinue) -and (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)
    Write-Step "Cuenta de servicio '$ServiceUser' ($(if ($upgrade) { 'actualización' } else { 'nueva' }))"
    if (-not $upgrade) {
        if (Get-LocalUser -Name $ServiceUser -ErrorAction SilentlyContinue) { Remove-LocalUser -Name $ServiceUser }
        $bytes = New-Object byte[] 36
        [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
        $plainPassword = [Convert]::ToBase64String($bytes) + "aA1!"
        $securePassword = ConvertTo-SecureString $plainPassword -AsPlainText -Force
        New-LocalUser -Name $ServiceUser -Password $securePassword -PasswordNeverExpires -UserMayNotChangePassword `
            -AccountNeverExpires -Description "Cuenta de servicio de SecretBroker" | Out-Null
    }
    # Hidden from the sign-in screen; may run scheduled tasks; may not sign in or be used over the network.
    $hideKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList"
    New-Item -Path $hideKey -Force | Out-Null
    New-ItemProperty -Path $hideKey -Name $ServiceUser -Value 0 -PropertyType DWord -Force | Out-Null
    foreach ($right in "SeBatchLogonRight", "SeDenyInteractiveLogonRight", "SeDenyRemoteInteractiveLogonRight", "SeDenyNetworkLogonRight") {
        [SecretBrokerLsa]::Add($account, $right)
    }

    Write-Step "Carpeta de datos $DataRoot"
    if (Test-Path $DataRoot) {
        # Someone could have pre-created the folder: take it over before trusting it.
        Invoke-Native { takeown /F $DataRoot /R /A /D Y } | Out-Null
        Invoke-Native { icacls $DataRoot /reset /T /C /Q } | Out-Null
    }
    $dataDir = Join-Path $DataRoot "data"
    $publicDir = Join-Path $DataRoot "public"
    New-Item -ItemType Directory -Force $dataDir, $publicDir | Out-Null
    $acls = @(
        @($DataRoot, "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F", "${account}:RX", "*S-1-5-32-545:RX"),
        @($dataDir, "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F", "${account}:(OI)(CI)M"),
        @($publicDir, "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F", "${account}:(OI)(CI)M", "*S-1-5-32-545:(OI)(CI)RX")
    )
    foreach ($acl in $acls) {
        $path, $grants = $acl[0], $acl[1..($acl.Count - 1)]
        Invoke-Native { icacls $path /inheritance:r /grant:r @grants /Q } | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "No se pudieron fijar los permisos de $path" }
    }
    Invoke-Native { icacls $DataRoot /setowner "*S-1-5-32-544" /T /C /Q } | Out-Null

    Write-Step "Bóveda existente"
    if ($OwnerAppData -and -not (Test-Path (Join-Path $dataDir "vault.json"))) {
        $devRoot = Join-Path $OwnerAppData "SecretBroker"
        if (Test-Path (Join-Path $devRoot "data\vault.json")) {
            foreach ($name in "vault.json", "hello.json", "audit.log", "known_hosts") {
                $file = Join-Path $devRoot "data\$name"
                if (Test-Path $file) { Copy-Item $file (Join-Path $dataDir $name) }
            }
            Write-Host "Importada la bóveda de desarrollo."
        } elseif ((Test-Path (Join-Path $devRoot "vault.json")) -and -not (Test-Path (Join-Path $dataDir "legacy_vault.json"))) {
            Copy-Item (Join-Path $devRoot "vault.json") (Join-Path $dataDir "legacy_vault.json")
            Write-Host "Copiada la bóveda de la versión 0.1 para importarla."
        }
    }

    Write-Step "Servicio"
    if (-not $upgrade) {
        $arguments = "-I -m secretbroker.service --isolated --root `"$DataRoot`" --owner `"$Owner`""
        $action = New-ScheduledTaskAction -Execute $PythonW -Argument $arguments -WorkingDirectory $InstallDir
        $trigger = New-ScheduledTaskTrigger -AtStartup
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
            -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings `
            -User $account -Password $plainPassword -RunLevel Limited -Force | Out-Null
        $plainPassword = $null
    }
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Remove-Item (Join-Path $publicDir "broker.json") -ErrorAction SilentlyContinue
    Start-ScheduledTask -TaskName $TaskName

    $ok = $false
    for ($i = 0; $i -lt 40 -and -not $ok; $i++) {
        Start-Sleep -Milliseconds 750
        $out = Invoke-Native { & $Python -I -c "from secretbroker import client; print('UP' if client.is_running() else 'DOWN')" }
        if ("$out" -match "UP") { $ok = $true }
    }
    if (-not $ok) { throw "El servicio no ha arrancado." }
    Write-Host "Servicio activo."
    exit 0
} catch {
    Write-Host "ERROR: $($_.Exception.Message)"
    exit 1
} finally {
    Stop-Transcript | Out-Null
}
