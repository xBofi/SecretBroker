; SecretBroker setup program. Build it with tools\build_installer.ps1 (stages Python first).

#ifndef AppVersion
  #define AppVersion "0.16.0"
#endif
#define StageDir "..\build\stage"
#define AppIcon "{app}\python\Lib\site-packages\secretbroker\assets\icon.ico"

[Setup]
AppId={{6B0F2E8A-4C1D-4E7B-9A35-5D2C8F1E7A90}
AppName=SecretBroker
AppVersion={#AppVersion}
AppVerName=SecretBroker {#AppVersion}
AppPublisher=CXIOME
DefaultDirName={autopf}\SecretBroker
DisableDirPage=yes
DisableProgramGroupPage=yes
DisableReadyPage=yes
DisableWelcomePage=no
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.17763
OutputDir=..\dist
OutputBaseFilename=SecretBroker-Setup-{#AppVersion}
SetupIconFile=..\secretbroker\assets\icon.ico
UninstallDisplayIcon={#AppIcon}
UninstallDisplayName=SecretBroker
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
WizardSizePercent=100
CloseApplications=yes
; The language of Windows (Spanish or English, else English), without asking: one click to install.
ShowLanguageDialog=no
LanguageDetectionMethod=uilanguage
RestartApplications=no
ChangesEnvironment=yes

[Languages]
Name: "en"; MessagesFile: "compiler:Default.isl"
Name: "es"; MessagesFile: "compiler:Languages\Spanish.isl"

[Messages]
en.WelcomeLabel2=This will install [name/ver] on this computer.%n%nSecretBroker keeps your passwords and API keys encrypted and lets AI use them without being able to read them. It runs under a Windows account of its own so that no other program can reach them.
es.WelcomeLabel2=Se instalará [name/ver] en este equipo.%n%nSecretBroker guarda tus contraseñas y API keys cifradas y deja que la IA las use sin poder leerlas. Funciona con una cuenta de Windows propia para que ningún otro programa pueda acceder a ellas.

[CustomMessages]
en.DesktopIcon=Create a desktop shortcut
es.DesktopIcon=Crear un acceso directo en el escritorio
en.AppComment=Credential vault for your AI
es.AppComment=Bóveda de credenciales para tu IA
en.OpenApp=Open SecretBroker
es.OpenApp=Abrir SecretBroker
en.OwnerUnknown=Couldn't identify the user running the installation.
es.OwnerUnknown=No se pudo identificar al usuario que ejecuta la instalación.
en.ConfiguringService=Setting up the protected service…
es.ConfiguringService=Configurando el servicio protegido…
en.ServiceFailed=Couldn't set up the SecretBroker service.
es.ServiceFailed=No se pudo configurar el servicio de SecretBroker.
en.Details=Details:
es.Details=Detalles:
en.ConnectingClaude=Connecting to Claude…
es.ConnectingClaude=Conectando con Claude…
en.RemoveVault=Also delete the vault with all your credentials?%n%nIf you choose “Yes”, they will be lost for good and can't be recovered.%nIf you choose “No”, they are kept in %1 and will be available again if you reinstall SecretBroker.
es.RemoveVault=¿Borrar también la bóveda con todas tus credenciales?%n%nSi eliges «Sí», se perderán definitivamente y no se podrán recuperar.%nSi eliges «No», se conservan en %1 y volverán a estar disponibles si reinstalas SecretBroker.
en.RemoveFailed=Couldn't completely delete %1. You can remove the folder by hand.
es.RemoveFailed=No se pudo borrar por completo %1. Puedes eliminar la carpeta a mano.

[Tasks]
Name: "desktopicon"; Description: "{cm:DesktopIcon}"

[InstallDelete]
; A clean runtime on every install or update, so no stale packages are left behind.
Type: filesandordirs; Name: "{app}\python"
Type: filesandordirs; Name: "{app}\extension"

[Files]
Source: "{#StageDir}\python\*"; DestDir: "{app}\python"; Flags: recursesubdirs createallsubdirs ignoreversion
Source: "common.ps1"; DestDir: "{app}\setup"; Flags: ignoreversion
Source: "configure.ps1"; DestDir: "{app}\setup"; Flags: ignoreversion
Source: "sb.cmd"; DestDir: "{app}\bin"; Flags: ignoreversion
; The browser extension, loaded from here until it is in the browsers' stores (Ajustes › Navegador explains how).
Source: "..\extension\*"; DestDir: "{app}\extension"; Flags: recursesubdirs createallsubdirs ignoreversion

[Registry]
; `sb` (sb run -- npm run dev) from any terminal.
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Control\Session Manager\Environment"; ValueType: expandsz; ValueName: "Path"; ValueData: "{olddata};{app}\bin"; Check: NeedsAddPath(ExpandConstant('{app}\bin'))
; Team invite links (secretbroker://join?server=…&email=…&code=…) open the app with the team form filled in.
Root: HKLM; Subkey: "Software\Classes\secretbroker"; ValueType: string; ValueName: ""; ValueData: "URL:SecretBroker"; Flags: uninsdeletekey
Root: HKLM; Subkey: "Software\Classes\secretbroker"; ValueType: string; ValueName: "URL Protocol"; ValueData: ""
Root: HKLM; Subkey: "Software\Classes\secretbroker\DefaultIcon"; ValueType: string; ValueName: ""; ValueData: "{#AppIcon}"
Root: HKLM; Subkey: "Software\Classes\secretbroker\shell\open\command"; ValueType: string; ValueName: ""; ValueData: """{app}\python\pythonw.exe"" -I -m secretbroker.app ""%1"""

[Icons]
Name: "{autoprograms}\SecretBroker"; Filename: "{app}\python\pythonw.exe"; Parameters: "-I -m secretbroker.app"; WorkingDir: "{app}"; IconFilename: "{#AppIcon}"; Comment: "{cm:AppComment}"
Name: "{autodesktop}\SecretBroker"; Filename: "{app}\python\pythonw.exe"; Parameters: "-I -m secretbroker.app"; WorkingDir: "{app}"; IconFilename: "{#AppIcon}"; Tasks: desktopicon

[Run]
Filename: "{app}\python\pythonw.exe"; Parameters: "-I -m secretbroker.app"; Description: "{cm:OpenApp}"; Flags: postinstall nowait skipifsilent runasoriginaluser
; Updates started from the app run silently: reopen it when they finish.
Filename: "{app}\python\pythonw.exe"; Parameters: "-I -m secretbroker.app"; Flags: nowait runasoriginaluser; Check: WizardSilent

[UninstallRun]
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\setup\configure.ps1"" -Uninstall"; Flags: runhidden waituntilterminated; RunOnceId: "RemoveService"

[UninstallDelete]
Type: filesandordirs; Name: "{app}"

[Code]
var
  OwnerName, OwnerAppData: String;
  RemoveVault: Boolean;

{ The setup runs elevated; the vault belongs to the person who started it. }
procedure ReadOriginalUser();
var
  OutFile: String;
  Lines: TArrayOfString;
  ResultCode: Integer;
begin
  OutFile := ExpandConstant('{%PUBLIC|C:\Users\Public}\secretbroker-setup-owner.txt');
  DeleteFile(OutFile);
  ExecAsOriginalUser(ExpandConstant('{cmd}'), '/c (whoami & echo %APPDATA%) > "' + OutFile + '"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  if LoadStringsFromFile(OutFile, Lines) and (GetArrayLength(Lines) >= 2) then
  begin
    OwnerName := Trim(Lines[0]);
    OwnerAppData := Trim(Lines[1]);
  end;
  DeleteFile(OutFile);
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ResultCode: Integer;
begin
  ReadOriginalUser();
  if OwnerName = '' then
  begin
    Result := CustomMessage('OwnerUnknown');
    exit;
  end;
  { Stop a running service and app so their files can be replaced. }
  Exec('schtasks.exe', '/End /TN "SecretBroker Service"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec('powershell.exe', '-NoProfile -Command "Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -like ''' +
       ExpandConstant('{app}') + '\*'' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }"',
       '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Result := '';
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  ResultCode: Integer;
begin
  if CurStep <> ssPostInstall then
    exit;
  WizardForm.StatusLabel.Caption := CustomMessage('ConfiguringService');
  WizardForm.ProgressGauge.Style := npbstMarquee;
  Exec('powershell.exe', '-NoProfile -ExecutionPolicy Bypass -File "' + ExpandConstant('{app}\setup\configure.ps1') +
       '" -Owner "' + OwnerName + '" -OwnerAppData "' + OwnerAppData + '"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  WizardForm.ProgressGauge.Style := npbstNormal;
  if ResultCode <> 0 then
  begin
    MsgBox(CustomMessage('ServiceFailed') + #13#10 + CustomMessage('Details') + ' ' +
           ExpandConstant('{app}\setup\configure.log'), mbError, MB_OK);
    exit;
  end;
  { Connect Claude Code / Claude Desktop for the desktop user, if they are installed. }
  WizardForm.StatusLabel.Caption := CustomMessage('ConnectingClaude');
  ExecAsOriginalUser(ExpandConstant('{app}\python\python.exe'),
       '-I -c "from secretbroker import integrations; integrations.auto_connect()"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  { Let the browser extension reach SecretBroker: native messaging host manifests and HKCU keys for Chrome,
    Chromium, Edge, Brave and Firefox, for the desktop user (the app does it again on every start). }
  ExecAsOriginalUser(ExpandConstant('{app}\python\python.exe'),
       '-I -c "from secretbroker import native_host; native_host.register()"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

function NeedsAddPath(Dir: String): Boolean;
var
  Path: String;
begin
  if not RegQueryStringValue(HKLM, 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment', 'Path', Path) then
  begin
    Result := True;
    exit;
  end;
  Result := Pos(';' + Uppercase(Dir) + ';', ';' + Uppercase(Path) + ';') = 0;
end;

procedure RemoveFromPath(Dir: String);
var
  Path: String;
  P: Integer;
begin
  if not RegQueryStringValue(HKLM, 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment', 'Path', Path) then
    exit;
  P := Pos(';' + Uppercase(Dir) + ';', ';' + Uppercase(Path) + ';');
  if P = 0 then
    exit;
  if P = 1 then
    Delete(Path, 1, Length(Dir) + 1)
  else
    Delete(Path, P - 1, Length(Dir) + 1);
  RegWriteExpandStringValue(HKLM, 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment', 'Path', Path);
end;

{ [UninstallRun] removes the service first; the vault is only deleted afterwards, and only if asked.
  Silent uninstalls keep it. }
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  DataRoot: String;
begin
  DataRoot := ExpandConstant('{commonappdata}\SecretBroker');
  if (CurUninstallStep = usUninstall) and DirExists(DataRoot + '\data') then
    RemoveVault := SuppressibleMsgBox(FmtMessage(CustomMessage('RemoveVault'), [DataRoot]),
      mbConfirmation, MB_YESNO or MB_DEFBUTTON2, IDNO) = IDYES;
  if CurUninstallStep = usUninstall then
    RemoveFromPath(ExpandConstant('{app}\bin'));
  if (CurUninstallStep = usPostUninstall) and RemoveVault then
    if not DelTree(DataRoot, True, True, True) then
      SuppressibleMsgBox(FmtMessage(CustomMessage('RemoveFailed'), [DataRoot]), mbError, MB_OK, IDOK);
end;
